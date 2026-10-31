//! CLI dummy phone for end-to-end protocol testing without Android.

use anyhow::{bail, Context, Result};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};
use tracing::info;
use uuid::Uuid;

use crate::config;
use crate::local_ctap;
use crate::protocol::{self, BridgeMessage, PairRequest, PairResponse};
use crate::tls::{fingerprint_der, fingerprint_pem};

pub async fn run(daemon_url: Option<String>, pair_json: Option<PathBuf>) -> Result<()> {
    let data = config::data_dir()?.join("dummy-phone");
    fs::create_dir_all(&data)?;
    let cert_path = data.join("cert.pem");
    let key_path = data.join("key.pem");

    if !cert_path.exists() {
        generate_client_identity(&cert_path, &key_path)?;
    }
    let cert_pem = fs::read_to_string(&cert_path)?;
    let phone_fp = fingerprint_pem(&cert_pem)?;
    info!("dummy phone fp={phone_fp}");

    if let Some(path) = pair_json {
        let text = fs::read_to_string(&path)?;
        let qr: crate::protocol::PairingQr = serde_json::from_str(&text)?;
        do_pair(&qr, &cert_pem).await?;
        println!("Paired with {}", qr.name);
        return Ok(());
    }

    let url = daemon_url.unwrap_or_else(|| "wss://127.0.0.1:17443/ws".into());
    let pinned = pinned_daemon_fp()?;
    connect_ws(&url, &cert_path, &key_path, pinned.as_deref()).await
}

fn generate_client_identity(cert_path: &PathBuf, key_path: &PathBuf) -> Result<()> {
    let mut params = CertificateParams::new(vec!["dummy-phone".into()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "dummy-phone");
    params.distinguished_name = dn;
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, key.serialize_pem())?;
    Ok(())
}

async fn do_pair(qr: &crate::protocol::PairingQr, cert_pem: &str) -> Result<()> {
    // Dangerously accept daemon cert matching fingerprint via custom verifier
    let url = format!("https://{}:{}/pair", qr.host, qr.port);
    info!("pairing POST {url}");

    // Use tokio + rustls manually for simplicity with fingerprint pin
    let addr = format!("{}:{}", qr.host, qr.port);
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect {addr}"))?;

    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            expected: qr.fp.to_lowercase(),
        }))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(qr.host.clone()).unwrap_or(ServerName::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
    ));
    let mut tls = connector.connect(server_name, tcp).await?;

    let body = serde_json::to_vec(&PairRequest {
        name: "dummy-phone".into(),
        cert_pem: cert_pem.to_string(),
    })?;
    let req = format!(
        "POST /pair HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Pairing-Secret: {}\r\nConnection: close\r\n\r\n",
        qr.host,
        body.len(),
        qr.secret
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(&body).await?;
    let mut resp = Vec::new();
    tls.read_to_end(&mut resp).await?;
    let text = String::from_utf8_lossy(&resp);
    info!("pair response:\n{text}");
    if let Some(json_start) = text.find('{') {
        let pr: PairResponse = serde_json::from_str(&text[json_start..])?;
        if !pr.ok {
            bail!("pair failed");
        }
        fs::write(config::data_dir()?.join("dummy-phone/daemon_fp.txt"), &pr.daemon_fp)?;
    } else {
        bail!("unexpected pair HTTP response");
    }
    Ok(())
}

fn pinned_daemon_fp() -> Result<Option<String>> {
    let path = config::data_dir()?.join("dummy-phone/daemon_fp.txt");
    if path.exists() {
        Ok(Some(fs::read_to_string(path)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

async fn connect_ws(
    url: &str,
    cert_path: &PathBuf,
    key_path: &PathBuf,
    pinned: Option<&str>,
) -> Result<()> {
    let certs = crate::tls::load_certs(cert_path)?;
    let key = crate::tls::load_private_key(key_path)?;

    let builder = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?;

    let config = if let Some(fp) = pinned {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                expected: fp.to_lowercase(),
            }))
            .with_client_auth_cert(certs, key)?
    } else {
        // Dev fallback: accept any server cert
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                expected: String::new(), // empty = accept any
            }))
            .with_client_auth_cert(certs, key)?
    };

    let connector = Connector::Rustls(Arc::new(config));
    let (ws, _) = connect_async_tls_with_config(url, None, false, Some(connector))
        .await
        .with_context(|| format!("ws connect {url}"))?;
    let (mut sink, mut stream) = ws.split();

    let hello = BridgeMessage::Hello {
        id: Uuid::new_v4().to_string(),
        name: "dummy-phone".into(),
        aaguid: Some(hex::encode(local_ctap::AAGUID)),
        versions: vec!["FIDO_2_0".into()],
    };
    sink.send(Message::Text(protocol::encode(&hello)?.into()))
        .await?;

    info!("dummy phone connected — answering getInfo locally already handled by daemon; for makeCredential/getAssertion returns DENIED with note");

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let Message::Text(text) = msg else {
            continue;
        };
        match protocol::decode(&text) {
            Ok(BridgeMessage::CtapRequest {
                id,
                cmd,
                rp_id,
                ..
            }) => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(&cmd)?;
                info!(
                    "ctap_request id={id} rp={:?} cmd={}",
                    rp_id,
                    local_ctap::command_name(&bytes)
                );
                // Dummy: return a getInfo if somehow forwarded, else DENIED
                let data = if let Some(local) = local_ctap::try_local_response(&bytes) {
                    local
                } else {
                    // Simulate biometric delay
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    local_ctap::denied_response()
                };
                let resp = BridgeMessage::CtapResponse {
                    id,
                    status: "ok".into(),
                    data: Some(base64::engine::general_purpose::STANDARD.encode(data)),
                    error: None,
                    ctap_status: None,
                };
                sink.send(Message::Text(protocol::encode(&resp)?.into()))
                    .await?;
            }
            Ok(BridgeMessage::CtapCancel { id }) => {
                info!("cancel {id}");
            }
            Ok(BridgeMessage::Ping { id, ts }) => {
                let pong = BridgeMessage::Pong { id, ts };
                sink.send(Message::Text(protocol::encode(&pong)?.into()))
                    .await?;
            }
            Ok(other) => info!("msg: {:?}", other),
            Err(e) => tracing::warn!("decode: {e}"),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct PinVerifier {
    expected: String,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.expected.is_empty() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        let fp = fingerprint_der(end_entity.as_ref());
        if fp == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server fp {fp} != expected {}",
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[allow(dead_code)]
fn _rng_touch() {
    let mut b = [0u8; 1];
    rand::rng().fill_bytes(&mut b);
}
