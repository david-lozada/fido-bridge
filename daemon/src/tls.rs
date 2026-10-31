use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::config::{cert_paths, Config};

pub fn ensure_daemon_identity(daemon_name: &str) -> Result<(PathBufPair, String)> {
    let (cert_path, key_path) = cert_paths()?;
    if !cert_path.exists() || !key_path.exists() {
        generate_self_signed(daemon_name, &cert_path, &key_path)?;
    }
    let cert_pem = fs::read_to_string(&cert_path)?;
    let fp = fingerprint_pem(&cert_pem)?;
    Ok((
        PathBufPair {
            cert: cert_path,
            key: key_path,
        },
        fp,
    ))
}

pub struct PathBufPair {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
}

fn generate_self_signed(name: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = CertificateParams::new(vec![name.to_string()])?;
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".try_into()?));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, key_pair.serialize_pem())?;
    // Restrict key permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn fingerprint_pem(pem: &str) -> Result<String> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert pem")?;
    let Some(cert) = certs.first() else {
        bail!("no certificate in pem");
    };
    Ok(fingerprint_der(cert.as_ref()))
}

pub fn fingerprint_der(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hex::encode(hash)
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("load certs")?;
    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path)?;
    let mut reader = std::io::Cursor::new(data);
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("load private key")?;
    let Some(key) = keys.into_iter().next() else {
        bail!("no private key in {}", path.display());
    };
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
}

/// Server config that optionally requires client certs from paired phones.
pub fn build_server_config(cfg: &Config, require_client: bool) -> Result<Arc<ServerConfig>> {
    let (cert_path, key_path) = cert_paths()?;
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let builder = if require_client && !cfg.paired_phones.is_empty() {
        let _ = WebPkiClientVerifier::builder(Arc::new(RootCertStore::empty()));
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(FingerprintVerifier {
                allowed: cfg
                    .paired_phones
                    .iter()
                    .map(|p| p.fingerprint.to_lowercase())
                    .collect(),
            }))
            .with_single_cert(certs, key)?
    } else {
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    Ok(Arc::new(builder))
}

/// During pairing we do not require a client cert (phone posts cert in JSON).
pub fn build_pairing_server_config() -> Result<Arc<ServerConfig>> {
    let (cert_path, key_path) = cert_paths()?;
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct FingerprintVerifier {
    allowed: Vec<String>,
}

impl rustls::server::danger::ClientCertVerifier for FingerprintVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let fp = fingerprint_der(end_entity.as_ref());
        if self.allowed.iter().any(|a| a == &fp) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "client certificate fingerprint {fp} is not paired"
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

pub fn parse_and_fingerprint_pem(pem: &str) -> Result<(Vec<u8>, String)> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse phone cert")?;
    let Some(cert) = certs.into_iter().next() else {
        bail!("empty phone certificate");
    };
    let fp = fingerprint_der(cert.as_ref());
    Ok((cert.as_ref().to_vec(), fp))
}
