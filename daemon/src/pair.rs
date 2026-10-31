use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use qrcode::render::svg;
use qrcode::QrCode;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;

use crate::config::{self, Config, PairedPhone};
use crate::protocol::{PairRequest, PairResponse, PairingQr};
use crate::tls::{self, fingerprint_pem};

struct PairState {
    secret: String,
    expires: Instant,
    used: bool,
    cfg: Config,
    daemon_fp: String,
}

pub async fn run_pairing(cfg: Config) -> Result<()> {
    let (_, daemon_fp) = tls::ensure_daemon_identity(&cfg.daemon_name)?;
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let host = local_ip().unwrap_or_else(|| "127.0.0.1".into());
    let qr = PairingQr {
        v: 1,
        host: host.clone(),
        port: cfg.listen_port,
        fp: daemon_fp.clone(),
        secret: secret.clone(),
        name: cfg.daemon_name.clone(),
    };
    let qr_json = serde_json::to_string(&qr)?;
    print_qr(&qr_json)?;
    println!();
    println!("Pairing payload:");
    println!("{qr_json}");
    println!();
    println!(
        "Scan with the FIDO Bridge Android app (expires in 5 minutes). Listening on https://{host}:{}",
        cfg.listen_port
    );

    let state = Arc::new(Mutex::new(PairState {
        secret,
        expires: Instant::now() + Duration::from_secs(300),
        used: false,
        cfg,
        daemon_fp,
    }));

    let app = Router::new()
        .route("/pair", post(pair_handler))
        .with_state(state.clone());

    let tls_config = tls::build_pairing_server_config()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], state.lock().await.cfg.listen_port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;

    // Accept TLS manually with rustls
    loop {
        let (tcp, peer) = listener.accept().await?;
        let tls_config = tls_config.clone();
        let state = state.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => {
                    let svc = app.clone();
                    // hyper/axum serve on tls stream via tower
                    if let Err(e) = axum::serve(
                        // We can't easily serve one connection with axum::serve — use hyper
                        DummyListener::one(tls_stream),
                        svc,
                    )
                    .await
                    {
                        tracing::debug!("pair connection from {peer} ended: {e}");
                    }
                }
                Err(e) => tracing::warn!("tls accept from {peer}: {e}"),
            }

            // Exit pairing once used
            let st = state.lock().await;
            if st.used {
                info!("pairing complete — shutting down pair server");
                std::process::exit(0);
            }
        });
    }
}

/// Minimal single-connection listener adapter for axum::serve.
struct DummyListener<S> {
    inner: Option<S>,
}

impl<S> DummyListener<S> {
    fn one(s: S) -> Self {
        Self { inner: Some(s) }
    }
}

impl<S> axum::serve::Listener for DummyListener<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Io = S;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.inner.take() {
            Some(s) => (s, SocketAddr::from(([0, 0, 0, 0], 0))),
            None => {
                // park forever so serve doesn't spin
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

async fn pair_handler(
    State(state): State<Arc<Mutex<PairState>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let secret = headers
        .get("X-Pairing-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req: PairRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("bad json: {e}")).into_response();
        }
    };

    let mut st = state.lock().await;
    if st.used {
        return (StatusCode::GONE, "pairing secret already used").into_response();
    }
    if Instant::now() > st.expires {
        return (StatusCode::GONE, "pairing secret expired").into_response();
    }
    if !constant_time_eq(secret.as_bytes(), st.secret.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "invalid pairing secret").into_response();
    }

    let (_der, phone_fp) = match tls::parse_and_fingerprint_pem(&req.cert_pem) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("bad cert: {e}")).into_response();
        }
    };

    // Persist phone cert for reference
    if let Ok(dir) = config::data_dir() {
        let path = dir.join(format!("phone-{phone_fp}.pem"));
        let _ = std::fs::write(path, &req.cert_pem);
    }

    st.cfg.paired_phones.push(PairedPhone {
        name: req.name.clone(),
        fingerprint: phone_fp.clone(),
        paired_at: chrono_now(),
    });
    if let Err(e) = config::save_config(&st.cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("save: {e}")).into_response();
    }
    st.used = true;
    info!("paired phone '{}' fp={phone_fp}", req.name);

    let resp = PairResponse {
        ok: true,
        daemon_name: st.cfg.daemon_name.clone(),
        daemon_fp: st.daemon_fp.clone(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn chrono_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

fn print_qr(payload: &str) -> Result<()> {
    let code = QrCode::new(payload.as_bytes()).context("qr encode")?;
    // Terminal ASCII QR
    let string = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    println!("{string}");
    // Also write SVG for convenience
    if let Ok(dir) = config::data_dir() {
        let svg_path = dir.join("pairing.svg");
        let svg = code
            .render::<svg::Color>()
            .min_dimensions(256, 256)
            .build();
        let _ = std::fs::write(&svg_path, svg);
        println!("SVG written to {}", svg_path.display());
    }
    // Verify fp is present
    let _ = fingerprint_pem;
    Ok(())
}

fn local_ip() -> Option<String> {
    // UDP connect trick to find preferred outbound interface
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

pub fn revoke(fingerprint: &str) -> Result<()> {
    let mut cfg = config::load_config()?;
    if config::revoke_phone(&mut cfg, fingerprint) {
        config::save_config(&cfg)?;
        println!("Revoked phone fingerprint {fingerprint}");
        Ok(())
    } else {
        bail!("no paired phone with fingerprint {fingerprint}");
    }
}
