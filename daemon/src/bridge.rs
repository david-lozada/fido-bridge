use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

use crate::audit::AuditLog;
use crate::config::Config;
use crate::ctaphid::{
    self, AssembledMessage, CtaphidEngine, CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_INIT,
    CTAPHID_KEEPALIVE, CTAPHID_PING, CTAPHID_WINK, ERR_CHANNEL_BUSY, ERR_INVALID_CMD,
    ERR_MSG_TIMEOUT, HID_REPORT_SIZE,
};
use crate::local_ctap;
use crate::mdns::MdnsAdvertisement;
use crate::protocol::{self, BridgeMessage};
use crate::rate_limit::RateLimiter;
use crate::tls;
use crate::uhid::UhidDevice;

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<Vec<u8>>>>>;

#[derive(Clone)]
struct AppState {
    phone_tx: Arc<Mutex<Option<mpsc::Sender<BridgeMessage>>>>,
    pending: PendingMap,
    audit: Arc<AuditLog>,
    rate: Arc<Mutex<RateLimiter>>,
    cfg: Config,
}

pub async fn run(cfg: Config) -> Result<()> {
    crate::audit::ensure_audit_file()?;
    let (_, daemon_fp) = tls::ensure_daemon_identity(&cfg.daemon_name)?;
    info!("daemon identity fp={daemon_fp}");

    if cfg.paired_phones.is_empty() {
        warn!("no paired phones — run `fido-bridged pair` first; getInfo still works locally");
    }

    let uhid = UhidDevice::create("FIDO Bridge", cfg.vendor_id, cfg.product_id)?;
    let uhid = Arc::new(std::sync::Mutex::new(uhid));
    let (hid_in_tx, mut hid_in_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);
    let (hid_out_tx, mut hid_out_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);

    {
        let uhid = uhid.clone();
        tokio::task::spawn_blocking(move || loop {
            while let Ok(report) = hid_out_rx.try_recv() {
                if let Ok(mut d) = uhid.lock() {
                    let _ = d.send_input(&report);
                }
            }
            if let Ok(mut d) = uhid.lock() {
                match d.read_event() {
                    Ok(Some(report)) => {
                        let _ = hid_in_tx.blocking_send(report);
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                    Err(e) => {
                        warn!("uhid read error: {e}");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }

    let _mdns = MdnsAdvertisement::start(&cfg.daemon_name, cfg.listen_port).ok();

    let state = AppState {
        phone_tx: Arc::new(Mutex::new(None)),
        pending: Arc::new(Mutex::new(HashMap::new())),
        audit: Arc::new(AuditLog::new()),
        rate: Arc::new(Mutex::new(RateLimiter::default_auth())),
        cfg: cfg.clone(),
    };

    let app_state = state.clone();
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(|| async { "ok" }))
        .with_state(app_state);

    let tls_config = tls::build_server_config(&cfg, true)?;
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.listen_port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!("listening on https://0.0.0.0:{}", cfg.listen_port);

    // Accept TLS + serve HTTP in background
    let app_clone = app.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("accept: {e}");
                    continue;
                }
            };
            let tls_config = tls_config.clone();
            let app = app_clone.clone();
            tokio::spawn(async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                info!("TLS client connected from {peer}");
                let _ = axum::serve(
                    SingleConnListener::new(stream, peer),
                    app,
                )
                .await;
            });
        }
    });

    // CTAPHID processing loop
    let mut engine = CtaphidEngine::new();
    while let Some(report) = hid_in_rx.recv().await {
        if let Some(msg) = engine.ingest(&report) {
            handle_hid_message(&state, &mut engine, msg, &hid_out_tx).await;
        }
    }
    Ok(())
}

struct SingleConnListener<S> {
    inner: Option<S>,
    addr: SocketAddr,
}

impl<S> SingleConnListener<S> {
    fn new(s: S, addr: SocketAddr) -> Self {
        Self {
            inner: Some(s),
            addr,
        }
    }
}

impl<S> axum::serve::Listener for SingleConnListener<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Io = S;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.inner.take() {
            Some(s) => (s, self.addr),
            None => {
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.addr)
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| phone_ws(socket, state))
}

async fn phone_ws(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<BridgeMessage>(32);
    {
        let mut slot = state.phone_tx.lock().await;
        *slot = Some(tx);
    }
    info!("phone WebSocket registered");

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(text) = protocol::encode(&msg) {
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    while let Some(Ok(msg)) = stream.next().await {
        let Message::Text(text) = msg else {
            continue;
        };
        match protocol::decode(&text) {
            Ok(BridgeMessage::Hello { name, .. }) => {
                info!("phone hello from {name}");
            }
            Ok(BridgeMessage::Pong { .. }) => {}
            Ok(BridgeMessage::CtapResponse {
                id,
                status,
                data,
                ctap_status,
                error,
            }) => {
                let bytes = if status == "ok" {
                    data.and_then(|d| {
                        base64::engine::general_purpose::STANDARD
                            .decode(d)
                            .ok()
                    })
                    .unwrap_or_else(|| {
                        vec![ctap_status.unwrap_or(local_ctap::CTAP2_ERR_OPERATION_DENIED)]
                    })
                } else {
                    tracing::warn!("phone error: {:?}", error);
                    vec![ctap_status.unwrap_or(local_ctap::CTAP2_ERR_OPERATION_DENIED)]
                };
                if let Some(sender) = state.pending.lock().await.remove(&id) {
                    let _ = sender.send(bytes);
                }
                state.rate.lock().await.end();
            }
            Ok(other) => {
                warn!("unexpected phone message: {:?}", other);
            }
            Err(e) => warn!("bad phone message: {e}"),
        }
    }

    {
        let mut slot = state.phone_tx.lock().await;
        *slot = None;
    }
    writer.abort();
    info!("phone WebSocket disconnected");
}

async fn handle_hid_message(
    state: &AppState,
    engine: &mut CtaphidEngine,
    msg: AssembledMessage,
    hid_out: &mpsc::Sender<[u8; HID_REPORT_SIZE]>,
) {
    match msg.cmd {
        CTAPHID_INIT => {
            if msg.payload.len() < 8 {
                send_packets(hid_out, CtaphidEngine::error_response(msg.cid, ERR_INVALID_CMD))
                    .await;
                return;
            }
            let nonce = &msg.payload[..8];
            let new_cid = if msg.cid == ctaphid::BROADCAST_CID {
                engine.alloc_cid()
            } else {
                msg.cid
            };
            let mut resp = Vec::with_capacity(17);
            resp.extend_from_slice(nonce);
            resp.extend_from_slice(&new_cid);
            resp.push(2); // CTAPHID version
            resp.push(0); // major
            resp.push(1); // minor
            resp.push(0); // build
            resp.push(0x04); // CAPABILITY_CBOR
            send_packets(
                hid_out,
                CtaphidEngine::encode_response(msg.cid, CTAPHID_INIT, &resp),
            )
            .await;
        }
        CTAPHID_PING => {
            send_packets(
                hid_out,
                CtaphidEngine::encode_response(msg.cid, CTAPHID_PING, &msg.payload),
            )
            .await;
        }
        CTAPHID_WINK => {
            info!("WINK");
            send_packets(
                hid_out,
                CtaphidEngine::encode_response(msg.cid, CTAPHID_WINK, &[]),
            )
            .await;
        }
        CTAPHID_CANCEL => {
            // Cancel all pending
            let mut pending = state.pending.lock().await;
            for (id, _) in pending.drain() {
                if let Some(tx) = state.phone_tx.lock().await.as_ref() {
                    let _ = tx
                        .send(BridgeMessage::CtapCancel { id })
                        .await;
                }
            }
            state.rate.lock().await.end();
        }
        CTAPHID_CBOR => {
            handle_cbor(state, msg, hid_out).await;
        }
        other => {
            warn!("unsupported CTAPHID cmd 0x{other:02x}");
            send_packets(
                hid_out,
                CtaphidEngine::error_response(msg.cid, ERR_INVALID_CMD),
            )
            .await;
        }
    }
}

async fn handle_cbor(
    state: &AppState,
    msg: AssembledMessage,
    hid_out: &mpsc::Sender<[u8; HID_REPORT_SIZE]>,
) {
    if let Some(local) = local_ctap::try_local_response(&msg.payload) {
        send_packets(
            hid_out,
            CtaphidEngine::encode_response(msg.cid, CTAPHID_CBOR, &local),
        )
        .await;
        return;
    }

    // Rate limit
    if state.rate.lock().await.begin().is_err() {
        send_packets(
            hid_out,
            CtaphidEngine::error_response(msg.cid, ERR_CHANNEL_BUSY),
        )
        .await;
        return;
    }

    let phone_tx = state.phone_tx.lock().await.clone();
    let Some(phone_tx) = phone_tx else {
        state.rate.lock().await.end();
        state.audit.log("-", local_ctap::extract_rp_id(&msg.payload).as_deref().unwrap_or("-"), "no_phone");
        // Return operation denied so browser fails cleanly
        send_packets(
            hid_out,
            CtaphidEngine::encode_response(msg.cid, CTAPHID_CBOR, &local_ctap::denied_response()),
        )
        .await;
        return;
    };

    let id = Uuid::new_v4().to_string();
    let rp_id = local_ctap::extract_rp_id(&msg.payload);
    let (resp_tx, resp_rx) = oneshot::channel();
    state.pending.lock().await.insert(id.clone(), resp_tx);

    let cmd_b64 = base64::engine::general_purpose::STANDARD.encode(&msg.payload);
    let _ = phone_tx
        .send(BridgeMessage::CtapRequest {
            id: id.clone(),
            cmd: cmd_b64,
            timeout_ms: 60_000,
            rp_id: rp_id.clone(),
        })
        .await;

    // Send keepalives while waiting
    let hid_out2 = hid_out.clone();
    let cid = msg.cid;
    let keepalive = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let pkt = CtaphidEngine::encode_response(
                cid,
                CTAPHID_KEEPALIVE,
                &[local_ctap::CTAP2_KEEPALIVE_STATUS_UPNEEDED],
            );
            send_packets(&hid_out2, pkt).await;
        }
    });

    let result = tokio::time::timeout(Duration::from_secs(60), resp_rx).await;
    keepalive.abort();
    state.rate.lock().await.end();
    state.pending.lock().await.remove(&id);

    match result {
        Ok(Ok(data)) => {
            state.audit.log(
                &id,
                rp_id.as_deref().unwrap_or("-"),
                if data.first() == Some(&0) { "ok" } else { "ctap_error" },
            );
            send_packets(
                hid_out,
                CtaphidEngine::encode_response(msg.cid, CTAPHID_CBOR, &data),
            )
            .await;
        }
        Ok(Err(_)) => {
            state.audit.log(&id, rp_id.as_deref().unwrap_or("-"), "cancelled");
            send_packets(
                hid_out,
                CtaphidEngine::error_response(msg.cid, ERR_MSG_TIMEOUT),
            )
            .await;
        }
        Err(_) => {
            state.audit.log(&id, rp_id.as_deref().unwrap_or("-"), "timeout");
            let _ = phone_tx
                .send(BridgeMessage::CtapCancel { id })
                .await;
            send_packets(
                hid_out,
                CtaphidEngine::error_response(msg.cid, ERR_MSG_TIMEOUT),
            )
            .await;
        }
    }
}

async fn send_packets(tx: &mpsc::Sender<[u8; HID_REPORT_SIZE]>, packets: Vec<[u8; HID_REPORT_SIZE]>) {
    for p in packets {
        let _ = tx.send(p).await;
    }
}

// Silence unused Instant import warning path
#[allow(dead_code)]
fn _now() -> Instant {
    Instant::now()
}
