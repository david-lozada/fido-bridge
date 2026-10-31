use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BridgeMessage {
    Hello {
        id: String,
        name: String,
        #[serde(default)]
        aaguid: Option<String>,
        #[serde(default)]
        versions: Vec<String>,
    },
    Ping {
        id: String,
        ts: i64,
    },
    Pong {
        id: String,
        ts: i64,
    },
    CtapRequest {
        id: String,
        /// Base64 of CTAP2 payload (cmd byte + CBOR).
        cmd: String,
        timeout_ms: u64,
        #[serde(default)]
        rp_id: Option<String>,
    },
    CtapCancel {
        id: String,
    },
    CtapResponse {
        id: String,
        status: String,
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        ctap_status: Option<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingQr {
    pub v: u32,
    pub host: String,
    pub port: u16,
    pub fp: String,
    pub secret: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub name: String,
    pub cert_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    pub ok: bool,
    pub daemon_name: String,
    pub daemon_fp: String,
}

pub fn encode(msg: &BridgeMessage) -> Result<String, serde_json::Error> {
    serde_json::to_string(msg)
}

pub fn decode(text: &str) -> Result<BridgeMessage, serde_json::Error> {
    serde_json::from_str(text)
}
