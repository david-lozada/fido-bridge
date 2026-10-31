//! Local CTAP2 responders used when no phone is connected (getInfo) and helpers.

use serde_cbor::Value;
use std::collections::BTreeMap;

/// Fixed AAGUID for this authenticator bridge (16 bytes).
pub const AAGUID: [u8; 16] = [
    0xf1, 0xd0, 0xb7, 0x1d, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0xf1, 0xd0, 0xb7, 0x1d,
];

pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_INVALID_CMD: u8 = 0x01;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_NO_OPERATIONS: u8 = 0x25;
pub const CTAP2_ERR_CHANNEL_BUSY: u8 = 0x06; // hid layer; keep for mapping
pub const CTAP2_KEEPALIVE_STATUS_PROCESSING: u8 = 0x01;
pub const CTAP2_KEEPALIVE_STATUS_UPNEEDED: u8 = 0x02;

const CMD_GET_INFO: u8 = 0x04;
const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_CLIENT_PIN: u8 = 0x06;
const CMD_SELECTION: u8 = 0x0B;

/// Handle CTAP2 commands that can be answered without the phone.
/// Returns None if the command must be forwarded.
pub fn try_local_response(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return Some(vec![CTAP2_ERR_INVALID_CMD]);
    }
    match payload[0] {
        CMD_GET_INFO => Some(get_info_response()),
        CMD_SELECTION => Some(vec![CTAP2_OK]),
        _ => None,
    }
}

pub fn get_info_response() -> Vec<u8> {
    let mut map = BTreeMap::new();
    // 1: versions
    map.insert(
        Value::Integer(1),
        Value::Array(vec![
            Value::Text("FIDO_2_0".into()),
            Value::Text("FIDO_2_1_PRE".into()),
        ]),
    );
    // 2: extensions (none for v1)
    map.insert(Value::Integer(2), Value::Array(vec![]));
    // 3: aaguid
    map.insert(Value::Integer(3), Value::Bytes(AAGUID.to_vec()));
    // 4: options
    let mut options = BTreeMap::new();
    options.insert(Value::Text("rk".into()), Value::Bool(true));
    options.insert(Value::Text("up".into()), Value::Bool(true));
    options.insert(Value::Text("uv".into()), Value::Bool(true));
    options.insert(Value::Text("plat".into()), Value::Bool(false));
    options.insert(Value::Text("clientPin".into()), Value::Bool(false));
    map.insert(Value::Integer(4), Value::Map(options));
    // 5: maxMsgSize
    map.insert(Value::Integer(5), Value::Integer(1200));
    // 9: algorithms — { "type": "public-key", "alg": -7 }
    let mut alg_entry = BTreeMap::new();
    alg_entry.insert(Value::Text("alg".into()), Value::Integer(-7));
    alg_entry.insert(Value::Text("type".into()), Value::Text("public-key".into()));
    map.insert(
        Value::Integer(9),
        Value::Array(vec![Value::Map(alg_entry)]),
    );

    let mut out = vec![CTAP2_OK];
    let body = serde_cbor::to_vec(&Value::Map(map)).unwrap_or_default();
    out.extend(body);
    out
}

/// Best-effort RP ID extraction for UI display.
pub fn extract_rp_id(payload: &[u8]) -> Option<String> {
    if payload.len() < 2 {
        return None;
    }
    let cmd = payload[0];
    if cmd != CMD_MAKE_CREDENTIAL && cmd != CMD_GET_ASSERTION {
        return None;
    }
    let value: Value = serde_cbor::from_slice(&payload[1..]).ok()?;
    let Value::Map(map) = value else {
        return None;
    };
    if cmd == CMD_MAKE_CREDENTIAL {
        // key 2: rp — map with "id"
        if let Some(Value::Map(rp)) = map.get(&Value::Integer(2)) {
            if let Some(Value::Text(id)) = rp.get(&Value::Text("id".into())) {
                return Some(id.clone());
            }
        }
    } else {
        // getAssertion key 1: rpId
        if let Some(Value::Text(id)) = map.get(&Value::Integer(1)) {
            return Some(id.clone());
        }
    }
    None
}

pub fn command_name(payload: &[u8]) -> &'static str {
    match payload.first().copied() {
        Some(CMD_MAKE_CREDENTIAL) => "makeCredential",
        Some(CMD_GET_ASSERTION) => "getAssertion",
        Some(CMD_GET_INFO) => "getInfo",
        Some(CMD_CLIENT_PIN) => "clientPin",
        Some(CMD_SELECTION) => "selection",
        _ => "unknown",
    }
}

pub fn denied_response() -> Vec<u8> {
    vec![CTAP2_ERR_OPERATION_DENIED]
}

pub fn busy_response() -> Vec<u8> {
    vec![0x2A] // CTAP2_ERR_CHANNEL_BUSY-ish / CTAP2_ERR_PROCESSING — use 0x01 invalid when unsure
}
