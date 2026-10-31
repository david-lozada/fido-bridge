//! CTAPHID framing (FIDO Alliance CTAP HID transport).

use std::collections::HashMap;
use tracing::{debug, warn};

pub const HID_REPORT_SIZE: usize = 64;
pub const CTAPHID_INIT: u8 = 0x06;
pub const CTAPHID_PING: u8 = 0x01;
pub const CTAPHID_WINK: u8 = 0x08;
pub const CTAPHID_CBOR: u8 = 0x10;
pub const CTAPHID_CANCEL: u8 = 0x11;
pub const CTAPHID_ERROR: u8 = 0x3F;
pub const CTAPHID_KEEPALIVE: u8 = 0x3B;
pub const CTAPHID_MSG: u8 = 0x03;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

pub const BROADCAST_CID: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

#[derive(Debug, Clone)]
pub struct AssembledMessage {
    pub cid: [u8; 4],
    pub cmd: u8,
    pub payload: Vec<u8>,
}

#[derive(Default)]
struct Partial {
    cmd: u8,
    expected: usize,
    next_seq: u8,
    buf: Vec<u8>,
}

/// Reassembles CTAPHID packets into complete messages and splits responses.
pub struct CtaphidEngine {
    partials: HashMap<[u8; 4], Partial>,
    next_cid: u32,
}

impl Default for CtaphidEngine {
    fn default() -> Self {
        Self {
            partials: HashMap::new(),
            next_cid: 1,
        }
    }
}

impl CtaphidEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alloc_cid(&mut self) -> [u8; 4] {
        loop {
            let cid = self.next_cid.to_be_bytes();
            self.next_cid = self.next_cid.wrapping_add(1).max(1);
            if cid != BROADCAST_CID && cid != [0, 0, 0, 0] {
                return cid;
            }
        }
    }

    /// Feed one 64-byte HID report from the host. Returns a complete message when ready.
    pub fn ingest(&mut self, report: &[u8]) -> Option<AssembledMessage> {
        if report.len() < 5 {
            return None;
        }
        let mut cid = [0u8; 4];
        cid.copy_from_slice(&report[0..4]);
        let b4 = report[4];

        if b4 & 0x80 != 0 {
            // Initialization packet
            if report.len() < 7 {
                return None;
            }
            let cmd = b4 & 0x7f;
            let len = u16::from_be_bytes([report[5], report[6]]) as usize;
            let data = &report[7..];
            let take = data.len().min(len);
            let mut buf = Vec::with_capacity(len);
            buf.extend_from_slice(&data[..take]);

            if buf.len() >= len {
                buf.truncate(len);
                self.partials.remove(&cid);
                return Some(AssembledMessage {
                    cid,
                    cmd,
                    payload: buf,
                });
            }

            self.partials.insert(
                cid,
                Partial {
                    cmd,
                    expected: len,
                    next_seq: 0,
                    buf,
                },
            );
            None
        } else {
            // Continuation packet
            let seq = b4;
            let Some(partial) = self.partials.get_mut(&cid) else {
                warn!("continuation for unknown cid {:02x?}", cid);
                return None;
            };
            if seq != partial.next_seq {
                warn!(
                    "bad seq for cid {:02x?}: got {seq} want {}",
                    cid, partial.next_seq
                );
                self.partials.remove(&cid);
                return None;
            }
            let need = partial.expected.saturating_sub(partial.buf.len());
            let data = &report[5..];
            let take = data.len().min(need);
            partial.buf.extend_from_slice(&data[..take]);
            partial.next_seq = partial.next_seq.wrapping_add(1);
            if partial.buf.len() >= partial.expected {
                let msg = AssembledMessage {
                    cid,
                    cmd: partial.cmd,
                    payload: {
                        let mut b = std::mem::take(&mut partial.buf);
                        b.truncate(partial.expected);
                        b
                    },
                };
                self.partials.remove(&cid);
                Some(msg)
            } else {
                None
            }
        }
    }

    /// Split a response into 64-byte HID reports (no report ID).
    pub fn encode_response(cid: [u8; 4], cmd: u8, payload: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        let mut out = Vec::new();
        let mut remaining = payload;
        let mut first = true;
        let mut seq = 0u8;

        while first || !remaining.is_empty() {
            let mut pkt = [0u8; HID_REPORT_SIZE];
            pkt[0..4].copy_from_slice(&cid);
            if first {
                pkt[4] = cmd | 0x80;
                let len = payload.len() as u16;
                pkt[5..7].copy_from_slice(&len.to_be_bytes());
                let space = HID_REPORT_SIZE - 7;
                let take = remaining.len().min(space);
                pkt[7..7 + take].copy_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
                first = false;
            } else {
                pkt[4] = seq;
                seq = seq.wrapping_add(1);
                let space = HID_REPORT_SIZE - 5;
                let take = remaining.len().min(space);
                pkt[5..5 + take].copy_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
            }
            out.push(pkt);
            if remaining.is_empty() && !first {
                // already pushed at least the init packet
                if payload.is_empty() && out.len() == 1 {
                    break;
                }
                if remaining.is_empty() {
                    break;
                }
            }
        }

        if out.is_empty() {
            // empty payload still needs an init packet
            let mut pkt = [0u8; HID_REPORT_SIZE];
            pkt[0..4].copy_from_slice(&cid);
            pkt[4] = cmd | 0x80;
            out.push(pkt);
        }

        debug!(
            "encoded cmd=0x{cmd:02x} len={} into {} packets",
            payload.len(),
            out.len()
        );
        out
    }

    pub fn error_response(cid: [u8; 4], code: u8) -> Vec<[u8; HID_REPORT_SIZE]> {
        Self::encode_response(cid, CTAPHID_ERROR, &[code])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let mut eng = CtaphidEngine::new();
        let cid = [1, 2, 3, 4];
        let packets = CtaphidEngine::encode_response(cid, CTAPHID_PING, b"hi");
        assert_eq!(packets.len(), 1);
        let msg = eng.ingest(&packets[0]).unwrap();
        assert_eq!(msg.cmd, CTAPHID_PING);
        assert_eq!(msg.payload, b"hi");
    }

    #[test]
    fn roundtrip_large() {
        let mut eng = CtaphidEngine::new();
        let cid = [9, 9, 9, 9];
        let payload = vec![0xABu8; 200];
        let packets = CtaphidEngine::encode_response(cid, CTAPHID_CBOR, &payload);
        assert!(packets.len() > 1);
        let mut got = None;
        for p in &packets {
            if let Some(m) = eng.ingest(p) {
                got = Some(m);
            }
        }
        let msg = got.unwrap();
        assert_eq!(msg.payload, payload);
    }
}
