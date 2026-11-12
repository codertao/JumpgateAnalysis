//! Jumpgate's own message framing, which sits *inside* a RakNet internal
//! packet's payload (above the RakNet transport):
//!
//! ```text
//! C → S :  [0x51][obfuscated]
//! S → C :  [0x1A][u32 time][0x51][obfuscated]      (0x1A = ID_TIMESTAMP)
//! ```
//!
//! The obfuscation is a reversible salt + running-sum scramble (not encryption),
//! ported from `0x9c8ca0` / `0x9c8d30` (and `tools/jgdecode.py`). Used only to
//! decode messages for logging; the proxy forwards payloads verbatim.

/// MSVC `rand()`-derived key byte for a given salt (verified in the binary).
fn obfuscation_k(salt: u8) -> u8 {
    let s = (salt as u32).wrapping_mul(0x89);
    let s = s.wrapping_mul(0x0003_43fd).wrapping_add(0x0026_9ec3); // one MSVC rand() step
    let r = (s >> 16) & 0x7fff;
    // 254/32767 as f32 (bytes fc 01 fe 3b); `_ftol` truncates toward zero.
    let f = f32::from_le_bytes([0xfc, 0x01, 0xfe, 0x3b]);
    ((r as f32 * f) as u32 & 0xff) as u8
}

/// Reverse the obfuscation. `enc[0]` is the salt; returns `enc.len()-1` bytes.
pub fn deobfuscate(enc: &[u8]) -> Vec<u8> {
    if enc.len() < 2 {
        return Vec::new();
    }
    let k = obfuscation_k(enc[0]);
    let mut out = Vec::with_capacity(enc.len() - 1);
    out.push(enc[1].wrapping_sub(k));
    for i in 2..enc.len() {
        out.push(enc[i].wrapping_sub(enc[i - 1]));
    }
    out
}

/// Apply the obfuscation to a plaintext message with the given salt.
pub fn obfuscate(msg: &[u8], salt: u8) -> Vec<u8> {
    let k = obfuscation_k(salt);
    let mut out = Vec::with_capacity(msg.len() + 1);
    out.push(salt);
    if msg.is_empty() {
        return out;
    }
    out.push(msg[0].wrapping_add(k));
    for &b in &msg[1..] {
        let prev = *out.last().unwrap();
        out.push(prev.wrapping_add(b));
    }
    out
}

/// A decoded game-layer message extracted from a RakNet packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameMessage {
    /// Present for server→client messages (ID_TIMESTAMP wrapper).
    pub timestamp: Option<u32>,
    /// Deobfuscated message bytes; `body[0]` is the game message type.
    pub body: Vec<u8>,
}

impl GameMessage {
    pub fn message_type(&self) -> Option<u8> {
        self.body.first().copied()
    }
}

/// Decode a RakNet packet payload (`packet.data`) into a game message, peeling
/// the optional 0x1A timestamp and the 0x51 frame. Returns `None` if the payload
/// is not a 0x51-framed game message (e.g. a pure transport ID).
pub fn decode_payload(payload: &[u8]) -> Option<GameMessage> {
    let mut p = payload;
    let mut timestamp = None;
    if p.first() == Some(&0x1A) && p.len() >= 5 {
        timestamp = Some(u32::from_le_bytes([p[1], p[2], p[3], p[4]]));
        p = &p[5..];
    }
    if p.first() != Some(&0x51) {
        return None;
    }
    Some(GameMessage {
        timestamp,
        body: deobfuscate(&p[1..]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_round_trips_all_salts() {
        let msg = vec![0x09, 0x03, 0x12, 0x00, 0x00, 0xf9, 0x0e];
        for salt in 0u8..=254 {
            let enc = obfuscate(&msg, salt);
            assert_eq!(enc[0], salt);
            assert_eq!(deobfuscate(&enc), msg, "salt {salt}");
        }
    }

    #[test]
    fn decode_client_and_server_frames() {
        let body = vec![0x09, 0xAB, 0xCD];
        let framed_c = {
            let mut v = vec![0x51];
            v.extend(obfuscate(&body, 42));
            v
        };
        let g = decode_payload(&framed_c).unwrap();
        assert_eq!(g.timestamp, None);
        assert_eq!(g.body, body);

        let framed_s = {
            let mut v = vec![0x1A, 0x44, 0x33, 0x22, 0x11, 0x51];
            v.extend(obfuscate(&body, 7));
            v
        };
        let g = decode_payload(&framed_s).unwrap();
        assert_eq!(g.timestamp, Some(0x1122_3344));
        assert_eq!(g.body, body);
        assert_eq!(g.message_type(), Some(0x09));
    }
}
