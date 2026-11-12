//! Reader for `jgcap.bin`, the message-layer capture written by the Msb32 shim.
//!
//! Record format (little-endian): `u8 dir | u32 ms | u16 len | u8 data[len]`,
//! where `dir` is 0 = server→client, 1 = client→server, `ms` is a `GetTickCount`
//! timestamp, and `data` is the fully-decoded game message (`data[0]` = type;
//! no 0x51 frame, no obfuscation, no RakNet framing, no crypto).
//!
//! SAFETY: a capture can contain a cleartext login in a client→server `0x05`
//! record (newer captures redact it; older ones may not). This reader never
//! implements `Debug`/`Display` over payloads, and the mock-server replay path
//! uses only server→client records. Treat any `jgcap.bin` as secret and keep it
//! out of the repo (see `../notes` and the workspace `.gitignore`).

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    ServerToClient,
    ClientToServer,
}

/// One captured game message. `data[0]` is the message type.
pub struct Record {
    pub dir: Dir,
    pub ms: u32,
    pub data: Vec<u8>,
}

impl Record {
    pub fn message_type(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CaptureError {
    Truncated,
}

/// Parse all records from raw `jgcap.bin` bytes.
pub fn parse(bytes: &[u8]) -> Result<Vec<Record>, CaptureError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 7 <= bytes.len() {
        let dir = match bytes[i] {
            0 => Dir::ServerToClient,
            _ => Dir::ClientToServer,
        };
        let ms = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
        let len = u16::from_le_bytes([bytes[i + 5], bytes[i + 6]]) as usize;
        i += 7;
        if i + len > bytes.len() {
            return Err(CaptureError::Truncated);
        }
        out.push(Record { dir, ms, data: bytes[i..i + len].to_vec() });
        i += len;
    }
    Ok(out)
}

/// Server→client records only, in capture order — the replay script for a mock
/// server. This deliberately drops client→server records (which may hold the
/// login) since the mock server generates its own.
pub fn server_messages(records: &[Record]) -> impl Iterator<Item = &Record> {
    records.iter().filter(|r| r.dir == Dir::ServerToClient)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(dir: u8, ms: u32, data: &[u8]) -> Vec<u8> {
        let mut v = vec![dir];
        v.extend_from_slice(&ms.to_le_bytes());
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn parse_records() {
        let mut buf = Vec::new();
        buf.extend(rec(0, 100, &[0x8F, 1, 2])); // S→C welcome
        buf.extend(rec(1, 150, &[0x09, 3])); // C→S command
        let recs = parse(&buf).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].dir, Dir::ServerToClient);
        assert_eq!(recs[0].message_type(), Some(0x8F));
        assert_eq!(recs[1].dir, Dir::ClientToServer);

        let s: Vec<_> = server_messages(&recs).collect();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].message_type(), Some(0x8F));
    }

    #[test]
    fn truncated_is_error() {
        let mut buf = rec(0, 1, &[1, 2, 3]);
        buf.truncate(buf.len() - 1);
        // `Record` has no Debug/PartialEq by design (payloads must not be
        // printed/compared casually), so match rather than assert_eq.
        assert!(matches!(parse(&buf), Err(CaptureError::Truncated)));
    }
}
