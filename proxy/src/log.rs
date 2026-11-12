//! Minimal logging for the proxy: a one-line summary per datagram, with an
//! optional best-effort decode of the unencrypted phases.
//!
//! Logging only observes; it never changes what is forwarded.

use raknet::game;
use raknet::ids::MessageId;
use raknet::reliability::Datagram;

/// How much to print per datagram.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// One line: direction, length, first byte.
    Summary,
    /// Also try to parse unencrypted reliability datagrams and decode messages.
    Decode,
    /// Add a hex preview of the raw bytes.
    Hex,
}

impl Verbosity {
    pub fn parse(s: &str) -> Option<Verbosity> {
        Some(match s {
            "summary" => Verbosity::Summary,
            "decode" => Verbosity::Decode,
            "hex" => Verbosity::Hex,
            _ => return None,
        })
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let n = bytes.len().min(max);
    let mut s: String = bytes[..n].iter().map(|b| format!("{b:02x} ")).collect();
    if bytes.len() > max {
        s.push('…');
    }
    s.trim_end().to_string()
}

/// `tag` is the connection name (e.g. "state"); `dir` is "C→S" or "S→C".
pub fn datagram(tag: &str, dir: &str, bytes: &[u8], v: Verbosity, decryptable: bool) {
    let first = bytes.first().copied();
    let id = first.and_then(MessageId::from_u8);
    let id_str = match (first, id) {
        (Some(b), Some(id)) => format!("{id:?}(0x{b:02x})"),
        (Some(b), None) => format!("0x{b:02x}"),
        (None, _) => "∅".to_string(),
    };
    print!("[{tag}] {dir} {:>4}B first={id_str}", bytes.len());

    // Offline connect messages (0x13/0x14) are bare, not reliability-wrapped.
    let is_offline = matches!(
        id,
        Some(MessageId::OpenConnectionRequest | MessageId::OpenConnectionReply)
    );
    if v != Verbosity::Summary && decryptable && !is_offline {
        // Only meaningful for the unencrypted phases (handshake / offline).
        match Datagram::parse(bytes) {
            Ok(dg) if !dg.packets.is_empty() || !dg.acks.is_empty() => {
                print!("  rel[acks={} pkts={}]", dg.acks.len(), dg.packets.len());
                for p in &dg.packets {
                    let inner = p.data.first().copied();
                    let iid = inner.and_then(MessageId::from_u8);
                    match iid {
                        Some(x) => print!(" <{x:?}>"),
                        None => {
                            if let Some(g) = game::decode_payload(&p.data) {
                                print!(" <game type=0x{:02x}>", g.message_type().unwrap_or(0));
                            } else if let Some(b) = inner {
                                print!(" <0x{b:02x}>");
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if v == Verbosity::Hex {
        print!("  [{}]", hex_preview(bytes, 32));
    }
    println!();
}

/// Log a decoded plaintext datagram (MitM mode, after decryption).
#[cfg_attr(not(feature = "mitm"), allow(dead_code))]
pub fn plaintext(tag: &str, dir: &str, plain: &[u8], v: Verbosity) {
    if v == Verbosity::Summary {
        return;
    }
    match Datagram::parse(plain) {
        Ok(dg) => {
            print!("[{tag}] {dir} PLAIN acks={} pkts={}", dg.acks.len(), dg.packets.len());
            for p in &dg.packets {
                if let Some(g) = game::decode_payload(&p.data) {
                    print!(" <game 0x{:02x} ts={:?}>", g.message_type().unwrap_or(0), g.timestamp);
                } else if let Some(b) = p.data.first() {
                    print!(" <0x{b:02x}>");
                }
            }
            println!();
        }
        Err(e) => println!("[{tag}] {dir} PLAIN (unparsed: {e:?})"),
    }
}
