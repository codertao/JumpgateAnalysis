//! RakNet 2.x reliability datagram: an optional acknowledgement list followed by
//! bit-packed internal packets. Follows the archived source
//! (`GenerateDatagram` / `WriteToBitStreamFromInternalPacket`); see
//! `../notes/raknet-spec.md` §3. Round-trip tested below.
//!
//! NOTE: this layer is for *inspection and the round-trip correctness test*. The
//! proxy forwards by re-encrypting the raw decrypted plaintext, so a bug here
//! cannot corrupt forwarded traffic — it only affects logging.
//!
//! Unverified-on-the-wire bits (flagged in the spec): the exact lead-bit / ack
//! ordering and split-packet reassembly. The `reparse_is_stable` test is the
//! guard — decode→encode→decode must be a fixed point.

use crate::bitstream::{BitError, BitReader, BitWriter};
use crate::ids::Reliability;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub min: u16,
    pub max: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitInfo {
    pub id: u16,
    pub index: u32,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalPacket {
    pub message_number: u16,
    pub reliability: Reliability,
    pub ordering_channel: u8,
    pub ordering_index: u16,
    pub split: Option<SplitInfo>,
    /// Message payload (first byte is the RakNet ID or game type).
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Datagram {
    pub acks: Vec<AckRange>,
    pub packets: Vec<InternalPacket>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadReliability(u8),
}

impl From<BitError> for ParseError {
    fn from(_: BitError) -> Self {
        ParseError::Truncated
    }
}

impl Datagram {
    pub fn parse(bytes: &[u8]) -> Result<Datagram, ParseError> {
        let mut r = BitReader::new(bytes);
        let mut dg = Datagram::default();
        if r.bits_left() == 0 {
            return Ok(dg);
        }
        let has_acks = r.read_bit()?;
        if has_acks {
            let count = r.read_compressed_u16()?;
            for _ in 0..count {
                let min_eq_max = r.read_bit()?;
                let min = r.read_u16()?;
                let max = if min_eq_max { min } else { r.read_u16()? };
                dg.acks.push(AckRange { min, max });
            }
        }
        // Remaining bits are internal packets. A full header needs well over 16
        // bits; stop when fewer than a messageNumber remain (trailing pad bits).
        while r.bits_left() >= 16 {
            let pkt = read_packet(&mut r)?;
            dg.packets.push(pkt);
        }
        Ok(dg)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = BitWriter::new();
        let mut wrote_lead = false;
        if !self.acks.is_empty() {
            w.write_bit(true);
            w.write_compressed_u16(self.acks.len() as u16);
            for a in &self.acks {
                w.write_bit(a.min == a.max);
                w.write_u16(a.min);
                if a.min != a.max {
                    w.write_u16(a.max);
                }
            }
            wrote_lead = true;
        }
        for (i, pkt) in self.packets.iter().enumerate() {
            if i == 0 && !wrote_lead {
                w.write_bit(false); // "writeFalseToHeader": no acks precede data.
            }
            write_packet(&mut w, pkt);
        }
        w.into_bytes()
    }
}

fn read_packet(r: &mut BitReader) -> Result<InternalPacket, ParseError> {
    let message_number = r.read_u16()?;
    let rel_raw = r.read_bits(4)? as u8;
    let reliability = Reliability::from_u8(rel_raw).ok_or(ParseError::BadReliability(rel_raw))?;

    let (mut ordering_channel, mut ordering_index) = (0u8, 0u16);
    if reliability.has_ordering() {
        ordering_channel = r.read_bits(5)? as u8;
        ordering_index = r.read_u16()?;
    }

    let is_split = r.read_bit()?;
    let split = if is_split {
        let id = r.read_u16()?;
        let index = r.read_compressed_u32()?;
        let count = r.read_compressed_u32()?;
        Some(SplitInfo { id, index, count })
    } else {
        None
    };

    let bit_len = r.read_compressed_u16()? as usize;
    let byte_len = bit_len.div_ceil(8);
    let data = r.read_aligned_bytes(byte_len)?;

    Ok(InternalPacket {
        message_number,
        reliability,
        ordering_channel,
        ordering_index,
        split,
        data,
    })
}

fn write_packet(w: &mut BitWriter, pkt: &InternalPacket) {
    w.write_u16(pkt.message_number);
    w.write_bits(pkt.reliability as u32, 4);
    if pkt.reliability.has_ordering() {
        w.write_bits(pkt.ordering_channel as u32, 5);
        w.write_u16(pkt.ordering_index);
    }
    match &pkt.split {
        Some(s) => {
            w.write_bit(true);
            w.write_u16(s.id);
            w.write_compressed_u32(s.index);
            w.write_compressed_u32(s.count);
        }
        None => w.write_bit(false),
    }
    // dataBitLength is a u16 on the wire (high bytes ignored by RakNet).
    let bit_len = (pkt.data.len() * 8) as u16;
    w.write_compressed_u16(bit_len);
    w.write_aligned_bytes(&pkt.data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Datagram {
        Datagram {
            acks: vec![AckRange { min: 5, max: 5 }, AckRange { min: 10, max: 14 }],
            packets: vec![
                InternalPacket {
                    message_number: 42,
                    reliability: Reliability::ReliableOrdered,
                    ordering_channel: 0,
                    ordering_index: 7,
                    split: None,
                    data: vec![0x51, 0xAA, 0xBB, 0xCC],
                },
                InternalPacket {
                    message_number: 43,
                    reliability: Reliability::UnreliableSequenced,
                    ordering_channel: 1,
                    ordering_index: 100,
                    split: Some(SplitInfo { id: 9, index: 2, count: 5 }),
                    data: vec![1, 2, 3],
                },
                InternalPacket {
                    message_number: 44,
                    reliability: Reliability::Reliable,
                    ordering_channel: 0,
                    ordering_index: 0,
                    split: None,
                    data: vec![0xFF; 20],
                },
            ],
        }
    }

    #[test]
    fn reparse_is_stable() {
        // decode(encode(x)) == x, and encode is a fixed point.
        let dg = sample();
        let bytes = dg.serialize();
        let got = Datagram::parse(&bytes).expect("parse");
        assert_eq!(got, dg);
        assert_eq!(got.serialize(), bytes);
    }

    #[test]
    fn acks_only_and_data_only() {
        let acks_only = Datagram {
            acks: vec![AckRange { min: 1, max: 3 }],
            packets: vec![],
        };
        assert_eq!(Datagram::parse(&acks_only.serialize()).unwrap(), acks_only);

        let data_only = Datagram {
            acks: vec![],
            packets: vec![InternalPacket {
                message_number: 1,
                reliability: Reliability::Unreliable,
                ordering_channel: 0,
                ordering_index: 0,
                split: None,
                data: vec![0x05, 0x06, 0x07],
            }],
        };
        assert_eq!(Datagram::parse(&data_only.serialize()).unwrap(), data_only);
    }

    #[test]
    fn empty_datagram() {
        assert_eq!(Datagram::parse(&[]).unwrap(), Datagram::default());
    }
}
