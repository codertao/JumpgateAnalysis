//! RakNet `BitStream`: MSB-first bit packing. Multi-byte integers are stored
//! little-endian *byte* order, each byte packed MSB-first (matches
//! `BitStream::WriteBits`/`ReadBits` with `rightAlignedBits`). See
//! `../notes/raknet-spec.md` §3.
//!
//! Only the pieces the reliability layer needs are implemented: bits, bytes,
//! u16, the compressed integer encoding, and byte-aligned raw bytes.

pub struct BitWriter {
    data: Vec<u8>,
    bit_len: usize,
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { data: Vec::new(), bit_len: 0 }
    }

    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    pub fn write_bit(&mut self, b: bool) {
        if self.bit_len % 8 == 0 {
            self.data.push(0);
        }
        if b {
            let byte = self.bit_len / 8;
            let shift = 7 - (self.bit_len % 8);
            self.data[byte] |= 1 << shift;
        }
        self.bit_len += 1;
    }

    /// Write the low `n` bits of `value`, MSB-first.
    pub fn write_bits(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn write_octet(&mut self, byte: u8) {
        self.write_bits(byte as u32, 8);
    }

    pub fn write_bool(&mut self, b: bool) {
        self.write_bit(b);
    }

    /// u16 in RakNet order: low byte (MSB-first) then high byte (MSB-first).
    pub fn write_u16(&mut self, v: u16) {
        self.write_octet((v & 0xff) as u8);
        self.write_octet((v >> 8) as u8);
    }

    /// Compressed unsigned write (RakNet `WriteCompressed`). Drops high zero
    /// bytes; the final byte uses a 4-bit short form if its high nibble is 0.
    pub fn write_compressed(&mut self, bytes_le: &[u8]) {
        let size = bytes_le.len();
        let mut current = size as isize - 1; // high byte index
        while current > 0 {
            if bytes_le[current as usize] == 0 {
                self.write_bit(true);
            } else {
                self.write_bit(false);
                // write bytes 0..=current (low..this), each MSB-first.
                for &b in &bytes_le[..=current as usize] {
                    self.write_octet(b);
                }
                return;
            }
            current -= 1;
        }
        // Last (low) byte.
        let low = bytes_le[0];
        if low & 0xF0 == 0 {
            self.write_bit(true);
            self.write_bits((low & 0x0F) as u32, 4);
        } else {
            self.write_bit(false);
            self.write_octet(low);
        }
    }

    pub fn write_compressed_u16(&mut self, v: u16) {
        self.write_compressed(&v.to_le_bytes());
    }

    pub fn write_compressed_u32(&mut self, v: u32) {
        self.write_compressed(&v.to_le_bytes());
    }

    /// Pad to the next byte boundary with zero bits.
    pub fn align(&mut self) {
        while self.bit_len % 8 != 0 {
            self.write_bit(false);
        }
    }

    /// Align, then append raw bytes (RakNet `WriteAlignedBytes`).
    pub fn write_aligned_bytes(&mut self, bytes: &[u8]) {
        self.align();
        self.data.extend_from_slice(bytes);
        self.bit_len += bytes.len() * 8;
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BitError;

pub struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
    bit_len: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, bit_pos: 0, bit_len: data.len() * 8 }
    }

    pub fn bits_left(&self) -> usize {
        self.bit_len - self.bit_pos
    }

    pub fn read_bit(&mut self) -> Result<bool, BitError> {
        if self.bit_pos >= self.bit_len {
            return Err(BitError);
        }
        let byte = self.bit_pos / 8;
        let shift = 7 - (self.bit_pos % 8);
        self.bit_pos += 1;
        Ok((self.data[byte] >> shift) & 1 == 1)
    }

    pub fn read_bool(&mut self) -> Result<bool, BitError> {
        self.read_bit()
    }

    /// Read `n` bits MSB-first as an integer (first bit = most significant).
    pub fn read_bits(&mut self, n: u32) -> Result<u32, BitError> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()? as u32;
        }
        Ok(v)
    }

    fn read_octet(&mut self) -> Result<u8, BitError> {
        Ok(self.read_bits(8)? as u8)
    }

    pub fn read_u16(&mut self) -> Result<u16, BitError> {
        let low = self.read_octet()? as u16;
        let high = self.read_octet()? as u16;
        Ok(low | (high << 8))
    }

    /// Inverse of [`BitWriter::write_compressed`] for an `n`-byte value.
    pub fn read_compressed(&mut self, size: usize) -> Result<Vec<u8>, BitError> {
        let mut out = vec![0u8; size];
        let mut current = size as isize - 1;
        while current > 0 {
            let all_zero = self.read_bit()?;
            if all_zero {
                out[current as usize] = 0;
            } else {
                for b in out[..=current as usize].iter_mut() {
                    *b = self.read_octet()?;
                }
                return Ok(out);
            }
            current -= 1;
        }
        // Last byte.
        let short = self.read_bit()?;
        out[0] = if short {
            self.read_bits(4)? as u8
        } else {
            self.read_octet()?
        };
        Ok(out)
    }

    pub fn read_compressed_u16(&mut self) -> Result<u16, BitError> {
        let b = self.read_compressed(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_compressed_u32(&mut self) -> Result<u32, BitError> {
        let b = self.read_compressed(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn align(&mut self) {
        while self.bit_pos % 8 != 0 {
            self.bit_pos += 1;
        }
    }

    /// Align then read `len` raw bytes.
    pub fn read_aligned_bytes(&mut self, len: usize) -> Result<Vec<u8>, BitError> {
        self.align();
        let start = self.bit_pos / 8;
        if start + len > self.data.len() {
            return Err(BitError);
        }
        self.bit_pos += len * 8;
        Ok(self.data[start..start + len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_and_ints_round_trip() {
        let mut w = BitWriter::new();
        w.write_bit(true);
        w.write_bits(0b1011, 4);
        w.write_u16(0xBEEF);
        w.write_bool(false);
        w.write_u16(1);
        let bytes = w.into_bytes();

        let mut r = BitReader::new(&bytes);
        assert!(r.read_bit().unwrap());
        assert_eq!(r.read_bits(4).unwrap(), 0b1011);
        assert_eq!(r.read_u16().unwrap(), 0xBEEF);
        assert!(!r.read_bool().unwrap());
        assert_eq!(r.read_u16().unwrap(), 1);
    }

    #[test]
    fn compressed_round_trip() {
        for v in [0u16, 1, 0x0F, 0x10, 0xFF, 0x100, 0x1234, 0xFFFF] {
            let mut w = BitWriter::new();
            w.write_compressed_u16(v);
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.read_compressed_u16().unwrap(), v, "u16 {v:#x}");
        }
        for v in [0u32, 1, 0xFF, 0x1_0000, 0x00AB_CDEF, 0xFFFF_FFFF] {
            let mut w = BitWriter::new();
            w.write_compressed_u32(v);
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes);
            assert_eq!(r.read_compressed_u32().unwrap(), v, "u32 {v:#x}");
        }
    }

    #[test]
    fn aligned_bytes() {
        let mut w = BitWriter::new();
        w.write_bit(true);
        w.write_aligned_bytes(&[1, 2, 3, 4]);
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        assert!(r.read_bit().unwrap());
        assert_eq!(r.read_aligned_bytes(4).unwrap(), vec![1, 2, 3, 4]);
    }
}
