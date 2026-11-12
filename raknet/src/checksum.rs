//! RakNet's `CheckSum` (from flounder.com/checksum.htm), used by the
//! `DataBlockEncryptor` to detect corrupt/forged datagrams.
//!
//! Byte-verified against `CheckSum::Add` at `0xa79e00`; the state constants
//! `r = 0xD971`, `c1 = 0xCE6D`, `c2 = 0x58BF` are the immediates loaded at
//! `0xa786c3` before the per-byte loop.

const SEED_R: u16 = 0xD971; // 55665
const C1: u16 = 0xCE6D; // 52845
const C2: u16 = 0x58BF; // 22719

#[derive(Clone)]
pub struct CheckSum {
    r: u16,
    sum: u32,
}

impl Default for CheckSum {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckSum {
    pub fn new() -> Self {
        CheckSum { r: SEED_R, sum: 0 }
    }

    #[inline]
    pub fn add_byte(&mut self, value: u8) {
        let cipher = value ^ (self.r >> 8) as u8;
        self.r = (cipher as u16).wrapping_add(self.r).wrapping_mul(C1).wrapping_add(C2);
        self.sum = self.sum.wrapping_add(cipher as u32);
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.add_byte(b);
        }
    }

    pub fn get(&self) -> u32 {
        self.sum
    }

    /// Convenience: checksum of a slice from a fresh state.
    pub fn of(bytes: &[u8]) -> u32 {
        let mut c = CheckSum::new();
        c.add_bytes(bytes);
        c.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_order_sensitive() {
        assert_eq!(CheckSum::of(b""), 0);
        let a = CheckSum::of(&[1, 2, 3, 4]);
        let b = CheckSum::of(&[4, 3, 2, 1]);
        assert_ne!(a, b);
        // Streaming equals one-shot.
        let mut c = CheckSum::new();
        c.add_bytes(&[1, 2]);
        c.add_bytes(&[3, 4]);
        assert_eq!(c.get(), a);
    }
}
