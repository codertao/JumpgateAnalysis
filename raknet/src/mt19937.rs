//! Textbook MT19937, the PRNG family RakNet uses (`randomMT` at `0xa758d0`,
//! `seedMT` at `0xa75780`).
//!
//! The proxy does **not** need to reproduce the game's exact stream: as a
//! legitimate endpoint it generates its own handshake randomness from the OS
//! RNG. This is provided for analysis/reference only. If you ever need to match
//! the game's stream byte-for-byte, verify the seeding and tempering against the
//! binary first — the tempering constants recorded in the notes looked
//! non-standard and were never confirmed.

pub struct Mt19937 {
    mt: [u32; 624],
    index: usize,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Mt19937 { mt, index: 624 }
    }

    fn generate(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x8000_0000) | (self.mt[(i + 1) % 624] & 0x7fff_ffff);
            let mut next = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y & 1 != 0 {
                next ^= 0x9908_b0df;
            }
            self.mt[i] = next;
        }
        self.index = 0;
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index >= 624 {
            self.generate();
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_seed_5489() {
        // Reference first outputs for the standard MT19937 seed 5489.
        let mut mt = Mt19937::new(5489);
        assert_eq!(mt.next_u32(), 3499211612);
        assert_eq!(mt.next_u32(), 581869302);
        assert_eq!(mt.next_u32(), 3890346734);
    }
}
