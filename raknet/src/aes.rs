//! AES-128 single-block ECB primitive (Rijndael), implemented directly so the
//! core crate has no dependencies and matches the cipher in the binary
//! (S-box / Te0 / inverse tables at `0xb2bb80` / `0xb2bd80` / `0xb2bc80`).
//!
//! RakNet's `DataBlockEncryptor` uses this in `MODE_ECB` and chains blocks by
//! hand (see [`crate::crypto`]). Only 128-bit keys are used by Jumpgate.
//!
//! Correctness is checked against the FIPS-197 known-answer vector in the tests.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (i, &s) in SBOX.iter().enumerate() {
        inv[s as usize] = i as u8;
    }
    inv
}

/// GF(2^8) multiply with the AES reduction polynomial 0x11b.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Expanded AES-128 cipher (11 round keys of 16 bytes).
pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
    inv_sbox: [u8; 256],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                // RotWord + SubWord + Rcon
                temp = [temp[1], temp[2], temp[3], temp[0]];
                for t in temp.iter_mut() {
                    *t = SBOX[*t as usize];
                }
                temp[0] ^= RCON[i / 4];
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ temp[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for r in 0..11 {
            for c in 0..4 {
                for j in 0..4 {
                    round_keys[r][4 * c + j] = w[4 * r + c][j];
                }
            }
        }
        Aes128 {
            round_keys,
            inv_sbox: inv_sbox(),
        }
    }

    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }

    fn inv_sub_bytes(&self, state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = self.inv_sbox[*b as usize];
        }
    }

    // State is column-major: index = row + 4*col.
    fn shift_rows(state: &mut [u8; 16]) {
        let s = *state;
        for r in 1..4 {
            for c in 0..4 {
                state[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
            }
        }
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let s = *state;
        for r in 1..4 {
            for c in 0..4 {
                state[r + 4 * c] = s[r + 4 * ((c + 4 - r) % 4)];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let i = 4 * c;
            let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            state[i] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
            state[i + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
            state[i + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
            state[i + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let i = 4 * c;
            let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            state[i] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
            state[i + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
            state[i + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
            state[i + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
        }
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        Self::add_round_key(block, &self.round_keys[0]);
        for r in 1..10 {
            Self::sub_bytes(block);
            Self::shift_rows(block);
            Self::mix_columns(block);
            Self::add_round_key(block, &self.round_keys[r]);
        }
        Self::sub_bytes(block);
        Self::shift_rows(block);
        Self::add_round_key(block, &self.round_keys[10]);
    }

    /// Decrypt one 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        Self::add_round_key(block, &self.round_keys[10]);
        for r in (1..10).rev() {
            Self::inv_shift_rows(block);
            self.inv_sub_bytes(block);
            Self::add_round_key(block, &self.round_keys[r]);
            Self::inv_mix_columns(block);
        }
        Self::inv_shift_rows(block);
        self.inv_sub_bytes(block);
        Self::add_round_key(block, &self.round_keys[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex16(s: &str) -> [u8; 16] {
        let b: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect();
        b.try_into().unwrap()
    }

    #[test]
    fn fips197_known_answer() {
        // FIPS-197 Appendix C.1.
        let key = hex16("000102030405060708090a0b0c0d0e0f");
        let mut block = hex16("00112233445566778899aabbccddeeff");
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(block, hex16("69c4e0d86a7b0430d8cdb78070b4c55a"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, hex16("00112233445566778899aabbccddeeff"));
    }
}
