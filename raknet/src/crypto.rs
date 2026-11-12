//! RakNet `DataBlockEncryptor`: AES-128 with a manual block chain, a leading
//! running checksum, and random padding. Byte-verified against the binary
//! (`Encrypt 0xa786b0`, `Decrypt 0xa78820`, `IsKeySet 0xa78640`; the encryptor
//! sub-object lives at `conn+0x414`). See `../notes/raknet-spec.md` §2.
//!
//! Layout of a plaintext block before encryption (then padded to a 16-byte
//! multiple and chained):
//! ```text
//! [0..4]   checksum (little-endian, computed over everything after it)
//! [4]      randomChar
//! [5]      encodedPad      (high nibble random, low nibble = paddingBytes)
//! [6 .. 6+pad)             random padding
//! [6+pad .. ]              plaintext
//! ```
//! The chain is an unusual reverse-order CBC: block 0 is encrypted ECB first,
//! then each following block (from last down to block 1) is XORed with the
//! ciphertext 16 bytes ahead of it and encrypted.
//!
//! The random bytes are padding/nonce only — correctness does not depend on
//! reproducing the game's RNG, so any source works. We never rely on them for
//! secrecy; integrity comes from the checksum.

use crate::aes::Aes128;
use crate::checksum::CheckSum;
use std::cell::Cell;

const HEADER: usize = 6; // 4 checksum + 1 randomChar + 1 encodedPad

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// Length is 0, below one block, or not a multiple of 16.
    BadLength,
    /// Recomputed checksum did not match (corrupt, wrong key, or forged).
    ChecksumMismatch,
    /// Declared padding leaves no room for the header.
    BadPadding,
}

pub struct DataBlockEncryptor {
    cipher: Aes128,
    rng: Cell<u64>,
}

impl DataBlockEncryptor {
    /// New encryptor for a 16-byte AES key, seeded for padding from wall-clock.
    pub fn new(key: &[u8; 16]) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15)
            ^ (key[0] as u64) << 1
            ^ 0x2545f4914f6cdd1d;
        Self::with_seed(key, seed.max(1))
    }

    /// Deterministic variant (padding RNG seeded explicitly) — used by tests.
    pub fn with_seed(key: &[u8; 16], seed: u64) -> Self {
        DataBlockEncryptor {
            cipher: Aes128::new(key),
            rng: Cell::new(seed.max(1)),
        }
    }

    fn next_rand(&self) -> u8 {
        // xorshift64 — padding only, not security-sensitive.
        let mut x = self.rng.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.set(x);
        (x >> 33) as u8
    }

    /// Encrypt `input`, returning the on-wire ciphertext (a multiple of 16).
    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let padding = {
            // total after checksum = len + randomChar + encodedPad + padding must
            // make the whole thing a multiple of 16: 16 - (((len+6-1) % 16)+1).
            let m = ((input.len() + HEADER - 1) % 16) + 1;
            16 - m
        };
        let out_len = input.len() + HEADER + padding;
        let mut out = vec![0u8; out_len];

        let random_char = self.next_rand();
        let encoded_pad = (self.next_rand() << 4) | (padding as u8);
        out[4] = random_char;
        out[5] = encoded_pad;
        for b in out.iter_mut().skip(HEADER).take(padding) {
            *b = self.next_rand();
        }
        out[HEADER + padding..].copy_from_slice(input);

        let checksum = CheckSum::of(&out[4..]);
        out[0..4].copy_from_slice(&checksum.to_le_bytes());

        self.chain_encrypt(&mut out);
        out
    }

    fn chain_encrypt(&self, out: &mut [u8]) {
        let mut block = [0u8; 16];
        block.copy_from_slice(&out[0..16]);
        self.cipher.encrypt_block(&mut block);
        out[0..16].copy_from_slice(&block);

        // index from out_len-16 down to 16, step -16; lastBlock starts at 0.
        let mut last_block = 0usize;
        let mut index = out.len().wrapping_sub(16);
        while index >= 16 {
            for b in 0..16 {
                out[index + b] ^= out[last_block + b];
            }
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&out[index..index + 16]);
            self.cipher.encrypt_block(&mut blk);
            out[index..index + 16].copy_from_slice(&blk);
            last_block = index;
            index = index.wrapping_sub(16);
        }
    }

    /// Decrypt a datagram, verifying its checksum. Returns the plaintext.
    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if input.is_empty() || input.len() < 16 || input.len() % 16 != 0 {
            return Err(DecryptError::BadLength);
        }
        let mut buf = input.to_vec();
        let len = buf.len();

        // Forward: decrypt blocks 16..len-16, XOR with ciphertext 16 ahead (or
        // block 0 for the last block), leaving block 0 for last.
        let mut index = 16;
        while index <= len - 16 {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&buf[index..index + 16]);
            self.cipher.decrypt_block(&mut blk);
            buf[index..index + 16].copy_from_slice(&blk);
            for b in 0..16 {
                let src = if index + 16 == len { b } else { index + 16 + b };
                buf[index + b] ^= buf[src];
            }
            index += 16;
        }
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&buf[0..16]);
        self.cipher.decrypt_block(&mut blk);
        buf[0..16].copy_from_slice(&blk);

        let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let padding = (buf[5] & 0x0F) as usize;
        if HEADER + padding > len {
            return Err(DecryptError::BadPadding);
        }
        if CheckSum::of(&buf[4..]) != checksum {
            return Err(DecryptError::ChecksumMismatch);
        }
        Ok(buf[HEADER + padding..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_lengths() {
        let key = [7u8; 16];
        let enc = DataBlockEncryptor::with_seed(&key, 0xdead_beef);
        for len in 0..200usize {
            if len == 0 {
                continue; // RakNet asserts input && inputLength; empty is not sent.
            }
            let msg: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let ct = enc.encrypt(&msg);
            assert_eq!(ct.len() % 16, 0, "len {len}");
            assert!(ct.len() >= 16);
            let pt = enc.decrypt(&ct).expect("decrypt");
            assert_eq!(pt, msg, "len {len}");
        }
    }

    #[test]
    fn tamper_is_rejected() {
        let key = [0x11u8; 16];
        let enc = DataBlockEncryptor::with_seed(&key, 1);
        let mut ct = enc.encrypt(b"hello world, this is a test");
        ct[5] ^= 0x80;
        assert!(matches!(
            enc.decrypt(&ct),
            Err(DecryptError::ChecksumMismatch) | Err(DecryptError::BadPadding)
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let a = DataBlockEncryptor::with_seed(&[1u8; 16], 5);
        let b = DataBlockEncryptor::with_seed(&[2u8; 16], 5);
        let ct = a.encrypt(b"secret payload bytes");
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn bad_length() {
        let enc = DataBlockEncryptor::with_seed(&[0u8; 16], 1);
        assert_eq!(enc.decrypt(&[0u8; 15]), Err(DecryptError::BadLength));
        assert_eq!(enc.decrypt(&[]), Err(DecryptError::BadLength));
    }
}
