//! Minimal textbook RSA over a 256-bit modulus, matching RakNet's `RSACrypt`
//! usage in the SecuredConnection handshake: the client RSA-encrypts a 20-byte
//! random (placed in a 32-byte little-endian buffer) with the server's public
//! `(e, n)`; the server decrypts with its private key. No padding (as in catid's
//! `RSACrypt`). Feature `mitm` only.
//!
//! WIRE FORMAT: `e`/`n`/the encrypted random are little-endian (catid's x86 limb
//! order). VERIFIED 2026-11-12: the real client completed the handshake against
//! the mock server, which only reports success once the client's traffic
//! decrypts with the RSA-agreed key.
//! For the self-contained round-trip (proxy talking to itself) the choice is
//! internally consistent and always works.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

/// Little-endian on the wire (verified against the real client, 2026-11-12).
pub const WIRE_LITTLE_ENDIAN: bool = true;

pub const MODULUS_BYTES: usize = 32; // 256-bit n
pub const E_BYTES: usize = 4;

fn to_wire(v: &BigUint, len: usize) -> Vec<u8> {
    let mut b = if WIRE_LITTLE_ENDIAN {
        v.to_bytes_le()
    } else {
        v.to_bytes_be()
    };
    if WIRE_LITTLE_ENDIAN {
        b.resize(len, 0);
    } else {
        // left-pad big-endian
        while b.len() < len {
            b.insert(0, 0);
        }
        if b.len() > len {
            b.drain(0..b.len() - len);
        }
    }
    b.truncate(len);
    b
}

fn from_wire(b: &[u8]) -> BigUint {
    if WIRE_LITTLE_ENDIAN {
        BigUint::from_bytes_le(b)
    } else {
        BigUint::from_bytes_be(b)
    }
}

/// Modular inverse of `a` mod `m` (extended Euclid), or `None` if not coprime.
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (a, m) = (BigInt::from(a.clone()), BigInt::from(m.clone()));
    let (mut old_r, mut r) = (a.clone(), m.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    while !r.is_zero() {
        let q = &old_r / &r;
        let tmp_r = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, tmp_r);
        let tmp_s = &old_s - &q * &s;
        old_s = std::mem::replace(&mut s, tmp_s);
    }
    if old_r != BigInt::one() {
        return None; // not invertible
    }
    let mut res = old_s % &m;
    if res.sign() == Sign::Minus {
        res += &m;
    }
    res.to_biguint()
}

fn is_probable_prime(n: &BigUint, rounds: usize) -> bool {
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let p = BigUint::from(p);
        if *n == p {
            return true;
        }
        if (n % &p).is_zero() {
            return false;
        }
    }
    // Miller-Rabin: n-1 = d * 2^r
    let one = BigUint::one();
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }
    let mut rng = rand::thread_rng();
    'witness: for _ in 0..rounds {
        let a = random_biguint_below(&mut rng, &(n - &two)) + &two;
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn random_biguint_below(rng: &mut impl RngCore, bound: &BigUint) -> BigUint {
    let bytes = bound.to_bytes_le().len().max(1);
    loop {
        let mut buf = vec![0u8; bytes];
        rng.fill_bytes(&mut buf);
        let v = BigUint::from_bytes_le(&buf);
        if &v < bound && !v.is_zero() {
            return v;
        }
    }
}

/// Generate a random prime of exactly `bits` bits (top and bottom bits set).
fn random_prime(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    let bytes = bits / 8;
    loop {
        let mut buf = vec![0u8; bytes];
        rng.fill_bytes(&mut buf);
        buf[0] |= 1; // odd (little-endian low byte)
        buf[bytes - 1] |= 0x80; // top bit set → exactly `bits` bits
        let cand = BigUint::from_bytes_le(&buf);
        if is_probable_prime(&cand, 25) {
            return cand;
        }
    }
}

/// An RSA keypair with a 256-bit modulus (two 128-bit primes), e = 65537.
pub struct KeyPair {
    pub e: BigUint,
    pub d: BigUint,
    pub n: BigUint,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let e = BigUint::from(65537u32);
        loop {
            let p = random_prime(128);
            let q = random_prime(128);
            if p == q {
                continue;
            }
            let n = &p * &q;
            let phi = (&p - BigUint::one()) * (&q - BigUint::one());
            if let Some(d) = modinv(&e, &phi) {
                return KeyPair { e, d, n };
            }
        }
    }

    /// Public key on the wire: (e as 4 bytes, n as 32 bytes).
    pub fn public_wire(&self) -> (Vec<u8>, Vec<u8>) {
        (to_wire(&self.e, E_BYTES), to_wire(&self.n, MODULUS_BYTES))
    }

    /// Decrypt a 32-byte ciphertext with the private key → 32-byte plaintext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let c = from_wire(ciphertext);
        let m = c.modpow(&self.d, &self.n);
        to_wire(&m, MODULUS_BYTES)
    }
}

/// Encrypt a 32-byte message with a wire public key → 32-byte ciphertext.
pub fn encrypt_with_public(e_wire: &[u8], n_wire: &[u8], message: &[u8]) -> Vec<u8> {
    let e = from_wire(e_wire);
    let n = from_wire(n_wire);
    let m = from_wire(message);
    let c = m.modpow(&e, &n);
    to_wire(&c, MODULUS_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_and_round_trip() {
        let kp = KeyPair::generate();
        let (e, n) = kp.public_wire();
        assert_eq!(e.len(), E_BYTES);
        assert_eq!(n.len(), MODULUS_BYTES);

        // 20-byte random in a 32-byte LE buffer, as the client builds it.
        let mut msg = [0u8; MODULUS_BYTES];
        for (i, b) in msg.iter_mut().take(20).enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(1);
        }
        let ct = encrypt_with_public(&e, &n, &msg);
        let pt = kp.decrypt(&ct);
        assert_eq!(pt, msg.to_vec());
    }

    #[test]
    fn modinv_basic() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        assert_eq!(modinv(&a, &m), Some(BigUint::from(4u32))); // 3*4=12≡1 mod 11
    }
}
