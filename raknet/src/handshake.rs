//! RakNet SecuredConnection handshake (message framing + AES-key derivation),
//! byte-verified against the binary (`../notes/key-exchange.md`,
//! `raknet-spec.md` §1). Feature `mitm` only.
//!
//! ```text
//! S → C  0x06  [06][20 cookie][4 e][32 n]              (57 bytes)
//! C → S  0x07  [07][20 echoed cookie][32 RSA(random)]  (53 bytes)
//! AES key = cookie[0..16] XOR randomNumber[0..16]       (both sides agree)
//! ```
//! `randomNumber` is 20 bytes placed low in a 32-byte little-endian buffer,
//! RSA-encrypted with the server's public key. The client does not authenticate
//! the key (no pinning — verified: `InitializeSecurity` has no call site), so a
//! proxy can present its own key to the client and a fresh request to the server.

use crate::rsa::{self, KeyPair};
use rand::RngCore;

pub const RESPONSE_LEN: usize = 57; // 0x06
pub const CONFIRMATION_LEN: usize = 53; // 0x07
pub const COOKIE_LEN: usize = 20;
pub const RANDOM_LEN: usize = 20;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Build a 0x06 SecuredConnectionResponse.
pub fn build_response(cookie: &[u8; COOKIE_LEN], e_wire: &[u8], n_wire: &[u8]) -> Vec<u8> {
    assert_eq!(e_wire.len(), rsa::E_BYTES);
    assert_eq!(n_wire.len(), rsa::MODULUS_BYTES);
    let mut m = Vec::with_capacity(RESPONSE_LEN);
    m.push(0x06);
    m.extend_from_slice(cookie);
    m.extend_from_slice(e_wire);
    m.extend_from_slice(n_wire);
    m
}

pub struct Response {
    pub cookie: [u8; COOKIE_LEN],
    pub e_wire: Vec<u8>,
    pub n_wire: Vec<u8>,
}

/// Parse a 0x06 message (as received from the real server).
pub fn parse_response(m: &[u8]) -> Option<Response> {
    if m.len() != RESPONSE_LEN || m[0] != 0x06 {
        return None;
    }
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&m[1..1 + COOKIE_LEN]);
    let e_off = 1 + COOKIE_LEN;
    let n_off = e_off + rsa::E_BYTES;
    Some(Response {
        cookie,
        e_wire: m[e_off..n_off].to_vec(),
        n_wire: m[n_off..n_off + rsa::MODULUS_BYTES].to_vec(),
    })
}

/// Client half: build a 0x07 confirmation under the server's public key and
/// return it along with the derived AES key. `random` is our own 20 bytes.
pub fn build_confirmation(
    echoed_cookie: &[u8; COOKIE_LEN],
    e_wire: &[u8],
    n_wire: &[u8],
    random: &[u8; RANDOM_LEN],
) -> (Vec<u8>, [u8; 16]) {
    let mut msg = [0u8; rsa::MODULUS_BYTES];
    msg[..RANDOM_LEN].copy_from_slice(random);
    let enc = rsa::encrypt_with_public(e_wire, n_wire, &msg);

    let mut out = Vec::with_capacity(CONFIRMATION_LEN);
    out.push(0x07);
    out.extend_from_slice(echoed_cookie);
    out.extend_from_slice(&enc);

    (out, derive_key(echoed_cookie, random))
}

pub struct Confirmation {
    pub echoed_cookie: [u8; COOKIE_LEN],
    pub encrypted: [u8; rsa::MODULUS_BYTES],
}

/// Parse a 0x07 message (as received from the real client).
pub fn parse_confirmation(m: &[u8]) -> Option<Confirmation> {
    if m.len() != CONFIRMATION_LEN || m[0] != 0x07 {
        return None;
    }
    let mut echoed_cookie = [0u8; COOKIE_LEN];
    echoed_cookie.copy_from_slice(&m[1..1 + COOKIE_LEN]);
    let mut encrypted = [0u8; rsa::MODULUS_BYTES];
    encrypted.copy_from_slice(&m[1 + COOKIE_LEN..CONFIRMATION_LEN]);
    Some(Confirmation { echoed_cookie, encrypted })
}

/// Server half: given our cookie, our keypair and the client's 0x07, recover the
/// client's randomNumber and derive the shared AES key. Returns `None` if the
/// echoed cookie does not match ours.
pub fn derive_key_from_confirmation(
    our_cookie: &[u8; COOKIE_LEN],
    keypair: &KeyPair,
    confirmation: &Confirmation,
) -> Option<[u8; 16]> {
    if &confirmation.echoed_cookie != our_cookie {
        return None;
    }
    let message = keypair.decrypt(&confirmation.encrypted);
    let mut random = [0u8; RANDOM_LEN];
    random.copy_from_slice(&message[..RANDOM_LEN]);
    Some(derive_key(our_cookie, &random))
}

/// AES key = cookie[0..16] XOR randomNumber[0..16].
fn derive_key(cookie: &[u8; COOKIE_LEN], random: &[u8; RANDOM_LEN]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = cookie[i] ^ random[i];
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_halves_agree_on_key() {
        // Model: proxy is the "server" to a client that runs build_confirmation.
        let server_kp = KeyPair::generate();
        let (e, n) = server_kp.public_wire();
        let cookie: [u8; COOKIE_LEN] = random_bytes();

        // Client side derives key from the 0x06 it received.
        let client_random: [u8; RANDOM_LEN] = random_bytes();
        let (confirmation_bytes, client_key) =
            build_confirmation(&cookie, &e, &n, &client_random);

        // Server side recovers the same key from the 0x07.
        let conf = parse_confirmation(&confirmation_bytes).unwrap();
        let server_key =
            derive_key_from_confirmation(&cookie, &server_kp, &conf).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn response_round_trip() {
        let kp = KeyPair::generate();
        let (e, n) = kp.public_wire();
        let cookie: [u8; COOKIE_LEN] = random_bytes();
        let bytes = build_response(&cookie, &e, &n);
        assert_eq!(bytes.len(), RESPONSE_LEN);
        let r = parse_response(&bytes).unwrap();
        assert_eq!(r.cookie, cookie);
        assert_eq!(r.e_wire, e);
        assert_eq!(r.n_wire, n);
    }
}
