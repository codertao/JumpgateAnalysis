//! RakNet 2.x transport as used by Jumpgate.exe (build `fef6e50f…`).
//!
//! Implements the layers described in `../notes/raknet-spec.md`:
//!
//! ```text
//! UDP datagram
//! └─ DataBlockEncryptor (AES-128, once a key is set)      [crypto]
//!    └─ RakNet datagram: acks? + internal packets         [reliability]
//!       └─ message: first byte = RakNet ID or game type   [ids]
//!          └─ (game) 0x1A timestamp, 0x51 frame, obfusc.  [game]
//! ```
//!
//! Verification status mirrors the spec: `crypto`, `checksum`, `aes` and `ids`
//! are byte-verified against the binary; `reliability` follows the archived
//! RakNet 2.x source (round-trip tested here, flagged where unconfirmed on the
//! wire); the `mitm` feature's `rsa`/`handshake` interop with the live server
//! still needs calibrating against a real capture (RSA byte order).
//!
//! Scope: this is for inspecting *your own* client and *your own* traffic. The
//! proxy built on top is an observer and does not intentionally alter content.

pub mod aes;
pub mod bitstream;
pub mod capture;
pub mod checksum;
pub mod crypto;
pub mod game;
pub mod ids;
pub mod mt19937;
pub mod reliability;

#[cfg(feature = "mitm")]
pub mod handshake;
#[cfg(feature = "mitm")]
pub mod rsa;
#[cfg(feature = "mitm")]
pub mod session;

pub use bitstream::{BitReader, BitWriter};
pub use crypto::{DataBlockEncryptor, DecryptError};
pub use ids::{MessageId, Reliability};
