//! RakNet 2.x message IDs (classic `PacketEnumerations.h`) and the stock
//! `PacketReliability` enum, both byte-verified for this binary
//! (`notes/network-protocol.md` §1.1b, `raknet-spec.md`).
//!
//! NB: Jumpgate uses the *stock* reliability numbering (0..4). The SA:MP source
//! renumbers it to 6..10 — do not use that here. `SendGameMessage` (`0x9c9c10`)
//! builds the field as `((guaranteed & 1) << 1) | 1`, i.e. 1 or 3.

/// Transport-level message IDs that appear as the first plaintext byte.
/// Game message types (`>= ~0x1D`, dispatched by `0x9cf6b0`) are not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageId {
    ConnectedPong = 3,
    RequestStaticData = 4,
    ConnectionRequest = 5,
    SecuredConnectionResponse = 6,
    SecuredConnectionConfirmation = 7,
    RpcMapping = 8,
    DetectLostConnections = 9,
    /// Bare offline `[0A 00]` — exactly 2 bytes (client sender `0xa6d34f`,
    /// server check `len == 2` at `0xa6b4e5`).
    OpenConnectionRequest = 0x0A,
    /// Bare offline `[0B 00]`; the client accepts it when `len <= 2` (`0xa6b021`).
    OpenConnectionReply = 0x0B,
    Rpc = 0x0C,
    ConnectionRequestAccepted = 0x10,
    ConnectionAttemptFailed = 0x11,
    NewIncomingConnection = 0x12,
    /// Server's alternative reply to `0x0A` when full (`0xa6b5f0`).
    NoFreeIncomingConnections = 0x13,
    DisconnectionNotification = 0x14,
    ConnectionLost = 0x15,
    Timestamp = 0x1A,
    ReceivedStaticData = 0x1C,
}

impl MessageId {
    pub fn from_u8(v: u8) -> Option<MessageId> {
        use MessageId::*;
        Some(match v {
            3 => ConnectedPong,
            4 => RequestStaticData,
            5 => ConnectionRequest,
            6 => SecuredConnectionResponse,
            7 => SecuredConnectionConfirmation,
            8 => RpcMapping,
            9 => DetectLostConnections,
            0x0A => OpenConnectionRequest,
            0x0B => OpenConnectionReply,
            0x0C => Rpc,
            0x10 => ConnectionRequestAccepted,
            0x11 => ConnectionAttemptFailed,
            0x12 => NewIncomingConnection,
            0x13 => NoFreeIncomingConnections,
            0x14 => DisconnectionNotification,
            0x15 => ConnectionLost,
            0x1A => Timestamp,
            0x1C => ReceivedStaticData,
            _ => return None,
        })
    }
}

/// Stock RakNet `PacketReliability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reliability {
    Unreliable = 0,
    UnreliableSequenced = 1,
    Reliable = 2,
    ReliableOrdered = 3,
    ReliableSequenced = 4,
}

impl Reliability {
    pub fn from_u8(v: u8) -> Option<Reliability> {
        use Reliability::*;
        Some(match v {
            0 => Unreliable,
            1 => UnreliableSequenced,
            2 => Reliable,
            3 => ReliableOrdered,
            4 => ReliableSequenced,
            _ => return None,
        })
    }

    /// Whether this reliability carries the 5-bit ordering channel + ordering
    /// index on the wire (sequenced or ordered kinds).
    pub fn has_ordering(self) -> bool {
        matches!(
            self,
            Reliability::UnreliableSequenced
                | Reliability::ReliableSequenced
                | Reliability::ReliableOrdered
        )
    }
}
