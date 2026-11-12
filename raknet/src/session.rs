//! A minimal RakNet 2.x connection endpoint (both the client and the server
//! role), enough to drive a real session end-to-end: offline connect →
//! SecuredConnection handshake → AES-encrypted reliability datagrams carrying
//! 0x51-framed game messages. Feature `mitm` (needs the RSA handshake).
//!
//! This is what a mock server (replaying a capture) and a from-scratch client
//! both need. It is intentionally simple: no retransmission (we rely on a clean
//! local path or the peer's retries); lenient receive (messages are emitted in
//! arrival order, reliable ones de-duplicated and acked); and no split-packet
//! reassembly (messages stay under the MTU).
//! These are fine for a loopback verification and an initial test against a real
//! client; a production client would tighten them. The handshake carries the two
//! live-calibration unknowns from the spec (RSA byte order, framing details).

use crate::crypto::DataBlockEncryptor;
use crate::game::{self, GameMessage};
use crate::handshake::{self, COOKIE_LEN, RANDOM_LEN};
use crate::ids::{MessageId, Reliability};
use crate::reliability::{AckRange, Datagram, InternalPacket};
use crate::rsa::KeyPair;
use std::collections::{HashSet, VecDeque};

const NUM_CHANNELS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Server,
    Client,
}

/// Something that happened as a result of feeding in a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Handshake finished; the link is encrypted and usable.
    Connected,
    /// A decoded game message arrived (`body[0]` is the message type).
    Message(GameMessage),
}

struct OutMsg {
    data: Vec<u8>,
    reliability: Reliability,
    channel: u8,
}

pub struct Endpoint {
    role: Role,
    crypto: Option<DataBlockEncryptor>,
    connected: bool,

    // Server handshake material.
    keypair: Option<KeyPair>,
    our_cookie: Option<[u8; COOKIE_LEN]>,
    // Client handshake material.
    client_random: Option<[u8; RANDOM_LEN]>,

    // Reliability bookkeeping.
    next_message_number: u16,
    ordering_index: [u16; NUM_CHANNELS],
    acks_pending: Vec<u16>,
    seen_reliable: HashSet<u16>,

    out_queue: VecDeque<OutMsg>,
    raw_out: Vec<Vec<u8>>, // fully-formed datagrams ready to send
    salt: u8,
    clock_ms: u32,
}

impl Endpoint {
    pub fn client() -> Self {
        Self::new(Role::Client)
    }

    pub fn server() -> Self {
        let mut e = Self::new(Role::Server);
        e.keypair = Some(KeyPair::generate());
        e
    }

    fn new(role: Role) -> Self {
        Endpoint {
            role,
            crypto: None,
            connected: false,
            keypair: None,
            our_cookie: None,
            client_random: None,
            next_message_number: 0,
            ordering_index: [0; NUM_CHANNELS],
            acks_pending: Vec::new(),
            seen_reliable: HashSet::new(),
            out_queue: VecDeque::new(),
            raw_out: Vec::new(),
            salt: 0,
            clock_ms: 1,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Initial datagrams to send (client kicks off the offline connect).
    pub fn start(&mut self) -> Vec<Vec<u8>> {
        if self.role == Role::Client {
            // ID_OPEN_CONNECTION_REQUEST: bare [0x13, 0, 0] (not reliability-wrapped).
            self.raw_out.push(vec![0x13, 0, 0]);
        }
        std::mem::take(&mut self.raw_out)
    }

    /// Queue an application game message (default: reliable-ordered, channel 0).
    pub fn queue_message(&mut self, msg: &[u8]) {
        self.queue_message_rel(msg, Reliability::ReliableOrdered, 0);
    }

    pub fn queue_message_rel(&mut self, msg: &[u8], reliability: Reliability, channel: u8) {
        // Frame as the game layer does: server adds the 0x1A timestamp.
        let add_ts = self.role == Role::Server;
        let framed = self.frame_game(msg, add_ts);
        self.out_queue.push_back(OutMsg { data: framed, reliability, channel });
    }

    fn frame_game(&mut self, msg: &[u8], add_ts: bool) -> Vec<u8> {
        let obf = game::obfuscate(msg, self.salt);
        self.salt = (self.salt + 1) % 255;
        let mut out = Vec::new();
        if add_ts {
            out.push(0x1A);
            out.extend_from_slice(&self.clock_ms.to_le_bytes());
            self.clock_ms = self.clock_ms.wrapping_add(1);
        }
        out.push(0x51);
        out.extend_from_slice(&obf);
        out
    }

    // ---- outgoing datagram helpers ----

    fn take_message_number(&mut self) -> u16 {
        let n = self.next_message_number;
        self.next_message_number = self.next_message_number.wrapping_add(1);
        n
    }

    fn make_packet(&mut self, data: Vec<u8>, reliability: Reliability, channel: u8) -> InternalPacket {
        let message_number = self.take_message_number();
        let ordering_index = if reliability.has_ordering() {
            let i = self.ordering_index[channel as usize];
            self.ordering_index[channel as usize] = i.wrapping_add(1);
            i
        } else {
            0
        };
        InternalPacket {
            message_number,
            reliability,
            ordering_channel: channel,
            ordering_index,
            split: None,
            data,
        }
    }

    /// Emit a single transport message (handshake) as its own datagram.
    fn emit_transport(&mut self, data: Vec<u8>, encrypt: bool) {
        let pkt = self.make_packet(data, Reliability::Reliable, 0);
        let dg = Datagram { acks: vec![], packets: vec![pkt] };
        let bytes = dg.serialize();
        self.raw_out.push(self.maybe_encrypt(bytes, encrypt));
    }

    fn maybe_encrypt(&self, bytes: Vec<u8>, encrypt: bool) -> Vec<u8> {
        match (encrypt, &self.crypto) {
            (true, Some(c)) => c.encrypt(&bytes),
            _ => bytes,
        }
    }

    fn ack_ranges(nums: &mut Vec<u16>) -> Vec<AckRange> {
        nums.sort_unstable();
        nums.dedup();
        let mut ranges = Vec::new();
        let mut iter = nums.iter().copied();
        if let Some(first) = iter.next() {
            let (mut min, mut max) = (first, first);
            for n in iter {
                if n == max.wrapping_add(1) {
                    max = n;
                } else {
                    ranges.push(AckRange { min, max });
                    min = n;
                    max = n;
                }
            }
            ranges.push(AckRange { min, max });
        }
        ranges
    }

    /// Produce datagrams to send now: handshake replies, plus (once connected) a
    /// datagram carrying pending acks and queued messages.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        let mut out = std::mem::take(&mut self.raw_out);
        if !self.connected {
            return out;
        }
        let have_acks = !self.acks_pending.is_empty();
        if !have_acks && self.out_queue.is_empty() {
            return out;
        }
        let mut acks_pending = std::mem::take(&mut self.acks_pending);
        let acks = Self::ack_ranges(&mut acks_pending);
        let mut packets = Vec::new();
        while let Some(m) = self.out_queue.pop_front() {
            packets.push(self.make_packet(m.data, m.reliability, m.channel));
        }
        let dg = Datagram { acks, packets };
        out.push(self.maybe_encrypt(dg.serialize(), true));
        out
    }

    // ---- incoming ----

    /// Feed one received UDP payload; returns resulting events. Call [`flush`]
    /// afterwards to collect datagrams to send.
    pub fn recv(&mut self, datagram: &[u8]) -> Vec<Event> {
        // Bare offline messages (not reliability-wrapped, never encrypted).
        match datagram.first().copied().and_then(MessageId::from_u8) {
            Some(MessageId::OpenConnectionRequest) if self.role == Role::Server => {
                self.raw_out.push(vec![0x14, 0]); // OPEN_CONNECTION_REPLY
                return vec![];
            }
            Some(MessageId::OpenConnectionReply) if self.role == Role::Client => {
                // Begin the secured handshake with a CONNECTION_REQUEST.
                self.emit_transport(vec![MessageId::ConnectionRequest as u8], false);
                return vec![];
            }
            _ => {}
        }

        // Decrypt if a key is active (fall back to raw for late pre-key frames).
        let plain = match &self.crypto {
            Some(c) => c.decrypt(datagram).unwrap_or_else(|_| datagram.to_vec()),
            None => datagram.to_vec(),
        };

        let dg = match Datagram::parse(&plain) {
            Ok(dg) => dg,
            Err(_) => return vec![],
        };

        let mut events = Vec::new();
        for pkt in dg.packets {
            // De-dupe reliable retransmissions and schedule an ack.
            if pkt.reliability != Reliability::Unreliable
                && pkt.reliability != Reliability::UnreliableSequenced
            {
                if self.connected {
                    self.acks_pending.push(pkt.message_number);
                }
                if !self.seen_reliable.insert(pkt.message_number) {
                    continue; // already handled
                }
            }
            self.handle_packet(pkt.data, &mut events);
        }
        events
    }

    fn handle_packet(&mut self, data: Vec<u8>, events: &mut Vec<Event>) {
        match data.first().copied() {
            Some(b) if b == MessageId::ConnectionRequest as u8 && self.role == Role::Server => {
                self.server_send_response();
            }
            Some(b) if b == MessageId::SecuredConnectionResponse as u8 && self.role == Role::Client => {
                self.client_handle_response(&data, events);
            }
            Some(b) if b == MessageId::SecuredConnectionConfirmation as u8 && self.role == Role::Server => {
                self.server_handle_confirmation(&data, events);
            }
            Some(b) if b == MessageId::ConnectionRequestAccepted as u8 && self.role == Role::Client => {
                if !self.connected {
                    self.connected = true;
                    events.push(Event::Connected);
                }
            }
            _ => {
                // A 0x51-framed game message (or an unknown transport id).
                if let Some(msg) = game::decode_payload(&data) {
                    events.push(Event::Message(msg));
                }
            }
        }
    }

    fn server_send_response(&mut self) {
        let cookie: [u8; COOKIE_LEN] = handshake::random_bytes();
        self.our_cookie = Some(cookie);
        let (e, n) = self.keypair.as_ref().unwrap().public_wire();
        let resp = handshake::build_response(&cookie, &e, &n);
        self.emit_transport(resp, false); // pre-key: unencrypted
    }

    fn client_handle_response(&mut self, data: &[u8], _events: &mut [Event]) {
        let Some(resp) = handshake::parse_response(data) else { return };
        let random: [u8; RANDOM_LEN] = handshake::random_bytes();
        self.client_random = Some(random);
        let (conf, key) =
            handshake::build_confirmation(&resp.cookie, &resp.e_wire, &resp.n_wire, &random);
        // The 0x07 is the last unencrypted message; set the key only after.
        self.emit_transport(conf, false);
        self.crypto = Some(DataBlockEncryptor::new(&key));
    }

    fn server_handle_confirmation(&mut self, data: &[u8], events: &mut Vec<Event>) {
        let (Some(conf), Some(cookie)) =
            (handshake::parse_confirmation(data), self.our_cookie)
        else {
            return;
        };
        let kp = self.keypair.as_ref().unwrap();
        let Some(key) = handshake::derive_key_from_confirmation(&cookie, kp, &conf) else {
            eprintln!("[session] cookie mismatch on 0x07");
            return;
        };
        self.crypto = Some(DataBlockEncryptor::new(&key));
        // ACCEPTED is the first encrypted message.
        self.emit_transport(vec![MessageId::ConnectionRequestAccepted as u8], true);
        self.connected = true;
        events.push(Event::Connected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a full client↔server session in-process (no sockets) and verify a
    /// scripted set of server→client messages arrives decoded intact.
    #[test]
    fn loopback_handshake_and_replay() {
        let mut server = Endpoint::server();
        let mut client = Endpoint::client();

        // Pump datagrams between the two until both are connected.
        let mut to_server = client.start();
        let mut to_client: Vec<Vec<u8>> = Vec::new();
        let mut client_events = Vec::new();

        for _ in 0..20 {
            for dg in to_client.drain(..) {
                client_events.extend(client.recv(&dg));
            }
            for dg in to_server.drain(..) {
                server.recv(&dg);
            }
            to_client.extend(server.flush());
            to_server.extend(client.flush());
            if client.is_connected() && server.is_connected()
                && to_client.is_empty() && to_server.is_empty()
            {
                break;
            }
        }
        assert!(client.is_connected(), "client should connect");
        assert!(server.is_connected(), "server should connect");
        assert!(client_events.contains(&Event::Connected));

        // Server replays some captured game messages.
        let script: Vec<Vec<u8>> = vec![
            vec![0x8F],                   // welcome
            vec![0x45, 0x01, 0x02, 0x03], // rank
            vec![0x33, 0xAA, 0xBB],       // smallloc
        ];
        for m in &script {
            server.queue_message(m);
        }
        let dgs = server.flush();
        let mut got = Vec::new();
        for dg in dgs {
            for ev in client.recv(&dg) {
                if let Event::Message(m) = ev {
                    got.push(m.body);
                }
            }
        }
        assert_eq!(got, script, "replayed messages must arrive intact");
    }
}
