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

/// Client MTU: default 1500, clamped to 512..=1500 by SetMTUSize (`0xa69b76`,
/// `0xa64122`). As in the reference reliability layer, a datagram's plaintext
/// budget is MTU − 28 (IP+UDP), minus 16 more once encryption is on.
const MTU: usize = 1500;
const UDP_HEADER: usize = 28;
const ENCRYPTION_OVERHEAD: usize = 16;

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
    /// Key agreed in the 0x07 exchange but not yet active. Stock 2.x installs it
    /// into the reliability layer only once ACCEPTED is processed (client
    /// `0xa6e183`), so ACCEPTED travels in the clear. The server turns it on
    /// when the first datagram decrypts with it.
    pending_crypto: Option<DataBlockEncryptor>,
    connected: bool,
    /// Peer address echoed in ACCEPTED / NEW_INCOMING_CONNECTION.
    peer: ([u8; 4], u16),

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
    /// `RAKNET_TRACE` set: log each received datagram and handshake step to stderr
    /// (lengths, IDs and decisions only — never payload bytes).
    trace: bool,
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
            pending_crypto: None,
            connected: false,
            peer: ([0; 4], 0),
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
            trace: std::env::var_os("RAKNET_TRACE").is_some(),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set the peer's address, echoed in ACCEPTED (server) or
    /// NEW_INCOMING_CONNECTION (client). Optional: zeros work otherwise.
    pub fn set_peer_addr(&mut self, addr: std::net::SocketAddr) {
        if let std::net::SocketAddr::V4(v4) = addr {
            self.peer = (v4.ip().octets(), v4.port());
        }
    }

    /// `[id][u32 binaryAddress][u16 port]`: address octets in network order,
    /// port little-endian (written as raw native ints, client `0xa6e10a`).
    fn addr_message(&self, id: MessageId) -> Vec<u8> {
        let mut m = vec![id as u8];
        m.extend_from_slice(&self.peer.0);
        m.extend_from_slice(&self.peer.1.to_le_bytes());
        m
    }

    /// Initial datagrams to send (client kicks off the offline connect).
    pub fn start(&mut self) -> Vec<Vec<u8>> {
        if self.role == Role::Client {
            // ID_OPEN_CONNECTION_REQUEST: bare [0A 00], exactly 2 bytes (0xa6d34f).
            self.raw_out.push(vec![MessageId::OpenConnectionRequest as u8, 0]);
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

    /// Emit a single transport message (handshake) as its own datagram, carrying
    /// any pending acks along with it so they share its encryption state.
    fn emit_transport(&mut self, data: Vec<u8>, encrypt: bool) {
        let pkt = self.make_packet(data, Reliability::Reliable, 0);
        let mut pending = std::mem::take(&mut self.acks_pending);
        let acks = Self::ack_ranges(&mut pending);
        let dg = Datagram { acks, packets: vec![pkt] };
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
        // Before the connection is up only acks go out (queued game messages wait).
        if !self.connected && self.acks_pending.is_empty() {
            return out;
        }
        let have_acks = !self.acks_pending.is_empty();
        if !have_acks && self.out_queue.is_empty() {
            return out;
        }
        let mut acks_pending = std::mem::take(&mut self.acks_pending);
        let acks = Self::ack_ranges(&mut acks_pending);
        if self.trace && !self.connected {
            eprintln!("[raknet:{:?}] -> ack-only datagram ({} range(s))", self.role, acks.len());
        }
        let budget = MTU - UDP_HEADER - if self.crypto.is_some() { ENCRYPTION_OVERHEAD } else { 0 };

        // Pack queued messages into as few datagrams as fit the budget; acks ride
        // in the first one.
        let mut dg = Datagram { acks, packets: Vec::new() };
        while self.connected {
            let Some(m) = self.out_queue.pop_front() else { break };
            let pkt = self.make_packet(m.data, m.reliability, m.channel);
            dg.packets.push(pkt);
            let fits = dg.serialize().len() <= budget;
            let lone = dg.packets.len() == 1 && dg.acks.is_empty();
            if fits {
                continue;
            }
            if lone {
                // No split-packet support yet; real server messages stay <= 896 B.
                eprintln!(
                    "[raknet:{:?}] warning: {}-byte packet exceeds the {budget}-byte budget (no split support)",
                    self.role,
                    dg.packets[0].data.len()
                );
                continue;
            }
            // Over budget: ship what fit and start the next datagram with this packet.
            let pkt = dg.packets.pop().unwrap();
            let full = std::mem::replace(&mut dg, Datagram { acks: vec![], packets: vec![pkt] });
            out.push(self.maybe_encrypt(full.serialize(), true));
        }
        if !dg.acks.is_empty() || !dg.packets.is_empty() {
            out.push(self.maybe_encrypt(dg.serialize(), true));
        }
        out
    }

    // ---- incoming ----

    /// Feed one received UDP payload; returns resulting events. Call [`flush`]
    /// afterwards to collect datagrams to send.
    pub fn recv(&mut self, datagram: &[u8]) -> Vec<Event> {
        if self.trace {
            eprintln!(
                "[raknet:{:?}] <- {}B first=0x{:02x} key={}",
                self.role,
                datagram.len(),
                datagram.first().copied().unwrap_or(0),
                self.crypto.is_some()
            );
        }
        // Bare offline messages (not reliability-wrapped, never encrypted). They
        // are only ever 2 bytes, so longer datagrams starting with these bytes
        // fall through to the reliability parser.
        let offline = datagram.len() <= 2;
        match datagram.first().copied().and_then(MessageId::from_u8) {
            Some(MessageId::OpenConnectionRequest) if offline && self.role == Role::Server => {
                self.tr("offline OPEN_CONNECTION_REQUEST -> OPEN_CONNECTION_REPLY");
                self.raw_out.push(vec![MessageId::OpenConnectionReply as u8, 0]);
                return vec![];
            }
            Some(MessageId::OpenConnectionReply) if offline && self.role == Role::Client => {
                self.tr("offline OPEN_CONNECTION_REPLY -> CONNECTION_REQUEST");
                // Begin the secured handshake with a CONNECTION_REQUEST.
                self.emit_transport(vec![MessageId::ConnectionRequest as u8], false);
                return vec![];
            }
            _ => {}
        }

        let mut events = Vec::new();

        // Decrypt if a key is active (fall back to raw for late pre-key frames).
        // A server holding a pending key activates it on the first datagram
        // that decrypts — proof the client accepted our RSA key.
        let plain = if let Some(c) = &self.crypto {
            c.decrypt(datagram).unwrap_or_else(|_| datagram.to_vec())
        } else if let Some(Ok(pl)) = self.pending_crypto.as_ref().map(|p| p.decrypt(datagram)) {
            self.crypto = self.pending_crypto.take();
            self.tr("first encrypted datagram decrypted -> key active, connected");
            if !self.connected {
                self.connected = true;
                events.push(Event::Connected);
            }
            pl
        } else {
            datagram.to_vec()
        };

        let dg = match Datagram::parse(&plain) {
            Ok(dg) => dg,
            Err(e) => {
                if self.trace {
                    eprintln!("[raknet:{:?}] datagram parse failed: {e:?}", self.role);
                }
                return vec![];
            }
        };
        if self.trace {
            eprintln!(
                "[raknet:{:?}]    {} ack range(s), {} packet(s): {}",
                self.role,
                dg.acks.len(),
                dg.packets.len(),
                dg.packets
                    .iter()
                    .map(|p| format!(
                        "#{} {:?} id=0x{:02x} {}B",
                        p.message_number,
                        p.reliability,
                        p.data.first().copied().unwrap_or(0),
                        p.data.len()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        for pkt in dg.packets {
            // De-dupe reliable retransmissions and schedule an ack.
            if pkt.reliability != Reliability::Unreliable
                && pkt.reliability != Reliability::UnreliableSequenced
            {
                // Ack every reliable packet, handshake included, as the stock
                // reliability layer does — otherwise the peer keeps resending.
                self.acks_pending.push(pkt.message_number);
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
                self.server_handle_confirmation(&data);
            }
            Some(b) if b == MessageId::ConnectionRequestAccepted as u8 && self.role == Role::Client => {
                // Client accepts only the exact 9-byte form (0xa6e0ad).
                if data.len() != 9 || self.connected {
                    self.tr("ACCEPTED ignored (not 9 bytes, or already connected)");
                    return;
                }
                if let Some(k) = self.pending_crypto.take() {
                    self.crypto = Some(k);
                }
                self.tr("ACCEPTED -> key active, NEW_INCOMING_CONNECTION (encrypted)");
                let nic = self.addr_message(MessageId::NewIncomingConnection);
                self.emit_transport(nic, true);
                self.connected = true;
                events.push(Event::Connected);
            }
            Some(b) if b == MessageId::NewIncomingConnection as u8 => {
                self.tr("NEW_INCOMING_CONNECTION");
            }
            Some(0x00) if data.len() >= 5 => {
                // ID_INTERNAL_PING [00][u32 sendTime] -> ID_CONNECTED_PONG
                // [03][u32 sendTime][u32 ourTime], unreliable.
                let mut pong = vec![MessageId::ConnectedPong as u8];
                pong.extend_from_slice(&data[1..5]);
                pong.extend_from_slice(&self.clock_ms.to_le_bytes());
                self.out_queue.push_back(OutMsg {
                    data: pong,
                    reliability: Reliability::Unreliable,
                    channel: 0,
                });
            }
            _ => {
                // A 0x51-framed game message (or an unknown transport id).
                if let Some(msg) = game::decode_payload(&data) {
                    events.push(Event::Message(msg));
                }
            }
        }
    }

    fn tr(&self, what: &str) {
        if self.trace {
            eprintln!("[raknet:{:?}]    {what}", self.role);
        }
    }

    fn server_send_response(&mut self) {
        self.tr("CONNECTION_REQUEST -> SECURED_CONNECTION_RESPONSE (0x06)");
        let cookie: [u8; COOKIE_LEN] = handshake::random_bytes();
        self.our_cookie = Some(cookie);
        let (e, n) = self.keypair.as_ref().unwrap().public_wire();
        let resp = handshake::build_response(&cookie, &e, &n);
        self.emit_transport(resp, false); // pre-key: unencrypted
    }

    fn client_handle_response(&mut self, data: &[u8], _events: &mut [Event]) {
        let Some(resp) = handshake::parse_response(data) else {
            self.tr("0x06 did not parse (expected 57 bytes)");
            return;
        };
        self.tr("SECURED_CONNECTION_RESPONSE -> CONFIRMATION (0x07), key set");
        let random: [u8; RANDOM_LEN] = handshake::random_bytes();
        self.client_random = Some(random);
        let (conf, key) =
            handshake::build_confirmation(&resp.cookie, &resp.e_wire, &resp.n_wire, &random);
        // 0x07 is unencrypted; the key goes live when ACCEPTED arrives.
        self.emit_transport(conf, false);
        self.pending_crypto = Some(DataBlockEncryptor::new(&key));
    }

    fn server_handle_confirmation(&mut self, data: &[u8]) {
        let (Some(conf), Some(cookie)) =
            (handshake::parse_confirmation(data), self.our_cookie)
        else {
            self.tr("0x07 did not parse, or no cookie issued yet");
            return;
        };
        let kp = self.keypair.as_ref().unwrap();
        let Some(key) = handshake::derive_key_from_confirmation(&cookie, kp, &conf) else {
            eprintln!("[session] cookie mismatch on 0x07");
            return;
        };
        self.tr("SECURED_CONNECTION_CONFIRMATION ok -> CONNECTION_REQUEST_ACCEPTED (clear), key pending");
        self.pending_crypto = Some(DataBlockEncryptor::new(&key));
        // ACCEPTED (9 bytes) goes in the clear; see `pending_crypto`.
        let mut accepted = self.addr_message(MessageId::ConnectionRequestAccepted);
        accepted.extend_from_slice(&0u16.to_le_bytes()); // playerIndex
        self.emit_transport(accepted, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pump datagrams between a fresh server and client until both connect.
    fn connected_pair() -> (Endpoint, Endpoint, Vec<Event>) {
        let mut server = Endpoint::server();
        let mut client = Endpoint::client();
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
        (server, client, client_events)
    }

    /// A burst of large messages is spread over datagrams that fit the MTU,
    /// and all arrive intact and in order.
    #[test]
    fn flush_respects_mtu() {
        let (mut server, mut client, _) = connected_pair();
        let script: Vec<Vec<u8>> = (0..20u8)
            .map(|i| {
                let mut m = vec![0x0d, i];
                m.resize(896, i);
                m
            })
            .collect();
        for m in &script {
            server.queue_message(m);
        }
        let dgs = server.flush();
        assert!(dgs.len() > 1, "burst should span several datagrams");
        let mut got = Vec::new();
        for dg in &dgs {
            assert!(dg.len() <= MTU - UDP_HEADER, "datagram of {} bytes exceeds MTU", dg.len());
            for ev in client.recv(dg) {
                if let Event::Message(m) = ev {
                    got.push(m.body);
                }
            }
        }
        assert_eq!(got, script);
    }

    /// Drive a full client↔server session in-process (no sockets) and verify a
    /// scripted set of server→client messages arrives decoded intact.
    #[test]
    fn loopback_handshake_and_replay() {
        let (mut server, mut client, client_events) = connected_pair();
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
