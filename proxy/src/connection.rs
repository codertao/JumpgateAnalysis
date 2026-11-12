//! Per-connection packet handlers.
//!
//! * [`RawRelay`] — the default: forwards every datagram byte-for-byte and logs
//!   it. It never alters content. For the unencrypted phases (offline connect +
//!   SecuredConnection handshake) it can also decode what it sees.
//!
//! * `MitmConn` (feature `mitm`, EXPERIMENTAL) — terminates both crypto halves
//!   so the encrypted phase can be observed. The established-phase crypto
//!   re-wrap is correct and offline-tested; the handshake orchestration still
//!   needs calibrating against a live capture (see `../notes/raknet-spec.md`:
//!   RSA byte order, and the reliability framing of injected handshake msgs).

use crate::log::{self, Verbosity};

/// Where a produced datagram should be sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dest {
    ToClient,
    ToServer,
}

pub trait Handler: Send {
    /// A datagram arrived from the client; return datagrams to emit.
    fn on_client(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)>;
    /// A datagram arrived from the server; return datagrams to emit.
    fn on_server(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)>;
}

/// Transparent relay + logger. Does not modify traffic.
pub struct RawRelay {
    tag: String,
    verbosity: Verbosity,
}

impl RawRelay {
    pub fn new(tag: impl Into<String>, verbosity: Verbosity) -> Self {
        RawRelay { tag: tag.into(), verbosity }
    }
}

impl Handler for RawRelay {
    fn on_client(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)> {
        // The handshake phase is unencrypted, so a decode attempt is meaningful;
        // once AES is active the bytes are opaque and parse will simply find
        // nothing useful. We never gate forwarding on that.
        log::datagram(&self.tag, "C→S", pkt, self.verbosity, true);
        vec![(Dest::ToServer, pkt.to_vec())]
    }

    fn on_server(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)> {
        log::datagram(&self.tag, "S→C", pkt, self.verbosity, true);
        vec![(Dest::ToClient, pkt.to_vec())]
    }
}

#[cfg(feature = "mitm")]
pub use mitm::MitmConn;

#[cfg(feature = "mitm")]
mod mitm {
    use super::*;
    use raknet::crypto::DataBlockEncryptor;
    use raknet::handshake::{self, COOKIE_LEN, RANDOM_LEN};
    use raknet::ids::Reliability;
    use raknet::reliability::{Datagram, InternalPacket};
    use raknet::rsa::KeyPair;

    /// A handshake message id we care about, found inside a reliability packet.
    fn find_handshake(pkt: &[u8], want: u8) -> Option<Vec<u8>> {
        // Offline/bare form first.
        if pkt.first() == Some(&want) {
            return Some(pkt.to_vec());
        }
        let dg = Datagram::parse(pkt).ok()?;
        dg.packets
            .into_iter()
            .find(|p| p.data.first() == Some(&want))
            .map(|p| p.data)
    }

    /// Wrap a handshake message as a single reliable internal packet in a
    /// datagram. Approximate: a faithful endpoint would track acks/retransmits.
    fn wrap(message: Vec<u8>, message_number: u16) -> Vec<u8> {
        let dg = Datagram {
            acks: vec![],
            packets: vec![InternalPacket {
                message_number,
                reliability: Reliability::Reliable,
                ordering_channel: 0,
                ordering_index: 0,
                split: None,
                data: message,
            }],
        };
        dg.serialize()
    }

    pub struct MitmConn {
        tag: String,
        verbosity: Verbosity,
        keypair: KeyPair, // proxy's RSA key, presented to the client
        server_cookie: Option<[u8; COOKIE_LEN]>,
        client_key: Option<DataBlockEncryptor>, // shared with the real client
        server_key: Option<DataBlockEncryptor>, // shared with the real server
        to_client_seq: u16,
        to_server_seq: u16,
        /// Plaintext datagrams from the server awaiting the client key.
        pending_to_client: Vec<Vec<u8>>,
    }

    impl MitmConn {
        pub fn new(tag: impl Into<String>, verbosity: Verbosity) -> Self {
            eprintln!("[mitm] generating RSA key for the client-facing half…");
            MitmConn {
                tag: tag.into(),
                verbosity,
                keypair: KeyPair::generate(),
                server_cookie: None,
                client_key: None,
                server_key: None,
                to_client_seq: 0,
                to_server_seq: 0,
                pending_to_client: Vec::new(),
            }
        }

        fn next_to_server(&mut self) -> u16 {
            let n = self.to_server_seq;
            self.to_server_seq = self.to_server_seq.wrapping_add(1);
            n
        }
        fn next_to_client(&mut self) -> u16 {
            let n = self.to_client_seq;
            self.to_client_seq = self.to_client_seq.wrapping_add(1);
            n
        }
    }

    impl Handler for MitmConn {
        fn on_client(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)> {
            // Established toward the client? Then client→proxy is AES.
            if let Some(ck) = &self.client_key {
                match ck.decrypt(pkt) {
                    Ok(plain) => {
                        log::plaintext(&self.tag, "C→S", &plain, self.verbosity);
                        // Re-wrap verbatim under the server key. Content unchanged.
                        if let Some(sk) = &self.server_key {
                            return vec![(Dest::ToServer, sk.encrypt(&plain))];
                        }
                        eprintln!("[mitm] client data before server key ready; dropping");
                        return vec![];
                    }
                    Err(e) => {
                        eprintln!("[mitm] client decrypt failed ({e:?}); passing through");
                        return vec![(Dest::ToServer, pkt.to_vec())];
                    }
                }
            }

            // Pre-key: the client's 0x07 confirms OUR 0x06.
            if let Some(conf_bytes) = find_handshake(pkt, 0x07) {
                if let (Some(conf), Some(cookie)) =
                    (handshake::parse_confirmation(&conf_bytes), self.server_cookie)
                {
                    match handshake::derive_key_from_confirmation(&cookie, &self.keypair, &conf) {
                        Some(key) => {
                            eprintln!("[mitm] client key established");
                            self.client_key = Some(DataBlockEncryptor::new(&key));
                            // Flush anything the server already sent.
                            let mut out = Vec::new();
                            let pending = std::mem::take(&mut self.pending_to_client);
                            if let Some(ck) = &self.client_key {
                                for plain in pending {
                                    out.push((Dest::ToClient, ck.encrypt(&plain)));
                                }
                            }
                            return out; // do not forward the client's 0x07
                        }
                        None => eprintln!("[mitm] cookie mismatch on client 0x07"),
                    }
                }
                return vec![]; // swallow a malformed 0x07
            }

            // Everything else pre-key (OPEN_CONNECTION_REQUEST, CONNECTION_REQUEST,
            // acks) is forwarded unchanged so the server drives the handshake.
            log::datagram(&self.tag, "C→S", pkt, self.verbosity, true);
            vec![(Dest::ToServer, pkt.to_vec())]
        }

        fn on_server(&mut self, pkt: &[u8]) -> Vec<(Dest, Vec<u8>)> {
            // Established toward the server? Then server→proxy is AES.
            if let Some(sk) = &self.server_key {
                // The server's 0x06 is the last plaintext; after we set the key,
                // everything is encrypted.
                match sk.decrypt(pkt) {
                    Ok(plain) => {
                        log::plaintext(&self.tag, "S→C", &plain, self.verbosity);
                        if let Some(ck) = &self.client_key {
                            return vec![(Dest::ToClient, ck.encrypt(&plain))];
                        }
                        // Client key not ready yet — buffer until the 0x07 lands.
                        self.pending_to_client.push(plain);
                        return vec![];
                    }
                    Err(e) => {
                        eprintln!("[mitm] server decrypt failed ({e:?}); passing through");
                        return vec![(Dest::ToClient, pkt.to_vec())];
                    }
                }
            }

            // Pre-key: the server's 0x06 carries its real (e, n). Terminate both
            // halves here.
            if let Some(resp_bytes) = find_handshake(pkt, 0x06) {
                if let Some(resp) = handshake::parse_response(&resp_bytes) {
                    eprintln!("[mitm] server 0x06 received; terminating handshake");
                    // Client-half: confirm to the server with our own random.
                    let random: [u8; RANDOM_LEN] = handshake::random_bytes();
                    let (conf, server_key) =
                        handshake::build_confirmation(&resp.cookie, &resp.e_wire, &resp.n_wire, &random);
                    self.server_key = Some(DataBlockEncryptor::new(&server_key));
                    let sn = self.next_to_server();

                    // Server-half: present our own 0x06 to the client.
                    let cookie: [u8; COOKIE_LEN] = handshake::random_bytes();
                    self.server_cookie = Some(cookie);
                    let (e, n) = self.keypair.public_wire();
                    let our_resp = handshake::build_response(&cookie, &e, &n);
                    let cn = self.next_to_client();

                    return vec![
                        (Dest::ToServer, wrap(conf, sn)),
                        (Dest::ToClient, wrap(our_resp, cn)),
                    ];
                }
            }

            // Other pre-key datagrams (OPEN_CONNECTION_REPLY, acks) pass through.
            log::datagram(&self.tag, "S→C", pkt, self.verbosity, true);
            vec![(Dest::ToClient, pkt.to_vec())]
        }
    }
}
