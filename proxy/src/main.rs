//! Observing MitM / relay proxy for a Jumpgate client.
//!
//! SCOPE & ETHICS: point this only at YOUR OWN client and YOUR OWN connection.
//! It is an observer — the relay never alters content, and the MitM mode only
//! re-wraps the crypto envelope (identical plaintext). Get the server
//! operators' permission before doing anything beyond observing your own
//! traffic. Captures can contain a cleartext login; keep them out of the repo.
//!
//! Usage:
//!   jumpgate-proxy --server <ip> [--mode raw|mitm] [--verbosity summary|decode|hex]
//!                  [--listen <ip>] [--state-port 5150] [--space-port 5151]
//!   jumpgate-proxy selftest
//!
//! Point the client at this proxy's host (it resolves the server via the DNS TXT
//! record `_game_server.jumpgate-tri.org`; override that in your hosts/DNS, or
//! patch the Msb32 fallback, to aim the client here). `--server` is the real
//! server IP the proxy forwards to.

mod connection;
mod log;
mod relay;

use connection::{Handler, RawRelay};
use log::Verbosity;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Raw,
    Mitm,
}

struct Config {
    server: IpAddr,
    listen: IpAddr,
    state_port: u16,
    space_port: u16,
    mode: Mode,
    verbosity: Verbosity,
}

fn usage() -> ! {
    eprintln!(
        "usage: jumpgate-proxy --server <ip> [--mode raw|mitm] \
         [--verbosity summary|decode|hex] [--listen <ip>] \
         [--state-port 5150] [--space-port 5151]\n   or: jumpgate-proxy selftest"
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    let mut args = std::env::args().skip(1).peekable();
    let mut server: Option<IpAddr> = None;
    let mut listen: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut state_port = 5150u16;
    let mut space_port = 5151u16;
    let mut mode = Mode::Raw;
    let mut verbosity = Verbosity::Decode;

    while let Some(a) = args.next() {
        let mut want = |name: &str| -> String {
            args.next().unwrap_or_else(|| {
                eprintln!("missing value for {name}");
                usage()
            })
        };
        match a.as_str() {
            "--server" => server = Some(want("--server").parse().unwrap_or_else(|_| usage())),
            "--listen" => listen = want("--listen").parse().unwrap_or_else(|_| usage()),
            "--state-port" => state_port = want("--state-port").parse().unwrap_or_else(|_| usage()),
            "--space-port" => space_port = want("--space-port").parse().unwrap_or_else(|_| usage()),
            "--mode" => {
                mode = match want("--mode").as_str() {
                    "raw" => Mode::Raw,
                    "mitm" => Mode::Mitm,
                    _ => usage(),
                }
            }
            "--verbosity" => {
                verbosity = Verbosity::parse(&want("--verbosity")).unwrap_or_else(|| usage())
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }

    Config {
        server: server.unwrap_or_else(|| {
            eprintln!("--server <ip> is required");
            usage()
        }),
        listen,
        state_port,
        space_port,
        mode,
        verbosity,
    }
}

fn make_handler(tag: &str, mode: Mode, verbosity: Verbosity) -> Box<dyn Handler> {
    match mode {
        Mode::Raw => Box::new(RawRelay::new(tag, verbosity)),
        Mode::Mitm => {
            #[cfg(feature = "mitm")]
            {
                Box::new(connection::MitmConn::new(tag, verbosity))
            }
            #[cfg(not(feature = "mitm"))]
            {
                let _ = tag;
                eprintln!("mitm mode needs `--features mitm` at build time; using raw relay");
                Box::new(RawRelay::new(tag, verbosity))
            }
        }
    }
}

fn spawn(tag: &'static str, cfg: &Config, port: u16) -> thread::JoinHandle<()> {
    let listen = SocketAddr::new(cfg.listen, port);
    let server = SocketAddr::new(cfg.server, port);
    let handler = make_handler(tag, cfg.mode, cfg.verbosity);
    thread::Builder::new()
        .name(tag.to_string())
        .spawn(move || {
            if let Err(e) = relay::run(listen, server, handler) {
                eprintln!("[{tag}] relay exited: {e}");
            }
        })
        .expect("spawn relay thread")
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("selftest") {
        selftest::run();
        return;
    }

    let cfg = parse_args();
    if cfg.mode == Mode::Mitm {
        eprintln!(
            "[warn] MitM mode is experimental: it terminates both crypto halves. \
             RSA wire-format and handshake framing may need calibrating against a \
             capture (see notes/raknet-spec.md). The relay never alters content."
        );
    }
    eprintln!("[main] mode={}", if cfg.mode == Mode::Mitm { "mitm" } else { "raw" });

    let state = spawn("state", &cfg, cfg.state_port);
    let space = spawn("space", &cfg, cfg.space_port);
    let _ = state.join();
    let _ = space.join();
}

/// In-process end-to-end checks that need no network.
mod selftest {
    use raknet::crypto::DataBlockEncryptor;
    use raknet::ids::Reliability;
    use raknet::reliability::{Datagram, InternalPacket};

    pub fn run() {
        println!("running in-process self-test…");
        reliability_crypto_rewrap();
        #[cfg(feature = "mitm")]
        handshake_then_rewrap();
        #[cfg(not(feature = "mitm"))]
        println!("  (build with --features mitm to also test the handshake)");
        println!("self-test OK");
    }

    fn sample_datagram() -> Datagram {
        Datagram {
            acks: vec![],
            packets: vec![InternalPacket {
                message_number: 1,
                reliability: Reliability::ReliableOrdered,
                ordering_channel: 0,
                ordering_index: 3,
                split: None,
                // a 0x51-framed game message would live here
                data: vec![0x51, 0x2a, 0x33, 0x44],
            }],
        }
    }

    /// Prove the established-phase path: a datagram encrypted under key A is
    /// decrypted and re-encrypted under key B with its content unchanged.
    fn reliability_crypto_rewrap() {
        let key_a = [0x11u8; 16];
        let key_b = [0x22u8; 16];
        let enc_a = DataBlockEncryptor::new(&key_a);
        let enc_b = DataBlockEncryptor::new(&key_b);

        let dg = sample_datagram();
        let plain = dg.serialize();

        let on_wire_a = enc_a.encrypt(&plain); // client → proxy
        let recovered = enc_a.decrypt(&on_wire_a).expect("decrypt A");
        assert_eq!(recovered, plain, "content must survive decrypt");
        let on_wire_b = enc_b.encrypt(&recovered); // proxy → server
        let at_server = enc_b.decrypt(&on_wire_b).expect("decrypt B");
        assert_eq!(at_server, plain, "content must be unchanged end to end");
        assert_eq!(Datagram::parse(&at_server).unwrap(), dg);
        println!("  crypto re-wrap: content preserved across key A → key B ✓");
    }

    #[cfg(feature = "mitm")]
    fn handshake_then_rewrap() {
        use raknet::handshake::{
            build_confirmation, derive_key_from_confirmation, parse_confirmation, random_bytes,
            COOKIE_LEN, RANDOM_LEN,
        };
        use raknet::rsa::KeyPair;

        // Proxy (as server to the client) generates a key and a cookie.
        let kp = KeyPair::generate();
        let (e, n) = kp.public_wire();
        let cookie: [u8; COOKIE_LEN] = random_bytes();

        // Client derives its key and sends 0x07.
        let client_random: [u8; RANDOM_LEN] = random_bytes();
        let (conf_bytes, client_key) = build_confirmation(&cookie, &e, &n, &client_random);

        // Proxy recovers the same key.
        let conf = parse_confirmation(&conf_bytes).unwrap();
        let proxy_key = derive_key_from_confirmation(&cookie, &kp, &conf).unwrap();
        assert_eq!(client_key, proxy_key, "handshake keys must agree");

        // And the key actually decrypts a datagram the "client" encrypts.
        let c = DataBlockEncryptor::new(&client_key);
        let p = DataBlockEncryptor::new(&proxy_key);
        let dg = sample_datagram().serialize();
        let wire = c.encrypt(&dg);
        assert_eq!(p.decrypt(&wire).unwrap(), dg);
        println!("  handshake: client/proxy keys agree and decrypt traffic ✓");
    }
}
