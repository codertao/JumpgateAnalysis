//! Mock server: replays the server→client messages from a `jgcap.bin` capture to
//! a connecting client, over the real RakNet stack (handshake → crypto →
//! reliability → framing) via [`raknet::session`]. Feature `mitm`.
//!
//! This lets you exercise the client/stack with NO live server involved — the
//! safest possible initial test. It only ever sends captured server→client
//! messages (client→server records, which can hold a login, are ignored) and
//! never prints payloads.
//!
//! Fidelity caveats are the same as the session endpoint: no retransmission,
//! lenient ordering, handshake RSA byte order unverified against a real client
//! (`raknet::rsa::WIRE_LITTLE_ENDIAN`). If a real client won't complete the
//! handshake, that flag is the first thing to flip; the `selftest`/loopback path
//! proves the rest.

use raknet::capture;
use raknet::session::{Endpoint, Event};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const BUF: usize = 2048;

/// A scripted message: its capture timestamp and the decoded game-message bytes.
type Script = Vec<(u32, Vec<u8>)>;

struct ReplayConn {
    tag: &'static str,
    sock: UdpSocket,
    endpoint: Endpoint,
    client_addr: Option<SocketAddr>,
    script: Script,
    sent: usize,
    connected_at: Option<Instant>,
    base_ms: u32,
    speed: f32,
}

impl ReplayConn {
    fn new(
        tag: &'static str,
        listen: SocketAddr,
        script: Script,
        speed: f32,
    ) -> io::Result<Self> {
        let sock = UdpSocket::bind(listen)?;
        sock.set_read_timeout(Some(POLL))?;
        let base_ms = script.first().map(|(ms, _)| *ms).unwrap_or(0);
        eprintln!("[{tag}] mock server on {listen} — {} messages queued", script.len());
        Ok(ReplayConn {
            tag,
            sock,
            endpoint: Endpoint::server(),
            client_addr: None,
            script,
            sent: 0,
            connected_at: None,
            base_ms,
            speed: speed.max(0.01),
        })
    }

    fn send_all(&self, datagrams: Vec<Vec<u8>>) {
        if let Some(addr) = self.client_addr {
            for dg in datagrams {
                if let Err(e) = self.sock.send_to(&dg, addr) {
                    eprintln!("[{}] send failed: {e}", self.tag);
                }
            }
        }
    }

    fn poll(&mut self) {
        let mut buf = [0u8; BUF];
        match self.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if self.client_addr != Some(from) {
                    eprintln!("[{}] client {from}", self.tag);
                    self.client_addr = Some(from);
                }
                for ev in self.endpoint.recv(&buf[..n]) {
                    match ev {
                        Event::Connected => {
                            eprintln!("[{}] handshake complete — replaying", self.tag);
                            self.connected_at = Some(Instant::now());
                        }
                        Event::Message(_) => {} // client→server; ignore for replay
                    }
                }
                let out = self.endpoint.flush();
                self.send_all(out);
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => eprintln!("[{}] recv error: {e}", self.tag),
        }

        self.pump_script();
    }

    /// Queue any script messages now due (paced by the capture timeline).
    fn pump_script(&mut self) {
        let Some(start) = self.connected_at else { return };
        if self.sent >= self.script.len() {
            return;
        }
        let elapsed = start.elapsed().as_secs_f32() * self.speed;
        let mut queued = 0;
        while self.sent < self.script.len() {
            let (ms, _) = &self.script[self.sent];
            let due = (ms.wrapping_sub(self.base_ms)) as f32 / 1000.0;
            if due > elapsed {
                break;
            }
            let (_, data) = &self.script[self.sent];
            // Never log payloads — type and count only.
            let ty = data.first().copied().unwrap_or(0);
            self.endpoint.queue_message(data);
            eprintln!("[{}] → msg #{} type=0x{ty:02x} ({}B)", self.tag, self.sent, data.len());
            self.sent += 1;
            queued += 1;
            if queued >= 32 {
                break; // avoid a huge burst in one poll
            }
        }
        if queued > 0 {
            let out = self.endpoint.flush();
            self.send_all(out);
            if self.sent == self.script.len() {
                eprintln!("[{}] replay complete ({} messages)", self.tag, self.sent);
            }
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Run the mock server. Replays the capture's server→client messages on the
/// state port; the space port completes the handshake and idles.
pub fn run(
    capture_path: &str,
    listen_ip: IpAddr,
    state_port: u16,
    space_port: u16,
    speed: f32,
) -> io::Result<()> {
    let bytes = std::fs::read(capture_path)?;
    let records = capture::parse(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad capture: {e:?}")))?;
    let script: Script = capture::server_messages(&records)
        .map(|r| (r.ms, r.data.clone()))
        .collect();
    eprintln!(
        "[replay] loaded {} records ({} server→client) from {}",
        records.len(),
        script.len(),
        capture_path
    );
    if script.is_empty() {
        eprintln!("[replay] no server→client messages to replay");
    }

    let mut state = ReplayConn::new("state", SocketAddr::new(listen_ip, state_port), script, speed)?;
    // Space connection: handshake + idle (no script). Keeps the client's second
    // connection from hanging; S→C routing (state vs space) isn't in the capture.
    let mut space = ReplayConn::new("space", SocketAddr::new(listen_ip, space_port), Vec::new(), speed)?;

    eprintln!("[replay] waiting for the client to connect (point it at this host)…");
    loop {
        state.poll();
        space.poll();
    }
}
