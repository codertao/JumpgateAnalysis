//! UDP relay loop for one connection (one server port). Binds the client-facing
//! socket, opens an ephemeral socket to the real server, and shuttles datagrams
//! between them through a [`Handler`]. A thread runs one of these per Jumpgate
//! server port (state 5150, space 5151).

use crate::connection::{Dest, Handler};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const POLL: Duration = Duration::from_millis(50);
const BUF: usize = 2048; // > MTU (RakNet caps datagrams at 576)

pub fn run(
    listen_addr: SocketAddr,
    server_addr: SocketAddr,
    mut handler: Box<dyn Handler>,
) -> io::Result<()> {
    let client_sock = UdpSocket::bind(listen_addr)?;
    client_sock.set_read_timeout(Some(POLL))?;
    let server_sock = UdpSocket::bind((listen_addr.ip(), 0))?;
    server_sock.connect(server_addr)?;
    server_sock.set_read_timeout(Some(POLL))?;

    eprintln!("[relay] listening on {listen_addr}, upstream {server_addr}");

    let mut client_addr: Option<SocketAddr> = None;
    let mut buf = [0u8; BUF];

    loop {
        match client_sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if client_addr != Some(from) {
                    eprintln!("[relay] client {from}");
                    client_addr = Some(from);
                }
                for (dest, bytes) in handler.on_client(&buf[..n]) {
                    emit(dest, &bytes, &client_sock, &server_sock, client_addr);
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(e),
        }

        match server_sock.recv(&mut buf) {
            Ok(n) => {
                for (dest, bytes) in handler.on_server(&buf[..n]) {
                    emit(dest, &bytes, &client_sock, &server_sock, client_addr);
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(e),
        }
    }
}

fn emit(
    dest: Dest,
    bytes: &[u8],
    client_sock: &UdpSocket,
    server_sock: &UdpSocket,
    client_addr: Option<SocketAddr>,
) {
    let res = match dest {
        Dest::ToServer => server_sock.send(bytes).map(|_| ()),
        Dest::ToClient => match client_addr {
            Some(addr) => client_sock.send_to(bytes, addr).map(|_| ()),
            None => Ok(()), // no client yet; nothing to answer
        },
    };
    if let Err(e) = res {
        eprintln!("[relay] send to {dest:?} failed: {e}");
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
