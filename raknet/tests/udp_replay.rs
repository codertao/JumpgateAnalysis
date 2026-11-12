//! End-to-end test over real localhost UDP sockets: a server endpoint and a
//! client endpoint complete the SecuredConnection handshake and the server
//! replays game messages that the client decodes intact. Proves the whole stack
//! (handshake → AES → reliability → framing) on the actual socket path, with no
//! live server and no real game client. Feature `mitm` only.
#![cfg(feature = "mitm")]

use raknet::session::{Endpoint, Event};
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn udp_loopback_handshake_and_replay() {
    let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    client_sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    client_sock.connect(server_addr).unwrap();

    let mut server = Endpoint::server();
    let mut client = Endpoint::client();
    let mut client_known: Option<std::net::SocketAddr> = None;

    // Client kicks off the offline connect.
    for dg in client.start() {
        client_sock.send(&dg).unwrap();
    }

    let script: Vec<Vec<u8>> = vec![
        vec![0x8F],                         // welcome
        vec![0x45, 1, 2, 3],                // rank
        vec![0x33, 0xDE, 0xAD, 0xBE, 0xEF], // smallloc
    ];
    let mut queued_script = false;
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 2048];

    for _ in 0..200 {
        // Server side.
        if let Ok((n, from)) = server_sock.recv_from(&mut buf) {
            client_known = Some(from);
            let _ = server.recv(&buf[..n]);
            for dg in server.flush() {
                server_sock.send_to(&dg, from).unwrap();
            }
        }
        if server.is_connected() && !queued_script {
            for m in &script {
                server.queue_message(m);
            }
            for dg in server.flush() {
                if let Some(a) = client_known {
                    server_sock.send_to(&dg, a).unwrap();
                }
            }
            queued_script = true;
        }

        // Client side.
        if let Ok(n) = client_sock.recv(&mut buf) {
            for ev in client.recv(&buf[..n]) {
                if let Event::Message(m) = ev {
                    got.push(m.body);
                }
            }
            for dg in client.flush() {
                client_sock.send(&dg).unwrap();
            }
        }

        if got.len() == script.len() {
            break;
        }
    }

    assert!(client.is_connected(), "client handshake over UDP failed");
    assert!(server.is_connected(), "server handshake over UDP failed");
    assert_eq!(got, script, "replayed messages must arrive intact over UDP");
}
