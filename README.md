# jumpgate-rs

A Rust workspace implementing the RakNet 2.x transport used by the Jumpgate
client, and a proxy that sits in front of **your own** client so the protocol in
[`../notes/raknet-spec.md`](../notes/raknet-spec.md) can be verified against live
traffic.

> **Scope / ethics.** This is an academic study of your own client and your own
> connection. The proxy is an *observer*: the relay never alters content, and the
> MitM mode only re-wraps the crypto envelope (the plaintext is forwarded
> unchanged). Get the fan server operators' permission before doing anything
> beyond observing your own traffic. Captures can contain a cleartext login —
> keep them out of the repo (`.gitignore` covers `*.bin`/`*.jgcap`/`*.pcap`).

## Crates

- **`raknet`** — the transport library. Zero external dependencies in its default
  build; the `mitm` feature adds the RSA handshake (pulls in `num-bigint`).
  Modules, with their verification status (mirrors the spec):

  | module | layer | status |
  |---|---|---|
  | `aes` | AES-128 block (FIPS-197 tested) | byte-verified vs binary |
  | `checksum` | RakNet running checksum | byte-verified (`0xa79e00`) |
  | `crypto` | `DataBlockEncryptor` (AES + manual chain) | byte-verified (`0xa786b0`/`0xa78820`) |
  | `bitstream` | MSB-first BitStream + compressed ints | matches reference |
  | `reliability` | datagram: acks + internal packets | reference; round-trip tested |
  | `ids` | message IDs + stock reliability enum | byte-verified |
  | `game` | 0x1A/0x51 framing + obfuscation | byte-verified (`0x9c8ca0`) |
  | `mt19937` | MT PRNG (reference only) | textbook; not on proxy path |
  | `rsa`/`handshake` (`mitm`) | SecuredConnection | structure verified; **RSA wire order needs live calibration** |
  | `session` (`mitm`) | full RakNet peer (client+server roles) | loopback + real-UDP tested |
  | `capture` | `jgcap.bin` reader | parsed; payloads never printed |

- **`proxy`** (`jumpgate-proxy`) — the UDP relay / MitM. Default build is the
  transparent relay (no crypto, no external deps).

## Build & test

```sh
cargo test --workspace                      # core library (15 tests)
cargo test --workspace --features jumpgate-proxy/mitm   # + RSA/handshake (19)
cargo run -p jumpgate-proxy -- selftest     # in-process end-to-end check
cargo run -p jumpgate-proxy --features mitm -- selftest
```

## Running the proxy

Point your client at the host running the proxy by setting `SERVER_IP` before
launch — the Msb32 shim's `GetIP` returns it instead of resolving the DNS TXT
record `_game_server.jumpgate-tri.org` (see `../notes/tools/README.txt`). No
hosts/DNS edits needed. `--server` is the real server IP the proxy forwards to.

```sh
SERVER_IP=<proxy-host-ip> Jumpgate.exe
```

```sh
# Transparent relay (default): observe + log, never modifies anything.
cargo run -p jumpgate-proxy -- --server <real-server-ip> --verbosity decode

# Experimental MitM: terminate both crypto halves to see the encrypted phase.
cargo run -p jumpgate-proxy --features mitm -- --server <real-server-ip> --verbosity decode
```

Options: `--mode raw|mitm`, `--verbosity summary|decode|hex`, `--listen <ip>`,
`--state-port 5150`, `--space-port 5151`. The proxy runs one relay per server
port (state 5150, space 5151) — both are independent RakNet sessions with their
own keys (see spec §1.1a).

### Modes

- **`raw` (default, working).** Forwards every datagram byte-for-byte and logs a
  line per datagram, decoding the *unencrypted* phases (offline connect +
  SecuredConnection handshake). Once AES is active the payload is opaque to raw
  mode. This is the safe way to capture a handshake for calibration.

- **`mitm` (experimental).** Generates its own RSA key for the client-facing
  half, terminates the SecuredConnection handshake on both sides, then decrypts →
  logs → re-encrypts each datagram transparently (content unchanged). The
  established-phase crypto re-wrap is correct and covered by `selftest`. Two
  things still need calibrating against a real capture before it will complete a
  live handshake, both flagged in the code and the spec:
  1. **RSA wire byte order** (`raknet::rsa::WIRE_LITTLE_ENDIAN`) — catid's
     big-integer serialization isn't fully reversed; defaults to little-endian.
  2. **Reliability framing of injected handshake messages** — the proxy becomes a
     partial reliability endpoint for the handshake; its message-number/ack
     handling is approximate.

## What "doesn't modify traffic" means here

- Raw mode: literally nothing is changed; bytes are copied through.
- MitM mode: game messages and their reliability framing are forwarded verbatim.
  Only the crypto envelope differs (fresh padding/nonce on re-encryption) and the
  handshake key material is substituted — both inherent to a decrypting proxy and
  neither alters game content. There are deliberately **no** content-edit hooks.

## Mock server — the safest first test (no live server)

Instead of touching the live server, replay a `jgcap.bin` capture to your own
client with a mock server. It stands up the full stack (handshake → AES →
reliability → framing) using `raknet::session` and plays back only the captured
**server→client** messages (client→server records — which can hold a login — are
ignored, and payloads are never printed).

```sh
# Serve a capture to a connecting client on the real ports.
cargo run -p jumpgate-proxy --features mitm -- replay path/to/jgcap.bin --speed 1.0

# Verify a mock server WITHOUT the game: a client built on the same library.
cargo run -p jumpgate-proxy --features mitm -- probe <mock-server-ip> --count 3
```

`probe` connects as a client, completes the handshake, and prints the message
types it receives — so you can confirm a mock server end-to-end before pointing
the real client at it. The `replay`↔`probe` path is exercised as two real
processes over UDP, and the in-crate tests cover it as a loopback
(`session::tests`) and over real sockets (`raknet/tests/udp_replay.rs`).

Caveat: completing the handshake with the **real game client** still depends on
the RSA wire byte order (`raknet::rsa::WIRE_LITTLE_ENDIAN`, default little-endian)
and on handshake framing details — both unverified against the real client. If
the real client won't connect, flip that flag first; everything downstream is
proven by the self-tests. Point the client at the mock server by launching it
with `SERVER_IP=<mock-server-ip>` (the Msb32 shim's `GetIP` honours it; see
`../notes/tools/README.txt`).

## Relation to the Msb32 shim

If you only need to observe or tweak *messages* (not the transport), the
in-process `Msb32.dll` shim in `../notes/tools/` sits inside the crypto boundary
and needs none of this. This proxy is for a standalone, out-of-process view of
the whole stack, and as groundwork for a from-scratch client.
