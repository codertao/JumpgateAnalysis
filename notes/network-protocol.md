# Jumpgate.exe — network protocol notes

Binary: `Jumpgate.exe`, SHA-256 `fef6e50fc4608c1514242932823fb8cbeeda9ac6217d9f819fd802d94ca7bdf8`
(v1.0127 / "2.0127" revival build of the NetDevil game, community server
`jumpgate-tri.org`). All addresses are for this exact binary — verify the hash
before trusting them.

Evidence tags: **[static]** = read from code, **[capture]** = seen in a real
session on 2026-11-10, **[inferred]** = reasoning not yet confirmed.

---

## 1. Layers (outermost to innermost)

```
UDP datagram
  └─ RakNet (old "SecuredConnection" build): reliability + AES transport
       └─ 0x51-tagged game payload
            └─ per-message obfuscation (salt + running sum)
                 └─ game message:  [type byte][fields...]
```

### 1.1 Transport — UDP + RakNet  [static][capture]
- Winsock imported by ordinal; `SOCK_DGRAM` only, no TCP. Socket setup
  `0xa6ea70`, `recvfrom` 1500-byte `0xa6ebc0`, `sendto` `0xa6ec80`. RakNet core
  around `0xa6af20`.
- **Two servers**, both on the IP from DNS (see 1.2):
  - **state server** UDP **5150** (connection object field `+0x08`)
  - **space server** UDP **5151** (field `+0x28`)
- Wrapper object at global `0xba7cd4`: poll `0xa62c10`, send `0xa631d0`/`0xa63200`.
  Outgoing payloads are prefixed with `0x51` in `0xa63710`.
- On the wire after the handshake, every datagram is a 16-byte multiple of
  high-entropy bytes → **RakNet AES is active** [capture]. A raw pcap therefore
  yields only sizes/timing; plaintext requires the in-process shim (see tools).

### 1.2 Server discovery  [static][capture]
- `Msb32.dll!GetIP` resolves a **DNS TXT** record `_game_server.jumpgate-tri.org`;
  the TXT value is the server IP (was `217.194.148.37`). Fallback `127.0.0.1`.

### 1.3 Game payload framing  [static][capture]
- Client→server message body: `[0x51][obfuscated payload]`.
- Server→client: `[0x1A][u32 timestamp][0x51][obfuscated payload]` (0x1A =
  RakNet timestamp id; the poll loop drops anything not tagged 0x51).

### 1.4 Per-message obfuscation  [static, verified by round-trip]
Not encryption — a reversible byte scramble applied under the AES layer.
- encode `0x9c8ca0`, decode `0x9c8d30`.
- `salt = time % 255`; `srand(salt * 0x89)`; `k = (int)(rand() * 254/32767.0)`
  using MSVC `rand` (`state*0x343FD + 0x269EC3`) and `_ftol` truncation.
- encode: `out[0]=salt; out[1]=msg[0]+k; out[i+1]=out[i]+msg[i]` (running sum).
- decode: `msg[0]=in[1]-k; msg[i-1]=in[i]-in[i-1]`.
- Reference implementation: `tools/jgdecode.py` (round-trips for all 255 salts).

### 1.5 Game message
- First decoded byte = **type**. Dispatcher `0x9cf6b0` switches on types
  `0x03..0xC3` via byte table `0x9da24c` + jump table `0x9da0f0`; 86 handled,
  rest hit "Received a packet of unknown type". `SendGameMessage` = `0x9c9c10`
  (turns a DirectPlay-style "guaranteed" flag into RakNet RELIABLE_ORDERED,
  else UNRELIABLE_SEQUENCED). This is a DirectPlay→RakNet port, hence leftover
  "Init Dplay"/`dwSize` strings.

See `message-types.md` for the per-type field layouts.

---

## 2. Key exchange  [static]

RakNet's old **SecuredConnection / RSACrypt** — see `key-exchange.md` for detail.
Summary:
- **256-bit prime-field modular exponentiation** (Diffie–Hellman/RSA family).
  **No elliptic curve, no fixed curve parameters**; the modulus is runtime data
  from the server's key material. Primitives: modexp `0xa689b0`, modinverse
  `0xa68fd0`, modmul `0xa663b0`, modular reduction `0xa66190`, modsquare `0xa669e0`.
- **Unauthenticated** — nothing signs the server's public value → active MitM is
  possible against an intercepted connection.
- Randomness from a **Mersenne Twister** (`0xa758d0`, seed `0xa75780`), not a
  crypto RNG → predictable if seed recoverable.
- Primitives present: SHA-1 (`0xa76720`/`0xa78560` reset, `0xa78370` update,
  `0xa78550` final) and AES tables at `0xb2bb80` (S-box) / `0xb2bd80` (Te0) /
  `0xb2bc80` (inverse S-box).
- Handshake (RakNet reliability header stripped):
  - S→C **ID 6**, 57 bytes: `[06][20B digest][4B cookie][32B server public]`
    (client handler `0xa6cc90`, gated on decoded len == 0x39).
  - C→S **ID 7**, 53 bytes: `[07][20B echoed digest][32B client public]`
    (host side via `0xa6c860`, gated len == 0x35).
  - Client derives key, XOR-mixes, stores session key at conn `+0x81d`; feeds AES.
  - `RakPeer::InitializeSecurity` `0xa6e7a0` (state flags conn `+0x9a4`/`+0x9a5`).

---

## 3. The Msb32.dll add-on  [static][capture]

Spliced into the client via extra `.NewIT` import sections — a post-release
patch, not original code. Exports `GetIP`, `Login`, `Tick`, `catchPacket`.
- `Login` writes the version string ("2.0127") at offset 0x16 of the login
  message and sends it.
- `catchPacket` replaces the decode step before the dispatcher and adds
  **message type 0xFE**: a list of `[0x01][u32 addr][u16 len][bytes]` records
  that it **writes straight into the client's memory**. Server-pushed patching,
  with **no bounds/signature checks** — whoever controls the server (or the DNS
  TXT record) can rewrite client code/data.
- In our capture, the single 0xFE message only rewrote **award/medal name
  strings** (table at ~`0xbe0e8b..0xbe34fb`, 60-byte stride) — harmless, but the
  mechanism is unrestricted.

---

## 4. Security assessment

| Property | Finding |
|---|---|
| Transport confidentiality | AES (RakNet secure mode) — resists passive sniffing |
| Authentication of server | **None** — anonymous DH → active MitM feasible |
| RNG | Mersenne Twister — not cryptographic, predictable |
| Login credentials | **Cleartext** inside the game layer (type 0x05); protected only by the AES layer on the wire. Capture files hold the password — treat as secret. |
| Server→client code exec | **Unrestricted** memory-write via type 0xFE |
| Per-message obfuscation | Trivial, reversible; not a security control |

Net: encryption raises the bar over plaintext but is unauthenticated with a weak
RNG; treat the channel as protected against casual sniffing only.
