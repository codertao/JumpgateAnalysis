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

### 1.1b RakNet version  [static + reference sources, 2026-11-12]
There are no version strings. The only RakNet text is "RakNet base connection to
'Unknown Server' acquired…". So the version was identified from the **message-ID
enum** the internal handler uses (comparisons at `0xa6d8e0..0xa6e2f0`, called from
`0xa6de95`/`0xa6dfe3`) and from the timestamp helpers `0xa63ae0`/`0xa63b00`.

| ID | Binary evidence | Classic 2.x `PacketEnumerations.h` |
|---|---|---|
| 3 | handled | ID_CONNECTED_PONG |
| 4 | handled | ID_REQUEST_STATIC_DATA |
| 5 | handled | ID_CONNECTION_REQUEST |
| 6 / 7 | handled (key exchange) | ID_SECURED_CONNECTION_RESPONSE / _CONFIRMATION |
| 8 | handled | ID_RPC_MAPPING |
| 9 | handled | ID_DETECT_LOST_CONNECTIONS |
| 0x0c | handled | ID_RPC |
| 0x10 | handled | ID_CONNECTION_REQUEST_ACCEPTED |
| 0x11 | emitted | ID_CONNECTION_ATTEMPT_FAILED |
| 0x12 | handled | ID_NEW_INCOMING_CONNECTION |
| 0x14 | handled | ID_DISCONNECTION_NOTIFICATION |
| 0x19 | emitted | ID_MODIFIED_PACKET |
| 0x1a | `[1a][u32 time]` skipped by the receive helpers (payload at +5/+6) | ID_TIMESTAMP (32-bit RakNetTime) |
| 0x1c | handled | ID_RECEIVED_STATIC_DATA |

All 14 match the classic RakNet **2.x** ordering. The source used to check is the
SA:MP RakNet header with its inserted `ID_DUMMY_*` entries removed. The later 2.x
reshuffle (ID_RPC = 8, ID_KEEPALIVE = 12, ID_TIMESTAMP = 28, e.g. Blobby Volley's copy)
does **not** match. Neither does 3.x `MessageIdentifiers.h`.

**Conclusion:** RakNet 2.x, before the enum reshuffle, roughly 2004–05. Signs of that
era: "static data", ID_RPC_MAPPING, a 32-bit timestamp, SecuredConnection/RSACrypt
handshake, and a DataBlockEncryptor-style AES. The exact minor version is not
pinned. Next step for that: diff the ReliabilityLayer datagram header bit layout
(`0xa6af20` area) against archived 2.x sources.

Practical notes for a reimplementation:
- Modern RakNet crates (e.g. Rust `rak-rs`, the Bedrock flavour) speak a different,
  incompatible protocol.
- The closest public code is the RakNet 2.x copies in the SA:MP community
  (resamp-raknet, 0xcds4r/RakNet, Alf21/samp). Mind the SA:MP-specific changes:
  the dummy IDs and their own packet scrambling.

### 1.1a Which server each message goes to  [static, 2026-11-12]
The client has **one sender per connection**. Both of them obfuscate the payload and
then call RakNet send:
- `0x9c9c10` SendGameMessage → `0xa631d0` → conn `+0x08` = **state server (5150)**.
  Buffer `0xba7ce8`, ordering channel 0.
- `0x9c9c90` SendSpaceMessage → `0xa63200` → conn `+0x28` = **space server (5151)**.
  Buffer `0xba84e8`. Takes a 4th argument, an ordering channel (forced to 0 if > 0x20).
- 14 hot-path sends call `0xa631d0`/`0xa63200` directly (7 each), all inside `0x9c9d10..0x9cf206`.

Of 293 send sites, 268 go to state (261 through the wrapper + 7 direct) and 25 go to
space (18 + 7 direct).

**→ space server:**
- **Position:** 0x05 full "loc2/gloc" report (176 B, from `send_location_tick` and
  `on_char_record`), 0x33 small loc (56), 0x34 mini loc (52), mloc (40, `0x9ca840`).
- **Bots:** 0x71 botloc (52; all the "botloc N" sites, bot AI, damage handler), 0x2C
  bot handoff "bxr".
- **Combat:** 0x1D new-fired / hit queue (unreliable-sequenced, g=2), 0x1A mkill,
  0x4D modx (one of the four sites: the PWD pulse `0x427af0`).
- **Other:** 0xB0 (20 B; teleport, launch, bot AI), 0xA0 (launch), 0x8F welcome/ack
  (1 B, `0x9cb4d0`).

**→ state server:** everything else, including:
- **Session/commands:** login, 0x07 dock/jump/launch, 0x09 commands, 0x17 companion
  (10 B, sent right after each 0x05).
- **Requests:** 0x75 (sent every 100th loc tick and on entering space), 0x8A weather,
  0xA1 (enter space), 0x6A player list.
- **Trade, chat and missions:** 0x4A/0x4C/0x4E…, 0x66/0x9C/0xC3 (the many-site
  UI types), the other 0x4D modx and 0x8F sites, and all the other C→S types in
  `captures/send_types.txt`.

The split is clean. State is the persistent, reliable traffic: account, inventory,
market, chat, missions, docking. Space is the real-time sector simulation:
positions, bots, shots, kills, and in-space effects like PWD.

**Receiving:** both sockets feed one queue. The poll loop `0xa62c10` compares the
sender address with the state peer (`+0x08`). It then tags the queued packet
`[pkt+0x10]` = 0 for state or 1 for space, and stamps that connection's last-heard
time (`+0x18`/`+0x1c` for state, `+0x38`/`+0x3c` for space). Everything then goes
through the single dispatcher `0x9cf6b0`. Whether any handler checks the tag
hasn't been verified.

**The capture doesn't have this.** The Msb32 shim hooks `catchPacket` (decode only)
and encoder `0x9c8ca0`, below the point where the connection is chosen. So
`timeline_sanitized.txt` has no state/space column. Two ways to add one:
- For C→S, the source buffer tells you: `0xba7ce8` is state and `0xba84e8` is space.
  The shim already sees it as the encoder's dst argument.
- For S→C, hook `0xa62c10` or read `[pkt+0x10]`.

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

RakNet's old **SecuredConnection / RSACrypt** — see `key-exchange.md` for the
handshake and `raknet-spec.md` for the full 2.x transport (crypto, reliability
datagram layout, MitM proxy plan).
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
