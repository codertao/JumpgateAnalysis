# RakNet 2.x wire spec (as used by Jumpgate.exe)

Goal: enough of the RakNet 2.x transport to build a **MitM proxy** that terminates
the connection on both sides and re-encrypts, so we can verify our understanding
of every layer against live traffic (own client, own account — see scope).

Status tags:
- **[bin]** verified in `Jumpgate.exe` (`fef6e50f…`) by disassembly.
- **[ref]** from archived RakNet 2.x source (SA:MP lineage: `resamp-raknet`,
  `0xcds4r/RakNet`), whose message-ID enum, after removing the inserted
  `ID_DUMMY_*` entries, matches this binary (network-protocol.md §1.1b).
- **[ref→bin]** taken from [ref] and spot-checked against the binary.

The SA:MP source carries SA:MP-only changes (dummy IDs, packet-cookie scrambling,
a shifted `PacketReliability` enum). Each place that matters is called out.

Layer stack (outermost first):
```
UDP datagram
└─ DataBlockEncryptor (AES-128, only after the key is set)   ← [bin]
   └─ RakNet datagram: [acks?] + internal packets, bit-packed ← [ref→bin]
      └─ message: first byte = RakNet ID or game type          ← [bin]
         └─ (game only) 0x1A timestamp wrap, then 0x51 frame + per-msg obfuscation
            └─ game message  (message-types.md)
```

---

## 1. Connection establishment

All pre-key packets are sent **unencrypted** (no AES key yet) and are dispatched
by their first byte. IDs are the classic 2.x `PacketEnumerations.h` values
(network-protocol.md §1.1b lists the full table).

```
C → S   ID_OPEN_CONNECTION_REQUEST  (0x0A)   2 bytes: [0A][00]           [bin]
S → C   ID_OPEN_CONNECTION_REPLY    (0x0B)   2 bytes: [0B][00]           [bin]
        (or ID_NO_FREE_INCOMING_CONNECTIONS (0x13) [13][00] when full)
C → S   ID_CONNECTION_REQUEST       (0x05)   [05] + optional password    [ref]
        — sent RELIABLE, i.e. now inside the reliability layer.
```
**[bin]** Client builds `[0A 00]` at `0xa6d34f` and sends it bare. The offline handler
takes `0x0A` only when the length is exactly 2 (`0xa6b4e5`) and answers `[0B 00]`
(`0xa6b5e9`) or `[13 00]` if no slot is free (`0xa6b5f0`). The client accepts `0x0B`
with length ≤ 2 (`0xa6b021`). These are the classic-enum values (§1.1b of
network-protocol.md: 0x13 = NO_FREE_INCOMING, 0x14 = DISCONNECTION_NOTIFICATION).
*Correction 2026-11-12:* earlier revisions said 0x13/0x14 with a 3-byte request.
Those are SA:MP's shifted numbers, and the first live mock-server test failed
because of them: the client's `0A` was ignored.

SA:MP's server also XORs a cookie into OPEN_CONNECTION_REQUEST (`^0x6969`,
`#ifdef SAMPSRV`). That is SA:MP-only. Jumpgate sends the plain form.

If the server uses security (Jumpgate does), it answers CONNECTION_REQUEST with
the **SecuredConnection handshake** instead of accepting immediately:

```
S → C   ID_SECURED_CONNECTION_RESPONSE      (0x06)  57 B   [bin, key-exchange.md]
        [06][20-byte SHA1 syn-cookie][4-byte RSA e][32-byte RSA n]
C → S   ID_SECURED_CONNECTION_CONFIRMATION  (0x07)  53 B   [bin]
        [07][20-byte echoed cookie][32-byte RSA-encrypted random]
S → C   ID_CONNECTION_REQUEST_ACCEPTED      (0x10)  9 B, IN THE CLEAR   [bin]
        [10][u32 ip][u16 port][u16 playerIndex]
C → S   ID_NEW_INCOMING_CONNECTION          (0x12)  7 B, first ENCRYPTED [bin]
        [12][u32 ip][u16 port]
```
**[bin] Key activation and the tail of the handshake** (client handler `0xa6e0a4`):
- ACCEPTED is accepted only when it is exactly 9 bytes (`0xa6e0ad`) and the
  connection state is 4 or 5. The client stores ip/port as its external address
  (`conn+0xc`/`+0x10`). The address is the four octets in network order and the
  port is LE (raw native-int bit writes).
- The AES key from the 0x07 step sits at `conn+0x81c`, with `+0x82c` as the "set"
  flag. It is installed into the reliability layer **only now** (`0xa6e183` →
  `0xa6f750`). So **ACCEPTED must travel unencrypted.** Everything after it is
  encrypted, starting with the client's 0x12 (RELIABLE), which is followed by
  pings (`0xa6aca0`).
- Once a key is installed, the receive path (`0xa739d7`/`0xa739f4`) **drops** any
  datagram that fails to decrypt. A plaintext datagram sent after ACCEPTED is lost,
  so acks for 0x07 should ride inside the ACCEPTED datagram.
- Server side, following the reference: hold the key as pending, send ACCEPTED in
  the clear, and turn encryption on when the first datagram decrypts with it.
  Seeing that happen proves the client accepted the server's RSA key.

**[bin] MTU.** The default is 1500 (`0xa69b76`); SetMTUSize clamps it to 512..1500
(`0xa64122`). Datagram plaintext budget: MTU − 28, minus 16 once encrypted, as in
the reference. The internal-packet reader rejects data of 1500 bytes or more, so
larger messages must be split. Captured server messages never exceed 896 B.
- Client handler `0xa6cc90` fires only when the decoded body length == 57. **[bin]**
- The client builds a 20-byte random from 5× `randomMT()` (`0xa6ce38` loop, step 4,
  limit 0x14), RSA-encrypts it with the server's (e,n), and echoes the cookie. **[bin]**
- **AES key = `randomNumber[j] XOR confirmation[1+j]` for j in 0..15.** In the
  binary this is the XOR loop at `0xa6cfd7` writing 16 bytes to `conn+0x81d`;
  `conn+0x82c` is then set to 1 (the "key is set" flag). **[bin]**
- **No key pinning.** `RakPeer::InitializeSecurity` (`0xa6e7a0`, vtable slot +8 at
  `0xb0ddb0`) has **no reachable call site** in the binary — the two 4-arg vcalls
  through slot +8 (`0xa60577`, `0xa60597`) are an unrelated plugin interface. So
  `keysLocallyGenerated`/`usingSecurity` stay false and the client accepts
  **whatever (e,n) arrives in 0x06**. The RSA-mismatch branch (`ID_RSA_PUBLIC_KEY_MISMATCH`,
  needs `publicKeyN` preset) is never taken. **[bin]** → a MitM can present its own
  RSA key to the client and a fresh request to the server; neither side authenticates.

**Verified end to end (2026-11-12):** the real client completed this whole handshake
against `jumpgate-rs`'s mock server and played through a replayed capture. The RSA
fields (`e`, `n`, the encrypted random) are **little-endian** on the wire.

MitM implication: the proxy runs the **server half** toward the real client (its
own RSA keypair, SHA1 cookie, decrypt 0x07, derive key A) and the **client half**
toward the real server (consume the server's 0x06, send its own 0x07, derive key
B). From then on it decrypts with key A and re-encrypts with key B (and vice
versa). This is exactly what the Msb32 shim avoids needing — but a standalone
network proxy needs it.

---

## 2. DataBlockEncryptor (AES-128)  [bin, matches ref line-for-line]

Applied to the whole RakNet datagram once a key is set. Gated on
`encryptor.IsKeySet()` (`0xa78640`); the encryptor sub-object is at `conn+0x414`.
Encrypt `0xa786b0` (called at `0xa6f806`), Decrypt `0xa78820` (called at `0xa739f4`).

Cipher setup (`SetKey`): `makeKey` for both directions, `cipherInit(MODE_ECB)`.
RakNet then chains blocks **manually** (so it is really CBC-ish, not ECB).

### Encrypt(input, len) → output
```
randomChar  = randomMT() & 0xFF
paddingBytes= 16 - (((len + 6 - 1) % 16) + 1)          # pad so total %16 == 0; 6 = 4+1+1 header
encodedPad  = (randomMT()&0xFF) << 4 | paddingBytes    # low nibble = paddingBytes
outLen      = len + 6 + paddingBytes
layout (before encryption), offsets:
  [0..3]   checksum (filled last)
  [4]      randomChar
  [5]      encodedPad
  [6 .. 6+paddingBytes-1]  random padding (randomMT bytes)
  [6+paddingBytes .. ]     plaintext
checksum    = CheckSum(output[4 .. outLen-1])          # over everything after the 4 cksum bytes
write checksum little-endian into output[0..3]
blockEncrypt(output[0..15])                            # first block, ECB
for index = outLen-16 downto 16 step 16:               # remaining blocks, high→low
    output[index..index+15] ^= output[lastBlock..]     # lastBlock starts at 0
    blockEncrypt(output[index..index+15])
    lastBlock = index
```
Constants confirmed in the binary: the checksum state seed/mults
`r=0xD971 (55665)`, `c1=0xCE6D (52845)`, `c2=0x58BF (22719)` are loaded at
`0xa786c3` and used by `CheckSum::Add` `0xa79e00`. **[bin]**

### CheckSum::Add(byte)  [bin]
```
cipher = byte ^ (r >> 8)
r      = (cipher + r) * c1 + c2        # 16-bit wrap
sum   += cipher                        # 32-bit running total → the checksum
```

### Decrypt(input, len) → output  [ref, inverse of the above]
Reject if `input==0 || len<16 || len%16!=0`. Decrypt block 0 last:
```
for index = 16 .. len-16 step 16:
    blockDecrypt(input[index..index+15])
    for b in 0..15:
        if index+16 == len: input[index+b] ^= input[b]
        else:               input[index+b] ^= input[index+16+b]
blockDecrypt(input[0..15])
checksum = LE32(input[0..3]); paddingBytes = input[5] & 0x0F
outLen   = len - 6 - paddingBytes
verify CheckSum(input[4 .. len-1]) == checksum   # else drop the datagram
output   = input[6 + paddingBytes ..]
```
AES primitives: `blockEncrypt 0xa79770`, `blockDecrypt 0xa79ac0`, tables at
`0xb2bb80` (S-box) / `0xb2bd80` (Te0) / `0xb2bc80` (inv S-box). **[bin]**

---

## 3. RakNet datagram (the decrypted bitstream)  [ref→bin]

RakNet's `BitStream` packs MSB-first; multi-byte integers are written in host
(little-endian) byte order but bit-packed, so a byte-aligned read is only valid
after `AlignWriteToByteBoundary`. `WriteCompressed` drops high zero-bytes (see §3.3).

A datagram (`GenerateDatagram`) is:
```
bit  hasAcks
if hasAcks:  acknowledgements (RangeList, §3.2)
             # data packets, if any, follow directly after the acks
else:        bit  (always 0 here; "writeFalseToHeader")
             # data packets follow
repeat: internal packet (§3.1) until bits run out
```
The receiver knows where acks end because the RangeList is self-delimiting
(count-prefixed). After acks/the lead bit, the rest of the datagram is a sequence
of internal packets read until the bitstream is exhausted.

### 3.1 Internal packet  [bin: writer 0xa70270, reader 0xa70390]
```
u16   messageNumber                       # MessageNumberType = unsigned short
3bit  reliability                         # enum below (SA:MP uses 4 bits — not here)
if reliability in {UNRELIABLE_SEQUENCED, RELIABLE_SEQUENCED, RELIABLE_ORDERED}:
    5bit  orderingChannel                 # 0..31
    u16   orderingIndex
bit   isSplitPacket
if isSplitPacket:
    u16   splitPacketId
    compressed u32  splitPacketIndex
    compressed u32  splitPacketCount
compressed u16  length                    # data length in BITS; reader rejects 0 and >= 1500 bytes
alignToByte
bytes[(length+7)/8]  data
```
The reader needs ≥ 16 bits left to start another packet. Example, the client's first
reliable datagram, CONNECTION_REQUEST `[05]` as message #0, RELIABLE, no acks:
`00 00 27 00 05` (5 bytes, seen live). *Correction 2026-11-12:* this section used
to say 4 bits, copied from the SA:MP source. That broke the first live test: every
client datagram failed to parse. The widths are now checked against the binary.

**Reliability enum — use the STOCK values, not SA:MP's.** [bin]
Jumpgate's `SendGameMessage` (`0x9c9c10`) builds the reliability arg as
`((guaranteed & 1) << 1) | 1` → **1 for a normal message, 3 for a guaranteed one**,
which are stock RakNet `UNRELIABLE_SEQUENCED` / `RELIABLE_ORDERED`:

| value | name | ordered/seq fields present? |
|---|---|---|
| 0 | UNRELIABLE | no |
| 1 | UNRELIABLE_SEQUENCED | yes |
| 2 | RELIABLE | no |
| 3 | RELIABLE_ORDERED | yes |
| 4 | RELIABLE_SEQUENCED | yes |

The SA:MP `PacketPriority.h` renumbers these to 6–10 — **ignore that**; it does
not match this binary.

### 3.2 Acknowledgements (RangeList::Serialize)  [bin: deserialize 0xa723c0]
```
compressed u16  rangeCount
repeat rangeCount:
    bit  minEqualsMax
    u16  minIndex
    if !minEqualsMax: u16 maxIndex
```
Each range acks message numbers `minIndex..maxIndex` inclusive. A reliable sender
retransmits any messageNumber not acked within a ping-scaled timeout.

### 3.3 WriteCompressed(unsigned, N bytes)  [ref]
From the high byte down to byte 1: if the byte is 0x00 write a `1` bit, else write
a `0` bit followed by that byte and all lower bytes (aligned), done. For the last
(low) byte: if the high nibble is 0 write `1`+low-nibble(4 bits), else `0`+full
byte. (Signed uses 0xFF as the match byte; RakNet uses the unsigned form here.)

---

## 4. Message / game layer  [bin]

Inside an internal packet's `data`:
- **First byte = message ID/type.** RakNet IDs ≤ ~0x1C are consumed by the
  transport; game types are dispatched by `0x9cf6b0`.
- **ID_TIMESTAMP (0x1A):** a message of the form `[1A][u32 time][…real message…]`.
  The receive helpers `0xa63ae0`/`0xa63b00` skip the 1+4 bytes when the first byte
  is 0x1A and hand the payload (at +5, length cue +6) to the game. So server→client
  game messages arrive timestamp-wrapped.
- **Game framing (inside the user payload):** `[0x51][obfuscated bytes]` with the
  running-sum/salt obfuscation (network-protocol.md §1.3–1.4, `tools/jgdecode.py`).
  This sits *above* RakNet and is unrelated to RakNet's own compression.

The two server connections (state 5150 / space 5151) are independent RakNet
sessions with independent keys and message-number spaces (network-protocol.md
§1.1a). A proxy must MitM both.

---

## 5. Building the MitM proxy — plan & checklist

Topology: `client ⇄ proxy(serverhalf) :5150/5151` and `proxy(clienthalf) ⇄ real server`.
Point the client at the proxy by setting the `SERVER_IP` environment variable
before launch; the Msb32 shim's `GetIP` returns it instead of resolving the DNS
TXT `_game_server.jumpgate-tri.org` (no hosts/DNS edits; see `tools/README.txt`).

Bring-up order, each step independently verifiable against a capture:
1. **Pass-through, pre-key.** Relay OPEN_CONNECTION_REQUEST/REPLY and
   CONNECTION_REQUEST verbatim. Confirm sizes (2 / 2 / 1+pw).
2. **Terminate the handshake.** Implement the server half (RSA keygen, SHA1
   cookie, 0x06) and client half (consume server 0x06, RSA-encrypt random, 0x07).
   Derive key A (client side) and key B (server side). Primitives to port: RSA
   modexp over a transmitted modulus, SHA1, MT19937 (temper consts
   `0xff3a58ad`/`0xffffdf8c`), AES-128. Verify: client reaches
   CONNECTION_REQUEST_ACCEPTED through the proxy.
3. **Decrypt/re-encrypt.** Implement DataBlockEncryptor (§2) both directions. Verify
   the checksum passes on every real datagram (a mismatch means the bit layout or
   key is wrong).
4. **Parse the datagram.** Implement §3 and re-serialize byte-identically for a
   datagram with no edits (round-trip test: decode→encode == original bits). This
   is the strongest correctness check for the reliability layer.
5. **Surface the message layer.** Hand each internal packet's data (minus 0x1A
   wrap, minus 0x51/obfuscation) to the existing `jgdecode.py`/message-types
   tooling, which is already capture-validated. Agreement with an Msb32-shim
   capture of the *same* session end-to-end confirms the whole stack.

What is already solid vs. what to watch:
- Solid: crypto (§2) and handshake (§1) are byte-verified; message IDs and the
  reliability enum are binary-confirmed; the message/0x51 layer is capture-proven.
- Watch (unverified [ref] details): the exact `GenerateDatagram` lead-bit/ack
  ordering, `WriteCompressed` edge cases, and split-packet reassembly. Step 4's
  round-trip test will catch any of these.
- A simpler alternative that needs **no** network crypto, if the goal is just to
  observe/alter messages: keep using the in-process Msb32 shim (tools/), which
  sits inside the crypto boundary. The proxy here is only needed for a standalone,
  out-of-process interceptor or a from-scratch Rust client.

## Function map (this binary)
| Addr | Role |
|---|---|
| `0xa62c10` | poll / receive loop (tags packet conn at `+0x10`, §1.1a) |
| `0xa6ebc0` / `0xa6ec80` | recvfrom (1500) / sendto |
| `0xa63710` | prepend `0x51`, obfuscate, hand to RakPeer::Send |
| `0xa637a0` → `0xa63710` | common send used by both wrappers |
| `0x9c9c10` / `0x9c9c90` | SendGameMessage (state) / SendSpaceMessage (space) |
| `0xa6af20` | reliability layer core (datagram build/parse) |
| `0xa786b0` / `0xa78820` / `0xa78640` | DataBlockEncryptor Encrypt / Decrypt / IsKeySet (obj `conn+0x414`) |
| `0xa79e00` | CheckSum::Add |
| `0xa79770` / `0xa79ac0` | AES blockEncrypt / blockDecrypt |
| `0xa758d0` / `0xa75780` | randomMT / seedMT (MT19937) |
| `0xa6cc90` | client ID_SECURED_CONNECTION_RESPONSE handler → key at `conn+0x81d`, flag `conn+0x82c` |
| `0xa6e7a0` | InitializeSecurity (vtable `0xb0ddb0`; **no call site** → no key pinning) |
| crypto primitives | modexp `0xa689b0`, SHA-1 `0xa78370`/`0xa78550`, see key-exchange.md |
