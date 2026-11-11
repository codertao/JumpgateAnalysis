# Jumpgate — RakNet key exchange (detail)

All **[static]** from decompilation of `Jumpgate.exe`
(`fef6e50f...`). This is RakNet's old "SecuredConnection" (`RSACrypt`-era) crypto.

## Verdict
- **Not elliptic curve.** The big-integer routines operate on 256-bit values with
  a **runtime-supplied modulus**, i.e. classic prime-field arithmetic (DH/RSA
  family). There is no hardcoded curve or field prime baked into a fixed-curve
  implementation; the modulus travels with the server's key material.
- **Unauthenticated.** No signature/certificate over the server's public value.
- **Mersenne-Twister randomness**, not a CSPRNG.
- These three together → an active man-in-the-middle on an intercepted
  connection can complete the handshake with each side and read/alter traffic.

## Primitive map
| Addr | Role |
|---|---|
| `0xa689b0` | modular exponentiation (square-and-multiply over exponent bits) |
| `0xa663b0` | modular multiply (inner primitive of modexp) |
| `0xa669e0` | modular square |
| `0xa68fd0` | modular inverse (binary ext-Euclid style) |
| `0xa66190` | modular reduction / division (512→256 shift-subtract) |
| `0xa6b970`, `0xa688e0`, `0xa6c7f0` | shared-secret derivation wrappers |
| `0xa758d0` | Mersenne Twister output (temper consts `0xff3a58ad`/`0xffffdf8c`, 623-word reload) |
| `0xa75780` | MT seed; counter `0xb2b514`, state ptr `0x1500a3c` |
| `0xa76720`,`0xa78560` | SHA-1 reset;  `0xa78370` update;  `0xa78550` final |
| `0xb2bb80`/`0xb2bd80`/`0xb2bc80` | AES S-box / Te0 / inverse S-box |
| `0xa6e7a0` | `RakPeer::InitializeSecurity` (host keypair; flags conn `+0x9a4`/`+0x9a5`) |
| `0xa6a990` | builds ID 6 (server side) |
| `0xa6cc90` | handles ID 6 / builds ID 7 (client side) |
| `0xa6c860`→`0xa6ba40` | handles ID 7 (host side) |

## Handshake messages (after RakNet reliability header is stripped)
```
S -> C   ID_SECURED_CONNECTION_RESPONSE      (id 6), 57 bytes:
         [06]  [20-byte digest]  [4-byte cookie]  [32-byte server public X]

C -> S   ID_SECURED_CONNECTION_CONFIRMATION  (id 7), 53 bytes:
         [07]  [20-byte echoed digest]        [32-byte client public X]
```
- Client handler `0xa6cc90` is entered only when the decoded body length == 0x39
  (57); it reads the 4-byte value at off 0x15 and the 32-byte value at 0x19,
  mixes in its own MT randomness, derives shared material (`0xa6b970`/`0xa688e0`/
  `0xa6c7f0`), then an XOR key-schedule loop writes the AES session key to
  conn `+0x81d` and emits ID 7.
- Host side checks len == 0x35 (53) and completes via `0xa6c860`→`0xa6ba40`.
- The on-wire sizes match the capture: the recorded handshake datagrams were 62 B
  (S→C) and 58 B (C→S), i.e. the 57/53-byte bodies plus RakNet framing. [capture]

## Still open
- Which of the 256-bit values is the generator vs. the transmitted public, and
  where the modulus is stored/received exactly (the modexp modulus arrives via a
  caller/`this` pointer not yet fully traced).
- Exact AES mode/IV handling for the bulk transport.
- These are **not** needed for the message-layer MitM (the shim works inside the
  crypto); they would be needed to build a standalone *network* crypto MitM.
