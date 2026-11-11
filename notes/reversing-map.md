# Jumpgate.exe — reversing map

Binary SHA-256 `fef6e50fc4608c1514242932823fb8cbeeda9ac6217d9f819fd802d94ca7bdf8`,
PE32 x86, image base `0x400000`. Addresses are virtual addresses in this build.

## Sections
| Section | VA | notes |
|---|---|---|
| .text | `0x401000` | code |
| .rdata | `0xac2000` | consts, imports, crypto tables |
| .data | `0xb1e000` | globals |
| .NewIT | `0x150a000`+ | appended import stubs for Msb32 (GetIP/Login/Tick/catchPacket at IAT `0x150e147..0x150e153`) |

## Networking
| Addr | Role |
|---|---|
| `0xa6ea70` | UDP socket create/bind |
| `0xa6ebc0` | recvfrom (1500) |
| `0xa6ec80` | sendto |
| `0xa6af20` | RakNet core / receive dispatch |
| `0xa62c10` | wrapper poll loop |
| `0xa631d0`,`0xa63200` | wrapper send (state / space) |
| `0xa63710` | prepend 0x51, hand to RakNet send |
| `0xba7cd4` | wrapper object (state conn +0x08, space conn +0x28) |
| global `0xbe5b3e` | u16 current location/sector id |
| global `0xbe5da0` | u32 player/session id |

## Game message layer
| Addr | Role |
|---|---|
| `0x9c8ca0` | obfuscation encode (send) |
| `0x9c8d30` | obfuscation decode (recv) |
| `0x9cf6b0` | game dispatcher (switch on type) |
| `0x9da24c` | switch index byte table |
| `0x9da0f0` | switch jump table |
| `0x9c9c10` | SendGameMessage(buf, len, guaranteed) |
| buffer `0xba8e20` | decoded incoming message |

## Crypto / key exchange
See `key-exchange.md` for the full table (modexp `0xa689b0`, SHA-1 `0xa76720`,
AES tables `0xb2bb80`, MT `0xa758d0`, handshake `0xa6cc90`/`0xa6a990`, etc.).

## Msb32.dll (36 KB, SHA-256 846ff7c5...e2 — the STOCK one, keep as Msb32_orig.dll)
| Export / addr | Role |
|---|---|
| GetIP | DNS TXT `_game_server.jumpgate-tri.org` → server IP (fallback 127.0.0.1) |
| Login | writes version at msg+0x16, sends login |
| Tick | periodic |
| catchPacket | decode + apply server **type 0xFE memory-patch** (unbounded write) |

## 0xFE memory-patch target (observed)
Award/medal name table, ~`0xbe0e8b .. 0xbe34fb`, 60-byte (0x3c) stride; filled
at startup by `0x9c7c00..0x9c8780`.

## Tooling / method
- Client send-site field recovery: static backward dataflow over the 260 calls to
  `0x9c9c10`, resolving each struct built on the stack/globals. Script lived in
  the session scratchpad; results in `captures/send_types.txt`.
- Plaintext capture: in-process `Msb32.dll` shim (hooks catchPacket + encoder
  `0x9c8ca0`). Source in `tools/`.

## Ghidra
A saved analysis snapshot is in `ghidra/` (see `ghidra/README.txt`) so the
~import can be skipped when re-opening with REA.

## Static world objects (asteroids etc.) — hardcoded in code  [static]
The sector scenery is compiled into the exe as immediates, not streamed and not
procedural. On a location change, `0x4ba4xx` frees the previous objects, then a
range dispatcher on the location id calls ONE region init function:

| loc id range | init fn | objects (`new` calls) |
|---|---|---|
| 0 | `0x4aeed0` | 158 |
| <110 | `0x6769c0` | 1712 |
| 110–115 | `0x721060` | 262 (extracted → `static_objects.csv`) |
| 116–118 | `0x590a10` | 322 |
| 119–207 | `0x72a8b0` | 1341 |
| … ~25 more ranges up to 1000 … | | |
| **total** | ~30 fns, ~1M instructions | **~35,000** |

Object = 44 B (`new 0x2c`), pointer table per region (region 110–115 at
`0xc5ca24..0xc61a08`): `+0 u8 flag, +2 u16 index, +4 u16 group,
+8/+c/+10 f32 XYZ, +14..+28 forward & up unit vectors`. The server only adds
per-object state (ore amount via `0x74`). Region-to-sector name mapping not yet
confirmed. Counts are `new` calls in each fn, so approximate.

### Location ids, blocks, and the mined-asteroid match  [static + capture, 2026-11-10]
- Location ids: below ~100 = stations (Quantar Depot station 18, TriPoint
  station 8); 101+ = space sectors (Quantar Depot 118, Long Walk 241,
  Tictac's Hook 249, TriPoint 108). `0x07` byte 4 is the gate index, not a loc.
- Each region init function holds one **block per location id** in its range,
  in id order. Block start = record with `b0=0, +2=6`. Verified: region 110–115
  has 6 blocks, 116–118 has 3, <110 has 9 (sectors 101–109).
- Inside a block: `b0=0` records (nav/centre objects) first, then `b0=1`
  objects whose `+2` field is the per-sector object id (types 15–29 dominate),
  then ~50 type-339 records numbered 950–999 (role unknown).
- **Match:** the capture mined `0x74` asteroid idx **94** in loc **108**.
  Block 7 of `0x6769c0` (loc 108) entry 94 has id 94: type 17 at
  (−448, 14754, −133). → `static_objects_loc108_tripoint.csv`.
- So the `0x74` asteroid id = hardcoded per-sector object id. Not verified
  spatially against the gate (gate positions aren't in this block).
- Extractor: `tools/extract_static_objects.py <fn_hex> <out.json>` (needs an
  `objdump -d -M intel` listing; path inside the script).
- **Spatial check (0x05 position @144/148/152):** arrived in TriPoint at
  (−558, 15093, −112) = the gate exit, 357 units from asteroid 94. Parked at
  (−416, 14681, −203), 106 units from it, for exactly the four reports that
  bracket the five `0x74` mining sends. Then flew to the sector origin and
  docked: the lone `b0=0` record at (31, −33, 0) is TriPoint **station**.
  Same pattern in Quantar Depot space (start near origin = station). Cruise
  ≈ 400 units/s in straight lines between 13.7 s reports.

### Sector → region map (authoritative)  [static, 2026-11-10]  → `sector_regions.csv`
- **Location names:** table at `0xfd9220 + id*100`, filled by `0x4a8d10`.
  Stations and their surrounding space share a name (18 & 118 = Quantar Depot;
  8 & 108 = TriPoint-Station).
- **Per-location object arrays:** `0xbef100 + id*0xff0`, 1000 pointer slots
  each (the dispatcher's free loop walks exactly this). So for any object,
  `loc id = (slot − 0xbef100) / 0xff0`. Check: mined asteroid 94's slot
  `0xc5abc0` → id 108.
- 174 location ids have static objects (35,019 total): 101–118 (core stations
  & depots), 201–349 (open space), 0 and 1000–1005 (unnamed, maybe sim/special).
  Region functions group 1–15 neighbouring ids each.
- **Correction:** the earlier per-block counts (e.g. "TriPoint block 7 = 283
  objects") came from a heuristic block marker (`b0=0, +2=6`) that's only
  sometimes right. Slot-derived counts are authoritative (TriPoint = 162).
  The asteroid-94 match itself is unaffected (its slot → 108, id 94).
  `static_objects_loc108_tripoint.csv` may include some loc-109 rows; filter by
  slot when using it.

### Object types, gates, and the dump script  [static + capture, 2026-11-10]
- **`+4` type = model id**: index into the model pointer array `0x14ff690`
  (each model object has hi/mid/low LOD meshes at +0/+0x950/+0x94c).
  2 beacon · 4–8, 321–323, 338, 380 station bodies · 11 `jump_ends` = jumpgate ·
  414 `x_ai_gate` = jumpgate (alt model, all linked) · 15–29 `ast1a..ast5c` ·
  317–319 huge minable rocks · 30–105 `aa/bb/cc` ship meshes · 305–316, 407–409
  `junk_*` debris · 304 `flat.x` nav marker (gate-numbered, never linked) ·
  339 invisible (no model), exactly 50 per sector, ids 950–999 (role unknown) ·
  424–428 misc meshes.
- **Asteroids:** digit = kind (1–5), letter = size. Mining code `0x43ce2e`:
  class table `0x43d674` → a=large (divisor 48), b=medium (16), c=small (8);
  317–319 = 128. Kind→flavour NOT found in client code. Kind 1 = 24,250 of
  32,763 → very likely Common Metals [inferred]; kinds 2–5 appear in ~160
  locations each.
- **Nav records** (`b0=0`): `+2` 1–4 gate number, 5 beacon, 6 station (at
  sector origin). `0x07` jump field = gate number − 1.
- **Gate links:** `0x4a7460` fills `0x146d7a0 + (gate−1)*0x4e20 + loc*0x14`
  = {+0 dest loc, +4 arrival gate}. 418 records; validated on the flown route.
- **Location struct** `0xfd9220 + loc*100`: name @0, galaxy-map XYZ @44, @60
  probably owning faction (3 = Quantar, 0 = unclaimed), @64, @68 unknown.
- **Script:** `tools/jg_static_dump.py Jumpgate.exe out.csv` (standalone; checks
  SHA-256, runs objdump, ~5 s) → `static_objects_all.csv`, 35,015 rows. Set
  `FLAVOR` in the script once kinds are confirmed.
- **Radius:** there is NO radius in the 44-byte record. `model_radius` in the
  CSV = max vertex distance from origin of the model's full-detail `.x` mesh
  (binary `.x`; a few are MSZIP `bzip` compressed), read from the game dir.
  Asteroids: a ≈ 60–64, b ≈ 21–27, c ≈ 6–8; huge 317 ≈ 138; jumpgate 183;
  stations 375–795; beacon 105.

## Location / position updates  [static, 2026-11-10]
| Addr | Role |
|---|---|
| `0x9cd410` | location sender: 0x33 small loc / 0x34 mini loc / 0x05 "gloc 3" (see message-types.md) |
| `0x9ce1c0` | its timer (0.3 s if input changed, else 0.8 s), caller at `0x9ce2f6` |
| `0x9ceb70` | force immediate full 0x05 |
| `0x9cb330` | 0x17 companion (10 B, state conn) |
| `0x9c77f0`/`0x9c7920` | "changed since last send?" filters for 0x33/0x34 |
| `0xbe5c18` | tick counter (2..18) · `0xbe5dc8`/`0xbe5dd8` QPC now/freq |
| `0x1042118 + i*0x160c` | contact/ship table (i 10..199; +0 active, +1 dead, +0x94 distance) |
| `0xff2a50..0xff2af0` | own-ship snapshot shared by all location packets |

## Conflux / bot AI — runs on the client  [static, 2026-11-11]
The server assigns each bot (conflux) an **owning player**. That player's client
runs the bot's AI and physics and reports its state back with `0x71` "botloc".
Ownership moves to whichever player is nearest.

| Addr | Role |
|---|---|
| `0xb341f0 + i*0x14`, i<50 | `pbotloc` table: +0 active, +1 AI state (0/1/2/3/8), +2/+3 bytes, +4 u16 bot id, +6 u16, +8 u16 ship slot, **+0xc u32 controller player id**, +0x10 u32 assigned/target player id |
| S→C `0x71` handler `0x9d6f25` | spawn/assign: bot id @8, loc @0xa, ship type @0xc (219–259, else "Bot error - pbotloc->Shiptype is not valid"), ids @0x20/@0x24. If @0x24 == me: ship `+2`=0 (locally driven), controller=me, send a botloc right away. Otherwise links the bot to the owning player's ship slot. |
| S→C `0x03` handler `0x9d1463` | also writes the table and ship `+2` (update/teardown) [inferred] |
| `0x4338c0` | **online bot AI**, called every frame (`0xa26863`): per-bot state machine (`+1`), steering toward the target ship (`ship+2` = slot), rand-driven events |
| `0x40bf50` | per-frame for bots *I* control: obstacle/ship avoidance (`0x409a40`), then sends botloc (`0x9ce490`) |
| `0x42f360` | offline-sim AI (loc 1005, `/ai #` "Spawns a flux ... offline sim mode") |
| `0x9c9d10` | botloc sender: 0x71 (52 B) per controlled bot (hull%, shield%, position, velocity, orientation). Runs after every 0x05 and on assignment. |
| C→S `0x71` sub 3 | "botloc 3" — sent from the AI when a condition fires within 60 units [inferred: arrival/attack] |
| C→S `0x2C` (12 B) "bxr" | handoff request: sent when a bot's controller is another player but **I** am closer to it (range scaled by ship radar) |
| C→S `0xB0` (20 B) sub 3 | controller-only, 1-in-32000 rand per frame for ship types 230–233 within 1–200 units of the target: random event with client-rand payload [inferred: drop/spawn] |
| `0x1042118 + slot*0x160c` | ship table: +0 active, +1 dead, **+2 controlling/target slot (0 = local, 0xfe = none)**, +3 0xff = valid, +0x94 distance, +0x15c8/+0x15cc hull, +0x15f8.. shields |

Not verified: whether bot weapon fire and hit/damage resolution also run on
the controlling client. Leads: missile update `0x42ca30` and hit processing
`0x43a4a0` (sends "mkill") both read `ship+2`.

## Weapon hits & damage — who reports what  [static, 2026-11-11]
| Addr | Role |
|---|---|
| `0x102b350 + i*0x48` | shot table: +0 active, +4 range, +8 u16 weapon id, +0xa u16 class (1 = gun → `0x43f0c0`, 2 = bot shot / beam → `0x43a4a0`), +0xc pos, +0x44 u8 bot shooter slot |
| `0x437590` | local player fires (callers `0x43da3e`/`0x43db90`, input) |
| `0x439260` | every frame: re-creates *other* ships' shots from their firing bitmask (`ship+0x156f`) and weapon slots. Bot shots get class 2 + shooter slot. **Aim/lead for bots is computed only when `ship+2 == 0` (I control the bot).** |
| `0x43f0c0` | gun hit test (shot vs ships slot ≥5) → hit queue |
| `0x43a4a0` | bot-shot / beam / missile hit processing; bot shot hitting **slot 0 (me)** → local damage, `shields -= weapon[+0x50]` (×mods), overflow to hull, hull ≤ 0 → death `0x9cec40`; last attacker `0xbe5ca0 = 0x8000+bot slot` |
| `0xb34660` | **hit queue** (16 × 20 B: u32 victim id, u16 bot id or 0xfe, u16 hit count (guns merged, ≤40), u8 kind, u8 weapon, f32 value (beam time / splash), u8 class 0 gun/1 missile splash/2 beam/3 special/…). Adders `0x43a060` gun, `0x43a130` missile splash, `0x43a1a0` mortar, `0x43a210` bldg repair, `0x43a2c0` beam, `0x43a360` special, `0x43efc0` missile dmg |
| `0x43a3d0` | flush: one **C→S `0x1D`** (32 B) per entry, `[1D][pad3][u32 shooter=me][u16 loc][pad2][u32 victim][u16 id][u16 count][u8 kind][u8 weapon][pad2][f32 value][u8 class]`, called after each 0x33/0x34 tick |
| S→C `0x03` handler `0x9d1463` | **damage delivery** `[03][?][u16 bot id or 0xfe @2][u32 attacker @4][f32 damage @8]`. 0xfe = me: subtract from own shields → hull, die locally. Bot id: only if I control that bot → damage it, retarget it at the attacker (aggro), botloc/killed. |
| C→S `0x1A` (16 B) "mkill" | I shot down a missile (missile table `0x14fd990`) |
| C→S `0x43` (12 B) | hits counter (fired/hit stats, periodic) |
| C→S `0x44` (16 B) "who killed me" | sent on own death (`0x9cec40`) and when a bot I control dies (`0x9ce490` botloc killed) |

Flow:
- **Player → player:** the shooter's client detects the hit and sends 0x1D (count + weapon,
  not a damage number). The server sends S→C 0x03 with an f32 damage value to the victim. The victim's client
  applies it and declares its own death. So hit detection is shooter-side; the damage number
  comes from the server (probably count × weapon damage [inferred]).
- **Player → bot:** if I control the bot, the hit is applied locally and nothing is sent per hit
  (the bot's hull/shield % goes out in botloc; death goes out as botloc-killed + 0x44). Otherwise
  I send 0x1D, and the server sends 0x03 to the controlling client, which applies it.
- **Bot → player:** the controller computes the bot's aim and firing. Every client replays the shots. The
  **victim's client** hit-tests and applies damage to itself from its local weapon table.
  Nothing is sent per hit; the server only sees the shield/hull numbers in the 0x05 state and
  the 0x44 on death.
- Open: whether a remote player's replayed gun shots also go through the victim's gun hit test
  (which would double-count with the 0x1D path). Probably not (class not 1) — not verified.
