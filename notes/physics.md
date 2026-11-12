# Jumpgate.exe — flight physics / simulation

Static analysis of the client-side ship physics in this build (SHA-256
`fef6e50f…`), done 2026-11-11 with objdump plus Ghidra 12.2 headless
decompilation (`ghidra/scripts/Decomp.java`). Nothing here has been checked at
runtime yet. Unless a line says **[inferred]**, it was read directly from code.

**Headline:** the player's own ship is simulated **entirely on the client**. That
covers thrust, quadratic drag, rotation, collisions, docking, gate pull and
hazard damage. The server gets the results (position, orientation, velocity,
shields/hull) through the location packets (`0x05`/`0x33`/`0x34`). The model is
arcade-Newtonian: velocity persists, thrust acts along the nose, drag is
quadratic in speed, and turning is kinematic (no angular momentum).
Integration is explicit Euler with a variable frame `dt`. Several impulses are
applied per frame, not per second, so they depend on frame rate.

---

## 1. Where the state lives: protected "cells"

Each scalar of the own-ship state is a separately `new`'d **4-byte heap cell**.
A global pointer table points at the cells: `0x14408b0..0x1440954`, plus a few
more at `0x14e86b8..c8`, `0xbe5acc/ad0`, `0xbe6e74` and `0x140ac2c..0x140acf8`.

- `0x403150` creates them. It runs once from WinMain (`0xa24348`).
- **`0x403740` runs at the top of every frame** (main loop `0xa25720`,
  checkpoint `0x3ea`). It reads all ~70 values, frees every cell, and
  re-allocates them in an order that starts at `rand() % 51` (jump table
  `0x404aa8` into an unrolled `new` sequence). Then it writes the values back.
  **The heap addresses change every frame.** This is an anti-memory-editor
  measure: you can't pin a Cheat-Engine-style address to speed or fuel.
- The flight code reaches the cells through a big game object at **`0xbdf578`**
  (passed as `this`/`param_1`). A cell is `**(this + off)`, where `this + off`
  is the pointer global. For example, `0xbdf578 + 0x861380 = 0x14408f8`. This
  is why a plain `ds:0x14408f8` cross-reference search misses most uses.

| pointer global | `this+` | meaning | set by |
|---|---|---|---|
| `0x14408b0` | `0x861338` | **fuel** (fuel cells: drained by afterburner and brakes; HUD shows ×0.01) | launch packet `+0x70`; 0x9cf6b0 cases |
| `0x14408b4` | `0x86133c` | **throttle fraction** = throttle × 0.01 (× 1.3 on afterburner) | `0x429bb0` |
| `0x14408d8` | `0x861360` | **roll rate** (ship-type `+0x44`) | `0x428290`, `0x9d23f9` |
| `0x14408dc` | `0x861364` | **pitch rate** (ship-type `+0x40`) | same |
| `0x14408e0` | `0x861368` | **yaw rate** (ship-type `+0x48`) | same |
| `0x14408f8/fc/900` | `0x861380..88` | **velocity** X/Y/Z (units/s) | `0x429bb0`, collisions |
| `0x1440904` | `0x86138c` | **speed** \|v\| | `0x429bb0` |
| `0x1440908` | `0x861390` | **mass** (hull + equipment + cargo, MODx-adjusted) | `0x428290` |
| `0x144090c` | `0x861394` | **drag coefficient** (ship-type `+0x38`) | `0x428290`, `0x9d2456` |
| `0x1440910` | `0x861398` | **thrust** (engine count × engine thrust, MODx-adjusted) | `0x428290`, `0x4680c0` |
| `0x1440914` | `0x86139c` | **dt**: frame time in seconds = ΔQPC / freq (`0xa25d1d`), unclamped | main loop |
| `0x1440918` | `0x8613a0` | drag deceleration (scratch) = speed² / mass × drag | `0x429bb0` |
| `0x144091c/20/24` | `0x8613a4..ac` | unit velocity direction (scratch) | `0x429bb0` |
| `0x1440928/2c/30` | `0x8613b0..b8` | orientation: **up** axis | `0x42a110` |
| `0x1440934/38/3c` | `0x8613bc..c4` | orientation: **forward / nose** axis (thrust direction) | `0x42a110` |
| `0x1440940/44/48` | `0x8613c8..d0` | orientation: **right** axis | `0x42a110` |
| `0x144094c/50/54` | `0x8613d4..dc` | **position** X/Y/Z (sector coordinates) | `0x9c7270` |
| `0x14e86c0` | `0x909148` | shields | — |
| `0x14e86c4` | `0x90914c` | hull | — |
| `0x14e86bc` | `0x909144` | hull scale for hazard damage (= table × ship-type armour, set at launch) [inferred: max hull] | `0x9cc750` |
| `0xbe5ad0` | `0x6558` | byte: **fuel-additive boost active** (FlashFire: "+200 % thrust for 10 s") | — |

The axis naming follows from the rotation code: yaw input moves the nose toward
`0x1440940` using the yaw rate, and pitch input moves it toward `0x1440928`
using the pitch rate. The ship's collision box pairs forward with ship-type
`+0x160`, up with `+0x15c` and right with `+0x158` (half-extents).

Plain (non-cell) globals used by the flight code:

| addr | `this+` | meaning |
|---|---|---|
| `0x1440878` | `0x861300` | **yaw stick**, int −100..100 |
| `0x144087c` | `0x861304` | **pitch stick**, int −100..100 |
| `0x1440880` | `0x861308` | **roll stick**, int −100..100 |
| `0x1440884` | `0x86130c` | **throttle**, int 0..100 (values below 6 are forced to 0) |
| `0x144088d` / `0x144088e` | `0x861315/16` | afterburner key / brake key |
| `0xbe5bc4` / `0xbe5bc0` | `0x664c` / `0x6648` | afterburner active / brake active (int 0/1) |
| `0xbe6db4` | `0x783c` | boost countdown (s) |
| `0xbe5af6` | `0x657e` | "flight controls live" flag (cleared while docking or in a service beam) |
| `0xbe5c80` | `0x6708` | own ship type (index into the ship-type table) |
| `0xbe5b3e` | `0x65c6` | current location id |

Input path: the DirectInput polls (`0x49d1e0` keyboard; `0x499d00`/`0x49bb20`
other devices [inferred]) feed an action handler at `~0x49c85e` (switch
`0x49d048`). Digital keys step each stick by ±10 and clamp at ±100. Analog
devices write the value directly. Throttle `0x1440884` is set directly. While
`0xbe5aee` is set (text entry [inferred]), the main loop zeroes the three
sticks.

## 2. Per-frame order (in space)

From the WinMain loop, checkpoint ids in `0x14ff668`:

1. `0x403740` reshuffles the cells (top of frame), then dt = ΔQPC / freq.
2. Input polls (`0x499d00` / `0x49bb20` / `0x49d1e0`).
3. `0x428b60` power and energy bookkeeping (MODx-aware).
4. **`0x42a110` attitude**: Auto-Dock autopilot, stick rotation, afterburner and
   brake state, sector hazard damage.
5. **`0x429bb0` linear dynamics**: thrust, drag, brakes, boost, sector current.
6. Unless docking/docked (`0xbe5af4`, `0xbe5b01`): **`0x40d630` collisions and
   docking** (which first calls `0x40cb50`, the service-beam pad), then
   `0x40bf50` avoidance for bots this client controls.
7. **`0x9c7270` position integration**, `pos += v·dt`, then the own ship is
   copied into contact slot 0 (`0x1042118`).
8. **`0x433010` dead reckoning for remote ships**, then `0x4338c0` bot AI.
9. Weapons (`0x439260`, `0x42ca30`, …), then the location-send timer `0x9ce1c0`.

The renderer (`0x9ede30`, a huge function Ghidra cuts short) only reads the
state. It draws the HUD speed, throttle and fuel gauges at `~0x9ff4ef`.

## 3. Linear dynamics: `0x429bb0`

```
throttle = min(throttle, 100);  thr = throttle * 0.01              // 0x14408b4
brake = 0
if throttle == 0 and speed > 0:                                     // brakes (needs brake active)
    brake = thrust * 0.08 / mass * brakeOn          ; ×2 if boost
    fuel -= engines * dt * 0.045 * brakeOn
speed    = |v|
dragDec  = speed² / mass * drag
if sector has a current, controls live, not in a gate's pull:     // see §7
    v += (current / mass) * drag * 100 * dt
if throttle > 0 or speed > 0:
    vhat = v / |v|
    dragDec += brake
    if afterburner: thr *= 1.3;  fuel -= engines * dt * (boost ? 0.2 : 0.16)
    if dragDec*dt <= speed or thr != 0:
        a = thrust * thr / mass ;  if boost and thr > 0: a *= 3
        if dt < 0.6:  v += (-dragDec * vhat + a * forward) * dt
    else:
        v = 0                         // drag would overshoot: stop dead
```

`engines` is the ship-type byte `+0x148` (number of engine mounts).
`boost` is `*0xbe5ad0`; its timer `0xbe6db4` runs down by dt.

Consequences:
- **Top speed** = √(thrust / drag), independent of mass. Mass only sets the
  acceleration. The HUD speed gauge uses √(1.3·thrust / drag) (afterburner top
  speed) as full scale (`0x9ff4ef`: `speed / sqrt(thrust*1.3/drag)`, clamped to 1).
- Drag always opposes the full velocity vector, so you can drift sideways
  and turning bleeds speed only through drag.
- The `dt < 0.6` guard skips thrust and drag on very long frames (e.g. after a
  stall), so velocity simply carries over.
- Velocity units ≈ units/s. The capture showed cruise ≈ 400 u/s (see
  reversing-map "Spatial check"), which is √(thrust/drag) for that ship.

## 4. Attitude: `0x42a110`

Kinematic rotation of the orthonormal frame (forward, up, right), one axis per
stick. The axes are re-orthogonalised with cross products and re-normalised
(`0x429b50`) after each step.

```
turnScale = (1.6 - thr) * 0.625            // 1.0 at idle, 0.375 at full, 0.1875 on afterburner
angle(stick, rate) = tan( sqrt|s| * s * rate * dt )     // signed s^1.5; deadzone |s| <= 1
yaw   (0x1440878): forward += angle(s, yawRate)*turnScale * right
pitch (0x144087c): forward += angle(s, pitchRate)*turnScale * up
roll  (0x1440880): up      += -angle(s, rollRate) * right        // roll NOT throttle-scaled
```

At full stick, sqrt(100)·100 = 1000, so the peak turn speed is about
**1000 × rate rad/s** (× turnScale for pitch/yaw). The same 1000 × rate × dt
figure is the per-frame cap used to smooth remote ships (§8). One yaw step
of this formula also appears in the launch handler `0x9cc750`.

The same function also handles:
- **Auto-Dock autopilot** (Auto-Dock MODx, `/dockoff`). It engages when the
  docking beacon is within **350** units (matches the item text "within 350
  meters"). State `0xbe5c6c` (`this+0x66f4`):
  - State 1: v and speed × 0.98 per frame until speed < 2.
  - State 2: steer the nose 0.023 per frame toward the beacon. While aligned
    (dot > 0.9999) and speed < 25, throttle goes up by 1 per frame (cap 22).
    If speed > 30, throttle drops to 0. Within 3 units it moves to state 3.
  - State 3: aim at the dock point. Throttle +1 while speed < 75, and 0 if
    speed > 90. Done within 60 units.
  - These steps are per frame, so they depend on frame rate.
- **Afterburner** needs throttle ≥ 6 and fuel > 0. **Brakes** need throttle ≤ 5
  and fuel > 0. Running out shows a message and plays a sound. Brakes spawn
  particle effects.
- Sector hazard damage and gate kill zone (§7).
- First-person view modes (`this+0x6620`, `this+0x413100..`). These are camera
  only.

## 5. Mass, thrust and turn rates: `0x428290`

It is called on loadout changes (from cargo/equipment code, the launch handler
and the shop). `FUN_00439f70(id)` = "MODx id installed?".
- **mass** = hull mass (type `+0x30`) + per-slot equipment masses (engine,
  power plant, shield, radar, ECM, capacitor, …) + cargo (count × unit mass)
  + engines × engine mass + type `+0x150` [inferred: armour mass], plus 5000 in
  one special case. **Countermass MODx** then multiplies it: ×0.92 / ×0.89 /
  ×0.85 / ×0.80 (MODx 0x30/0x31/0x32/0x33). This matches the item texts
  (8 / 11 / 15 / 20 %).
- **thrust** = engines (type `+0x148`) × engine thrust (engine table at
  `0x146c880 + idx*0x10`, idx `0x140ac0c`). **Thrust MODx** add +3 / +5 / +8 %
  (0x10/0x14/0x18). **Power-distribution MODx** add +2 / +4 / +6 / +9 %
  (0x1c/0x1d/0x1e/0x1f). All of this matches the item texts.
- **drag, pitch, roll and yaw rates** are copied straight from the ship-type
  record.

### Ship-type table `0xff7eac + type*0x1e0`
**Loader: `0xa08440` `init_ship_types`.** There is no data file and no static
initialiser. The table is compiled into the code as about 7,400 `mov
[esi+disp], imm` stores, with esi = `0xbdf578`, so the record is at
this+`0x418934`. Names and class strings are `sprintf`'d into `+0x04` / `+0x18`.
`tools/jg_tables.py` re-extracts it to **`ship_types.csv`**. 88 types are
defined:
- 30–45 Solrain
- 60–75 Quantar
- 90–105 Octavius
- 196–199 TRI AI
- 220–225 faction defenders
- 230–259 conflux

The config screen (`0x46e9xx`, `0x4708xx`) displays these fields:

| off | type | meaning |
|---|---|---|
| `+0x04` | char[] | name |
| `+0x30` | f32 | hull mass (`config_mass`) |
| `+0x38` | f32 | drag (`config_drag`) |
| `+0x40` / `+0x44` / `+0x48` | f32 | pitch / roll / yaw rate (`config_pitch/roll/yaw`) |
| `+0x140` | i16 | cargo (`config_cargo`) |
| `+0x142` | i16 | spawn-offset length [inferred] |
| `+0x144` | f32 | ship size (diameter) used in docking clearance |
| `+0x148` | u8 | number of engines |
| `+0x14a..` | u8 | shield/radar/… class bytes |
| `+0x150` | i32 | armour (`config_armor`) |
| `+0x158/15c/160` | f32 | collision half-extents: right / up / forward |
| `+0x34` | f32 | unknown. Often 20,000–90,000 or equal to the mass [maybe max loaded mass]. |
| `+0x59..0x125` | 12-byte rows | per-slot equipment lists [not decoded] |

Peak full-stick turn rate ≈ 1000 × rate rad/s (§4). For example, the Premia
pitches at about 0.96 rad/s.

### Engine table `0x146c878 + idx*0x10` (27 engines)
**Loader: `0x414460` `init_item_tables`.** This one function hard-codes every
equipment category: the category names, then shields, engines, power plants
and so on. Each item's name goes to `0x14814d0 + idx*0x32`, its description
to `0x1488cbc + …`, and its stats as absolute `mov ds:addr, imm` stores.
Extracted to **`engines.csv`**.

| off | type | meaning |
|---|---|---|
| `+0` / `+1` | u8 | unknown. `+0` rises with tier (Money 0 … Dream 25, Tangent 31); `+1` takes values 0–5 [maybe manufacturer or faction]. |
| `+2` | u8 | 1 = sold, 0 = the pre-collapse PCE artifacts |
| `+4` | i16 | size (mount size 1–7) |
| `+6` | i16 | mass. Read in `0x428290` at `+0x88d306`. |
| `+8` | f32 | **thrust**. The UI shows thrust × 0.001 as "%.0fK" (`0x44e805`). |
| `+0xc` | f32 | efficiency. Power drawn = engines × thrust / efficiency, checked against the power plant (`0x146ca30 + idx*0xc`) in `0x46ffc1`. |

Examples:
- Money 758K
- Mitoria 720K
- Rush 3.2M at 0.65 efficiency
- PCE-5 3.8M at 0.95 efficiency (artifact)
- Tangent 16.65M, size 7, mass 32,500 (the "Roc" engine)
- Faction stock engines: S-E-15 745K, Mitoria-S 670K, Oteca 1.2M

**Top speed** follows from the drag law (§3): v_max = √(engines × thrust /
drag), and mass cancels out. `ship_types.csv` has a `vmax_per_sqrt_thrust`
column for this. Examples, before thrust and power MODx:

| ship | engines | v_max |
|---|---|---|
| Premia | 2 × S-E-15 | 320 |
| Premia | 2 × Respect | 460 |
| Interceptor | 2 × Rush | 600 |
| Storm | 2 × Oteca | 422 |
| Apteryx | 1 × Mitoria-S | 227 |
| Viceroy | 2 × Money | 112 |

Acceleration from rest is engines × thrust / mass. Mass includes equipment, so
acceleration is lower than hull mass alone suggests.

## 6. Collisions and docking: `0x40d630`

`0x40d630` is about 12 KB. Ghidra lumps it together with its tail up to
`0x410c9x`. Sibling `0x40ad30` handles player-built structures (table
`0x14c2f48`).

**Probe.** First a broad-phase test (`0x407b00`, model radius at `model+0x2b0`).
Then up to 7 segment-vs-model tests (`0x409a40`; it fills the contact point at
`0xb3377c..84`). The probe points are the ship centre and the centre ±½·extent
along the forward, up and right axes, swept by v·dt.

**Response to static objects and buildings** (same code in many copies):
```
n   = normalize(pos - contact)
pos += 0.1 * n
E   = 0.1 * mass * |v|^2                  // "impact energy" -> damage
v   = -0.8 * v + 5 * n                    // 80 % restitution plus a 5 u/s kick
shields -= E; overflow -> hull; hull < 0 -> death (0x9cec40)
```
If you die from an impact, the client sends a `0x0C` "impact" packet
(`"Failed to send impact packet"`). The `0xbe6e30` counter accumulates
E × 1e-6.

**Mass-ratio "elastic" bounce: slots 1–5 and world objects only, not ships.**
*Corrected 2026-11-11.* An earlier version said this formula applies ship vs
ship. That is wrong. The formula is real, but it only runs in two loops, and
neither one visits the ship slots (10–199):
1. **Contact slots 1–5.** These are the gate slots plus slot 5. The loop is
   `esi = 1 … < 6` at `0x40f9ab` / `0x41062e`. Response:
   - `e = (m − m2)/(m + m2)`, using m2 = slot `+0x15c0`
   - `v' = v2 + (v − v2)·e`
   - `pos += 0.1·n`
   - damage E = 0.1·m·|Δv|² to shields, then hull
   - debug print `"Mass F1 %f\n"` (`0xac2a20`)

   Gates have v2 = 0, so this is effectively a bounce off a fixed body.
2. **The sector world-object table** at `0x140ad48 + i*0xdc`, 1000 entries.
   Each entry holds a model at `+0`, mass at `+0x58` and active at `+0xa8`.
   The table is filled on location change by `0x4ba420` and covers asteroids,
   debris and the like. Entry 969 is skipped; it is a special model-`0x1ad`
   object set up by `0x9c99ef`. Tests are `0x4083f0` / `0x40a3f0`. Response:
   - `v' = e·v + 5·n`
   - the same damage formula

   So rocks and junk bounce you and hurt.

**Other ships (players and bots) get only a soft separation push** (`0x410659`).
There is no bounce and no damage. The push applies to every slot 10–199 that
is active, has `+3 == 0xff`, has model < `0x154`, and is within
`(size_a + size_b)·5/12`, where size is the model's `+0x2e0`, measured by slot
`+0x94` distance. It runs only when not docked (`0xbe5bc8`) and when no slot
1–5 contact happened this frame. Per frame:
```
n    = normalize(other.pos - my.pos)
v   -= n * 4 * dt * m_other/(m_me + m_other)     // heavier other ship pushes harder
pos -= 0.05 * n
seal(1)
```
At 60 fps that is only 4 u/s² scaled by the mass share, so a ship moving at
any real speed passes through another ship and gets nudged slightly. Only
your own ship is moved; each client pushes itself. In practice, then, **there
are no collisions between player ships**, which matches how the game is
remembered. Remote ships are not run through the static-object probe either
(§8).

**Special objects in contact slots 1–4 (gates) and 300–349** (slot model id at
`ship+0x34`):
| model | effect |
|---|---|
| `0x19e` (414, `x_ai_gate`, the active jumpgate) | **Pull** for 1 < d < 400: `v -= (10000/m)·(1 − cos(d·π/200))·r̂` (r̂ points away from the gate centre). Applied **per frame, not × dt**. **Gate burn:** after loitering within 375 units for more than 17.99 s, shields/hull take `(400−d)·0.0025·(ln(1+t')+t')·dt·1e7 / (110−t')` per frame, with t' = t − 17.99. |
| `0x19a` (410) | Excluded from the pull. Within 129.5 units you die instantly (`0x42a110` tail). `0x9cc750` puts this model into flagged gate slots [inferred: closed/inactive gate]. |
| `0x130` (304) | On contact, damage = (1 / distance)·dt·1e8 per frame [inferred: sun/hazard body]. |
| `0x1ae` (430) | **Repulsor** within 2000: `v += r̂·(10000/m)·(1 + 1/d)` per frame (not × dt). |

**Docking with stations** (model points `+0x7f4` → `+0x814` define the docking
axis; four guide segments at `+0x834 + k*0x20`):
- **Dock** when all of these hold: inside the tube (radial² + (size/2)² < 761);
  less than **60** units along the axis; **speed < 100**; controls live; you
  are allowed to dock there (faction table `0xbe5abc[owner]` == 1, location not
  "unregulated" (6), `0xbe5aeb` clear). Docking zeroes v and all sticks and the
  throttle, sends `0x0F` (392 B loadout) and `0x07` sub 2 "dock" (`"Error
  Sending Dock Packet"`), and sets `0xbe5bc8`/`0xbe5b01`.
- **Otherwise** you are pushed along the guide segments by 3 u/s per frame
  (3.3 for player stations, whose thresholds are 1250 / 1761 within a 1500
  range).

**Service beam `0x40cb50`** (refuel / repair / rearm / transaction pads, models
`0x157..0x177`): it freezes the ship (v = 0, sticks = 0) and shows "Hold
position to complete transaction". The transaction packet `0x79` goes out.
After 14 s it pushes you out at 10 u/s² along the pad axis.

## 7. Sector fields

The location struct `0xfd9220 + loc*100` gains three physics fields:
- `+0x4c` byte: the sector has a field.
- `+0x4d` byte: field kind. 7 = damaging.
- `+0x54` f32: strength. `+0x58/5c/60` f32: vector.

When the field is present, controls are live, and you are not in a gate's
pull (`0xbe5bb4`/`0xbe5bb8` clear), `0x429bb0` adds a **current**:
`v += (vec / mass)·drag·100·dt`.
For kind 7, `0x42a110` drains **hull** by `(strength / hullScale)·dt·3e8` and
kills you below 0.
`0x9dc570` switches the space-dust effect to streaming along v in these
sectors (visual only).

## 8. Other ships

**Remote players and bots I don't control** (`0x433010`). This covers every
active contact slot with `+3 == 0xff`, not dead, and model < 0x103:
- Orientation slews (`0x42c540`) toward the networked forward/up vectors
  (`+0x15d4`, `+0x15e0`). The per-frame step is capped at the type's
  yaw/pitch/roll rate × dt × 1000.
- Velocity follows **the same thrust/drag law**. It uses slot mass (`+0x15c0`,
  int), type drag, and slot thrust `+0x1608` (= thrust × throttle, as each
  client publishes for itself in `0x9c7270`), pushing along the slot's forward
  vector. Zero thrust means drag only, and the ship stops when drag·dt > speed.
- Gate pull (`0x19e`) and repulsor (`0x1ae`) apply as for the own ship.
- `pos += v·dt`.
- Other active slots get plain linear extrapolation, `pos += v·dt`.
- An extra entity at `0x140abb0..ac08` (type, mass, thrust, forward, velocity,
  position) uses the same law. It is parked at (−1e5, 1e5, 1e5) on sector entry
  [role unknown].

### Network snapshots vs the local simulation  [static, 2026-11-11]
**There is no separate "displayed" and "true" position.** Each remote ship has
one position (`+0x15c8`) and one velocity (`+0x15ec`). They are dead-reckoned
every frame (above) and corrected when a packet arrives. Orientation is the
only state kept in two copies. The networked forward and up vectors
(`+0x15d4` / `+0x15e0`) are snapped from each packet, and the displayed
axes (`+0x68` / `+0x74` / `+0x80`) slew toward them at the type's turn rate.

There are three S→C handlers, all in dispatcher `0x9cf6b0`. Each one is the
server relaying another client's own packet, with the same layout as C→S;
see message-types.md:

| msg | handler | carries |
|---|---|---|
| `0x05` gloc | `0x9cf7c8` | full state: position @0x90, velocity i16 ×0.1 @0x54, fwd/up i16 ×1e-4, thrust, loadout, names |
| `0x33` small loc | `0x9d573c` | position @0x1c, **velocity** i16 ×0.1 @0x12, fwd/up @6/@0xc, thrust @0x28, clock @0x34 |
| `0x34` mini loc | `0x9d5a9d` | position @0x18, fwd/up, thrust @0x24, clock @0x30. No velocity. |

The packet is matched to a slot by player id: packet `0x18` / `0x14` / `0x5c`
against slot `+0x15b4`. The slot must be active, have `+3 == 0xff` and not be
dead. Then:
1. **Ordering.** The packet clock must be newer than slot `+0x15bc`;
   otherwise it is dropped. For 0x05 the log says `"throwing away old loc2
   packet!"`.
2. old = slot position (the current dead-reckoned value). Copy the packet
   position into the slot; 0x33 and 0x05 also overwrite velocity.
3. Δ = new − old. **If |Δ|² < 40000 (error < 200 units): put the position back
   to old and add 0.1·Δ to velocity.** Otherwise keep the new position, a hard
   snap.
4. Store the new fwd/up, effective thrust (`+0x1608`) and clock. The
   engine-glow byte `+0x156d` is 0 when thrust is 0, otherwise 50.

So small errors are never applied to the position directly. They become a
velocity nudge, which dead reckoning integrates over the next frames, and
drag partly damps the extra velocity. Large errors (≥ 200 units, e.g. after a
gate jump or packet loss) teleport the ship. No latency compensation is done:
the packet clock is used only for ordering. A remote ship is therefore shown
where its owner was about one-way-latency ago, plus whatever extrapolation
has run since. When 0x33/0x34 stop (no one within 10,000 units), remote ships
coast on dead reckoning until the next 0x05, which arrives every 5–13.6 s.

**How the blend behaves over time** [reasoned from the code, not measured]:
- **It decays exponentially, with a time constant of about 10 s.** Each packet
  re-measures Δ against the drifted dead-reckoned position and nudges
  velocity by 0.1·Δ, so dΔ/dt ≈ −0.1·Δ. About 63 % of an error is gone after
  10 s and about 95 % after 30 s. Errors under 200 u can persist for a long
  time.
- **0x33 and 0x05 replace the nudge; 0x34 stacks on it.** 0x33 and 0x05
  overwrite velocity, so v becomes packet velocity + 0.1·Δ and the old nudge
  is discarded. 0x34 has no velocity field and only does `v += 0.1·Δ`, so
  nudges build up across a 0x34 tick and are cleared at the next 0x33.
- **Drag erodes the nudge.** Dead reckoning applies the thrust/drag law to the
  whole velocity. Near top speed, thrust and drag balance, and the excess
  decays quickly; a linearised estimate for a Premia at about 320 u/s gives
  roughly 1 s. Fast ships therefore converge more slowly than 10 s. At low
  speed, drag ∝ v² barely touches the nudge.
- **The target is stale.** There is no latency compensation, so the ship
  converges toward a track delayed by about one-way latency. It can carry up
  to about 200 u of standing error before a snap.

**Bots controlled by someone else** (S→C `0x71` → `0x9d6f25`) are a hard
snap. Position, velocity (i16 ×0.1) and orientation (i16 × `0xaeae10`) are
written straight into both the networked *and* the displayed axes, with no
blend.

**Contact slot layout** (`0x1042118 + i*0x160c`), additions to reversing-map:
| off | meaning |
|---|---|
| `+0x34` | model id |
| `+0x156d` | engine-glow / thrusting byte (0 or 50) |
| `+0x15b4` | player id (matched against relayed packets) |
| `+0x15bc` | clock of last applied location packet (ordering) |
| `+0x68/+0x74/+0x80` | displayed up / forward / right |
| `+0x94` | distance to me |
| `+0x15c0` | mass (int) |
| **`+0x15c8/+0x15cc/+0x15d0`** | **position** X/Y/Z (verified: `0x9c7270`, all distance code) |
| `+0x15d4` / `+0x15e0` | networked forward / up |
| `+0x15ec/+0x15f0/+0x15f4` | velocity |
| `+0x1608` | effective thrust |

> Conflict: reversing-map.md's conflux table lists "+0x15c8/+0x15cc hull". In
> the physics code those offsets are the position. Hull is likely elsewhere;
> re-check that entry.

**Bots I control** run their own AI and steering code (`0x4338c0`,
`0x40bf50`; reversing-map "Conflux"). Its integrator was not traced here.

## 9. Anti-tamper around the physics

1. **Cell shuffling** every frame (§1).
2. **Velocity seal** `0xa1a700(arg)`. It computes `chk = vx + K − vz + vy`,
   where K = 26.2879 (double at `0xb0a690`). With arg = 1 it stores chk as a
   double at `0xbdf3e8`; every legitimate velocity write is followed by
   `a1a700(1)`. With any other arg it compares and, on a mismatch, sets
   checkpoint `0x3fd` and calls **`0xa215e0`, the shutdown routine**. That
   routine logs "Last Code: %d", sends the logout message and writes
   `error.txt`. So a velocity edit that the check catches **closes the
   client** with Last Code 1021. Which call sites verify (rather than re-seal)
   is only partly mapped: most pass the argument in a register.
3. A speed tripwire `0x403120` runs every frame (`0xa2666c`, gated on
   `0xbe5b90`, `!0xbe5b08`, `!0xbe3d75`):
   if speed > **1225**, it calls `0x440660(1)` and sets `0xb8e288 = 2`
   [inferred: autopilot/cruise or anti-speedhack reaction; not traced].
4. Velocity does not go into the frequent packets: `0x33` carries
   **velocity × 10 as i16** at `@0x12` (from snapshot `0xff2ad0..d8`, scale
   const `0xb05ac8` = 10.0). Orientation goes as i16 × 10000. So the server
   *could* sanity-check speed. Whether it does is unknown (server-side).

Taken together, the protections are local obfuscation and detection only.
Since the client is authoritative for its own movement, any real enforcement
would have to happen on the server.

## 10. Function names added

`0x403150` cells_alloc · `0x403740` cells_shuffle_per_frame · `0x403120`
speed_tripwire · `0x428290` recalc_mass_thrust · `0x428b60` power_tick ·
`0x429bb0` flight_linear_dynamics · `0x42a110` flight_attitude_autodock ·
`0x40d630` own_collisions_docking · `0x40ad30` collide_player_structures ·
`0x40cb50` service_beam_pad · `0x9c7270` integrate_position_publish_slot0 ·
`0x433010` remote_ships_dead_reckon · `0x42c540` remote_orient_slew ·
`0xa1a700` velocity_seal · `0xa215e0` shutdown_error_exit · `0x9cc750`
enter_space_handler · `0x4bbfb0` freecam_tick · `0x9dc570` space_dust_fx ·
`0x49d1e0` dinput_keyboard_poll · `0xa08440` init_ship_types ·
`0x414460` init_item_tables · `0x4083f0` collide_broadphase_worldobj ·
`0x40a3f0` collide_segment_vs_worldobj.

## Open items
- Which `0xa1a700` call sites verify vs re-seal, and what `0x440660` does.
- ~~Ship-type table loader~~: done. Hard-coded in `0xa08440`; engines in
  `0x414460` (`ship_types.csv`, `engines.csv`). Still open: ship `+0x34`, the
  `+0x59..` slot lists, and engine bytes `+0`/`+1`.
- Contact slot 5: what object it holds (it gets the gate-style elastic test).
- Runtime check of the 200-unit snap / 0.1·Δ velocity blend: compare a remote
  ship's slot position with relayed 0x33 positions in a two-client capture.
- Bot steering/integration (`0x4338c0`, `0x42f360`), missile flight
  (`0x42ca30`, the `fptan` sites at `0x42af2f..0x42efd0`).
- Runtime confirmation: hook `0x429bb0` (or read the cells through the pointer
  table) and compare with the 0x33 velocity field in a capture.
