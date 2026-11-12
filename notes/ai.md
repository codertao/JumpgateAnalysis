# Jumpgate.exe — AI: missiles, conflux, defenders, turrets

Static analysis of SHA-256 `fef6e50f…`, done 2026-11-11, with no runtime
confirmation. Related notes:
- [physics.md](physics.md): flight law, cells, collision
- [reversing-map.md](reversing-map.md): "Conflux / bot AI" (ownership,
  botloc, bxr handoff) and "Weapon hits & damage"

All AI runs **on the clients**. The server only assigns ownership, relays
state and applies player damage.

**Data tables**, all hard-coded and extracted by
`tools/jg_tables.py Jumpgate.exe .`:
- `missiles.csv`: 24 missile types
- `ai_types.csv`: 36 bot types
- `ship_types.csv`: hull, drag and turn rates, shared with player ships

---

## 1. Missiles: `0x42ca30` missile_update (every frame)

### Tables
- **Own missiles:** `0x14fd058 + i*0x48`, 32 slots. Each one is mirrored
  into contact slot 201+i so it renders and can be targeted:

  | off | field |
  |---|---|
  | +0 | forward (f32×3) |
  | +0xc | up (f32×3) |
  | +0x18 | position |
  | +0x24 | velocity |
  | +0x30 | launch time (QPC, i64) |
  | +0x38 | type (u8; `0xfa` = free, `0x80` = dying) |
  | +0x3a | target slot (i16; 0 = none, −1 = lost) |

- **Other players' missiles:** `0x14fd998 + i*0x48`, same layout. They are
  flown by the same guidance code but only for display, with no hit tests.
  This loop runs only while online (`0xbe5b90`).
- **Missile types:** `0x14fcbd4 + t*0x30`, filled in `0x414460`
  init_item_tables. Names are at `0x1481020 + t*0x32`.

  | off | field |
  |---|---|
  | +0 / +1 | u8: tier, and 1 = sold |
  | +4 / +8 | pitch / yaw turn rate (rad/s) |
  | +0xc | thrust |
  | +0x10 | drag |
  | +0x14 | mass |
  | +0x18 | damage |
  | +0x1c | lifetime (s) |
  | +0x20 | model |
  | +0x22 | guidance class |
  | +0x24 / +0x26 | cluster count / child model |

### Flight
Missiles use exactly the ship drag law:
`v += (thrust/m · fwd − |v|²·drag/m · v̂)·dt` and `pos += v·dt`. Top speed is
therefore √(thrust/drag):
- Spear and Smacker: 1000
- Sirrus: 951
- Rapier: 701
- Maul: 453

### Guidance
This is the class at `+0x22`.
- **Class 0** (Spear, Smacker, Drop Tank): unguided. They fly straight.
- **All guided classes** steer toward `d = 2·LOŜ − v̂`, where LOŜ is the unit
  vector to the target and v̂ is the missile's own velocity direction. This
  aims at the line of sight mirrored about the current heading, so it
  cancels sideways drift. It behaves like a cheap proportional-navigation
  pursuit.
- **Class 2 and 4** also add lead when the target is a ship (models 30–259)
  moving with vx+vy+vz ≥ 15. That test sums the components rather than
  taking the magnitude, so it is a bug or a shortcut:
  `d = normalize(2·d + v̂_target)`.
- **Class 1** (Long Sword, Lance, Kataka, Hatchet, Maul, Sabre, Glaive,
  C29 Lamprey) uses pure pursuit with no lead. These are the slow, heavy
  torpedoes.
- **Steering:** the code computes pitch = atan(d·up / d·fwd), clamped to
  ±pitch_rate·dt; a target behind the missile gets the full rate. It rotates
  fwd toward up by tan(pitch) and re-orthonormalises. It then does the same
  for yaw with the right vector, which only happens while the target is in
  front. This is the same tan-step scheme the player ship uses.
- **Jammer ECM:** if the target has Jammer ECM (ECM type 6) switched on, the
  aim point is offset ±70 units along one axis, chosen by `type % 6`. The
  offset is ±50 when another player's missile targets a third party. Missiles
  then tend to pass beside a jamming ship.

### Fusing and impact (own missiles only)
Each frame a swept segment test runs against several target sets:
1. Ships in slots 1–199. Models 30–121 get a mesh test (`0x409e10` /
   `0x409a40`). Otherwise:
   - **Class < 3:** a contact fuse. It fires when the closest approach is
     under radius/2 and the point lies inside the model's extents
     ellipsoid. It hits anything.
   - **Class ≥ 3** (only Cutlass, class 4): a proximity fuse that fires only
     on its own target, within radius/2 + 15.
2. Special objects in slots 300–349. The repulsor (`0x1ae`) destroys
   missiles.
3. The 1000-entry world-object table (asteroids etc.).
4. Player structures (`0x14c2f4c`).

What a hit does depends on the target:
- **Stations, gates and repulsors:** a structure-damage packet goes out with
  damage × 0.001, or × 0.01 for types 18–20 (Maul, Sabre, Glaive). That
  ×10 bonus makes those three the anti-structure weapons.
- **Bots I control:** damage is applied locally, to shields first and then
  hull.
- **Player ships:** the hit goes through the hit queue → C→S `0x1D`
  (reversing-map).
- **Splash:** models 284–287 (Maul, Sabre, Glaive, C29 Lamprey) call
  `0x43eb30` with radius 2000.

### Life and expiry
- A missile is deleted when its age exceeds its lifetime (`"pATime Deleted
  Missile %i %f"`).
- **PWD ECM** (ECM type 7, "PWD100") broadcasts C→S `0x4d` sub `0xd`. Every
  client then sets that ship's slot `+0x4c` = 40. While it is non-zero, any
  missile within **1500** units has its launch time pushed back by a full
  lifetime, so it expires on the next frame. PWD is a missile-killing pulse.
- **Grave Robber misfire** (type 16): between 1.9 and 2.4 s of flight, each
  frame has a 1-in-6000 `rand()` chance of self-destructing. Its item text
  claims "misfiring problems have now been solved".
- **Clusters:** Morning Star carries 4 × ScrewDriver (model 277) and
  HellRazor carries 2 × Stiletto (280), per `+0x24` / `+0x26`. The split code
  was not traced.

---

## 2. Bots (conflux, faction defenders, turrets): `0x4338c0` online_bot_ai

It runs every frame over the 50-entry `pbotloc` table (`0xb341f0 + i*0x14`,
see reversing-map). Each bot is a normal contact slot. Its target is
**slot `+2`**, where 0 means it is attacking *me*. The server sets the target
in S→C `0x71` @0x24, and damage re-targets the bot at the attacker (S→C
`0x03`). In loc 1005, offline-sim mode, `0x42f360` runs instead.

> The loop does **not** check whether this client is the bot's controller. It
> requires only: pbotloc active, ship slot active, and slot `+1` ≠ 0. So
> every client appears to simulate every bot, which acts as prediction. The
> controller's botloc (sent after each 0x05) hard-snaps the bot on everyone
> else (physics.md §8). Shots are only *aimed* by the controller (`0x439260`)
> [inferred from the code paths; not runtime-checked]. Note that the 0x33
> handler requires `+1 == 0` for players, so `+1` behaves like an "AI bot"
> flag here. reversing-map labels it "dead", which needs re-checking.

### Per-type AI table: `0xbe7f7c + type*0x40` (filled by `0xa07240`)
Extracted to `ai_types.csv`. Types 220–225 and 230–259 are defined.

| off | field |
|---|---|
| +0 | thrust (the throttle-1.0 value written to slot `+0x1608`) |
| +4 | mass |
| +8 | hull [inferred] |
| +0xc | max shields |
| +0x10 | shield regen per second (applied at the end of each AI tick) |
| +0x14 | bxr handoff range |
| +0x18 + 4k | 8 weapon slots (u8 weapon id, `0xfe` empty), k = 0..7. Some are written from registers the extractor could not resolve. |
| +0x38 | type id |
| +0x3c | **skill** 1–4 |

**Skill:**
- **≥ 3:** dodges incoming missiles and flanks.
- **Even (2, 4):** full lead when shooting.
- **Odd (1, 3):** half lead.

All defenders (220–225) are skill 4 with a handoff range of 150,000. Conflux
skill varies from 1 to 4.

### Turrets: models 258 "Unknown" and 259 "Globule" (`0x429b20`)
These have zero thrust, so they never move. Each tick:
1. Compute a lead aim point. The weapon's projectile speed and range come
   from the gun table `0x14e8474[weapon]` (+0x58 / +0x5c).
2. Slew toward it with `0x42c540`.
3. Within weapon range, fire every non-empty weapon slot (fire bitmask
   `+0x156f`) if a line-of-fire check (`0x409a40`) is clear.

### Mobile bots: state machine on pbotloc `+1`
1. **Jink (evasion).** While its timer (`+0xbc`) has run out and shields are
   below 70 %, the bot sets fwd ± 0.3·(up | right), with the axis chosen by
   `slot+0x32 & 3`. The timer is then 4 s. Skill ≥ 3 also jinks by 0.4 when
   one of its targeting missiles is closer than 3 s of missile top speed. It
   checks both its own missiles and other players'. A jinking bot runs at
   ×1.2 throttle until the timer expires.
2. **Obstacle avoidance.** It probes ahead along velocity × 6 s (slow) or
   × 3 s (fast), and later × 12 / × 9 s against player structures. The
   probe covers world objects, ships 0–199, special objects 300–349 and
   player stations. If something is ahead (dot > 0.1), `0x42c1c0` steers
   away and the attack logic is skipped for that frame.
3. **State 0, attack** (default). Full throttle toward the target, then:
   - **Inside weapon range:** lead the target. With t = range / closing
     speed, aim = target + t·v_target (×½ if skill is odd), minus the bot's
     own sideways velocity.
   - **Outside range with skill ≥ 3:** aim 120 units off the target's
     up/right axis, using the same `& 3` pick, so it flanks rather than
     flying straight in.
   - **Conflux 230–257 inside range:** throttle drops to ×0.5, or ×0.25 if
     the target is nearly stopped, so it hangs around the target.
   - **Firing:** all weapon slots fire when the aim dot is > 0.99 and the
     target is inside weapon range.
   - **Nautiloids (243–245)** switch weapon sets beyond 4400 units.
   - **Jellyfish and Squids (230–233):** within 200 units of the target, if
     I am the controller, a 1-in-32000 `rand()` per frame sends C→S `0xB0`
     (reversing-map).
4. **Target gone** (target slot inactive):
   - **Faction defender (220–225) in a sector with a station:** go to
     state 1 and head home.
   - **Anything else:** despawns (slot cleared, `0x9cb9c0`).
5. **State 1, head home:** coast until stopped, then go to state 2.
6. **State 2, approach dock:** fly to a point on the sector station's
   docking axis (model `+0x7f4` → `+0x814`), aligned with the station's up
   vector. Near it, stop and go to state 3.
7. **State 3, dock:** fly into the dock point. Within 60 units it despawns.
   The controller sends botloc sub 3 (`"Failed to send botloc 3 packet"`).
8. **State 8:** a one-shot jink request, applied and then reset to 0.

Every state then slews orientation with `0x42c540` and integrates with the
ship drag law: `v += (thrust/m·fwd − |v|²·drag/m·v̂)·dt` and `pos += v·dt`.
Drag comes from the ship type and mass from the slot.

### Defenders in summary
Defenders are not a separate AI. They are faction-flavoured bots (types
220–225, "Sol / Oct / Quan Def 1 / 2"):
- skill 4: full lead, missile dodging, flanking
- strong shields with fast regen (e.g. Oct Def 2: 36M shields)
- long handoff range
- they **return to the station and dock** when their target disappears,
  instead of despawning

TRI Shuttle and TRI Defender (196–199) have ship records but no AI-table
entry, so they are driven elsewhere [not traced].

---

## Function names
- `0x42ca30` missile_update
- `0x4338c0` online_bot_ai_tick
- `0x429b20` is_turret_model
- `0x42c1c0` bot_steer_avoid
- `0xa07240` init_ai_types
- `0x427c00` ecm_toggle
- `0x427af0` pwd_pulse_send

## Open items
- Cluster split, mortar splash damage (`0x43eb30`), and how missile damage
  for player victims is scaled server-side.
- The TRI shuttle and defender (196–199) driver, and `0x42f360` offline sim.
- Confirm that every client runs bot AI as prediction. Hook `0x4338c0` with
  two clients near a conflux.
- Unresolved weapon-slot bytes in `ai_types.csv` (register-sourced stores).
