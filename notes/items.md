# Item, weapon and location tables  [static, 2026-11-12]

None of the game data ships as a data file. It is all compiled into straight-line
initialiser code: `mov [abs], imm` stores, with sprintf() calls for the strings. The
compiler interleaves item *k*'s name sprintf with item *k−1*'s field stores, so
attributing fields by address (not by order) is essential. `tools/jg_tables.py`
re-extracts everything below in about 0.3 s (it needs objdump and checks the SHA-256):

    python3 tools/jg_tables.py ../Jumpgate.exe .        (from notes/)

| CSV | Source | Rows |
|---|---|---|
| `items.csv` | master list: id, category, name, description (all items + guns as `g<n>`) | 395 (335 items + 60 guns) |
| `missiles.csv` | missile table (see ai.md) | 24 |
| `engines.csv` | engine table (see physics.md §5) | 27 |
| `powerplants.csv`, `radars.csv`, `ecms.csv`, `shields.csv`, `capacitors.csv` | equipment tables | 27/20/8/25/21 |
| `devices.csv` | "special": MODx, PCMs, station kits, misc | 70 |
| `cargo.csv` | commodities, artifacts, mission cargo, ores | 113 |
| `guns.csv` | gun objects (separate struct, see below) | 60 |
| `ship_types.csv`, `ai_types.csv` | ship hulls, bot AI (physics.md, ai.md) | 88/36 |
| `locations.csv` | sectors/stations: name, galaxy XYZ, faction | 173 |

## Global item ids — `init_item_tables` `0x414460`..`0x424e70`

All non-gun items share one id space, 0–401:

- name: `0x1481020 + id*0x32` (char[50])
- description: `0x148628c + id*0x1c2` (char[450])
- category names (UI): Guns, Missiles, —, Commodities, —, Engines, Powerplants, Radar,
  ECMs, Shields, Capacitors, MODx. These are the category indices used by the market
  popup `0x44c7b0` (0 gun, 1 missile, 3 commodity, 5–10 as listed, 11 special).

| Category | Ids | Record base | Stride | Known fields (beyond common) |
|---|---|---|---|---|
| missile | 0–23 | `0x14fcbd4` | 0x30 | see ai.md; +0x2c i16 size |
| engine | 24–50 | `0x146c878` | 0x10 | +8 f thrust, +0xc f efficiency |
| powerplant | 51–77 | `0x146ca28` | 0xc | +8 i32 output |
| radar | 78–97 | `0x146cb6c` | 0x10 | +8 i32 range, +0xc i32 power draw |
| ECM | 98–105 | `0x146ccac` | 0xc | +8 i32 power |
| shield | 106–130 | `0x146cd0c` | 0x18 | +8 i16 ?, +0xc f regen/s, +0x10 f efficiency, +0x14 i32 capacity |
| capacitor | 131–151 | `0x146cf64` | 0x10 | +8 f capacity, +0xc f efficiency % |
| device | 152–221 | `0x146d0b4` | 8 | common only |
| cargo | 222–401 | `0x146d2ee + (id−222)*6` | 6 | +0 u8 (1 = commodity, 0 = artifact), +2 i16 size, +4 i16 mass |

Common to the equipment tables: +0 u8 rank/tier (the licence level needed), +4 i16
size (slot size), +6 i16 mass. The bytes at +1..+3 are output as `o01..o03`. They are
small enums (often 1). They are probably manufacturer/faction or availability flags,
but not confirmed.

How the fields were labelled:
- **Market popup `0x44c7b0`:** which field is printed under which caption.
- **Power budget `0x4680c0`:** reads the radar power (×0.8 with the matching MODx), ECM
  power and shield/capacitor fields against the powerplant output.
- **Shield regen `0x433309`:** adds regen × dt × efficiency, capped at capacity.
- **Radar targeting `0x43de8d`:** compares range.
- **Gun fire `0x43d96c`:** energy per shot against the capacitor charge at `0x140ac18`.

**Own loadout** (item id bytes): `0x140ac0c` engine, `0d` powerplant, `0e` radar, `0f`
ECM, `10` shield, `11` capacitor, `12` ? (used with a table at `0x146d2e4`).

**Devices** have no effect parameters in the table. Each MODx/PCM's effect is
hard-coded wherever it applies, keyed on the item id (e.g. the radar-power MODx
check in `0x4680c0`). Ids 205–221 are station components and POS kits (Docking
Computer, Ore Silo, BuildKit -2/-4/-8, POS MoveKit, …).

**Cargo** ids are sparse (113 of 180 defined). 372–380 are mission cargo (X-xxxx crates,
Recon Relay, Passenger Cryopod) and 397–401 are mined ores.

## Guns — separate objects

Guns are not in the id table. Each one is `new(0xbd4)` + constructor `0xa60b90`,
and the pointer is stored at `0x14e8474 + g*4` (this sits in the protected
"cell" area, see physics.md). The extractor tracks the pointer through registers.
Fields:

| Off | Field | Notes |
|---|---|---|
| +0x10 | name | sprintf |
| +0x42 | rank | |
| +0x50 | damage | UI shows ÷1000 as "K" |
| +0x58 | lifetime_s | |
| +0x5c | speed | |
| +0x60 | refire_s | |
| +0x64 | ammo | 0 for energy weapons |
| +0x68 | energy_per_shot | checked against capacitor charge `0x140ac18`; power budget uses energy/refire |
| +0x6c | sound | |
| +0x78 / +0x98 / +0xb8 | bolt / bolt-LOD / hit asset names | `files` column |
| +0xe0 | class | 0 projectile, 2 beam |
| +0xe8 | mass | |
| +0xec | description | |

Computed columns: `range` = speed × lifetime for class 0 (for beams, speed *is* the
range), `energy_per_s` = energy / refire, and `dps` = damage / refire.
Unlabelled: `b08`, `b09`, `f54`, `f70`, `id4`, `fd8`, `idc`. Some `b08`/`b09` cells are
blank because they are register-sourced stores the tracker couldn't resolve.

Example: Liar does 251 K damage at speed 10000 and lifetime 0.1 s (range 1000). Refire
is 0.75 s and each shot costs 402 K energy, so 536 K/s energy and 335 K dps.

## Locations — `0x4a8d10`..`0x4ad0d2`, `0xfd9220 + id*100`

| Off | Field |
|---|---|
| +0 | name (char[40]). Written by inlined strcpy: dword/word loads from the string, `rep movs`, or for ≤3-char names ("GBS", "T&P") a single dword immediate |
| +0x28 | flag (1 on 50 locations; meaning unknown) |
| +0x2c/+0x30/+0x34 | galaxy-map x, y, z (f32) |
| +0x3c | owning faction (set only on the faction core/home stations 101–118) |
| +0x40 | faction / region (1 Solrain, 2 Octavius, 3 Quantar, 4 Hyperial, 5 Amananth, 6 independent); the game compares it with the own faction `0xbe5b0e` |
| +0x44 | 301 for station locations (1xx), 302 for space sectors (2xx–3xx) |
| +0x4c.. | nav-field data, zero statically (set at runtime) |

Ids 101–118 are stations and 201–349 are sectors. 1000–1005 have only a faction and no
name or position. Names match `sector_regions.csv` (from `jg_static_dump.py`).
Ids 1–18 are also partly written (station records without coordinates).
They are not exported.

## Open
- The meanings of `o01..o03` in the equipment tables and the shield `+8` i16.
- The unlabelled gun fields, and their register-sourced `b08`/`b09`.
- The device effects (one hard-coded check per id; not catalogued).
- Prices: none of these tables has a price. It presumably comes from the server's
  market messages.
