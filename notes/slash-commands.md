# Slash commands  [static, 2026-11-12]

All slash commands are parsed in one function, **`0x49da20`** (~39 KB; earlier
mis-named `send_SqdCmd`). It is called with the chat line and the game object
(`this` = `0xbdf578`).

How it works:
1. A line not starting with `/` goes to the chat path (`0x49e10c`).
2. `sscanf(line, "%s %s %s %s %s %s %s")` splits the line into 7 tokens. Token 0
   is upper-cased, so commands are case-insensitive.
3. A chain of ~146 `repz cmpsb` compares checks token 0 against literal names
   (`mov edi,<str>; lea esi,[esp+0x130]`). Subcommands compare token 1
   (`[esp+0x180]`).
4. **Unknown commands are silently ignored.** Nothing is forwarded to the server.
5. Local output goes to the chat log through `0x4848a0` (print line), or straight
   into the chat-line ring (`this+0x413578 + n*0x84`, 100 lines, index `this+0x66a4`).

Online/offline: `[this+0x6618]` is non-zero when connected. Several commands
check it ("Not available in offline mode", or offline-only).

Server-bound commands use `SendGameMessage` `0x9c9c10`, so they go to the
**state** server (network-protocol.md §1.1a). Sending one only *requests* the
action. Permissions (GM, Optimus, rank) are presumably enforced by the server;
the client does no GM check before sending.

Method: `slash2.py` in the session scratchpad attributes each compare's body.
"Type" is the first byte the body stores before calling 0x9c9c10, so treat it as
approximate. 0x09 and 0x9C are multi-purpose types with a sub-op (0x9C bodies
print errors such as "Packet 1-238").

## Local only (no packet)

| Command | What it does |
|---|---|
| `/cargo` | Lists the hold. Walks **48 cargo slots at `this+0x4187b4`** (`0xff7d2c`), 8-byte records: `+0` u8 category (switch over 0–11 via jump table `0x4a7334`), `+1` u8 index in category, `+4` f32 quantity. Prints `name(qty)`: guns take the name from the gun object (`this+0x908efc[idx]+0x10` = `0x14e8474` table), other items from the item-name table (`this+0x8a1aa8 + idx*0x32` = `0x1481020`; per-category offsets). Format `%s(%.2f)` / `%s(%.4f)`. |
| `/credits` | Prints credits (`%I64d`, a 64-bit balance) |
| `/exp`, `/experience` | Prints experience |
| `/mission` | Prints current mission objectives from local state |
| `/bounty` | Transponder bounty |
| `/bcu` | Whether a BCU device is equipped |
| `/sec`, `/sector` | "Current Sector: %s" (uses the location names table) |
| `/reg`, `/registry` | Flight registry (Military / Pirate / Mercenary …) |
| `/ratings` | Faction ratings S/O/Q/H/A |
| `/warinfo` | Faction relationship table (local; "Not available offline") |
| `/channel` | Current F5/F4 chat settings |
| `/time` | PC clock |
| `/xyz` | **undocumented**: prints own position `%.0f,%.0f,%.0f` |
| `/toggleroll` | **undocumented**: roll control dampen/continuous, saved to `rollctrl.bin` |
| `/flashfire` | HUD FlashFire indicator toggle (`options.bin`) |
| `/toggletips` | Mutes the TIPS: channel |
| `/setrender <n>` | Render distance 10000–50000 |
| `/ignore [name]`, `/voice`/`/hear <name>` | Local ignore list in `ignore.txt` |
| `/r`, `/reply` | Sets F4 to the last whisperer |
| `/rotacol x y z`, `/rotacoloff` | Local sector waypoint |
| `/help`, `/` and `/opti` | Print the help text (strings `0xaf3384..0xaf4170`) |
| `/q`, `/quit` | Quit (`0xa215e0`) |
| `/ai <n>` | Offline sim only: spawns flux type n (n < 6) |
| `/m`, `/missile` | **undocumented**, offline only: refills every missile slot to 12 ("Missiles reloaded.") |
| `/win` | Easter egg: "Congratulations, you have won Jumpgate." |
| `/setowner` | Prints "Function currently disabled" |

Not clear from the static pass (the body is very short or shared; may toggle a
flag): `/dockoff`, `/mentor`, `/assist`, `/cancelad[vert]`, `/list`/`/l` (calls
`0x441740(100)`), `/adjwari` (only validates its argument here).

## Sends a request to the server

Player-facing (in `/help`):

| Command | ~Type | Notes |
|---|---|---|
| `/sq …` (`/sq who`) | 0x9C | squad commands |
| `/chat join/setpass/who`, F5 channels | 0x65 / 0x04 / 0xC3 / 0x9C | |
| `/listchannels` | 0x83 | undocumented |
| `/profit`, `/prof`, `/p`, `/cargonet` `<space> <credits> [faction]` | 0x9C | **trade-route query: the server answers.** Relevant to a cargo bot |
| `/listprices`, `/listprice` | 0x9C | custom POS prices (online only) |
| `/setprice`, `/noprice`, `/clearallprices`, `/dump [squad]` | 0xB1 | POS market |
| `/give <x>` | 0x6E | credits to target |
| `/shipname` | 0xAC | undocumented |
| `/tour` | 0xC3 | military tour |
| `/wing <name>`, `/wingoff` | 0x36 | |
| `/mentoroff`, `/students` | 0x4E | |
| `/home`, `/homeoff`, `/homewhere` | 0x59 / 0xBB / 0xC3 | |
| `/build`, `/publish` | 0xA3 | POS |
| `/gear` | 0xB9 | starter equipment |
| `/vouch` | 0x9D | |
| `/oredepots`, `/prodefc` | 0xC3 | Optimus |
| `/prodboost <item>` | 0x10 | Optimus |
| `/assistoff`, `/gms` | 0x09 | |
| `/away [msg]` | 0x9C | |
| `/event`, `/puredist tri/flux/arty`, `/setsevent`, `/sendghostdata` | 0x9C / 0x29 | undocumented event tools |

Staff/GM/test (not in `/help`; the server presumably rejects them for normal
accounts):
- **Accounts:** `/kick` (0x7A), `/setexp` (0x3F), `/setcredits` (0x40), `/credit`
  (0x41), `/find` (0x3D), `/changepr` (0xBA), `/commission` (0xC5), `/medal` (0x37),
  `/mute`, `/muteoff`.
- **Teleport and help queue:** `/jump`, `/ajump` (0x09; "No anomaly there."), `/go`
  (0x99), `/summon` (0x9A), `/refer` (0x98), `/volunteer[off]` (0x96/0x9B),
  `/assistlist`, `/empty`, `/eps` (0x09).
- **Broadcasts:** `/allcast` (0x38), `/ktri` (0x39), `/stcast` (0x3A), `/fcast`,
  `/ktrimsg`, `/ktrilist` (0x3C), `/mode 0–3` (0x93).
- **Reports:** `/report` (0x67), `/complaint` (0xC4).
- **World and test tools (0x9C):** `/market`, `/infest`, `/setreg`, `/eventreg[on|off]`,
  `/testver`, `/testack`, `/adjwar`, `/setdestruct`, `/spawnoff`, `/setspawnon/off`,
  `/purgeusers`, `/chkhive`, `/bldginfo`, `/warquery`, `/testartys`, `/sentreload`,
  `/spawnitem`. Also `/posowner` (0x90) and `/bot …` (handler `0x49c080`).

## Notes for a cargo bot
- The **hold layout** used by `/cargo` (48 × {category, index, f32 qty} at
  `0xff7d2c`) is the client's own view of the cargo. The 0x05 report and 0x06
  char record carry a related slot array (`fe fe` = empty; message-types.md),
  but I haven't checked that its format is the same.
- **`/profit`** is a server-side trade-route calculator. It is worth capturing
  its request and reply layout.
