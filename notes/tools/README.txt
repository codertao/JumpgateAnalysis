Jumpgate protocol tooling
=========================
Everything here works at the GAME MESSAGE layer, inside the RakNet AES
transport and the per-message obfuscation, so no network crypto is touched.
Use it only on your own client / your own connection.

FILES
  Msb32.dll          drop-in replacement for the game's Msb32.dll (records + MitM)
  msb32_proxy.c      its source; rebuild: see BUILD below
  jgmitm_rules.txt   optional edit/drop rules (copy next to Jumpgate.exe)
  jgdecode.py        salt/running-sum decode+encode (offline)
  jgcap_dump.py      pretty-print / stats of jgcap.bin
  pcapread.py        parse a udp pcap (timing/size only; payload is AES)

INSTALL (records both directions to jgcap.bin; applies rules if present)
  cd /home/matt/misc/Jumpgate
  mv Msb32.dll Msb32_orig.dll            # once; keep the stock DLL
  cp <this dir>/Msb32.dll Msb32.dll
  cp <this dir>/jgmitm_rules.txt .       # optional
UNINSTALL
  mv Msb32_orig.dll Msb32.dll

NOTES / LIMITS
  * jgcap.bin contains your cleartext login. Treat it as sensitive; delete between runs.
  * 'drop C' (suppressing an outgoing message) is not supported by the encoder
    hook; use 'set C' to neutralize instead.
  * Type 0xFE (server memory-patch) is applied *inside* the stock Msb32 before
    this shim sees the decoded bytes, so 'drop S FE' records but does NOT block
    the write. Blocking 0xFE needs a deeper hook (can be added on request).

BUILD
  i686-w64-mingw32-gcc -O2 -Wall -shared -static-libgcc -o Msb32.dll msb32_proxy.c msb32.def

jg_static_dump.py  Jumpgate.exe [out.csv]
    Dump all ~35k hardcoded static objects (asteroids, gates + destinations,
    beacons, stations, ...) with position/orientation to CSV. Standalone:
    needs only an objdump with PE/i386 support. Build-specific (checks SHA-256).
extract_static_objects.py  (older, superseded by jg_static_dump.py)

jg_functions.py — function inventory / naming coverage
  python3 tools/jg_functions.py ../Jumpgate.exe        (from notes/; ~5 s)
  Reads function_names.csv (hand-curated: addr,name,area,confidence,ref),
  enumerates ~3,360 functions (call targets + pointer-table starts), auto-adds
  the 30 region-init functions and the 86 game-dispatcher cases, and writes
  functions.csv + a coverage summary. To name something: add a row to
  function_names.csv and re-run. Don't hand-edit functions.csv.
  Naming tiers in functions.csv (column name_source), highest priority first:
    curated   function_names.csv          region     static-world init fns
    fid/fid-multi  Ghidra Function ID (ghidra/ghidra_functions.tsv, vsOlder_x86)
    compiler  Unwind@/Catch@ SEH funclets (excluded from coverage counts)
    libstring libpng 1.0.5 / zlib 1.1.3 error strings (inside D3DX8)
    import    thin wrapper around one DLL import
    string    the game's own debug/error strings ("Failed to send X packet", "Map.cpp: Fn:")
  Regenerate ghidra/ghidra_functions.tsv with analyzeHeadless + ExportFuncs.java
  (see ghidra/README.txt); ~3 min.

Login redaction (2026-11-11): the shim zeroes the password in the RECORDED copy of
the C>S login (short type 0x05, password slot shows '*'); the real login is sent
unchanged. Older captures (jgcap.firstgood.bin etc.) still contain the password.
