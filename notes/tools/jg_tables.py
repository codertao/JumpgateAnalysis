#!/usr/bin/env python3
"""Extract the hard-coded ship-type and engine tables from Jumpgate.exe.

Neither table exists as static data. Both are written by straight-line
initialiser code made of `mov [mem], imm` stores and sprintf() calls for the
names:

  * ship types: 0xa08440 writes [esi+disp] with esi = 0xbdf578, so a record
    lives at 0xff7eac + type*0x1e0 (written as this+0x418934).
  * engines:    0x414460 writes absolute addresses 0x146c878 + idx*0x10
    (u8 b0,b1,b2; i16 size @+4; i16 mass @+6; f32 thrust @+8; f32 eff @+0xc).
    Their names go to 0x14814d0 + idx*0x32, which is the same item-name
    table used for power plants, shields and so on.

Usage:  jg_tables.py Jumpgate.exe [outdir]
Writes outdir/ship_types.csv and outdir/engines.csv (outdir defaults to .).
Needs objdump (binutils) on PATH. Verify the exe SHA-256 starts fef6e50f.
"""
import csv, math, os, re, struct, subprocess, sys

EXE = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else '.'
img = open(EXE, 'rb').read()
import hashlib
if not hashlib.sha256(img).hexdigest().startswith('fef6e50f'):
    sys.exit('wrong Jumpgate.exe build (SHA-256 must start fef6e50f); addresses would be invalid')
SPRINTF = 0xaa970c
REG8 = {'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx',
        'ax': 'eax', 'bx': 'ebx', 'cx': 'ecx', 'dx': 'edx',
        'di': 'edi', 'si': 'esi', 'bp': 'ebp'}


def cstr(va):
    o = va - 0x400000                       # .rdata/.data: file off = VA - 0x400000
    return img[o:img.index(b'\0', o)].decode('latin1')


def disasm(lo, hi):
    out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                          '--start-address=%#x' % lo, '--stop-address=%#x' % hi, EXE],
                         capture_output=True, text=True, check=True).stdout
    for l in out.splitlines():
        m = re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)', l)
        if m:
            yield int(m.group(1), 16), m.group(2), m.group(3).strip()


def scan(lo, hi, mem_re):
    """Track register constants and collect memory stores and sprintf(dst, src) calls.
    mem_re captures the store target as a hex displacement (group 1)."""
    regs, stores, strs, pushes = {}, {}, {}, []
    for a, op, args in disasm(lo, hi):
        m = re.match(r'(e[a-d]x|e[sd]i|ebp),0x([0-9a-f]+)$', args)
        if op == 'mov' and m:
            regs[m.group(1)] = int(m.group(2), 16); continue
        m = re.match(r'(e[a-d]x|e[sd]i|ebp),\1$', args)
        if op == 'xor' and m:
            regs[m.group(1)] = 0; continue
        m = re.match(r'(DWORD|WORD|BYTE) PTR ' + mem_re + r',(\S+)$', args)
        if op == 'mov' and m:
            sz = {'DWORD': 4, 'WORD': 2, 'BYTE': 1}[m.group(1)]
            v = m.group(3)
            if v.startswith('0x'):
                val = int(v, 16)
            else:
                r = REG8.get(v, v)
                if r not in regs:
                    continue
                val = regs[r]
            stores[int(m.group(2), 16)] = (sz, val & ((1 << 8 * sz) - 1))
            continue
        m = re.match(r'(e[a-d]x|edi|ebp),\[esi\+0x([0-9a-f]+)\]$', args)
        if op == 'lea' and m:
            regs['lea_' + m.group(1)] = int(m.group(2), 16)
        if op == 'push':
            pushes.append(args)
        if op == 'call':
            if args == '%#x' % SPRINTF and len(pushes) >= 2:
                dst, src = pushes[-1], pushes[-2]
                if dst.startswith('0x'):
                    dst = int(dst, 16)
                elif 'lea_' + dst in regs:
                    dst = regs['lea_' + dst]
                else:
                    dst = None
                # 3-arg form sprintf(dst, "%s", src): use the third push
                if len(pushes) >= 3 and src.startswith('0x') and cstr(int(src, 16)) == '%s':
                    src = pushes[-3]
                if dst is not None and src.startswith('0x'):
                    try:
                        strs[dst] = cstr(int(src, 16))
                    except (ValueError, IndexError):
                        pass
            pushes = []
        m = re.match(r'(e[a-d]x|e[sd]i|ebp),', args)
        if m and op not in ('mov', 'xor', 'lea', 'cmp', 'test', 'push'):
            regs.pop(m.group(1), None)
    return stores, strs


def get(st, addr, kind):
    v = st.get(addr)
    if v is None:
        return ''
    sz, x = v
    if kind == 'f':
        return round(struct.unpack('<f', struct.pack('<I', x))[0], 6)
    if kind == 'h':
        return struct.unpack('<h', struct.pack('<H', x & 0xffff))[0]
    if kind == 'i':
        return struct.unpack('<i', struct.pack('<I', x))[0]
    return x


# ---------------- engines ----------------
ENG, ENG_N, NAMES = 0x146c878, 27, 0x14814d0   # record base; thrust read at base+8 = 0x146c880
est, estr = scan(0x414460, 0x424e70, r'ds:0x([0-9a-f]+)')   # whole init_item_tables
engines = []
for i in range(ENG_N):
    a = ENG + i * 0x10
    engines.append(dict(idx=i, name=estr.get(NAMES + i * 0x32, ''),
                        thrust=get(est, a + 8, 'f'), efficiency=get(est, a + 12, 'f'),
                        b0=get(est, a, 'b'), b1=get(est, a + 1, 'b'), b2=get(est, a + 2, 'b'),
                        size=get(est, a + 4, 'h'), mass=get(est, a + 6, 'h')))
with open(os.path.join(OUT, 'engines.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, engines[0].keys()); w.writeheader(); w.writerows(engines)

# ---------------- missiles ----------------
# 0x14fcbd4 + t*0x30, names at 0x1481020 + t*0x32 (item index t-24). Read by
# missile_update 0x42ca30 at +4.. (it indexes 0x14fcbd8 + t*0x30).
MIS, MIS_N, MNAMES = 0x14fcbd4, 24, 0x1481020
missiles = []
for t in range(MIS_N):
    a = MIS + t * 0x30
    missiles.append(dict(idx=t, name=estr.get(MNAMES + t * 0x32, ''),
                         b0=get(est, a, 'b'), b1=get(est, a + 1, 'b'),
                         pitch_rate=get(est, a + 4, 'f'), yaw_rate=get(est, a + 8, 'f'),
                         thrust=get(est, a + 0xc, 'f'), drag=get(est, a + 0x10, 'f'),
                         mass=get(est, a + 0x14, 'f'), damage=get(est, a + 0x18, 'f'),
                         lifetime_s=get(est, a + 0x1c, 'f'), model=get(est, a + 0x20, 'h'),
                         guidance=get(est, a + 0x22, 'h'),
                         sub_count=get(est, a + 0x24, 'h'), sub_model=get(est, a + 0x26, 'h'),
                         w28=get(est, a + 0x28, 'h'), size=get(est, a + 0x2c, 'h')))
for m in missiles:   # top speed from the same drag law as ships
    m['vmax'] = round((m['thrust'] / m['drag']) ** 0.5) if m['thrust'] and m['drag'] else ''
with open(os.path.join(OUT, 'missiles.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, missiles[0].keys()); w.writeheader(); w.writerows(missiles)

# ---------------- generic item tables (init_item_tables 0x414460) ----------------
# Every item has a global id. Name = 0x1481020 + id*0x32, description = 0x148628c + id*0x1c2.
# Each category has its own fixed-stride stat table; the market popup (0x44c7b0) reads
# +0 u8 rank (tier), +4 i16 size, +6 i16 mass for every equipment table. Cargo items use
# +2 size / +4 mass. Unlabelled fields come out as o<hex offset> with their stored width.
INAME, IDESC = 0x1481020, 0x148628c
CATS = [  # name, first id, last id, table base, stride, {offset: (column, kind)}
    ('missile',    0,  23, 0x14fcbd4, 0x30, {}),
    ('engine',    24,  50, 0x146c878, 0x10, {8: ('thrust', 'f'), 0xc: ('efficiency', 'f')}),
    ('powerplant', 51, 77, 0x146ca28, 0x0c, {8: ('output', 'i')}),
    ('radar',     78,  97, 0x146cb6c, 0x10, {8: ('range', 'i'), 0xc: ('power', 'i')}),
    ('ecm',       98, 105, 0x146ccac, 0x0c, {8: ('power', 'i')}),
    ('shield',   106, 130, 0x146cd0c, 0x18, {0xc: ('regen', 'f'), 0x10: ('efficiency', 'f'), 0x14: ('capacity', 'i')}),
    ('capacitor', 131, 151, 0x146cf64, 0x10, {8: ('capacity', 'f'), 0xc: ('efficiency_pct', 'f')}),
    ('device',   152, 221, 0x146d0b4, 0x08, {}),      # market category "special": MODx, PCM, kits
    ('cargo',    222, 401, 0x146d2ee, 0x06, {2: ('size', 'h'), 4: ('mass', 'h')}),
]
COMMON = {0: ('rank', 'b'), 4: ('size', 'h'), 6: ('mass', 'h')}


def kind_of(width, values):
    if width == 1:
        return 'b'
    if width == 2:
        return 'h'
    # DWORD: float if most non-zero values have a sane float exponent
    nz = [v for v in values if v]
    fl = sum(1 for v in nz if 0x30000000 <= (v & 0x7fffffff) <= 0x52000000)
    return 'f' if nz and fl * 2 >= len(nz) else 'i'


items, tables = [], {}
for cat, lo, hi, base, stride, known in CATS:
    n = hi - lo + 1
    width, vals = {}, {}
    for a, (sz, v) in est.items():
        if base <= a < base + n * stride and v is not None:
            o = (a - base) % stride
            width[o] = max(width.get(o, 0), sz)
            vals.setdefault(o, []).append(v)
    labels = dict(COMMON) if cat not in ('cargo', 'missile') else {}
    labels.update(known)
    cols = []
    for o in sorted(width):
        if o in labels:
            cols.append((o, labels[o][0], labels[o][1]))
        else:
            cols.append((o, 'o%02x' % o, kind_of(width[o], vals[o])))
    rows = []
    for i in range(n):
        iid, a = lo + i, base + i * stride
        r = dict(id=iid, name=estr.get(INAME + iid * 0x32, ''))
        for o, col, k in cols:
            r[col] = get(est, a + o, k)
        rows.append(r)
    for i in range(n):
        iid = lo + i
        nm = estr.get(INAME + iid * 0x32, '')
        if nm or cat != 'cargo':
            items.append(dict(id=iid, category=cat, name=nm,
                              description=estr.get(IDESC + iid * 0x1c2, '').replace('\n', ' ')))
    rows = [r for r in rows if r['name'] or any(r[c] not in ('', 0) for _, c, _ in cols)]
    tables[cat] = rows
    if cat not in ('missile', 'engine'):          # those two have their own labelled CSVs
        with open(os.path.join(OUT, cat + 's.csv' if cat != 'cargo' else 'cargo.csv'), 'w', newline='') as f:
            w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)

# ---------------- guns ----------------
# Each gun is a heap object (new 0xbd4, ctor 0xa60b90); pointers at 0x14e8474 + g*4.
# init_item_tables writes it via `mov reg, ds:ptr ; mov [reg+off], val`.
GPTR = 0x14e8474
GUN_FIELDS = {0x08: ('b08', 'b'), 0x09: ('b09', 'b'), 0x42: ('rank', 'b'),
              0x50: ('damage', 'f'), 0x54: ('f54', 'f'), 0x58: ('lifetime_s', 'f'),
              0x5c: ('speed', 'f'), 0x60: ('refire_s', 'f'), 0x64: ('ammo', 'i'),
              0x68: ('energy_per_shot', 'f'), 0x6c: ('sound', 'i'), 0x70: ('f70', 'f'),
              0xd4: ('id4', 'i'), 0xd8: ('fd8', 'f'), 0xdc: ('idc', 'i'),
              0xe0: ('class', 'i'), 0xe8: ('mass', 'i')}
gregs, gst, gstr, regs, pushes = {}, {}, {}, {}, []
for a, op, args in disasm(0x414460, 0x424e70):
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),0x([0-9a-f]+)$', args)
    if op == 'mov' and m:
        regs[m.group(1)] = int(m.group(2), 16); gregs.pop(m.group(1), None); continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),\1$', args)
    if op == 'xor' and m:
        regs[m.group(1)] = 0; gregs.pop(m.group(1), None); continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),(?:DWORD PTR )?ds:0x([0-9a-f]+)$', args)
    if op == 'mov' and m:
        p = int(m.group(2), 16)
        if GPTR <= p < GPTR + 0x400 and (p - GPTR) % 4 == 0:
            gregs[m.group(1)] = ((p - GPTR) // 4, 0)
        else:
            gregs.pop(m.group(1), None)
        continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),0x([0-9a-f]+)$', args)
    if op == 'add' and m and m.group(1) in gregs:
        g, o = gregs[m.group(1)]; gregs[m.group(1)] = (g, o + int(m.group(2), 16)); continue
    m = re.match(r'(DWORD|WORD|BYTE) PTR \[(e[a-d]x|e[sd]i|ebp)(?:\+0x([0-9a-f]+))?\],(\S+)$', args)
    if op == 'mov' and m and m.group(2) in gregs:
        g, o0 = gregs[m.group(2)]
        o = o0 + (int(m.group(3), 16) if m.group(3) else 0)
        v = m.group(4)
        val = int(v, 16) if v.startswith('0x') else regs.get(REG8.get(v, v))
        if val is not None:
            gst[(g, o)] = val
        continue
    if op == 'push':
        pushes.append(args); continue
    if op == 'call':
        if args == '%#x' % SPRINTF and len(pushes) >= 2 and pushes[-1] in gregs and pushes[-2].startswith('0x'):
            g, o = gregs[pushes[-1]]
            try:
                gstr[(g, o)] = cstr(int(pushes[-2], 16))
            except (ValueError, IndexError):
                pass
        pushes = []
        for r in ('eax', 'ecx', 'edx'):     # caller-saved
            gregs.pop(r, None); regs.pop(r, None)
        continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),', args)
    if m and op not in ('cmp', 'test', 'push'):
        gregs.pop(m.group(1), None); regs.pop(m.group(1), None)


def gval(g, o, k):
    v = gst.get((g, o))
    if v is None:
        return ''
    return get({0: (4, v)}, 0, k)


guns = []
for g in sorted({g for g, _ in list(gst) + list(gstr)}):
    r = dict(gun=g, name=gstr.get((g, 0x10), ''))
    for o, (col, k) in GUN_FIELDS.items():
        r[col] = gval(g, o, k)
    r['range'] = (round(r['speed'] * r['lifetime_s']) if r['class'] in (0, '') and r['speed'] != ''
                  and r['lifetime_s'] != '' else r['speed'])
    r['energy_per_s'] = (round(r['energy_per_shot'] / r['refire_s']) if r['refire_s'] else '')
    r['dps'] = (round(r['damage'] / r['refire_s']) if r['refire_s'] and r['damage'] != '' else '')
    r['files'] = ' '.join(gstr.get((g, o), '') for o in (0x78, 0x98, 0xb8)).strip()
    r['description'] = gstr.get((g, 0xec), '').replace('\n', ' ')
    guns.append(r)
if guns:
    with open(os.path.join(OUT, 'guns.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, guns[0].keys()); w.writeheader(); w.writerows(guns)
for r in guns:
    items.append(dict(id='g%d' % r['gun'], category='gun', name=r['name'], description=r['description']))
with open(os.path.join(OUT, 'items.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, ['id', 'category', 'name', 'description']); w.writeheader(); w.writerows(items)

# ---------------- AI (bot) types ----------------
# 0xbe7f7c + type*0x40, filled by 0xa07240 (absolute stores). Read by the bot AI 0x4338c0.
AI = 0xbe7f7c
ast, _ = scan(0xa07240, 0xa08440, r'ds:0x([0-9a-f]+)')
ai = []
for t in range(300):
    a = AI + t * 0x40
    if not any((a + o) in ast for o in range(0, 0x40, 2)):
        continue
    w = [get(ast, a + 0x18 + 4 * k, 'b') for k in range(8)]
    ai.append(dict(type=t, thrust=get(ast, a, 'f'), mass=get(ast, a + 4, 'f'),
                   hull=get(ast, a + 8, 'f'), shield_max=get(ast, a + 0xc, 'f'),
                   shield_regen=get(ast, a + 0x10, 'f'), handoff_range=get(ast, a + 0x14, 'f'),
                   weapons=' '.join('' if x == '' else ('-' if x == 0xfe else str(x)) for x in w).strip(),
                   skill=get(ast, a + 0x3c, 'i')))
with open(os.path.join(OUT, 'ai_types.csv'), 'w', newline='') as f:
    wr = csv.DictWriter(f, ai[0].keys()); wr.writeheader(); wr.writerows(ai)

# ---------------- ship types ----------------
B, N = 0x418934, 0x1af                       # this-relative; absolute 0xff7eac
sst, sstr = scan(0xa08440, 0xa08440 + 66363, r'\[esi\+0x([0-9a-f]+)\]')
ships = []
for t in range(N):
    r = B + t * 0x1e0
    name = sstr.get(r + 4)
    if name is None and (r + 0x30) not in sst:
        continue
    drag, eng = get(sst, r + 0x38, 'f'), get(sst, r + 0x148, 'b')
    ships.append(dict(
        type=t, name=name or '', cls=sstr.get(r + 0x18, ''),
        mass=get(sst, r + 0x30, 'f'), f34=get(sst, r + 0x34, 'f'), drag=drag,
        pitch=get(sst, r + 0x40, 'f'), roll=get(sst, r + 0x44, 'f'), yaw=get(sst, r + 0x48, 'f'),
        cargo=get(sst, r + 0x140, 'h'), f142=get(sst, r + 0x142, 'h'),
        size=get(sst, r + 0x144, 'f'), engines=eng, armour=get(sst, r + 0x150, 'i'),
        ext_right=get(sst, r + 0x158, 'f'), ext_up=get(sst, r + 0x15c, 'f'),
        ext_fwd=get(sst, r + 0x160, 'f'),
        # v_max = sqrt(engines*thrust/drag); this is the factor that multiplies sqrt(thrust per engine)
        vmax_per_sqrt_thrust=round(math.sqrt(eng / drag), 5) if drag and eng else ''))
with open(os.path.join(OUT, 'ship_types.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, ships[0].keys()); w.writeheader(); w.writerows(ships)
# ---------------- locations (sectors/stations) ----------------
# 0x4a8d10..0x4ad0d2 fills a 100-byte record per location id at 0xfd9220 + id*100.
# The name at +0 is an inlined strcpy: `mov reg, ds:<string>` then `mov ds:<rec>, reg`,
# so the first load names the source string. Numbers are imm stores or come through registers.
#   +0x28 flag   +0x2c/0x30/0x34 galaxy-map x,y,z (f32)   +0x3c owning faction (core stations)
#   +0x40 faction/region (compared with own faction 0xbe5b0e)   +0x44 301/302 (unknown)
#   +0x4c.. nav-field data is zero here; it is set at runtime.
LB, LS = 0xfd9220, 100
def memval(va, sz):
    o = va - 0x400000
    return int.from_bytes(img[o:o + sz], 'little') if 0 <= o < len(img) - sz else None
lrec, lname, regs, rsrc = {}, {}, {}, {}
SZ = {'DWORD': 4, 'WORD': 2, 'BYTE': 1}
for a, op, args in disasm(0x4a8d10, 0x4ad0d2):
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),0x([0-9a-f]+)$', args)
    if op == 'mov' and m: regs[m.group(1)] = int(m.group(2), 16); rsrc.pop(m.group(1), None); continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),(?:DWORD PTR )?ds:0x([0-9a-f]+)$', args)
    if op == 'mov' and m:
        r, src = m.group(1), int(m.group(2), 16); regs[r] = memval(src, 4); rsrc[r] = src; continue
    m = re.match(r'([a-d][xl]|[sd]i),(?:\w+ PTR )?ds:0x([0-9a-f]+)$', args)
    if op == 'mov' and m:                   # short names: 16/8-bit loads of the string head
        r = REG8.get(m.group(1), m.group(1)); regs.pop(r, None); rsrc[m.group(1)] = int(m.group(2), 16); continue
    if op == 'rep' and args.startswith('movs') and regs.get('edi') is not None:
        d = regs['edi'] - LB                # long names: rep movs from esi to edi
        if 0 <= d < LS * 1100 and d % LS == 0 and regs.get('esi'):
            lname.setdefault(d // LS, cstr(regs['esi']))
        continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),\1$', args)
    if op == 'xor' and m: regs[m.group(1)] = 0; rsrc.pop(m.group(1), None); continue
    m = re.match(r'(?:(DWORD|WORD|BYTE) PTR )?ds:0x([0-9a-f]+),(\S+)$', args)
    if op == 'mov' and m:
        d, v = int(m.group(2), 16) - LB, m.group(3)
        if not 0 <= d < LS * 1100: continue
        loc, off = divmod(d, LS)
        if off == 0 and v in rsrc:
            s = cstr(rsrc[v])
            if s.isprintable(): lname.setdefault(loc, s)
        sz = SZ.get(m.group(1), 4)
        val = int(v, 16) if v.startswith('0x') else regs.get(REG8.get(v, v))
        if off == 0 and v not in rsrc and val:  # <=3-char names are stored as one dword ("GBS", "T&P")
            b = val.to_bytes(4, 'little').split(b'\0')[0]
            if b and all(32 <= c < 127 for c in b): lname.setdefault(loc, b.decode())
        if val is not None and off >= 0x28: lrec.setdefault(loc, {})[off] = (sz, val & ((1 << 8 * sz) - 1))
        continue
    if op == 'call':
        for r in ('eax', 'ecx', 'edx'): regs.pop(r, None); rsrc.pop(r, None)
        continue
    m = re.match(r'(e[a-d]x|e[sd]i|ebp),', args)
    if m and op not in ('cmp', 'test', 'push'): regs.pop(m.group(1), None); rsrc.pop(m.group(1), None)
def lget(loc, off, k):
    sz, v = lrec.get(loc, {}).get(off, (4, 0))
    return round(struct.unpack('<f', struct.pack('<I', v))[0], 2) if k == 'f' else v
locations = [dict(loc_id=l, name=lname.get(l, ''), flag28=lget(l, 0x28, 'i'),
                  x=lget(l, 0x2c, 'f'), y=lget(l, 0x30, 'f'), z=lget(l, 0x34, 'f'),
                  owner_faction=lget(l, 0x3c, 'i'), faction=lget(l, 0x40, 'i'), f44=lget(l, 0x44, 'i'))
             for l in sorted(set(lname) | set(lrec)) if l >= 100]
with open(os.path.join(OUT, 'locations.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, locations[0].keys()); w.writeheader(); w.writerows(locations)

print('%d engines, %d missiles, %d guns, %d AI types, %d ship types, %d locations; %s' % (len(engines), len(missiles), len(guns), len(ai), len(ships), len(locations),
      ', '.join('%s %d' % (k, len(v)) for k, v in tables.items())))
