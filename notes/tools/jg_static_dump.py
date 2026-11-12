#!/usr/bin/env python3
"""Dump every hardcoded static world object in Jumpgate.exe (2.0127 build) to CSV.

usage: jg_static_dump.py [Jumpgate.exe] [out.csv]

What it recovers (all static analysis of the exe, no game files or network):
  * ~35,000 objects (asteroids, gates, beacons, stations, junk, ...) built by
    ~30 "region init" functions, each object = 44 bytes:
        +0 u8 nav flag (0 = nav object: gate/beacon/station, 1 = scenery)
        +2 u16 index (per-location object id; for nav objects 1-4 = gate
               number, 5 = beacon, 6 = station)
        +4 u16 type = index into the model table (0x14ff690)
        +8/+c/+10  f32 position;  +14..+1c forward vector;  +20..+28 up vector
  * location of each object from its pointer slot: 0xbef100 + loc*0xff0
  * location names from 0x4a8d10 (table 0xfd9220 + loc*100)
  * gate links from 0x4a7460 (table 0x146d7a0 + (gate-1)*0x4e20 + loc*0x14:
        +0 destination location, +4 arrival gate number)
  * model (mesh) names from the model loader (pointer array 0x14ff690)
  * model_radius: NOT in the exe's object record (there is no radius field);
    computed here as the max vertex distance from origin of the model's
    full-detail .x mesh, read from the exe's directory (blank if not found).
    Objects are not scaled per instance, so this is the instance radius.

Requires an objdump that understands PE/i386 (i686-w64-mingw32-objdump or a
binutils objdump with pei-i386 support). Addresses are specific to this build;
the SHA-256 is checked first.

Asteroid FLAVOUR (common/ice/...) per kind is not yet confirmed from code;
the five mesh kinds ast1..ast5 are reported as asteroid_kind 1-5. Fill in
FLAVOR below once each kind is identified in game.
"""
import hashlib, re, shutil, struct, subprocess, sys, csv, collections, math, os

EXPECTED_SHA256 = "fef6e50fc4608c1514242932823fb8cbeeda9ac6217d9f819fd802d94ca7bdf8"
NEW_FN = 0xaa8600                       # operator new
DISPATCH = (0x4ba465, 0x4ba66b)         # location-id range dispatcher
OBJ_BASE, OBJ_STRIDE, OBJ_SLOTS = 0xbef100, 0xff0, 1000
NAME_FN, NAME_BASE, NAME_STRIDE = (0x4a8d10, 0x4ad0d2), 0xfd9220, 100
GATE_FN, GATE_BASE, GATE_STRIDE, GATE_REC = 0x4a7460, 0x146d7a0, 0x4e20, 0x14
MODEL_BASE = 0x14ff690

FLAVOR = {1: None, 2: None, 3: None, 4: None, 5: None}   # e.g. {1: "Common", ...}
SIZE = {0: ("large", 48), 1: ("medium", 16), 2: ("small", 8)}   # a/b/c, mining divisor @0x43ce2e

R32 = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
SUB = {'al': ('eax', 0xff), 'bl': ('ebx', 0xff), 'cl': ('ecx', 0xff), 'dl': ('edx', 0xff),
       'ax': ('eax', 0xffff), 'bx': ('ebx', 0xffff), 'cx': ('ecx', 0xffff), 'dx': ('edx', 0xffff),
       'si': ('esi', 0xffff), 'di': ('edi', 0xffff), 'bp': ('ebp', 0xffff)}
INS = re.compile(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)')


def f32(v): return struct.unpack('<f', struct.pack('<I', v & 0xffffffff))[0]


class PE:
    def __init__(self, data):
        self.d = data
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        nsec = struct.unpack_from('<H', data, pe + 6)[0]
        opt = struct.unpack_from('<H', data, pe + 20)[0]
        self.base = struct.unpack_from('<I', data, pe + 24 + 28)[0]
        self.secs = []
        for i in range(nsec):
            o = pe + 24 + opt + 40 * i
            vsz, va, rsz, raw = struct.unpack_from('<IIII', data, o + 8)
            self.secs.append((self.base + va, max(vsz, rsz), raw, rsz))

    def cstr(self, va):
        for sva, sz, raw, rsz in self.secs:
            if sva <= va < sva + rsz:
                o = raw + va - sva
                return self.d[o:self.d.index(b'\0', o)].decode('latin1')
        return None


def disassemble(exe):
    od = next((t for t in ('i686-w64-mingw32-objdump', 'objdump') if shutil.which(t)), None)
    if not od: sys.exit("need objdump (i686-w64-mingw32-objdump or binutils objdump)")
    out = subprocess.run([od, '-d', '-M', 'intel', '--no-show-raw-insn', exe],
                         capture_output=True, text=True, check=True).stdout
    lines, idx = [], {}
    for l in out.splitlines():
        m = INS.match(l)
        if m:
            idx[int(m.group(1), 16)] = len(lines)
            lines.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return lines, idx


def body(lines, idx, start, end=None):
    for ins in lines[idx[start]:]:
        yield ins
        if end is None and ins[1].startswith('ret'): return
        if end is not None and ins[0] >= end: return


def region_functions(lines, idx):
    return [int(arg, 16) for a, op, arg in body(lines, idx, *DISPATCH)
            if op == 'call' and arg.startswith('0x')]


def extract_objects(lines, idx, fn):
    reg, ptr, slots, pend = {}, {}, {}, False
    for a, op, arg in body(lines, idx, fn):
        if op == 'call':
            pend = arg == hex(NEW_FN); reg.pop('eax', None); continue
        p = arg.split(',', 1)
        if op == 'xor' and len(p) == 2 and p[0] == p[1] and p[0] in R32:
            reg[p[0]] = 0; ptr.pop(p[0], None); continue
        if op != 'mov' or len(p) != 2:
            if p and p[0] in R32: reg.pop(p[0], None); ptr.pop(p[0], None)
            continue
        dst, src = p
        if pend and src == 'eax' and dst.startswith('ds:'):
            s = int(dst[3:], 16); slots[s] = {}; ptr['eax'] = s; pend = False; continue
        if dst in R32:
            m = re.match(r'(?:DWORD PTR )?ds:(0x[0-9a-f]+)$', src)
            if m and int(m.group(1), 16) in slots:
                ptr[dst] = int(m.group(1), 16); reg.pop(dst, None)
            elif src.startswith('0x'):
                reg[dst] = int(src, 16); ptr.pop(dst, None)
            elif src in R32:
                for t in (reg, ptr):
                    if src in t: t[dst] = t[src]
                    else: t.pop(dst, None)
            else:
                reg.pop(dst, None); ptr.pop(dst, None)
            continue
        m = re.match(r'(?:BYTE|WORD|DWORD) PTR \[(e[a-d]x|e[sd]i|ebp)(?:\+0x([0-9a-f]+))?\]$', dst)
        if m and m.group(1) in ptr:
            off = int(m.group(2) or '0', 16)
            if src.startswith('0x'): v = int(src, 16)
            elif src in R32: v = reg.get(src)
            elif src in SUB:
                r, mask = SUB[src]; v = reg.get(r); v = None if v is None else v & mask
            else: v = None
            slots[ptr[m.group(1)]][off] = v
    return slots


def location_names(lines, idx, pe):
    reg, names = {}, {}
    for a, op, arg in body(lines, idx, *NAME_FN):
        p = arg.split(',', 1)
        if op != 'mov' or len(p) != 2: continue
        dst, src = p
        m = re.match(r'(\w+),(?:\w+ PTR )?ds:(0x[0-9a-f]+)$', arg)
        if m: reg[m.group(1)] = int(m.group(2), 16); continue
        m = re.match(r'(?:\w+ PTR )?ds:(0x[0-9a-f]+)$', dst)
        if m and src in reg:
            d = int(m.group(1), 16) - NAME_BASE
            if d >= 0 and d % NAME_STRIDE == 0:
                s = pe.cstr(reg[src])
                if s and s.isprintable(): names.setdefault(d // NAME_STRIDE, s)
    return names


def gate_links(lines, idx):
    reg, links = {}, collections.defaultdict(dict)
    for a, op, arg in body(lines, idx, GATE_FN):
        p = arg.split(',', 1)
        if op == 'xor' and len(p) == 2 and p[0] == p[1]: reg[p[0]] = 0; continue
        if op in ('inc', 'dec', 'add', 'sub', 'lea') and p[0] in R32: reg.pop(p[0], None); continue
        if op != 'mov' or len(p) != 2: continue
        dst, src = p
        if dst in R32:
            reg[dst] = int(src, 16) if src.startswith('0x') else reg.get(src); continue
        m = re.match(r'(?:DWORD PTR )?ds:(0x[0-9a-f]+)$', dst)
        if m:
            o = int(m.group(1), 16) - GATE_BASE
            if 0 <= o < 4 * GATE_STRIDE:
                v = int(src, 16) if src.startswith('0x') else reg.get(src)
                links[((o % GATE_STRIDE) // GATE_REC, o // GATE_STRIDE + 1)][(o % GATE_STRIDE) % GATE_REC] = v
    return links


def model_names(lines, idx, pe):
    cur, models = None, {}
    for a, op, arg in lines:            # model loads are spread across .text
        m = re.match(r'(?:DWORD PTR )?ds:(0x14f[0-9a-f]{4}),eax$', arg)
        if op == 'mov' and m: cur = int(m.group(1), 16); continue
        if op == 'push' and cur is not None and re.match(r'0x[0-9a-f]+$', arg):
            s = pe.cstr(int(arg, 16))
            if s and s.lower().endswith('.x'):
                t = (cur - MODEL_BASE) // 4
                if cur >= MODEL_BASE and (cur - MODEL_BASE) % 4 == 0: models.setdefault(t, s)
    return models


# ---- mesh bounding radius (game data dir; optional) ----
def _xinflate(d):
    """'bzip' = MSZIP-compressed binary .x: u32 total, then [u16 raw][u16 csize]['CK' deflate] blocks."""
    import zlib
    p, out = 20, b''
    while p + 4 <= len(d):
        _, cs = struct.unpack_from('<HH', d, p); p += 4
        z = zlib.decompressobj(-15, zdict=out[-32768:]) if out else zlib.decompressobj(-15)
        out += z.decompress(d[p + 2:p + cs]); p += cs
    return d[:8] + b'bin ' + d[12:16] + out


def _xtokens(d):
    if d[8:12] == b'bzip': d = _xinflate(d)
    assert d[:4]==b'xof ' and d[8:12]==b'bin '
    fsz = 8 if d[12:16]==b'0064' else 4
    p=16
    while p+2<=len(d):
        t,=struct.unpack_from('<H',d,p); p+=2
        if t==1: n,=struct.unpack_from('<I',d,p); p+=4; yield ('name',d[p:p+n].decode('latin1')); p+=n
        elif t==2: n,=struct.unpack_from('<I',d,p); p+=4; yield ('str',d[p:p+n]); p+=n+2
        elif t==3: yield ('int',struct.unpack_from('<I',d,p)[0]); p+=4
        elif t==5: p+=16; yield ('guid',None)
        elif t==6: n,=struct.unpack_from('<I',d,p); p+=4; yield ('ilist',struct.unpack_from('<%dI'%n,d,p)); p+=4*n
        elif t==7: n,=struct.unpack_from('<I',d,p); p+=4; yield ('flist',struct.unpack_from('<%d%s'%(n,'d' if fsz==8 else 'f'),d,p)); p+=fsz*n
        else: yield ('tok',t)
def mesh_radius(path):
    """Max vertex distance from the model origin (binary DirectX .x, frame matrices applied)."""
    d=open(path,'rb').read()
    stack=[]; pending=[]; mats=[]; best=0.0; cur=None; mesh_state=None
    M=None
    for k,v in _xtokens(d):
        if k=='name': pending.append(v); continue
        if k=='tok' and v==10:  # {
            stack.append(pending[0] if pending else '?'); pending=[]
            if stack[-1]=='Mesh': mesh_state='n'
            continue
        if k=='tok' and v==11:
            s=stack.pop()
            if s=='Frame': mats.pop() if mats and mats[-1][0]==len(stack) else None
            continue
        pending=[] if k!='tok' else pending
        top=stack[-1] if stack else None
        if top=='FrameTransformMatrix' and k=='flist':
            mats.append((len(stack)-2, v[:16]))
        if top=='Mesh' and mesh_state=='n' and k=='ilist':
            nv=v[0]; mesh_state='v'; continue
        if top=='Mesh' and mesh_state=='v' and k=='flist':
            vs=v[:nv*3]; mesh_state=None
            for i in range(0,len(vs),3):
                x,y,z=vs[i:i+3]
                for _,m in reversed(mats):  # row-vector D3D convention
                    x,y,z=(x*m[0]+y*m[4]+z*m[8]+m[12], x*m[1]+y*m[5]+z*m[9]+m[13], x*m[2]+y*m[6]+z*m[10]+m[14])
                best=max(best,math.sqrt(x*x+y*y+z*z))
    return best


def model_radii(models, gamedir):
    files = {f.lower(): os.path.join(gamedir, f) for f in os.listdir(gamedir)}
    out = {}
    for t, name in models.items():
        f = files.get(os.path.basename(name.replace("\\", "/")).lower())
        if f:
            try: out[t] = round(mesh_radius(f), 2)
            except Exception: pass
    return out


def classify(t, model, nav, idx_):
    m = (model or '').lower()
    if 15 <= t <= 29:
        k, s = divmod(t - 15, 3)
        return 'asteroid', k + 1, SIZE[s][0], SIZE[s][1]
    if t in (317, 318, 319):      # huge minable rocks; textured ast1/ast1/ast3
        return 'asteroid', {317: 1, 318: 1, 319: 3}[t], 'huge', 128
    if nav and t == 11: return 'jumpgate', None, None, None
    if nav and t == 414: return 'jumpgate (x_ai_gate model)', None, None, None
    if t == 2: return 'beacon', None, None, None
    if 'station' in m: return 'station', None, None, None
    if m.startswith('junk_'): return 'junk/debris', None, None, None
    if re.match(r'(aa|bb|cc)\d\d\.x', m): return 'ship model', None, None, None
    if t == 304: return 'nav marker (flat.x, unlinked)', None, None, None
    if t == 339: return 'invisible marker (no model)', None, None, None
    return ('nav object' if nav else 'structure'), None, None, None


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else 'Jumpgate.exe'
    out = sys.argv[2] if len(sys.argv) > 2 else 'static_objects_all.csv'
    data = open(exe, 'rb').read()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA256:
        sys.exit(f"SHA-256 mismatch ({sha}); addresses are for build {EXPECTED_SHA256[:12]}...")
    pe = PE(data)
    print("disassembling (this takes a minute)...", file=sys.stderr)
    lines, idx = disassemble(exe)
    names = location_names(lines, idx, pe)
    links = gate_links(lines, idx)
    models = model_names(lines, idx, pe)
    radii = model_radii(models, os.path.dirname(os.path.abspath(exe)))
    rows = []
    for fn in region_functions(lines, idx):
        for slot, f in extract_objects(lines, idx, fn).items():
            if not (OBJ_BASE <= slot < OBJ_BASE + OBJ_STRIDE * 1006): continue
            loc = (slot - OBJ_BASE) // OBJ_STRIDE
            g = lambda o: f.get(o)
            fl = lambda o: None if g(o) is None else round(f32(g(o)), 3)
            nav, i, t = g(0) == 0, g(2), g(4)
            cat, kind, size, div = classify(t, models.get(t), nav, i)
            link = links.get((loc, i)) if nav and i in (1, 2, 3, 4) else None
            dest = link.get(0) if link else None
            rows.append({
                'loc_id': loc, 'loc_name': names.get(loc, ''), 'region_fn': hex(fn),
                'slot': (slot - OBJ_BASE) % OBJ_STRIDE // 4, 'object_id': i,
                'nav': int(nav), 'type': t, 'model': models.get(t, ''), 'category': cat,
                'asteroid_kind': kind or '', 'asteroid_flavor': (FLAVOR.get(kind) or '') if kind else '',
                'asteroid_size': size or '', 'mining_divisor': div or '',
                'model_radius': radii.get(t, ''),
                'x': fl(8), 'y': fl(12), 'z': fl(16),
                'fwd_x': fl(20), 'fwd_y': fl(24), 'fwd_z': fl(28),
                'up_x': fl(32), 'up_y': fl(36), 'up_z': fl(40),
                'gate_number': i if link is not None or cat.startswith('jumpgate') else '',
                'gate_dest_loc': dest if dest is not None else '',
                'gate_dest_name': names.get(dest, '') if dest is not None else '',
                'gate_dest_gate': link.get(4, '') if link else '',
            })
    rows.sort(key=lambda r: (r['loc_id'], r['slot']))
    with open(out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    c = collections.Counter(r['category'] for r in rows)
    print(f"wrote {len(rows)} objects across {len({r['loc_id'] for r in rows})} locations to {out}",
          file=sys.stderr)
    for k, v in c.most_common(): print(f"  {v:6d}  {k}", file=sys.stderr)


if __name__ == '__main__':
    main()
