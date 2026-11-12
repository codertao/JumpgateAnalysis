#!/usr/bin/env python3
"""Function inventory / naming-coverage tracker for Jumpgate.exe (2.0127).

usage: jg_functions.py [Jumpgate.exe] [notes/function_names.csv] [notes/functions.csv]

Enumerates functions statically (direct call targets + pointer-table references
that land on padding-aligned starts), merges the hand-curated names in
function_names.csv, auto-names the ~30 static-world region-init functions and
the game-message dispatcher cases, and writes functions.csv plus a coverage
summary on stderr.

To name a function: add a row to function_names.csv and re-run. Never edit
functions.csv by hand -- it is regenerated.
"""
import csv, os, re, struct, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jg_static_dump as jsd  # disassemble(), region_functions(), PE, SHA check

DISPATCH_IDX, DISPATCH_TBL, DISPATCH_BASE, DISPATCH_N = 0x9da24c, 0x9da0f0, 3, 0xc1
DISPATCH_DEFAULT = 0x9d9f3e
TEXT = (0x401000, 0xac2000)
# known S->C message names for dispatcher cases (see message-types.md)
MSG_NAMES = {0x03: 'damage', 0x04: 'chat', 0x06: 'char_record', 0x08: 'redirect',
             0x0a: 'listing', 0x0b: 'listing', 0x0d: 'listing', 0x13: 'sector_table',
             0x15: 'force_location', 0x33: 'smallloc_relay', 0x34: 'miniloc_relay',
             0x42: 'heartbeat_ack', 0x45: 'rank', 0x50: 'listing', 0x51: 'listing',
             0x52: 'listing', 0x53: 'listing', 0x54: 'listing', 0x55: 'listing',
             0x56: 'listing', 0x62: 'contacts_table', 0x65: 'channel_ack',
             0x71: 'bot_spawn_assign', 0x73: 'slot_table', 0x78: 'object_list',
             0x81: 'motd', 0x87: 'nearfield_transforms', 0x8c: 'status', 0x8f: 'welcome',
             0xa7: 'sector_station', 0xb3: 'ownship_echo', 0xc2: 'table_c2'}


def enumerate_functions(lines, data, pe):
    calls, callers, pad_starts, prev = set(), collections.Counter(), set(), None
    for a, op, arg in lines:
        if op == 'call':
            m = re.match(r'0x([0-9a-f]+)$', arg)
            if m:
                t = int(m.group(1), 16)
                if TEXT[0] <= t < TEXT[1]:
                    calls.add(t); callers[t] += 1
        if prev in ('int3', 'ret', 'nop') and op not in ('int3', 'nop', 'ret'):
            pad_starts.add(a)
        prev = op
    ptr = set()
    for sva, sz, raw_off, raw_sz in pe.secs:
        if 0xac2000 <= sva < 0x1103000:          # .rdata + .data (file-backed part)
            for o in range(raw_off, raw_off + raw_sz - 3, 4):
                v = struct.unpack_from('<I', data, o)[0]
                if v in pad_starts: ptr.add(v)
    return calls, ptr, callers


def read_imports(data):
    """IAT VA -> (dll, symbol)."""
    pe = struct.unpack_from('<I', data, 0x3c)[0]; opt = pe + 24
    base = struct.unpack_from('<I', data, opt + 28)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]; optsz = struct.unpack_from('<H', data, pe + 20)[0]
    secs = [struct.unpack_from('<IIII', data, pe + 24 + optsz + 40 * i + 8) for i in range(nsec)]
    def off(rva):
        for vs, va, rs, ro in secs:
            if va <= rva < va + max(vs, rs): return ro + rva - va
    iat, o = {}, off(struct.unpack_from('<I', data, opt + 96 + 8)[0])
    while True:
        ilt, _, _, name, ft = struct.unpack_from('<IIIII', data, o); o += 20
        if not name: break
        dll = data[off(name):data.index(b'\0', off(name))].decode()
        t, i = ilt or ft, 0
        while True:
            e = struct.unpack_from('<I', data, off(t) + 4 * i)[0]
            if not e: break
            nm = f'ord{e & 0xffff}' if e & 0x80000000 else data[off(e) + 2:data.index(b'\0', off(e) + 2)].decode()
            iat[base + ft + 4 * i] = (dll, nm); i += 1
    return iat


STR_PATTERNS = [   # (regex on a string the function references, name template, confidence)
    (re.compile(r'^([A-Za-z_]\w+)\.cpp: ?([A-Za-z_]\w+)'), r'\2', 'med'),
    (re.compile(r'^(?:FAIL: |Error in )([A-Za-z_]\w{3,})'), r'\1', 'med'),
    (re.compile(r'^([A-Z]?[a-z]+[A-Z][A-Za-z0-9_]*): '), r'\1', 'low'),   # CamelCase only
    (re.compile(r'^(?:Failed to send|Error Sending|Error sending) (?:an? )?([A-Za-z0-9 _]+?) ?[Pp]acket'),
     r'send_\1', 'med'),
]


# Code bands (VA ranges) -> area, for otherwise-unlabelled functions.
BANDS = [(0x401000, 0xa62000, 'game'), (0xa62000, 0xa64000, 'net-wrapper'),
         (0xa64000, 0xa7e000, 'lib-raknet'), (0xa7e000, 0xaa8600, 'lib-d3dx8'),
         (0xaa8600, 0xac2000, 'lib-crt')]
band = lambda a: next((n for lo, hi, n in BANDS if lo <= a < hi), '')

# Unique error strings of libraries statically linked inside D3DX8 (libpng 1.0.5, zlib 1.1.3).
LIB_STRINGS = {
    'Incompatible libpng version in application and library': 'png_create_read_struct',
    'Not a PNG file': 'png_read_info', 'PNG file corrupted by ASCII conversion': 'png_read_info',
    'Missing IHDR before IDAT': 'png_read_info', 'Missing PLTE before IDAT': 'png_read_info',
    'Invalid attempt to read row data': 'png_read_row', 'Not enough image data': 'png_read_row',
    'Decompression error': 'png_read_row', 'Extra compressed data': 'png_read_finish_row',
    'NULL row buffer': 'png_do_read_transformations',
    'png_do_dither returned rowbytes=0': 'png_do_read_transformations',
    'Call to NULL read function': 'png_read_data',
    'Invalid PLTE after IDAT': 'png_handle_PLTE', 'Duplicate PLTE chunk': 'png_handle_PLTE',
    'Invalid palette chunk': 'png_handle_PLTE',
    'Truncating incorrect tRNS chunk length': 'png_handle_tRNS',
    'No image in file': 'png_handle_IEND', 'Incorrect IEND chunk length': 'png_handle_IEND',
    'Unknown zlib error': 'png_zlib_error_handler', 'zlib memory error': 'png_zlib_error_handler',
    'unknown compression method': 'inflate', 'invalid window size': 'inflate',
    'incorrect header check': 'inflate', 'incorrect data check': 'inflate', 'need dictionary': 'inflate',
    'invalid block type': 'inflate_blocks', 'invalid stored block lengths': 'inflate_blocks',
    'too many length or distance symbols': 'inflate_blocks', 'invalid bit length repeat': 'inflate_blocks',
    'oversubscribed dynamic bit lengths tree': 'inflate_trees_bits',
    'incomplete dynamic bit lengths tree': 'inflate_trees_bits',
    'oversubscribed literal/length tree': 'inflate_trees_dynamic',
    'invalid literal/length code': 'inflate_codes_or_fast', 'invalid distance code': 'inflate_codes_or_fast',
}


def auto_names(lines, starts, pe, iat):
    """Import-wrapper and debug-string names, keyed by function start."""
    import bisect
    owner = lambda a: starts[bisect.bisect_right(starts, a) - 1] if a >= starts[0] else None
    ninsn, imps, strs = collections.Counter(), collections.defaultdict(set), collections.defaultdict(list)
    for a, op, arg in lines:
        f = owner(a)
        if f is None: continue
        ninsn[f] += 1
        m = re.search(r'ds:0x([0-9a-f]+)\]?$', arg) if op in ('call', 'jmp') else None
        if m and int(m.group(1), 16) in iat: imps[f].add(iat[int(m.group(1), 16)][1])
        m = re.match(r'(?:push|mov)\s.*?(0xa[c-f][0-9a-f]{4}|0xb[01][0-9a-f]{4})$', op + ' ' + arg)
        if m:
            sv = pe.cstr(int(m.group(1), 16))
            if sv and 4 <= len(sv) < 200: strs[f].append(sv)
    out = {}
    for f in starts:
        lib = next((LIB_STRINGS[sv] for sv in strs[f] if sv in LIB_STRINGS), None)
        if lib and band(f) == 'lib-d3dx8':
            out[f] = (lib, 'libstring', 'med', 'libpng 1.0.5 / zlib 1.1.3 error string'); continue
        if len(imps[f]) == 1 and ninsn[f] <= 12:
            out[f] = ('wrap_' + next(iter(imps[f])), 'import', 'high', 'thin import wrapper')
            continue
        for rx, tmpl, conf in STR_PATTERNS:
            hit = next((rx.sub(tmpl, sv[:rx.match(sv).end()]) for sv in strs[f] if rx.match(sv)), None)
            if hit:
                hit = re.sub(r'\W+', '_', hit.strip()).strip('_')
                out[f] = (hit, 'string', conf, 'debug string'); break
    return out, imps


def dispatcher_cases(data, pe):
    off = lambda va: va - 0x401000 + 0x1000     # .text VA -> file offset
    cases = collections.defaultdict(list)
    for i in range(DISPATCH_N):
        b = data[off(DISPATCH_IDX) + i]
        tgt = struct.unpack_from('<I', data, off(DISPATCH_TBL) + 4 * b)[0]
        if tgt != DISPATCH_DEFAULT: cases[tgt].append(i + DISPATCH_BASE)
    return cases


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else 'Jumpgate.exe'
    names_csv = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, '..', 'function_names.csv')
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, '..', 'functions.csv')
    data = open(exe, 'rb').read()
    import hashlib
    if hashlib.sha256(data).hexdigest() != jsd.EXPECTED_SHA256:
        sys.exit('SHA-256 mismatch: addresses are for the 2.0127 build')
    pe = jsd.PE(data)
    print('disassembling...', file=sys.stderr)
    lines, idx = jsd.disassemble(exe)
    calls, ptr, callers = enumerate_functions(lines, data, pe)
    funcs = calls | ptr

    curated = {}
    with open(names_csv) as fh:
        rows = [l for l in fh if l.strip() and not l.lstrip().startswith('#')]
    for r in csv.DictReader(rows):
        curated[int(r['addr'], 16)] = r
    for fn in jsd.region_functions(lines, idx):
        curated.setdefault(fn, {'name': f'region_init_{fn:x}', 'area': 'world-static',
                                'confidence': 'high', 'ref': 'sector_regions.csv'})
    cases = dispatcher_cases(data, pe)

    # optional Ghidra export (addr, name, source, size, thunk, library) -> extra starts + FID names
    gh_path = os.path.join(HERE, '..', 'ghidra', 'ghidra_functions.tsv')
    fid = {}
    if os.path.exists(gh_path):
        for r in csv.DictReader(open(gh_path), delimiter='\t'):
            a = int(r['addr'], 16)
            if not TEXT[0] <= a < TEXT[1]: continue
            funcs.add(a)
            if r['library']:
                multi = 'Multiple' in r['library']
                fid[a] = (r['name'], 'fid-multi' if multi else 'fid', 'low' if multi else 'high', r['library'])
            elif re.match(r'(Unwind|Catch)@', r['name']):
                fid[a] = (r['name'].split('@')[0].lower() + '_funclet', 'compiler', 'high', 'SEH funclet')
            elif r['name'] == 'entry':
                fid[a] = ('entry', 'pe', 'high', 'PE entry point')

    starts = sorted(funcs | set(curated))
    iat = read_imports(data)
    auto, imps = auto_names(lines, starts, pe, iat)
    size = {a: (starts[i + 1] - a) if i + 1 < len(starts) else 0 for i, a in enumerate(starts)}
    rows = []
    for a in starts:
        c = curated.get(a)
        kind = 'call' if a in calls else ('ptr' if a in ptr else ('ghidra' if a in funcs else 'curated'))
        if c:
            src = 'region' if c.get('area') == 'world-static' and a not in () and c.get('ref') == 'sector_regions.csv' else 'curated'
            name, area, conf, ref = c.get('name', ''), c.get('area', ''), c.get('confidence', ''), c.get('ref', '')
        elif a in fid:
            name, src, conf, ref = fid[a]
            area = 'compiler' if src == 'compiler' else ('crt' if src.startswith('fid') else '')
        elif a in auto:
            name, src, conf, ref = auto[a]; area = ''
        else:
            name = area = conf = ref = src = ''
        if not area: area = band(a)
        rows.append({'addr': f'0x{a:x}', 'kind': kind, 'size_est': size[a],
                     'callers': callers.get(a, 0), 'name': name, 'name_source': src,
                     'area': area, 'confidence': conf, 'ref': ref,
                     'imports': ' '.join(sorted(imps.get(a, ())))[:120]})
    for a, types in sorted(cases.items()):
        nm = '/'.join(MSG_NAMES.get(t, '') or f'{t:02x}' for t in types)
        known = any(t in MSG_NAMES for t in types)
        rows.append({'addr': f'0x{a:x}', 'kind': 'dispatch_case', 'size_est': '',
                     'callers': '', 'name': ('on_' + nm) if known else '',
                     'name_source': 'dispatch' if known else '',
                     'area': 'net-msg-handler', 'confidence': 'med' if known else '',
                     'ref': 'S->C type ' + ','.join(f'0x{t:02x}' for t in types), 'imports': ''})
    with open(out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    fn_rows = [r for r in rows if r['kind'] != 'dispatch_case' and r['name_source'] != 'compiler']
    funclets = sum(1 for r in rows if r['name_source'] == 'compiler')
    print(f"(excluding {funclets} compiler-generated SEH funclets from the counts below)", file=sys.stderr)
    named = [r for r in fn_rows if r['name']]
    text_bytes = TEXT[1] - TEXT[0]
    nb = sum(r['size_est'] for r in named)
    region_b = sum(r['size_est'] for r in named if r['area'] == 'world-static')
    case_rows = [r for r in rows if r['kind'] == 'dispatch_case']
    print(f"wrote {out}", file=sys.stderr)
    print(f"functions: {len(fn_rows)} (call targets {len(calls)}, pointer-only {len(ptr - calls)})", file=sys.stderr)
    print(f"named:     {len(named)} ({100*len(named)/len(fn_rows):.1f}%)", file=sys.stderr)
    print(f"  by bytes: {100*nb/text_bytes:.1f}% of .text "
          f"({100*(nb-region_b)/(text_bytes-region_b):.1f}% excluding region-init map code)", file=sys.stderr)
    for k, v in collections.Counter(r['name_source'] for r in named).most_common():
        print(f"    {v:5d}  source={k}", file=sys.stderr)
    print("  by band (named/total):", file=sys.stderr)
    for lo, hi, nm in BANDS:
        tot = [r for r in fn_rows if lo <= int(r['addr'], 16) < hi]
        print(f"    {nm:12s} {sum(1 for r in tot if r['name']):5d} / {len(tot):5d}", file=sys.stderr)
    print(f"dispatcher cases: {len(case_rows)} handlers, {sum(1 for r in case_rows if r['name'])} named",
          file=sys.stderr)


if __name__ == '__main__':
    main()
