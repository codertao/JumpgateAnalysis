#!/usr/bin/env python3
"""Read jgcap.bin written by the Msb32 logging proxy.

usage: jgcap_dump.py jgcap.bin               # one line per message
       jgcap_dump.py jgcap.bin --type 0x33   # only that type
       jgcap_dump.py jgcap.bin --stats       # per-type length/offset variability
"""
import argparse, collections, struct, sys

# Names established statically so far (C = client->server, S = server->client).
NAMES = {
    0x07: 'launch/dock/jump (C, sub@1: 1/2/3)', 0x08: 'ship (C)', 0x09: 'command (C, cmd@1)',
    0x0C: 'impact', 0x0E: 'consumables update (C)', 0x0F: 'building (C)', 0x10: 'prodboost (C)',
    0x16: 'reject spawn (C)', 0x18: 'medal? (S)', 0x1B: 'insurance update req (C)', 0x2E: 'chkbldg (C)',
    0x33: 'smallloc (S)', 0x34: 'miniloc (S)', 0x36: 'wingman (C)', 0x37: 'packet 55', 0x3D: 'packet 61',
    0x3F: 'packet 63', 0x40: 'packet 64', 0x41: 'packet 65', 0x43: 'hits counter (C)', 0x44: 'who killed me (C)',
    0x45: 'rank (S)', 0x4A: 'trade ack (sub@1)', 0x4C: 'mission (C)', 0x4D: 'modx (C)', 0x4E: 'mentor (C)',
    0x4F: 'teleport (C)', 0x59: 'home (C)', 0x6A: 'player list / player request (C)', 0x74: 'asteroid amount (C)',
    0x79: 'building (C)', 0x7A: 'packet 122', 0x7B: 'registry chg (C)', 0x83: 'list channels (C)',
    0x8A: 'weather request (C)', 0x8F: 'welcome (S)', 0x90: 'findPOSowner (C)', 0x91: 'available missions (C)',
    0x93: 'mode (C)', 0x96: 'volunteer (C)', 0x98: 'refer (C)', 0x9B: 'volunteer off (C)',
    0x9C: 'event/query (C, sub u16@8)', 0x9D: 'vouch (C)', 0xAA: 'invite (C)', 0xAB: 'invite (C)',
    0xAC: 'shipname (C)', 0xBA: 'UPDPRPACKET (C)', 0xBB: 'home off (C)', 0xC1: 'job list request (C)',
    0xC3: 'util (C, sub@1)', 0xC5: 'commission/away (C)', 0xFE: 'Msb32 memory patch (S)',
}

def read(path):
    data = open(path, 'rb').read()
    i = 0
    while i + 7 <= len(data):
        d, ms, ln = struct.unpack_from('<BIH', data, i)
        i += 7
        if i + ln > len(data):
            print('warning: truncated final record', file=sys.stderr)
            break
        yield d, ms, data[i:i + ln]
        i += ln

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--type', type=lambda s: int(s, 0))
    ap.add_argument('--stats', action='store_true')
    a = ap.parse_args()
    recs = [r for r in read(a.log) if a.type is None or (r[2] and r[2][0] == a.type)]
    if not recs:
        print('no records'); return
    t0 = recs[0][1]
    if not a.stats:
        for d, ms, m in recs:
            t = m[0] if m else -1
            print('%9.3f %s 0x%02x %-34s len=%-4d %s' % ((ms - t0) / 1000, 'C>S' if d else 'S>C', t,
                  NAMES.get(t, '?')[:34], len(m), m.hex(' ')))
        return
    by = collections.defaultdict(list)
    for d, ms, m in recs:
        if m:
            by[(m[0], d)].append(m)
    for (t, d), ms_ in sorted(by.items()):
        lens = collections.Counter(len(m) for m in ms_)
        print('0x%02x %s n=%d lens=%s  %s' % (t, 'C>S' if d else 'S>C', len(ms_), dict(lens.most_common(5)),
              NAMES.get(t, '?')))
        L = lens.most_common(1)[0][0]
        same = [m for m in ms_ if len(m) == L]
        row = []
        for o in range(L):
            vals = {m[o] for m in same}
            row.append('%02x' % vals.pop() if len(vals) == 1 else '..')
        print('     const/varying bytes:', ' '.join(row))

if __name__ == '__main__':
    main()
