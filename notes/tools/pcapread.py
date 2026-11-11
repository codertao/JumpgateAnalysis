import struct
def udp_packets(path):
    d = open(path, 'rb').read()
    magic = struct.unpack_from('<I', d, 0)[0]
    e = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    nsec = magic in (0xa1b23c4d, 0x4d3cb2a1)
    link = struct.unpack_from(e + 'I', d, 20)[0]
    i = 24
    while i + 16 <= len(d):
        ts, tu, incl, orig = struct.unpack_from(e + 'IIII', d, i); i += 16
        pkt = d[i:i + incl]; i += incl
        if link == 113: ip = pkt[16:]; 
        elif link == 276: ip = pkt[20:]
        elif link == 1: ip = pkt[14:]
        else: raise SystemExit('linktype %d' % link)
        if not ip or ip[0] >> 4 != 4 or ip[9] != 17: continue
        ihl = (ip[0] & 15) * 4
        src = '.'.join(map(str, ip[12:16])); dst = '.'.join(map(str, ip[16:20]))
        sp, dp, ul = struct.unpack_from('>HHH', ip, ihl)
        yield ts + tu / (1e9 if nsec else 1e6), src, sp, dst, dp, ip[ihl + 8:ihl + ul]
