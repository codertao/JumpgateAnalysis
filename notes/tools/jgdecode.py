"""Jumpgate message obfuscation (salt + running sum), from 0x9c8ca0 / 0x9c8d30."""
import struct

def _k(salt):
    s = (salt * 0x89) & 0xffffffff
    s = (s * 0x343fd + 0x269ec3) & 0xffffffff          # MSVC rand()
    r = (s >> 16) & 0x7fff
    f = struct.unpack('<f', bytes.fromhex('fc01fe3b'))[0]  # 254/32767 as float32
    return int(r * f) & 0xff                           # _ftol truncation

def decode(enc):
    """enc = encoded bytes (salt first). returns len(enc)-1 plaintext bytes."""
    if len(enc) < 2:
        return b''
    out = bytearray([(enc[1] - _k(enc[0])) & 0xff])
    for i in range(2, len(enc)):
        out.append((enc[i] - enc[i - 1]) & 0xff)
    return bytes(out)

def encode(msg, salt):
    k = _k(salt)
    out = bytearray([salt, (msg[0] + k) & 0xff])
    for b in msg[1:]:
        out.append((out[-1] + b) & 0xff)
    return bytes(out)
