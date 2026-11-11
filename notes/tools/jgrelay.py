#!/usr/bin/env python3
"""Local UDP relay / network-layer MitM insertion point for Jumpgate.

The client must be pointed at this relay instead of the real server. Easiest
way, since you already control Msb32.dll: make the shim's GetIP return the
relay IP (e.g. 127.0.0.1) -- a one-line change -- or use an iptables REDIRECT.

The relay forwards UDP both ways for the state (5150) and space (5151) ports and
records every datagram to jgraw.bin in the jgcap format:
    u8 dir(0=S>C,1=C>S)  u32 ms  u16 len  u8 data[len]
Payloads are the RakNet AES ciphertext (the handshake at 0xa6cc90 negotiates the
key); this gives timing/size and a tamper point, NOT plaintext. For plaintext,
use the in-process Msb32 shim. jgcap_dump.py shows the timing view of jgraw.bin.

A tamper() hook lets you drop/delay/corrupt at the datagram level for robustness
testing. Returns the (possibly modified) payload, or None to drop.

usage: jgrelay.py --server 217.194.148.37 [--listen 0.0.0.0] [--ports 5150 5151]
Use only to intercept your own client's own connection.
"""
import argparse, socket, struct, threading, time, random

t0 = time.time()
logf = None
loglock = threading.Lock()

def log(direction, data):
    if not logf:
        return
    with loglock:
        logf.write(struct.pack('<BIH', direction, int((time.time() - t0) * 1000) & 0xffffffff, len(data)))
        logf.write(data)
        logf.flush()

def tamper(direction, data):
    """Return payload to forward, or None to drop. Edit for experiments."""
    # Examples:
    # if random.random() < 0.02: return None            # 2% packet loss
    # if direction == 0: time.sleep(0.15)               # add 150ms server->client lag
    return data

def relay_port(listen_ip, listen_port, server_ip, server_port):
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.bind((listen_ip, listen_port))
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    state = {'client': None}

    def c2s():
        while True:
            data, addr = cli.recvfrom(65535)
            state['client'] = addr
            log(1, data)
            out = tamper(1, data)
            if out is not None:
                srv.sendto(out, (server_ip, server_port))

    def s2c():
        while True:
            data, _ = srv.recvfrom(65535)
            log(0, data)
            out = tamper(0, data)
            if out is not None and state['client']:
                cli.sendto(out, state['client'])

    threading.Thread(target=c2s, daemon=True).start()
    threading.Thread(target=s2c, daemon=True).start()
    print('relay %s:%d  <->  %s:%d' % (listen_ip, listen_port, server_ip, server_port))

def main():
    global logf
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True, help='real server IP (DNS TXT _game_server.jumpgate-tri.org)')
    ap.add_argument('--listen', default='0.0.0.0')
    ap.add_argument('--ports', type=int, nargs='+', default=[5150, 5151])
    ap.add_argument('--log', default='jgraw.bin')
    a = ap.parse_args()
    logf = open(a.log, 'ab')
    for p in a.ports:
        relay_port(a.listen, p, a.server, p)
    print('recording ciphertext+timing to', a.log, '(Ctrl-C to stop)')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
