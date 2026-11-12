import re,struct,collections,json
lines=open('/tmp/claude-1000/-home-matt-misc-Jumpgate/09f00288-768e-4085-9cef-033b6d69a0aa/scratchpad/all.asm').read().splitlines()
def F(h): return struct.unpack('<f',struct.pack('<I',h))[0]
import sys
FN=sys.argv[1]; OUT=sys.argv[2]
start=next(i for i,l in enumerate(lines) if re.match(r'\s*'+FN+':',l))
end=next(i for i in range(start,len(lines)) if re.search(r'\tret',lines[i]))
reg={}; ptr={}   # reg values; register->object slot it currently holds
objs=collections.OrderedDict(); last_new=None; other=[]
for l in lines[start:end+1]:
    m=re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)',l)
    if not m: continue
    a,op,args=m.groups()
    if op=='call' and args=='0xaa8600': reg['eax']='NEW'; continue
    mm=re.match(r'(e[a-d]x|e[sd]i|ebp),0x([0-9a-f]+)$',args)
    if op=='mov' and mm: reg[mm.group(1)]=int(mm.group(2),16); ptr.pop(mm.group(1),None); continue
    mm=re.match(r'(e[a-d]x|e[sd]i|ebp),(e[a-d]x|e[sd]i|ebp)$',args)
    if op=='xor' and mm and mm.group(1)==mm.group(2): reg[mm.group(1)]=0; continue
    mm=re.match(r'ds:(0x[0-9a-f]+),eax$',args)
    if op=='mov' and mm and reg.get('eax')=='NEW':
        slot=int(mm.group(1),16); objs[slot]={}; reg['eax']=None; continue
    mm=re.match(r'(?:DWORD PTR )?(e[a-d]x|e[sd]i|ebp),(?:DWORD PTR )?ds:(0x[0-9a-f]+)$',args)
    if op=='mov' and mm and int(mm.group(2),16) in objs:
        ptr[mm.group(1)]=int(mm.group(2),16); continue
    mm=re.match(r'(BYTE|WORD|DWORD) PTR \[(e[a-d]x|e[sd]i|ebp)(?:\+0x([0-9a-f]+))?\],(.+)$',args)
    if op=='mov' and mm and mm.group(2) in ptr:
        sz,r,off,src=mm.groups(); off=int(off or '0',16)
        if src.startswith('0x'): v=int(src,16)
        elif src in reg and isinstance(reg[src],int): v=reg[src]
        elif src in ('bl','bx'): v=reg.get('ebx',0)&(0xff if src=='bl' else 0xffff)
        elif src in ('ax','cx','dx','bx','si','di','bp') and isinstance(reg.get('e'+src),int): v=reg['e'+src]&0xffff
        elif src in ('al','cl','dl') and isinstance(reg.get('e'+src[0]+'x'),int): v=reg['e'+src[0]+'x']&0xff
        else: v=None
        objs[ptr[r]][off]=v
out=[]
for slot,f in objs.items():
    rec={'slot':hex(slot),'b0':f.get(0),'w2':f.get(2),'w4':f.get(4)}
    for k,o in (('x',8),('y',12),('z',16),('qx',20),('qy',24),('qz',28),('qw',32),('f24',36),('f28',40)):
        rec[k]=round(F(f[o]),3) if f.get(o) is not None else None
    out.append(rec)
json.dump(out,open(OUT,'w'),indent=0)
print("objects:",len(out),"  slot range",out[0]['slot'],"..",out[-1]['slot'])
print("w4 (class?) tally:",collections.Counter(o['w4'] for o in out).most_common())
print("w2 tally:",collections.Counter(o['w2'] for o in out).most_common(25))
print("missing-field objects:",sum(1 for o in out if None in (o['x'],o['y'],o['z'])))
for o in out[:6]: print(o)
