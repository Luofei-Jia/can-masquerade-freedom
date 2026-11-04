"""Can value-domain freedom be computed for ROAD?

ROAD's masquerade removes the genuine frames inside the interval, so there is no
"benign counterpart inside the same capture" for the target ID during the attack.
We therefore build the benign value domain from ROAD's ambient captures instead,
and ask whether the same byte-level analysis is possible.
"""
import re, glob, json, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE=DATA_ROOT + "/sixth/data_external/ROAD/road"
META=json.load(open(f"{BASE}/attacks/capture_metadata.json"))
pat=re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def norm(s):
    s=s.strip().upper()
    if s.startswith("0X"): s=s[2:]
    return s.zfill(3)

def wildcard_pred(ps):
    p=ps.upper()
    return lambda s: len(s)==len(p) and all(pc=='X' or pc==sc for pc,sc in zip(p,s.upper()))

# benign value domain per (id, dlc) from ambient
print("building benign value domain from ROAD ambient ...")
doms=collections.defaultdict(lambda: [set() for _ in range(8)])
cnt=collections.Counter()
for f in sorted(glob.glob(f"{BASE}/ambient/*.log")):
    with open(f) as fh:
        for line in fh:
            m=pat.match(line)
            if not m: continue
            i=norm(m.group(2)); d=m.group(3).upper()
            if len(d)%2: continue
            b=np.frombuffer(bytes.fromhex(d),dtype=np.uint8)
            for k in range(len(b)): doms[(i,len(b))][k].add(int(b[k]))
            cnt[i]+=1
print(f"IDs profiled: {len(cnt)}")

pairs=[(k[:-len("_masquerade")],k) for k in META
       if k.endswith("_masquerade") and k[:-len("_masquerade")] in META]

print(f"\n{'pair':32s}{'tgt':>5s}{'DLC':>5s}{'nAtk':>7s}{'indomain':>9s}{'freedom':>9s}")
print("-"*70)
rows=[]
for b,m in pairs:
    mm=META[m]
    if "X" in str(mm["injection_id"]): continue
    tid=norm(mm["injection_id"]); ps=mm["injection_data_str"]; iv=mm["injection_interval"]
    pred=wildcard_pred(ps)
    pay=[]; t0=None
    with open(f"{BASE}/attacks/{m}.log") as fh:
        for line in fh:
            mm2=pat.match(line)
            if not mm2: continue
            tt=float(mm2.group(1))
            if t0 is None: t0=tt
            t=tt-t0                      # ROAD intervals are relative to capture start
            if norm(mm2.group(2))!=tid: continue
            if not (iv[0]<=t<=iv[1]): continue
            d=mm2.group(3).upper()
            if len(d)%2: continue
            pay.append(np.frombuffer(bytes.fromhex(d),dtype=np.uint8))
    if len(pay)<20: continue
    L=len(pay[0])
    key=(tid,L)
    if key not in doms: 
        print(f"{b[:31]:32s}{tid:>5s}{L:>5d}   (no benign domain)"); continue
    A=pay[0]
    indom=sum(1 for k in range(L) if int(A[k]) in doms[key][k])
    rows.append(dict(pair=b,tid=tid,dlc=L,n_atk=len(pay),in_domain=indom,freedom=indom/L))
    print(f"{b[:31]:32s}{tid:>5s}{L:>5d}{len(pay):>7d}{indom:>6d}/{L:<2d}{indom/L:>9.2f}")

json.dump(rows, open(".","w"), indent=2)
print(f"\n=== summary ===\n  pairs analysed: {len(rows)}")
if rows:
    fr=[r["freedom"] for r in rows]
    print(f"  freedom: min={min(fr):.2f} median={np.median(fr):.2f} max={max(fr):.2f}")
    print(f"  pairs at freedom 1.00: {sum(1 for x in fr if x==1.0)}/{len(fr)}")
