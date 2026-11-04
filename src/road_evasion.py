"""ROAD evasion: does free-byte randomisation work on the second dataset?

ROAD's masquerade removes genuine frames, so we use ROAD's ambient captures as
the benign reference for both the value domain and the byte-role split.
"""
import re, glob, json, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE=DATA_ROOT + "/sixth/data_external/ROAD/road"
META=json.load(open(f"{BASE}/attacks/capture_metadata.json"))
OUT=PKG_ROOT + "/results"
pat=re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def norm(s):
    s=s.strip().upper()
    if s.startswith("0X"): s=s[2:]
    return s.zfill(3)

def maxrun(seq):
    mr=0;cur=0;last=None
    for x in seq:
        cur=cur+1 if x==last else 1
        last=x;mr=max(mr,cur)
    return mr

# benign reference: ambient frames per (id, dlc)
print("loading ROAD ambient reference ...")
ben=collections.defaultdict(list)
for f in sorted(glob.glob(f"{BASE}/ambient/*.log")):
    with open(f) as fh:
        for line in fh:
            m=pat.match(line)
            if not m: continue
            d=m.group(3).upper()
            if len(d)%2: continue
            ben[(norm(m.group(2)), len(d)//2)].append(np.frombuffer(bytes.fromhex(d),dtype=np.uint8))
print(f"benign groups: {len(ben)}")

pairs=[(k[:-len("_masquerade")],k) for k in META
       if k.endswith("_masquerade") and k[:-len("_masquerade")] in META]

print(f"\n{'pair':30s}{'tgt':>5s}{'nAtk':>6s}{'free':>5s}{'runA':>7s}{'runE':>6s}{'uniqE':>7s}{'keep':>6s}")
print("-"*74)
rows=[]
for pair_name,m in pairs:
    mm=META[m]
    if "X" in str(mm["injection_id"]): continue
    tid=norm(mm["injection_id"]); iv=mm["injection_interval"]
    frames=[]; t0=None
    with open(f"{BASE}/attacks/{m}.log") as fh:
        for line in fh:
            mm2=pat.match(line)
            if not mm2: continue
            tt=float(mm2.group(1))
            if t0 is None: t0=tt
            if norm(mm2.group(2))!=tid: continue
            if not (iv[0]<=tt-t0<=iv[1]): continue
            d=mm2.group(3).upper()
            if len(d)%2: continue
            frames.append(np.frombuffer(bytes.fromhex(d),dtype=np.uint8))
    if len(frames)<20: continue
    L=len(frames[0]); key=(tid,L)
    if key not in ben: continue
    B=np.stack(ben[key])
    A=frames[0]
    mu=B.mean(0); sd=B.std(0)+1.0
    # free: attack value equals the most common benign value at that byte
    mode=np.array([np.bincount(B[:,k].astype(int),minlength=256).argmax() for k in range(L)])
    # more robust: free if attack value occurs in benign at this byte with >=1% freq
    free=[int(k) for k in range(L) if np.mean(B[:,k]==A[k])>=0.01]
    sem=[k for k in range(L) if k not in free]
    seq_orig=[x.tobytes().hex().upper() for x in frames]
    rng=np.random.default_rng(0)
    ev=[]
    for _ in range(len(frames)):
        src=B[int(rng.integers(0,len(B)))]
        b=A.copy()
        for k in free: b[k]=src[k]
        ev.append(b.astype(np.uint8).tobytes().hex().upper())
    E=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ev])
    keep=float(np.all(E[:,sem]==A[sem][None,:],axis=1).mean()) if sem else 1.0
    r=dict(pair=pair_name,tid=tid,n_atk=len(frames),free=free,
           run_orig=int(maxrun(seq_orig)),run_evade=int(maxrun(ev)),
           uniq_evade=len(set(ev))/len(ev),semantic_keep=keep,
           dist_orig=float(np.abs((A-mu)/sd).mean()),
           dist_evade=float(np.abs((E-mu)/sd).mean(1).mean()))
    rows.append(r)
    nfr=int(len(frames)); nfree=int(len(free))
    print("%-30s%5s%6d%5d%7d%6d%6d%%%5d%%" % (str(pair_name)[:29], str(tid), nfr, nfree,
          int(r["run_orig"]), int(r["run_evade"]), int(100*float(r["uniq_evade"])), int(100*float(keep))))

json.dump(rows, open(f"{OUT}/road_evasion.json","w"), indent=2)
if rows:
    print(f"\n=== summary ({len(rows)} pairs) ===")
    print(f"  semantic preserved at 100%: {sum(1 for r in rows if r['semantic_keep']>0.999)}/{len(rows)}")
    print(f"  frozen run below 50 after evasion: {sum(1 for r in rows if r['run_evade']<50)}/{len(rows)}")
    print(f"  mean distance shift: {np.mean([r['dist_evade']-r['dist_orig'] for r in rows]):+.3f}")
