"""Adaptive control: sample free bytes FROM the benign marginal, not uniformly.

The uniform variant increases distance from the benign centroid, which flatters
D3. A real adaptive attacker draws free-byte values from what benign traffic
actually contains, staying close to the centroid while still never repeating.
"""
import csv, os, json, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CTT=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
OUT=PKG_ROOT + "/results"

files=[]
for s in ["set_02","set_03","set_04"]:
    d=f"{CTT}/{s}/test_06_masquerade"
    if not os.path.isdir(d): continue
    for f in sorted(os.listdir(d)):
        if f.endswith(".csv"): files.append((s,f,os.path.join(d,f)))

def load(p):
    aps=collections.Counter(); bps=collections.Counter(); ids=collections.Counter()
    with open(p, newline="") as fh:
        r=csv.reader(fh); next(r)
        rows=[]
        for row in r:
            if len(row)<4: continue
            i=row[1].strip().upper(); pay=row[2].strip().upper()
            if len(pay)%2: pay="0"+pay
            try: lab=int(float(row[3]))
            except Exception: continue
            rows.append((i,pay,lab))
            if lab==1: ids[i]+=1
    if not ids: return None
    tid=ids.most_common(1)[0][0]
    for i,pay,lab in rows:
        if i!=tid: continue
        (aps if lab==1 else bps)[pay]+=1
    return tid,aps,bps

def maxrun(seq):
    mr=0;cur=0;last=None
    for x in seq:
        cur=cur+1 if x==last else 1
        last=x;mr=max(mr,cur)
    return mr

def ent(b):
    v=np.bincount(b,minlength=256).astype(float); p=v[v>0]/v.sum()
    return float(-(p*np.log2(p)).sum())

print(f"{'set':>6s}{'tgt':>5s}{'free':>5s} | {'strategy':<14s}{'D1 frz':>8s}{'D2 ent':>8s}{'D3 dist':>9s}{'dist_shift':>11s}")
print("-"*80)
rows=[]
for s,f,p in files:
    got=load(p)
    if not got: continue
    tid,aps,bps=got
    if sum(bps.values())<20 or sum(aps.values())<20: continue
    seq_ben=[]
    for v,c in bps.items(): seq_ben += [v]*c
    pa=aps.most_common(1)[0][0]; pb=bps.most_common(1)[0][0]
    if len(pa)!=len(pb): continue
    A=np.frombuffer(bytes.fromhex(pa),dtype=np.uint8)
    Bm=np.frombuffer(bytes.fromhex(pb),dtype=np.uint8)
    free=[k for k in range(len(A)) if A[k]==Bm[k]]
    if not free: continue
    B=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in seq_ben])
    mu=B.mean(0); sd=B.std(0)+1.0
    eB=np.array([ent(b) for b in B]); d_B=np.abs((B-mu)/sd).mean(1)
    thr2=np.quantile(eB,0.01); thr3=np.quantile(d_B,0.99)
    d_base=d_B.mean()

    N=sum(aps.values())
    rng=np.random.default_rng(0)
    # adaptive: draw free bytes from the benign marginal
    ev=[]
    for _ in range(N):
        src=B[int(rng.integers(0,len(B)))]
        b=A.copy()
        for k in free: b[k]=src[k]
        ev.append(b.astype(np.uint8).tobytes().hex().upper())
    E=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ev])
    eE=np.array([ent(b) for b in E]); d_E=np.abs((E-mu)/sd).mean(1)
    r=[dict(set=s,tid=tid,free=free,
            d1=1.0 if maxrun(ev)>=50 else 0.0,
            d2=float(np.mean(eE<thr2)), d3=float(np.mean(d_E>thr3)),
            dist_shift=float(d_E.mean()-d_base))]
    rows.append(r[0])
    print(f"{s:>6s}{tid:>5s}{len(free):>5d} | {'adaptive(benign)':<14s}"
          f"{r[0]['d1']:>8.2f}{r[0]['d2']:>8.2f}{r[0]['d3']:>9.2f}{r[0]['dist_shift']:>+11.2f}")

json.dump(rows, open(f"{OUT}/adaptive_benign.json","w"), indent=2)
if rows:
    print(f"\nmean over {len(rows)} pairs (adaptive attacker sampling benign values):")
    for k,nm in (("d1","D1 freeze"),("d2","D2 entropy"),("d3","D3 distance")):
        print(f"  {nm:12s} detection={np.mean([r[k] for r in rows]):.3f}")
