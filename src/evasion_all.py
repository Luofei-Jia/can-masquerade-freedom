"""Evasion experiment repeated on EVERY evaluable pair.

For each pair we:
  1. take the dominant attack payload of the target ID
  2. classify each byte SEMANTIC (attack value differs from the dominant benign
     value AND the attack value is rare in benign) or FREE (identical to benign)
  3. build an evading attack that randomises FREE bytes only
  4. report: longest frozen run, payload uniqueness, semantic preservation

Semantic preservation is measured as: do the bytes that carry the attack keep
their exact attack values? That is the operational definition of "the attack is
unchanged".
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

def max_run(seq):
    mr=0;cur=0;last=None
    for x in seq:
        cur=cur+1 if x==last else 1
        last=x;mr=max(mr,cur)
    return mr

def load_pair(path):
    aps=collections.Counter(); bps=collections.Counter()
    ids=collections.Counter()
    with open(path, newline="") as fh:
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
    return tid, aps, bps, rows

print(f"{'set':>6s}{'file':>11s}{'tgt':>5s}{'nAtk':>6s}{'nBen':>7s}"
      f"{'free':>5s}{'sem':>5s}{'runA':>7s}{'runE':>6s}{'uniqE':>7s}{'semKeep':>8s}")
print("-"*78)
rows=[]
for s,f,p in files:
    got=load_pair(p)
    if not got:
        print(f"  SKIP(no pair): {s}/{f}"); continue
    tid, aps, bps, allrows = got
    n_ben=sum(bps.values()); n_atk=sum(aps.values())
    if n_ben<20 or n_atk<20:
        print(f"  SKIP(small): {s}/{f} frames atk={n_atk} ben={n_ben}"); continue
    pa=aps.most_common(1)[0][0]
    A=np.frombuffer(bytes.fromhex(pa),dtype=np.uint8)
    L=len(A)
    Mb=[np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in bps.elements()]
    Mb=[x for x in Mb if len(x)==L]
    if not Mb:
        print(f"  SKIP(dlc): {s}/{f} L={L}"); continue
    B=np.stack(Mb)
    # FREE: attack value identical to the dominant benign value (byte-for-byte)
    pb=bps.most_common(1)[0][0]
    Bm=np.frombuffer(bytes.fromhex(pb),dtype=np.uint8)
    free=[k for k in range(L) if A[k]==Bm[k]]
    sem=[k for k in range(L) if k not in free]

    N=sum(aps.values())
    seq_orig=[]
    for v,c in aps.items(): seq_orig += [v]*c
    # evading sequence
    rng=np.random.default_rng(0)
    ev=[]
    for _ in range(N):
        b=A.copy()
        for k in free: b[k]=int(rng.integers(0,256))
        ev.append(b.astype(np.uint8).tobytes().hex().upper())
    # semantic preservation: do semantic bytes still equal the attack?
    E=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ev])
    keep=float(np.all(E[:,sem]==A[sem][None,:],axis=1).mean()) if sem else 1.0

    rows.append(dict(set=s,file=f,tid=tid,n_atk=N,n_ben=sum(bps.values()),
                     free=free,semantic=sem,run_orig=max_run(seq_orig),
                     run_evade=max_run(ev),uniq_evade=len(set(ev))/len(ev),
                     semantic_keep=keep))
    r=rows[-1]
    print(f"{s:>6s}{f.replace('masquerade-timed-','T').replace('.csv',''):>11s}{tid:>5s}"
          f"{N:>6d}{sum(bps.values()):>7d}{len(free):>5d}{len(sem):>5d}"
          f"{r['run_orig']:>7d}{r['run_evade']:>6d}{100*r['uniq_evade']:>6.0f}%{100*keep:>7.1f}%")

json.dump(rows, open(f"{OUT}/evasion_all.json","w"), indent=2)
print(f"\n=== summary over {len(rows)} pairs ===")
if rows:
    ok=[r for r in rows if r["semantic_keep"]>0.999 and r["free"]]
    print(f"pairs where evasion keeps semantics at 100%: {len(ok)}/{len(rows)}")
    print(f"pairs where evasion destroys the frozen run (<50): "
          f"{sum(1 for r in rows if r['run_evade']<50)}/{len(rows)}")
    print(f"pairs with zero free bytes (evasion impossible): "
          f"{sum(1 for r in rows if not r['free'])}")
    print(f"max frozen run after evasion: {max(r['run_evade'] for r in rows)}")
