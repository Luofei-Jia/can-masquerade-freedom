"""Value-domain freedom: the corrected predictor of masquerade detectability.

For each attack we compute, per byte of the attacked identifier:
  in_domain : the attack value occurs in benign traffic (attack can mimic there)
  out_of_domain : the attack value never occurs in benign traffic

freedom = (# in_domain bytes) / DLC

We then relate freedom to (i) whether the attacker can randomise those bytes
without changing the attack, and (ii) the observed detectability.
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

print(f"{'set':>7s}{'file':>12s}{'tgt':>5s}{'DLC':>4s}{'nAtk':>7s}{'nBen':>8s}{'benVocab':>9s}"
      f"{'in-domain':>10s}{'freedom':>9s}  in-domain byte list")
print("-"*104)
rows=[]
for s,f,p in files:
    aps=collections.Counter(); bps=collections.Counter(); tid=None
    attk_ids=collections.Counter()
    with open(p, newline="") as fh:
        r=csv.reader(fh); next(r)
        for row in r:
            if len(row)<4: continue
            i=row[1].strip().upper(); pay=row[2].strip().upper()
            if len(pay)%2: pay="0"+pay
            try: lab=int(float(row[3]))
            except Exception: continue
            if lab==1: attk_ids[i]+=1
    if not attk_ids: continue
    tid=attk_ids.most_common(1)[0][0]
    with open(p, newline="") as fh:
        r=csv.reader(fh); next(r)
        for row in r:
            if len(row)<4: continue
            if row[1].strip().upper()!=tid: continue
            pay=row[2].strip().upper()
            if len(pay)%2: pay="0"+pay
            try: lab=int(float(row[3]))
            except Exception: continue
            (aps if lab==1 else bps)[pay]+=1
    if not aps or not bps: continue
    pa=aps.most_common(1)[0][0]
    A=np.frombuffer(bytes.fromhex(pa),dtype=np.uint8)
    L=len(A)
    Mb=[np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in bps.elements()]
    Mb=[x for x in Mb if len(x)==L]
    if not Mb: continue
    M=np.stack(Mb)
    indom=[k for k in range(L) if A[k] in set(M[:,k].tolist())]
    out=[k for k in range(L) if k not in indom]
    rows.append(dict(set=s,file=f,tid=tid,dlc=L,n_atk=sum(aps.values()),n_ben=sum(bps.values()),
                     vocab=len(bps),in_domain=indom,freedom=len(indom)/L,
                     attack_payload=pa))
    print(f"{s:>7s}{f.replace('.csv','')[:11]:>12s}{tid:>5s}{L:>4d}{sum(aps.values()):>7d}"
          f"{sum(bps.values()):>8d}{len(bps):>9d}{len(indom):>10d}{len(indom)/L:>9.2f}  {indom}")

json.dump(rows, open(f"{OUT}/freedom.json","w"), indent=2)
print(f"\n=== summary ===")
if rows:
    fr=[r["freedom"] for r in rows]
    print(f"pairs: {len(rows)}   freedom: min={min(fr):.2f} median={np.median(fr):.2f} max={max(fr):.2f}")
    print(f"pairs with freedom == 0 (no in-domain byte): {sum(1 for x in fr if x==0)}")
    print(f"pairs with freedom >= 0.5: {sum(1 for x in fr if x>=0.5)}")
