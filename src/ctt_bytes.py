"""What do can-train-and-test masquerade frames actually change?

For each masquerade instance we compare, per byte of the attacked ID:
  - benign frames : mean, std, and value set
  - attack frames : mean, std, and value set
and report which bytes actually move. This settles whether a byte-level
detector *could* see the attack at all.
"""
import csv, os, glob, collections
import numpy as np
from scipy import stats as sps

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
OUT=PKG_ROOT + "/results"

def load(path):
    rows=[]
    with open(path, newline="") as f:
        r=csv.reader(f); next(r)
        for row in r:
            if len(row)<4: continue
            try: t=float(row[0]); a=row[1].strip().upper(); d=row[2].strip().upper(); l=int(float(row[3]))
            except Exception: continue
            if len(d)%2: d="0"+d          # tolerate odd-length hex
            rows.append((t,a,d,l))
    return rows

for s in ["set_02","set_03","set_04"]:
    d=f"{BASE}/{s}/test_06_masquerade"
    if not os.path.isdir(d): continue
    print(f"\n########## {s} ##########")
    for f in sorted(glob.glob(f"{d}/masquerade-timed-*.csv"))[:3]:
        rows=load(f)
        cnt=collections.Counter(a for _,a,_,l in rows if l==1)
        if not cnt: continue
        tid=cnt.most_common(1)[0][0]
        ben=[d_ for _,a,d_,l in rows if a==tid and l==0]
        atk=[d_ for _,a,d_,l in rows if a==tid and l==1]
        if len(ben)<50 or len(atk)<20: continue
        def toarr(lst):
            arrs=[np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in lst]
            L=max(len(a) for a in arrs)
            return np.stack([np.pad(a,(0,L-len(a))) for a in arrs]).astype(float)
        vb=toarr(ben); va=toarr(atk)
        if vb.shape[1]!=va.shape[1]:
            print(f"  {os.path.basename(f)}: DLC mismatch {vb.shape[1]} vs {va.shape[1]}"); continue
        print(f"\n  {os.path.basename(f)}  attackedID={tid}  benign={len(ben)} attack={len(atk)}  DLC={vb.shape[1]}")
        print(f"    {'byte':>4s}{'ben_mean':>10s}{'atk_mean':>10s}{'ben_std':>9s}{'atk_std':>9s}"
              f"{'KS':>8s}{'newvals':>9s}")
        for k in range(vb.shape[1]):
            ks,p=sps.ks_2samp(vb[:,k],va[:,k])
            nb=set(vb[:,k].astype(int)); na=set(va[:,k].astype(int))
            newv=len(na-nb)
            flag=" <== CHANGED" if (ks>0.2 and p<1e-3) else ""
            print(f"    {k:>4d}{vb[:,k].mean():>10.2f}{va[:,k].mean():>10.2f}{vb[:,k].std():>9.2f}"
                  f"{va[:,k].std():>9.2f}{ks:>8.3f}{newv:>9d}{flag}")
