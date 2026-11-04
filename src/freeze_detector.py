"""(ID,payload)-conditioned freeze detector.

Idea obtained from the benign analysis: for a given ID, long frozen runs are
associated with SPECIFIC payload values (e.g. ID 371 freezes on
001E000000000010, ID 372 on 0000100000000000). Freezing on a payload that has
never been seen to freeze before is therefore suspicious.

Profile (built on benign only):
    for each (ID, payload): max_run_len, n_occurrences
Detector:
    flag a frame if its (ID,payload) run length exceeds
        max( THR_MIN, K * max_run_seen_benign[ID,payload] )
    where unseen (ID,payload) pairs get max_run_seen = 0.
"""
import re, glob, os, json, collections, csv
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MIRGU=DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"
CTT=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
OUT=PKG_ROOT + "/results"
pat=re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")
THR_MIN=50          # never flag runs shorter than this
K=2.0               # allow twice the benign maximum before flagging

def profile(paths, cap_each=800000):
    """(ID,payload) -> max frozen run length in benign traffic."""
    mx=collections.defaultdict(int)
    seen=collections.Counter()
    for p in paths:
        last={}; run={}; n=0
        with open(p) as f:
            for line in f:
                m=pat.match(line)
                if not m: continue
                i=m.group(2).upper().zfill(3); pay=m.group(3).upper()
                if last.get(i)==pay:
                    run[i]=run.get(i,1)+1
                else:
                    if i in run: 
                        key=(i,last[i]); 
                        if run[i]>mx[key]: mx[key]=run[i]
                    run[i]=1
                last[i]=pay; seen[(i,pay)]+=1
                n+=1
                if n>=cap_each: break
        for i,r in run.items():
            key=(i,last[i])
            if r>mx[key]: mx[key]=r
    return mx, seen

print("profiling benign (Day 1-6) ...")
benpaths=[]
for d in range(1,7):
    benpaths += sorted(glob.glob(f"{MIRGU}/Benign/Day_{d}/*.log"))[:1]
mx,seen = profile(benpaths)
print(f"  (ID,payload) pairs: {len(mx)}   max run overall: {max(mx.values())}")
json.dump({f"{i}|{p}":v for (i,p),v in mx.items()}, open(f"{OUT}/freeze_profile.json","w"))

def eval_runs(path, tid):
    """Return per-frame flags for one ID using the profile."""
    last=None; run=0
    flagged=0; total=0; maxrun=0
    with open(path) as f:
        for line in f:
            m=pat.match(line)
            if not m: continue
            i=m.group(2).upper().zfill(3)
            if i!=tid: continue
            pay=m.group(3).upper()
            if pay==last: run+=1
            else: last=pay; run=1
            total+=1
            maxrun=max(maxrun,run)
            limit=max(THR_MIN, K*mx.get((tid,pay),0))
            if run>limit: flagged+=1
    return flagged, total, maxrun

def load_csv_ids(path, cap=None):
    ids=collections.Counter()
    with open(path, newline="") as f:
        r=csv.reader(f); next(r)
        for row in r:
            if len(row)>=4:
                try:
                    if int(float(row[3]))==1: ids[row[1].strip().upper()]+=1
                except Exception: pass
            if cap and sum(ids.values())>cap: break
    return ids

def eval_ctt(path, tid):
    last=None; run=0; tot=0; fl=0; mxr=0
    with open(path, newline="") as f:
        r=csv.reader(f); next(r)
        for row in r:
            if len(row)<4: continue
            if row[1].strip().upper()!=tid: continue
            pay=row[2].strip().upper()
            if len(pay)%2: pay="0"+pay
            try: lab=int(float(row[3]))
            except Exception: continue
            if pay==last: run+=1
            else: last=pay; run=1
            tot+=1; mxr=max(mxr,run)
            if lab==1:
                limit=max(THR_MIN,K*mx.get((tid,pay),0))
                if run>limit: fl+=1
    return fl, tot, mxr

print("\n=== CTRL: false alarms on held-out benign (Day 6 full) ===")
tot_fl=tot_fr=0
for f in sorted(glob.glob(f"{MIRGU}/Benign/Day_6/*.log"))[:1]:
    for tid in ["371","372","140","251","160","386"]:
        fl,tot,mr=eval_runs(f,tid)
        print(f"  {tid}: flags={fl}/{tot}  ({100*fl/max(1,tot):.4f}%)  maxrun={mr}")
        tot_fl+=fl; tot_fr+=tot
print(f"  overall benign flag rate: {100*tot_fl/max(1,tot_fr):.4f}%")

print("\n=== ATTACKS: can-train-and-test masquerade ===")
print(f"{'file':30s}{'id':>5s}{'flags':>8s}{'nAtkRows':>10s}")
for s in ["set_02","set_03","set_04"]:
    d=f"{CTT}/{s}/test_06_masquerade"
    if not os.path.isdir(d): continue
    for f in sorted(glob.glob(f"{d}/masquerade-timed-*.csv")):
        ids=load_csv_ids(f)
        if not ids: continue
        tid=ids.most_common(1)[0][0]
        fl,tot,mr=eval_ctt(f,tid)
        print(f"{os.path.basename(f)[:29]:30s}{tid:>5s}{fl:>8d}{tot:>10d}  maxrun={mr}")
