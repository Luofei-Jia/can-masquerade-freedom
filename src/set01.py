"""Extend every analysis to set_01 (the fourth can-train-and-test vehicle)."""
import csv, os, json, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CTT=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
OUT=PKG_ROOT + "/results"

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
    return int(mr)

print("=== set_01 ===")
d=f"{CTT}/set_01/test_06_masquerade"
rows_f=[]; rows_e=[]
for f in sorted(os.listdir(d)):
    if not f.endswith(".csv"): continue
    p=os.path.join(d,f)
    got=load(p)
    if not got: continue
    tid,aps,bps=got
    n_ben=sum(bps.values()); n_atk=sum(aps.values())
    if n_ben<20 or n_atk<20:
        print(f"  {f}: SKIP ben={n_ben} atk={n_atk}")
        continue
    pa=aps.most_common(1)[0][0]; pb=bps.most_common(1)[0][0]
    if len(pa)!=len(pb): continue
    A=np.frombuffer(bytes.fromhex(pa),dtype=np.uint8)
    Bm=np.frombuffer(bytes.fromhex(pb),dtype=np.uint8)
    L=len(A)
    Braw=[np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in bps.elements()]
    Braw=[x for x in Braw if len(x)==L]
    if not Braw:
        print(f"  {f}: SKIP no benign with DLC={L}")
        continue
    B=np.stack(Braw)
    indom=sum(1 for k in range(L) if int(A[k]) in set(B[:,k].tolist()))
    free=[int(k) for k in range(L) if A[k]==Bm[k]]
    sem=[k for k in range(L) if k not in free]
    seq_orig=[]
    for v,c in aps.items(): seq_orig += [v]*c
    rng=np.random.default_rng(0)
    ev=[]
    for _ in range(len(seq_orig)):
        src=B[int(rng.integers(0,len(B)))]
        bb=A.astype(int).copy()
        for k in free: bb[k]=src[k]
        ev.append(bb.astype(np.uint8).tobytes().hex().upper())
    E=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ev])
    keep=float(np.all(E[:,sem]==A[sem][None,:],axis=1).mean()) if sem else 1.0
    print(f"  {f:<26s} tgt=0x{tid} n_atk={n_atk:>5d} free={len(free)} "
          f"freedom={indom/L:.2f} runA={maxrun(seq_orig):>6d} runE={maxrun(ev):>3d} keep={100*keep:.0f}%")
    rows_f.append(dict(set="set_01",file=f,tid=tid,n_atk=n_atk,n_ben=n_ben,
                       dlc=L,in_domain=indom,freedom=indom/L,attack_payload=pa))
    rows_e.append(dict(set="set_01",file=f,tid=tid,n_atk=n_atk,n_ben=n_ben,
                       free=free,semantic=sem,run_orig=maxrun(seq_orig),
                       run_evade=maxrun(ev),uniq_evade=len(set(ev))/len(ev),
                       semantic_keep=keep))

# merge into the existing result files
for fn,new in (("freedom.json",rows_f),("evasion_all.json",rows_e)):
    p=f"{OUT}/{fn}"
    old=json.load(open(p)) if os.path.exists(p) else []
    old=[r for r in old if r.get("set")!="set_01"]
    json.dump(old+new, open(p,"w"), indent=2, default=str)
    print(f"\n{fn}: {len(old)} -> {len(old)+len(new)} entries")

print(f"\n=== set_01 summary ===")
print(f"  pairs added: {len(rows_f)}")
if rows_e:
    print(f"  semantic preserved: {sum(1 for r in rows_e if r['semantic_keep']>0.999)}/{len(rows_e)}")
    print(f"  run below 50 after evasion: {sum(1 for r in rows_e if r['run_evade']<50)}/{len(rows_e)}")
