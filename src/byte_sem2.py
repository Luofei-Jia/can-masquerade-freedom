import csv, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTT=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
F=f"{CTT}/set_04/test_06_masquerade/masquerade-timed-1.csv"
ben=[]
with open(F, newline="") as f:
    r=csv.reader(f); next(r)
    for row in r:
        if len(row)<4: continue
        if row[1].strip().upper()!="140": continue
        p=row[2].strip().upper()
        if len(p)%2: p="0"+p
        if int(float(row[3]))==0: ben.append(p)
print("benign payload lengths:", collections.Counter(len(x) for x in ben))
L=collections.Counter(len(x) for x in ben).most_common(1)[0][0]
Mm=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ben if len(x)==L])
print(f"\nusing DLC={L}, n={len(Mm)}")
for k in range(Mm.shape[1]):
    print(f"  byte {k}: mean={Mm[:,k].mean():7.2f} std={Mm[:,k].std():6.2f} uniq={len(set(Mm[:,k].tolist())):5d} "
          f"{'VARYING' if Mm[:,k].std()>0.5 else 'static'}")
