"""Are the very long freezes real ECU behaviour, or capture gaps?

For each suspicious (ID, long freeze) we check whether OTHER IDs kept sending
during the same time window. If the whole bus goes quiet, it is a recording
gap, not an ECU state.
"""
import re, glob, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MIRGU=DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"
pat=re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")
CAP=1_500_000

def analyse(path, target_ids, cap=CAP):
    """Collect frozen runs >=200 for target IDs, plus bus activity in window."""
    last={}; run={}; start={}; runs=collections.defaultdict(list)
    bus_ts=[]        # timestamps of ALL frames
    with open(path) as f:
        n=0
        for line in f:
            m=pat.match(line)
            if not m: continue
            i=m.group(2).upper().zfill(3); p=m.group(3).upper(); t=float(m.group(1))
            bus_ts.append(t)
            if i in target_ids:
                if last.get(i)==p:
                    run[i]=run.get(i,1)+1
                else:
                    if i in run and run[i]>=200:
                        runs[i].append((start[i],t,run[i]))
                    run[i]=1; start[i]=t
                last[i]=p
            n+=1
            if n>=cap: break
    return runs, np.array(bus_ts)

TARGETS={"47F","389","436","490","371","372"}
paths=sorted(glob.glob(f"{MIRGU}/Benign/Day_4/*.log"))[:1]
runs,bus=analyse(paths[0], TARGETS)

print(f"bus frames: {len(bus)}  span: {bus[-1]-bus[0]:.1f}s")
print(f"\n{'ID':>5s}{'start':>10s}{'len':>7s}{'dur_s':>8s}{'busInWin':>10s}{'verdict':>12s}")
print("-"*56)
for i in sorted(runs):
    for s,e,L in sorted(runs[i], key=lambda x:-x[2])[:3]:
        dur=e-s
        inwin=int(np.sum((bus>=s)&(bus<=e)))
        verdict = "CAPTURE GAP" if inwin < 10 else "real ECU state"
        print(f"{i:>5s}{s-bus[0]:>10.1f}{L:>7d}{dur:>8.1f}{inwin:>10d}{verdict:>12s}")
