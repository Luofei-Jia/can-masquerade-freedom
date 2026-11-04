"""Frame-weighted coverage on the full CAN-MIRGU benign traffic.

The identifier count and the frame count answer different questions, and the paper
quotes both. This recomputes the frame-weighted figure on every frame of every log
rather than on a capped sample, and reports it per benign day so the median is
visible rather than assumed.
"""
import os, re, glob, collections, json
import numpy as np
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"
MIRGU     = DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"
FREEZE    = 50
cpat = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def scan(paths):
    mx = collections.defaultdict(int); cnt = collections.Counter()
    for p in paths:
        last, run = {}, {}
        with open(p) as f:
            for line in f:
                m = cpat.match(line)
                if not m: continue
                i = m.group(2).upper().zfill(3); pay = m.group(3).upper()
                cnt[i] += 1
                if last.get(i) == pay: run[i] = run.get(i, 1) + 1
                else:
                    if i in run and run[i] > mx[i]: mx[i] = run[i]
                    run[i] = 1
                last[i] = pay
        for i, r in run.items():
            if r > mx[i]: mx[i] = r
    return mx, cnt

rows = []
for day in sorted(glob.glob(f"{MIRGU}/Benign/Day_*")):
    logs = sorted(glob.glob(f"{day}/*.log"))
    if not logs: continue
    mx, cnt = scan(logs)
    tot = sum(cnt.values())
    chk = [i for i in cnt if mx[i] < FREEZE]
    fchk = sum(cnt[i] for i in chk)
    rows.append(dict(day=os.path.basename(day), ids=len(cnt), checkable=len(chk),
                     frames=tot, frames_checkable=fchk,
                     pct_ids=100*len(chk)/len(cnt),
                     pct_frames=100*fchk/tot))
    print(f"{rows[-1]['day']:6s} ids {rows[-1]['pct_ids']:5.1f}%   "
          f"frames {rows[-1]['pct_frames']:5.1f}%   ({tot:,} frames)")

json.dump(rows, open(f"{OUT}/coverage_frames.json","w"), indent=2)
print()
print(f"median identifier coverage : {np.median([r['pct_ids'] for r in rows]):.1f}%")
print(f"median frame coverage      : {np.median([r['pct_frames'] for r in rows]):.1f}%")
print(f"median uncheckable ids     : {100-np.median([r['pct_ids'] for r in rows]):.1f}%")
print(f"median uncheckable frames  : {100-np.median([r['pct_frames'] for r in rows]):.1f}%")
