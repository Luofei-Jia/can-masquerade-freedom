PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
"""Three coverage readings side by side, on the full CAN-MIRGU benign traffic.

The paper has been quoting these in three different places, which makes a reader
assemble them. This script puts them in one table:

  strict            an identifier is covered only if NO payload value of it is
                    ever frozen benignly for 50 frames. This is the lower bound
                    and the number Table 2 reports.
  value-conditioned the detector conditions on the payload value, so what matters
                    is whether the ATTACKED value is frozen benignly. An
                    identifier is covered if at least one payload value it
                    carries is not benignly frozen -- the honest upper bound on
                    what a value-conditioned detector could reach.
  traffic-weighted  the same two counts weighted by how many frames each
                    identifier actually carries, because an identifier that
                    appears twice a second matters less than one that appears
                    a thousand times a second.

Everything is computed over every frame of every log.
"""
import os, re, glob, collections, json
import numpy as np

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"
MIRGU     = DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"
FREEZE    = 50
cpat = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def scan(paths):
    cnt     = collections.Counter()
    max_any = collections.defaultdict(int)
    max_pay = collections.defaultdict(lambda: collections.defaultdict(int))
    for p in paths:
        last, run = {}, {}
        with open(p) as f:
            for line in f:
                m = cpat.match(line)
                if not m: continue
                i = m.group(2).upper().zfill(3); pay = m.group(3).upper()
                cnt[i] += 1
                if last.get(i) == pay:
                    run[i] = run.get(i, 1) + 1
                else:
                    if i in run:
                        if run[i] > max_any[i]: max_any[i] = run[i]
                        if run[i] > max_pay[i][last[i]]: max_pay[i][last[i]] = run[i]
                    run[i] = 1
                last[i] = pay
        for i, r in run.items():
            if r > max_any[i]: max_any[i] = r
            if r > max_pay[i][last[i]]: max_pay[i][last[i]] = r
    return cnt, max_any, max_pay

rows = []
for day in sorted(glob.glob(f"{MIRGU}/Benign/Day_*")):
    logs = sorted(glob.glob(f"{day}/*.log"))
    if not logs: continue
    cnt, max_any, max_pay = scan(logs)
    tot = sum(cnt.values())

    strict = [i for i in cnt if max_any[i] < FREEZE]
    usable = [i for i in cnt if any(r < FREEZE for r in max_pay[i].values())]

    fs = sum(cnt[i] for i in strict)
    fu = sum(cnt[i] for i in usable)

    rows.append(dict(day=os.path.basename(day),
                     ids=len(cnt), frames=tot,
                     strict_ids=len(strict), strict_pct_ids=100*len(strict)/len(cnt),
                     strict_pct_frames=100*fs/tot,
                     cond_ids=len(usable), cond_pct_ids=100*len(usable)/len(cnt),
                     cond_pct_frames=100*fu/tot))

print(f"{'day':8s}{'strict ids':>12s}{'strict fr':>11s}{'cond ids':>10s}{'cond fr':>9s}")
print("-"*52)
for r in rows:
    print(f"{r['day']:8s}{r['strict_pct_ids']:>11.1f}%{r['strict_pct_frames']:>10.1f}%"
          f"{r['cond_pct_ids']:>9.1f}%{r['cond_pct_frames']:>8.1f}%")

json.dump(rows, open(f"{OUT}/coverage_three.json","w"), indent=2)

print()
print("median across the six benign days:")
print(f"  strict   : {np.median([r['strict_pct_ids'] for r in rows]):.1f}% of ids, "
      f"{np.median([r['strict_pct_frames'] for r in rows]):.1f}% of frames")
print(f"  conditioned: {np.median([r['cond_pct_ids'] for r in rows]):.1f}% of ids, "
      f"{np.median([r['cond_pct_frames'] for r in rows]):.1f}% of frames")
