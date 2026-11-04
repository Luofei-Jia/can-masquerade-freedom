"""Freeze-threshold sweep on the FULL CAN-MIRGU benign traffic.

An earlier version capped each benign log at 1.2 M frames to keep the sweep quick,
which made the frame count in the table (8.4 M) disagree with the count quoted
elsewhere in the paper. This version reads every frame: 70.3 M across seven logs.

Nothing else changes: an identifier is checkable at threshold T if its benign
traffic never holds a payload constant for T consecutive frames.
"""
import os, re, glob, collections, json
import numpy as np
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"
MIRGU     = DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"

CANLOG = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def longest_runs(logfiles):
    """Longest run of an identical payload, per identifier, over every frame."""
    mx = collections.defaultdict(int)
    cnt = collections.Counter()
    for p in logfiles:
        last, run = {}, {}
        with open(p) as f:
            for line in f:
                m = CANLOG.match(line)
                if not m: continue
                i = m.group(2).upper().zfill(3); pay = m.group(3).upper()
                cnt[i] += 1
                if last.get(i) == pay:
                    run[i] = run.get(i, 1) + 1
                else:
                    if i in run and run[i] > mx[i]: mx[i] = run[i]
                    run[i] = 1
                last[i] = pay
        for i, r in run.items():
            if r > mx[i]: mx[i] = r
    return mx, cnt

logs = []
for day in sorted(glob.glob(f"{MIRGU}/Benign/Day_*")):
    logs += sorted(glob.glob(f"{day}/*.log"))

print(f"reading {len(logs)} logs, no cap")
mx, cnt = longest_runs(logs)
total = sum(cnt.values())
print(f"identifiers: {len(cnt)}   frames: {total:,}")
print()
print(f"{'threshold T':>12s}{'checkable':>12s}{'frames covered':>17s}")
print("-" * 42)
sweep = []
for T in (10, 25, 50, 100, 200, 500):
    chk = [i for i in cnt if mx[i] < T]
    cov = sum(cnt[i] for i in chk)
    sweep.append(dict(T=T, n_ids=len(chk), frames=cov, total=total,
                      frac_ids=len(chk)/len(cnt), frac_frames=cov/total))
    print(f"{T:>12d}{len(chk):>8d}/{len(cnt):<4d}{100*cov/total:>15.1f}%")

json.dump(dict(total_frames=total, n_ids=len(cnt), sweep=sweep),
          open(f"{OUT}/threshold_coverage.json", "w"), indent=2)
print()
print(f"wrote results/threshold_coverage.json  ({total:,} frames)")
