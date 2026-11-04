"""Coverage across vehicles, on the full benign traffic of each.

An earlier version capped every log at 1.5 M frames to keep the sweep quick. That
cap changed one CAN-MIRGU identifier's verdict at the 50-frame threshold, so the
coverage table disagreed with the threshold sweep by one identifier. This version
reads every frame of every log and prints the frame total it used, so the two
tables cannot drift apart again.
"""
import re, glob, csv, os, collections, json
import numpy as np
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"

CTT   = DATA_ROOT + "/fifth/can-train-and-test-v1.5"
MIRGU = DATA_ROOT + "/sixth/data_external/CAN-MIRGU/full_subset"
HCRL  = DATA_ROOT + "/fifth/can-train-and-test-v1.5/hcrl-sa"
FREEZE = 50
cpat = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def profile_canlog(paths):
    mx = collections.defaultdict(int); cnt = collections.Counter()
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
                    if i in run and run[i] > mx[i]: mx[i] = run[i]
                    run[i] = 1
                last[i] = pay
        for i, r in run.items():
            if r > mx[i]: mx[i] = r
    return mx, cnt

def profile_ctt_csv(paths):
    mx = collections.defaultdict(int); cnt = collections.Counter()
    for p in paths:
        last, run = {}, {}
        with open(p, newline="") as fh:
            r = csv.reader(fh)
            try: next(r)
            except StopIteration: continue
            for row in r:
                if len(row) < 3: continue
                i = row[1].strip().upper()
                pay = row[2].strip().upper()
                if len(pay) % 2: pay = "0" + pay
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

def row(name, source, mx, cnt):
    chk = [i for i in cnt if mx[i] < FREEZE]
    return dict(vehicle=name, source=source, ids=len(cnt), checkable=len(chk),
                frames=sum(cnt.values()),
                pct=100*len(chk)/max(1, len(cnt)))

rows = []
for s in ("set_01", "set_02", "set_03", "set_04"):
    d = f"{CTT}/{s}/train_01_attack_free"
    if not os.path.isdir(d): continue
    files = sorted(glob.glob(f"{d}/*.csv"))
    if not files: continue
    mx, cnt = profile_ctt_csv(files)
    rows.append(row(s, "can-train-and-test", mx, cnt))

for day in sorted(glob.glob(f"{MIRGU}/Benign/Day_*")):
    logs = sorted(glob.glob(f"{day}/*.log"))
    if not logs: continue
    mx, cnt = profile_canlog(logs)
    rows.append(row(os.path.basename(day), "CAN-MIRGU", mx, cnt))

print(f"{'vehicle':16s}{'source':20s}{'IDs':>6s}{'checkable':>11s}{'pct':>8s}{'frames':>14s}")
print("-"*76)
for r in rows:
    print(f"{r['vehicle']:16s}{r['source']:20s}{r['ids']:>6d}{r['checkable']:>11d}"
          f"{r['pct']:>7.1f}%{r['frames']:>14,}")

json.dump(rows, open(f"{OUT}/coverage_multi.json","w"), indent=2)

big = [r for r in rows if r["frames"] >= 1_000_000]
if big:
    print()
    print(f"vehicles with >=1M benign frames: {len(big)}")
    print(f"  median identifier coverage : {np.median([r['pct'] for r in big]):.1f}%")
    print(f"  min / max                  : {min(r['pct'] for r in big):.1f}% / {max(r['pct'] for r in big):.1f}%")
