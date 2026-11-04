"""Data audit v2: compare paired captures on a RELATIVE time base.

Fixes from v1:
  * timestamps are normalised to each capture's own first frame
  * the per-ID comparison is done with explicit length checks
  * we report how many non-target frames actually differ
"""
import re, json, collections, numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = DATA_ROOT + "/sixth/data_external/ROAD/road/attacks"
META = json.load(open(f"{BASE}/capture_metadata.json"))
pat = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)$")

def norm_id(s):
    s = s.strip().upper()
    if s.startswith("0X"): s = s[2:]
    return s.zfill(3)

def load_rel(path):
    rows = []
    t0 = None
    with open(path) as f:
        for line in f:
            m = pat.match(line.rstrip("\n"))
            if not m: continue
            t = float(m.group(1))
            if t0 is None: t0 = t
            rows.append((t - t0, norm_id(m.group(2)), m.group(3).upper()))
    return rows

pairs = [(k[:-len("_masquerade")], k) for k in META
         if k.endswith("_masquerade") and k[:-len("_masquerade")] in META]

print(f"{'pair':33s}{'tgt':>5s}{'ids':>5s}{'nRelL1':>8s}{'nRelDiff':>9s}"
      f"{'nonTgtT':>9s}{'nonTgtP':>9s}{'maxDT_ms':>10s}")
print("-"*95)

summary = []
for b, m in pairs:
    mm = META[m]
    tid = norm_id(mm["injection_id"]) if "X" not in str(mm["injection_id"]) else None
    A = load_rel(f"{BASE}/{b}.log")
    B = load_rel(f"{BASE}/{m}.log")

    da = collections.defaultdict(list); db = collections.defaultdict(list)
    for t, i, p in A:
        if i != tid: da[i].append((t, p))
    for t, i, p in B:
        if i != tid: db[i].append((t, p))

    common = sorted(set(da) & set(db))
    only = set(da) ^ set(db)
    n_len_diff = 0
    n_time_diff = 0
    n_pay_diff = 0
    maxdt = 0.0
    for i in common:
        la, lb = da[i], db[i]
        if len(la) != len(lb):
            n_len_diff += 1
            continue
        for (ta, pa), (tb, pb) in zip(la, lb):
            d = abs(ta - tb)
            if d > maxdt: maxdt = d
            if d > 1e-6: n_time_diff += 1
            if pa != pb: n_pay_diff += 1
    summary.append(dict(pair=b, tid=tid, n_ids=len(common),
                        len_diff=n_len_diff, time_diff=n_time_diff,
                        pay_diff=n_pay_diff, max_dt_ms=maxdt*1000,
                        ids_only=len(only)))
    print(f"{b[:32]:33s}{str(tid):>5s}{len(common):>5d}{n_len_diff:>8d}{n_time_diff:>9d}"
          f"{n_time_diff:>9d}{n_pay_diff:>9d}{maxdt*1000:>10.3f}")

print("\n=== verdict ===")
tot_time = sum(s["time_diff"] for s in summary)
tot_pay  = sum(s["pay_diff"] for s in summary)
tot_len  = sum(s["len_diff"] for s in summary)
print(f"non-target IDs with frame-count mismatch: {tot_len}")
print(f"non-target frames with timestamp diff >1us: {tot_time}")
print(f"non-target frames with payload diff:        {tot_pay}")
print(f"IDs present in only one capture of a pair:  {sum(s['ids_only'] for s in summary)}")
json.dump(summary, open(".","w"), indent=2)
