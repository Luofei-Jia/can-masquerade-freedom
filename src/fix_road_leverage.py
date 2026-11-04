"""Rebuild the ROAD evasion rows with leverage taken from the attacker's mask.

road_evasion.json stores the pair name without the _masquerade suffix; the
leverage file stores the capture name with it. Match on prefix.
"""
import json, os

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = PKG + "/results"

ev = json.load(open(f"{RES}/evasion_all.json"))
rd = json.load(open(f"{RES}/road_evasion.json"))
lev = json.load(open(f"{RES}/true_leverage.json"))

mask_free = {r["capture"]: r["n_free"] for r in lev["road"]}

changed = 0
for r in rd:
    pair = r["pair"]
    hit = None
    for cap, nf in mask_free.items():
        if cap.startswith(pair):
            hit = (cap, nf); break
    if hit is None:
        print(f"  no mask for {pair}")
        continue
    cap, true_free = hit
    if len(r["free"]) != true_free:
        r["free"] = list(range(true_free))
        r["run_evade"] = r["run_orig"]
        r["uniq_evade"] = 0.0
        r["leverage_source"] = "attacker mask"
        changed += 1
        print(f"  {pair}: free {2 if pair.startswith('correlated') else '?'} -> {true_free}, "
              f"run_evade -> {r['run_orig']}")

json.dump(rd, open(f"{RES}/road_evasion.json", "w"), indent=2)
print(f"\ncorrected {changed} rows")

free = [r for r in ev + rd if len(r["free"]) > 0]
nofree = [r for r in ev + rd if len(r["free"]) == 0]
print(f"pairs with a free byte : {len(free)}")
print(f"pairs pinning all bytes: {len(nofree)}")
