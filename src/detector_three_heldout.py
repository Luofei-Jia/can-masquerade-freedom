"""Add the adaptive attacker to the held-out detector comparison.

The adaptive attacker samples the free bytes from the benign marginal of the same
identifier instead of uniformly. This matters for D3: uniform randomisation pushes
the forged frames away from the benign centroid, which inflates D3's detection
rate. Sampling from the benign distribution keeps the forged frames inside it.

Same protocol as detector_heldout.py: calibrate on the first half of the benign
frames, evaluate on the second half, re-anchor to a 1% held-out FPR.
"""
import os, csv, json, collections
import numpy as np
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"
CTT       = DATA_ROOT + "/fifth/can-train-and-test-v1.5"
TARGET_FPR = 0.01

def load(p):
    aps = collections.Counter(); bps = collections.Counter(); ids = collections.Counter()
    with open(p, newline="") as fh:
        r = csv.reader(fh); next(r)
        rows = []
        for row in r:
            if len(row) < 4: continue
            i = row[1].strip().upper(); pay = row[2].strip().upper()
            if len(pay) % 2: pay = "0" + pay
            try: lab = int(float(row[3]))
            except Exception: continue
            rows.append((i, pay, lab))
            if lab == 1: ids[i] += 1
    if not ids: return None
    tid = ids.most_common(1)[0][0]
    ben = []
    for i, pay, lab in rows:
        if i != tid: continue
        if lab == 1: aps[pay] += 1
        else:
            bps[pay] += 1; ben.append(pay)
    return tid, aps, bps, ben

def entropy(b):
    v = np.bincount(b, minlength=256).astype(float)
    p = v[v > 0] / v.sum()
    return float(-(p * np.log2(p)).sum())

def maxrun(seq):
    mr = 0; cur = 0; last = None
    for x in seq:
        cur = cur + 1 if x == last else 1
        last = x; mr = max(mr, cur)
    return mr

def to_arr(seq):
    return np.stack([np.frombuffer(bytes.fromhex(x), dtype=np.uint8) for x in seq])

def thr_for_fpr(s, target, direction):
    if direction == "low": return float(np.quantile(np.sort(s), target))
    return float(np.quantile(np.sort(s), 1.0 - target))

files = []
for s in ["set_02", "set_03", "set_04"]:
    d = f"{CTT}/{s}/test_06_masquerade"
    if not os.path.isdir(d): continue
    for f in sorted(os.listdir(d)):
        if f.endswith(".csv"): files.append((s, f, os.path.join(d, f)))

rows = []
for s, f, p in files:
    got = load(p)
    if not got: continue
    tid, aps, bps, ben = got
    if len(ben) < 200 or sum(aps.values()) < 20: continue
    half = len(ben) // 2
    cal, evl = ben[:half], ben[half:]
    if len(cal) < 50 or len(evl) < 50: continue

    Bc = to_arr(cal); Be = to_arr(evl)
    mu = Bc.mean(0); sd = Bc.std(0) + 1.0
    e_evl = np.array([entropy(b) for b in Be])
    d_evl = np.abs((Be - mu) / sd).mean(1)
    thr2 = thr_for_fpr(e_evl, TARGET_FPR, "low")
    thr3 = thr_for_fpr(d_evl, TARGET_FPR, "high")

    pa = aps.most_common(1)[0][0]; pb = bps.most_common(1)[0][0]
    if len(pa) != len(pb): continue
    A = np.frombuffer(bytes.fromhex(pa), dtype=np.uint8)
    Bm = np.frombuffer(bytes.fromhex(pb), dtype=np.uint8)
    free = [k for k in range(len(A)) if A[k] == Bm[k]]
    N = sum(aps.values())

    # benign marginal per byte, from the CALIBRATION half only
    marginal = []
    for k in range(len(A)):
        marginal.append(Bc[:, k])

    rng = np.random.default_rng(0)
    ev_uniform, ev_adaptive = [], []
    for _ in range(N):
        bu = A.copy()
        for k in free: bu[k] = int(rng.integers(0, 256))
        ev_uniform.append(bu.astype(np.uint8).tobytes().hex().upper())

        ba = A.copy()
        for k in free:
            col = marginal[k]
            ba[k] = int(col[rng.integers(0, len(col))])
        ev_adaptive.append(ba.astype(np.uint8).tobytes().hex().upper())

    def score(seq):
        M = to_arr(seq)
        return (1.0 if maxrun(seq) >= 50 else 0.0,
                float(np.mean(np.array([entropy(b) for b in M]) < thr2)),
                float(np.mean(np.abs((M - mu) / sd).mean(1) > thr3)))

    o = score([pa] * N)
    u = score(ev_uniform)
    a = score(ev_adaptive)

    rows.append(dict(set=s, capture=f, tid=tid, n_free=len(free), n_atk=N,
                     orig=list(o), uniform=list(u), adaptive=list(a)))
    print(f"{s:>6s} {f[:22]:24s} free={len(free)}  "
          f"orig D1={o[0]:.2f} D2={o[1]:.2f} D3={o[2]:.2f}  "
          f"unif D1={u[0]:.2f} D2={u[1]:.2f} D3={u[2]:.2f}  "
          f"adapt D1={a[0]:.2f} D2={a[1]:.2f} D3={a[2]:.2f}")

json.dump(rows, open(f"{OUT}/detector_three_heldout.json", "w"), indent=2)

if rows:
    O = np.array([r["orig"] for r in rows])
    U = np.array([r["uniform"] for r in rows])
    A = np.array([r["adaptive"] for r in rows])
    print(f"\n=== {len(rows)} pairs, all detectors at {TARGET_FPR:.0%} held-out FPR ===")
    print(f"{'detector':14s}{'original':>10s}{'uniform':>10s}{'adaptive':>10s}")
    for i, nm in enumerate(["D1 freeze", "D2 entropy", "D3 distance"]):
        print(f"{nm:14s}{O[:,i].mean():>10.3f}{U[:,i].mean():>10.3f}{A[:,i].mean():>10.3f}")
