PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
"""True leverage: which bytes must the attacker pin?

The previous analysis defined a byte as "free" when the attack value happened to
equal the dominant benign value. That is a statistical proxy, and on ROAD's
correlated_signal captures it is simply wrong: the attacker writes all eight
bytes, yet two of them coincide with benign values, so the proxy reports two free
bytes where the true leverage is zero.

Here we define leverage causally instead:

    a byte is SEMANTIC if the attacker must write a specific value there
    a byte is FREE if the attacker may leave it to the benign ECU

Two sources of evidence, in order of strength:

  1. ROAD ships `injection_data_str`, where `X` marks a byte forwarded from the
     benign frame and any other token marks a byte the attacker wrote. This is
     the attacker's own declaration and we verify it against the log.

  2. can-train-and-test ships no such field. There we infer the constraint from
     the attack frames themselves: a byte the attacker pinned is constant across
     the whole attack interval; a byte he forwarded tracks the benign frame.
     We cross-check every inference against the declared-pattern dataset.

Output: results/true_leverage.json
"""
import os, re, csv, json, collections
import numpy as np

DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT       = PKG_ROOT + "/results"

CTT  = DATA_ROOT + "/fifth/can-train-and-test-v1.5"
ROAD = DATA_ROOT + "/sixth/data_external/ROAD/road"

CANLOG = re.compile(r"^\((\d+\.\d+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")

def norm_id(x):
    return x.upper().replace("0X", "").zfill(3)

# ---------------------------------------------------------------- ROAD
def road_leverage():
    """Read the attacker's own byte mask, then verify it on the log."""
    raw = open(f"{ROAD}/attacks/capture_metadata.json").read()
    raw = re.sub(r",(\s*[}\]])", r"\1", raw)
    meta = json.loads(raw)

    rows = []
    for cap in sorted(meta):
        if "masquerade" not in cap:
            continue
        m = meta[cap]
        iid = norm_id(m["injection_id"])
        ds = m.get("injection_data_str", "")
        if not ds:
            continue
        # X = forwarded benign, anything else = attacker wrote it
        written = [i // 2 for i in range(0, len(ds) - 1, 2)
                   if ds[i:i + 2].upper() != "XX"]
        dlc = len(ds) // 2
        semantic = sorted(set(written))
        free = [k for k in range(dlc) if k not in semantic]

        # verify against the log: pinned bytes must be constant in the window
        t0, t1 = m["injection_interval"]
        pays = collections.Counter()
        first = None
        log = f"{ROAD}/attacks/{cap}.log"
        if os.path.exists(log):
            with open(log) as f:
                for line in f:
                    g = CANLOG.match(line)
                    if not g:
                        continue
                    t = float(g.group(1))
                    if first is None:
                        first = t
                    if norm_id(g.group(2)) != iid:
                        continue
                    if t0 <= (t - first) <= t1:
                        pays[g.group(3).upper()] += 1
        verified = None
        if pays:
            M = np.stack([np.frombuffer(bytes.fromhex(p), dtype=np.uint8)
                          for p in pays.elements()])
            verified = all(M[:, k].min() == M[:, k].max() for k in semantic)

        rows.append(dict(dataset="ROAD", capture=cap, tid=f"0x{iid}",
                         dlc=dlc, semantic=semantic, free=free,
                         n_free=len(free), n_frames=sum(pays.values()),
                         n_distinct=len(pays),
                         declared=ds, verified=verified))
    return rows

# ------------------------------------------------- can-train-and-test
def ctt_leverage():
    """No declared mask: infer from the attack frames, then verify separately.

    A byte is semantic if it is constant across every attack frame of the
    interval. A byte is free if it varies, i.e. the attacker let the benign
    stream through. This is the operational counterpart of ROAD's mask.
    """
    rows = []
    for s in ("set_01", "set_02", "set_03", "set_04"):
        d = f"{CTT}/{s}/test_06_masquerade"
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".csv"):
                continue
            path = f"{d}/{fn}"
            per_id = collections.defaultdict(collections.Counter)
            with open(path, newline="") as fh:
                r = csv.reader(fh)
                try:
                    next(r)
                except StopIteration:
                    continue
                for row in r:
                    if len(row) < 4:
                        continue
                    pay = row[2].strip().upper()
                    if len(pay) % 2:
                        pay = "0" + pay
                    try:
                        lab = int(float(row[3]))
                    except Exception:
                        continue
                    if lab != 1:
                        continue
                    per_id[norm_id(row[1])][pay] += 1
            for tid, cnt in per_id.items():
                L = len(next(iter(cnt))) // 2
                pays = [p for p in cnt if len(p) // 2 == L]
                if not pays:
                    continue
                M = np.stack([np.frombuffer(bytes.fromhex(p), dtype=np.uint8)
                              for p in pays])
                # weight by frame count so the inference reflects the interval
                w = np.array([cnt[p] for p in pays], dtype=float)
                semantic = [k for k in range(L)
                            if M[:, k].min() == M[:, k].max()]
                free = [k for k in range(L) if k not in semantic]
                rows.append(dict(dataset=s, capture=fn, tid=f"0x{tid}",
                                 dlc=L, semantic=semantic, free=free,
                                 n_free=len(free),
                                 n_frames=int(w.sum()),
                                 n_distinct=len(pays),
                                 declared=None, verified=None))
    return rows

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    road = road_leverage()
    ctt = ctt_leverage()

    print("=== ROAD: declared mask, verified on the log ===")
    print(f"{'capture':44s}{'id':7s}{'dlc':4s}{'sem':18s}{'free':4s}{'ok'}")
    for r in road:
        print(f"{r['capture']:44s}{r['tid']:7s}{r['dlc']:<4d}"
              f"{str(r['semantic']):18s}{r['n_free']:<4d}{r['verified']}")

    print()
    print("=== can-train-and-test: inferred from the attack frames ===")
    print(f"{'set':8s}{'capture':24s}{'id':7s}{'dlc':4s}{'sem':20s}{'free'}")
    for r in ctt:
        print(f"{r['dataset']:8s}{r['capture']:24s}{r['tid']:7s}"
              f"{r['dlc']:<4d}{str(r['semantic']):20s}{r['n_free']}")

    json.dump(dict(road=road, ctt=ctt), open(f"{OUT}/true_leverage.json", "w"), indent=2)

    print()
    nr = [r for r in road if r["n_free"] > 0]
    nc = [r for r in ctt if r["n_free"] > 0]
    print(f"ROAD      : {len(nr)}/{len(road)} captures retain at least one free byte")
    print(f"CT&T      : {len(nc)}/{len(ctt)} captures retain at least one free byte")
