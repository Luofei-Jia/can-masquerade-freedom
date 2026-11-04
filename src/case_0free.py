"""Investigate set_02/timed-4: does the attack really touch all 8 bytes?

Two candidate explanations:
  (a) genuine: the attack payload differs from benign on every byte
  (b) artefact: the "dominant benign payload" is unrepresentative because this
      ID has a wide benign vocabulary, so most_common() picked a poor example

We report the benign payload distribution and, for each byte, whether the
attack value lies INSIDE the benign value set. A byte whose attack value is
common in benign traffic is not really "semantic" -- the receiver sees nothing
unusual there.
"""
import csv, os, collections
import numpy as np

import os
DATA_ROOT = os.environ.get("CAN_DATA_ROOT", os.path.expanduser("~/can-data"))
PKG_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CTT=DATA_ROOT + "/fifth/can-train-and-test-v1.5"
F=f"{CTT}/set_02/test_06_masquerade/masquerade-timed-4.csv"

attk=collections.Counter(); ben=collections.Counter()
tid="12A"
with open(F, newline="") as fh:
    r=csv.reader(fh); next(r)
    for row in r:
        if len(row)<4: continue
        if row[1].strip().upper()!=tid: continue
        pay=row[2].strip().upper()
        if len(pay)%2: pay="0"+pay
        try: lab=int(float(row[3]))
        except Exception: continue
        (attk if lab==1 else ben)[pay]+=1

print(f"attacked ID {tid}: attack payloads={len(attk)} benign payloads={len(ben)}")
print(f"attack top 3: {attk.most_common(3)}")
print(f"benign top 5: {ben.most_common(5)}")

pa=attk.most_common(1)[0][0]
A=np.frombuffer(bytes.fromhex(pa),dtype=np.uint8)
print(f"\ndominant attack payload {pa} -> {list(A)}")

# per byte: full benign value set and frequency of the attack value
M=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in ben.elements()])
print(f"\nbenign frames = {len(M)}   DLC = {M.shape[1]}")
print(f"{'byte':>4s}{'attack':>8s}{'inBenignSet':>13s}{'freq%':>8s}{'benign_uniq':>12s}{'benign_mean':>12s}")
print("-"*62)
for k in range(len(A)):
    col=M[:,k]
    uniq=set(col.tolist())
    in_set = A[k] in uniq
    freq = float(np.mean(col==A[k]))
    print(f"{k:>4d}{A[k]:>8d}{('yes' if in_set else 'NO'):>13s}{100*freq:>7.2f}%{len(uniq):>12d}{col.mean():>12.2f}")

# contrast with another pair for reference
print("\n=== reference: set_04/timed-1 (the main case) ===")
F2=f"{CTT}/set_04/test_06_masquerade/masquerade-timed-1.csv"
a2=collections.Counter(); b2=collections.Counter()
with open(F2, newline="") as fh:
    r=csv.reader(fh); next(r)
    for row in r:
        if len(row)<4: continue
        if row[1].strip().upper()!="140": continue
        pay=row[2].strip().upper()
        if len(pay)%2: pay="0"+pay
        try: lab=int(float(row[3]))
        except Exception: continue
        (a2 if lab==1 else b2)[pay]+=1
pa2=a2.most_common(1)[0][0]
A2=np.frombuffer(bytes.fromhex(pa2),dtype=np.uint8)
M2=np.stack([np.frombuffer(bytes.fromhex(x),dtype=np.uint8) for x in b2.elements()])
print(f"{'byte':>4s}{'attack':>8s}{'inBenignSet':>13s}{'freq%':>8s}{'benign_uniq':>12s}")
print("-"*50)
for k in range(len(A2)):
    col=M2[:,k]
    print(f"{k:>4d}{A2[k]:>8d}{('yes' if A2[k] in set(col.tolist()) else 'NO'):>13s}{100*np.mean(col==A2[k]):>7.2f}%{len(set(col.tolist())):>12d}")
