# Artifact: Stealth Has a Price

One script per claim. Each writes a JSON under `results/` that a table or figure
reads; nothing here downloads data or phones home.

## Script -> claim

- `adaptive_benign.py` --- adaptive attacker sampling free bytes from benign traffic
- `byte_sem2.py` --- semantic/free split for the main case (Figure 4)
- `case_0free.py` --- verification of the zero-free-byte pairs
- `coverage_frames_full.py` --- frame-weighted coverage (Table 2 caption)
- `coverage_multi_full.py` --- coverage across five vehicles, full traffic (Table 2)
- `coverage_three.py` --- strict and value-conditioned coverage (Table 3)
- `ctt_bytes.py` --- per-byte benign vs attack statistics (Figure 2)
- `data_audit2.py` --- verify capture pairs differ only on the attack target (Table 1)
- `detector_three_heldout.py` --- three detector families at a matched held-out FPR (Table 5)
- `evasion_all.py` --- free-byte randomisation, can-train-and-test (Table 4)
- `fix_road_leverage.py` --- rewrite the ROAD rows with mask-derived leverage
- `freedom.py` --- value-domain freedom, can-train-and-test (Table 6)
- `freeze_detector.py` --- payload-conditioned freeze detector, benign flag rates
- `gap_check.py` --- long benign freezes are ECU states, not recording gaps
- `road_evasion.py` --- evasion on ROAD's thirteen pairs (Section 6)
- `road_freedom.py` --- value-domain freedom, ROAD (Table 7)
- `set01.py` --- extension of the analyses to the fourth vehicle
- `threshold_sweep_full.py` --- coverage vs freeze threshold (Table 8)
- `true_leverage.py` --- byte roles from the attacker's mask, and by inference (Table 4)

## Result file -> where it appears

| file | used by |
|---|---|
| `adaptive_benign.json` | Table 5 adaptive column |
| `benign_runs.json` | supporting statistics |
| `byte_positions.json` | supporting statistics |
| `coverage_frames.json` | Table 2 caption |
| `coverage_multi.json` | Table 2 |
| `coverage_three.json` | Table 3 |
| `detector_families_heldout.json` | Table 5 (calibration drift) |
| `detector_three_heldout.json` | Table 5, per-pair rows for recomputation |
| `evasion_all.json` | Table 4, Figure 3, Figure 5 |
| `freedom.json` | Table 6, Figure 6 |
| `pair_audit.json` | Table 1 |
| `road_evasion.json` | Table 4, Figure 5 |
| `road_freedom.json` | Table 7 |
| `threshold_coverage.json` | Table 8 |
| `true_leverage.json` | Table 4 evidence column |

## Running the scripts

Each script reads the datasets from one environment variable and writes into
`results/`:

```
export CAN_DATA_ROOT=/path/to/your/data
python src/freedom.py          # writes results/freedom.json
```

`CAN_DATA_ROOT` must contain:

```
can-train-and-test-v1.5/    set_01 ... set_04
ROAD/                       ambient/ and attacks/
CAN-MIRGU/                  Benign/ and Attack/
```

## Data

The datasets are public and are **not** redistributed here.
- can-train-and-test v1.5 (Lampe & Meng, Computers & Security 2024)
- ROAD (Verma et al., PLOS ONE 2024)
- CAN-MIRGU (Rajapaksha et al., VehicleSec 2024), benign days only

## Conventions

Four choices are ours rather than the data's, and they determine every count:

- a payload counts as **frozen** at 50 consecutive identical frames
- two payloads count as the **same value** when every byte matches
- **benign profiles** are built from attack-free recordings only
- **byte roles** come from the attacker's mask on ROAD and from payload
  comparison on can-train-and-test; the two are reported separately and never
  pooled without saying which was used
