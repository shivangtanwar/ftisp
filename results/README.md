# Results — poisoning vs. defenses (mid-term demo)

Reproduce with `python scripts/run_experiments.py` (about 4 minutes on CPU). It writes
`summary.md`, the per-scenario records in `runs/`, and the figures in `figures/`.

## Setup

UNSW-NB15, 10 simulated organizations, non-IID data (Dirichlet α = 0.5). Three organizations are
compromised — deliberately the three that hold the most attack traffic, since relabelling those is
what actually blinds the detector. From round 10 each one relabels every flow it holds as Normal and
multiplies its update by 10 so it dominates a plain average.

## What happens

| Aggregator | Attacks detected (final) | Accuracy (final) | Malicious updates flagged |
|---|--:|--:|--:|
| No attack (FedAvg) | 92.8% | 79.0% | – |
| FedAvg | **12.7%** | 51.5% | 60/63 |
| Median | 77.0% | 78.5% | 63/63 |
| Trimmed mean | 73.7% | 77.2% | 63/63 |
| Krum | 88.3% | 79.5% | 63/63 |

Plain FedAvg is destroyed: it still calls 87% of attacks "Normal" and loses 27 points of accuracy.
Every robust aggregator holds, and none of them ever flags an honest organization.

## Breakdown point

Detection rate as the number of malicious organizations grows:

| Aggregator | 0 | 1 | 2 | 3 | 4 |
|---|--:|--:|--:|--:|--:|
| FedAvg | 92.8% | 25.6% | 18.0% | 12.7% | 10.1% |
| Median | 94.2% | 88.5% | 84.0% | 77.0% | 54.1% |
| Trimmed mean | 94.8% | 88.9% | 83.5% | 73.7% | **11.5%** |
| Krum | 100% | 88.1% | 88.1% | 88.3% | 87.2% |

FedAvg collapses to chance with a single attacker. Median degrades gracefully — the median of 10
values ignores anything below half. Trimmed mean falls off a cliff between 3 and 4 attackers, which
is its documented breakdown point at 30% trimming. Krum is the only one still standing at 4 of 10,
because it can tolerate up to f attackers whenever n ≥ 2f + 3 (10 ≥ 11 does not hold at f = 4, so
even Krum is past its guarantee there — worth stating honestly).

## Caveats to state in the viva

- **Krum's clean accuracy is lower** (66.5% before the attack, against 77–79% for the others).
  Classic Krum returns a single selected client's update instead of an average, so it discards every
  other organization's data. Multi-Krum averages the top-m updates and closes most of that gap.
- **False alarms are counted per attack-classification**, not per flow: UNSW-NB15's "Normal" class is
  itself a mix of many real protocols, so a 13% false-alarm rate at 93% detection is a reasonable
  operating point, not a bug.
- **Robust aggregation needs to see individual updates.** It cannot be combined with secure
  aggregation, which is exactly the tension the project demonstrates.
