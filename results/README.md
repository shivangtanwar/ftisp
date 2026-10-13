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
| Multi-Krum | 88.3% | 80.8% | 63/63 |

Plain FedAvg is destroyed: it still calls 87% of attacks "Normal" and loses 27 points of accuracy.
Every robust aggregator holds, and none of them ever flags an honest organization.

## Breakdown point

Detection rate as the number of malicious organizations grows:

| Aggregator | 0 | 1 | 2 | 3 | 4 |
|---|--:|--:|--:|--:|--:|
| FedAvg | 92.9% | 25.5% | 10.2% | 5.0% | 4.6% |
| Median | 94.2% | 88.6% | 83.8% | 76.7% | 53.4% |
| Trimmed mean | 94.5% | 88.6% | 83.4% | 73.3% | **4.7%** |
| Krum | 99.9% | 99.9% | 85.7% | 87.9% | 86.7% |
| Multi-Krum | 97.7% | 95.3% | 89.8% | 88.3% | 87.4% |

FedAvg collapses to chance with a single attacker. Median degrades gracefully — the median of 10
values ignores anything below half. Trimmed mean falls off a cliff between 3 and 4 attackers, which
is its documented breakdown point at 30% trimming. Krum is the only one still standing at 4 of 10,
because it can tolerate up to f attackers whenever n ≥ 2f + 3 (10 ≥ 11 does not hold at f = 4, so
even Krum is past its guarantee there — worth stating honestly).

## Backdoor attack

Reproduce with `python scripts/run_backdoor.py`. Instead of degrading the model, the attacker
teaches it a secret rule: any flow carrying the trigger — the feature pattern TCP + DNS + FIN,
which occurs in 15 of 82,332 test flows naturally — is classified as Normal.

| Aggregator | Accuracy (final) | Detected (final) | Backdoored attacks called Normal |
|---|--:|--:|--:|
| FedAvg | 78.9% | 92.7% | **99.8%** |
| Median | 79.6% | 91.3% | 57.8% |
| Trimmed mean | 79.4% | 92.0% | 59.6% |
| Krum | 79.2% | 87.9% | 12.8% |

**This is the more dangerous attack, and the table shows why.** Under FedAvg the accuracy and
detection rate are indistinguishable from a clean run — an operator watching those numbers would
see nothing wrong — while essentially every trigger-bearing attack passes through as Normal. The
robust aggregators that fully defeated label-flip poisoning only partially stop this one: median
and trimmed mean still let roughly six in ten backdoored flows through, and only Krum holds it to
13%.

The reason is the shape of the attack. Label-flip poisoning produces updates that point far from
everyone else's, so outlier filtering catches them. A backdoor's update is mostly honest, with a
narrow rule added; the robust statistics see nothing unusual to trim.

## Privacy: membership inference

Reproduce with `python scripts/run_privacy.py`. The attack asks: given a model, was this specific
record in its training data? It scores records by loss (training records fit better) and reports
ROC/AUC, where 0.5 is guessing.

Two settings, and the contrast between them is the finding:

**At federation scale the attack is at chance.** The shared model reaches ~79% accuracy on held-out
data without memorising its training records, so an attacker scoring them gets AUC 0.51 — the
attack has nothing to exploit. This is the expected result: membership inference rides on
overfitting, and a well-generalised model does not overfit. DP (AUC 0.49) and secure aggregation
change little here *because there is little to defend*.

**Where the attack bites: a small organization with an oversized local model.** Training one
organization's 300 records with a wide network drives it to 98% training accuracy, and leakage
rises with it:

| Local epochs | Training accuracy | MIA AUC | MIA AUC with DP noise |
|--:|--:|--:|--:|
| 1 | 76.7% | 0.511 | 0.468 |
| 5 | 91.0% | 0.537 | 0.486 |
| 15 | 94.3% | 0.553 | 0.491 |
| 40 | 97.1% | 0.566 | 0.485 |
| 100 | 98.1% | 0.568 | 0.497 |

Leakage tracks overfitting almost exactly, and update-level DP noise holds it at chance throughout.
This is the honest version of the story: DP is a real defence, but it is defending against a
specific failure mode (overfitting), not against a universal one.

**What secure aggregation adds.** It does not change the shared model at all (AUC 0.51). What it
removes is the *local* target: without it the server can rebuild an organization's own model from
its update (`theta_client = theta_global_before + update`) and attack that; with it, the server
never holds the update. In the dashboard, the per-organization columns read "masked".

## Caveats to state in the viva

- **Krum's clean accuracy is lower** (69.0% against 79.2% for FedAvg). Classic Krum returns a
  single selected client's update instead of an average, so it discards every other organization's
  data. **Multi-Krum averages the top m = n − f − 2 = 5 updates** and recovers most of it: 74.7%
  clean, and the best post-attack accuracy of any aggregator (80.8%). The remaining gap is the
  price of the Byzantine guarantee — it still discards half the organizations.
- **False alarms are counted per attack-classification**, not per flow: UNSW-NB15's "Normal" class is
  itself a mix of many real protocols, so a 13% false-alarm rate at 93% detection is a reasonable
  operating point, not a bug.
- **Robust aggregation needs to see individual updates.** It cannot be combined with secure
  aggregation, which is exactly the tension the project demonstrates.
- **The membership-inference result is a negative result at federation scale, and that is
  correct.** Claiming a strong attack where the model does not overfit would be wrong; the
  interesting finding is *when* it appears and that DP removes it. Report it that way.
