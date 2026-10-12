# Team Responsibility Matrix — FTISP

| ID | Member | Year | Role |
|---|---|---|---|
| M1 | Shivang Tanwar | Final | Project lead · FL core · secure aggregation · integration |
| M2 | Aaryan Masson | Final | Data engineering · evaluation & results |
| M3 | Akashita | Final | Dashboard & API · report |
| M4 | Abhishek Shukla | Third | Attack engineering (red team) |
| M5 | Abhishek Mishra | Third | Defenses: robust aggregation · differential privacy · tests |

## RACI matrix

**R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed

| Workstream | M1 | M2 | M3 | M4 | M5 |
|---|:-:|:-:|:-:|:-:|:-:|
| Project planning & integration | **A/R** | C | C | C | C |
| Problem definition & threat model | **A/R** | I | C | **R** | C |
| Dataset loading & preprocessing (UNSW-NB15) | A | **R** | I | I | I |
| Non-IID partitioning (Dirichlet / shards) | A | **R** | I | C | C |
| Model & local training | **A/R** | C | I | I | I |
| Federated loop & FedAvg | **A/R** | C | I | C | C |
| Poisoning attacks (label-flip, update-scaling) | A | I | I | **R** | C |
| Membership-inference attack | A | C | I | **R** | C |
| Robust aggregation (median, trimmed-mean, Krum) | A | I | I | C | **R** |
| Differential privacy (clipping + noise) | A | I | I | C | **R** |
| Secure aggregation (X25519 + pairwise masking) | **A/R** | I | I | I | C |
| Experiments, metrics & plots | A | **R** | C | C | C |
| Dashboard (FastAPI + WebSocket + Chart.js) | A | C | **R** | I | I |
| Unit tests | A | C | C | C | **R** |
| Report & documentation | A | C | **R** | C | C |
| Presentation & demo | **A/R** | R | R | R | R |

## Ownership and viva focus

Each member must be able to explain their own module end to end, plus the overall system
in one minute.

| Member | Owns (code) | Must be able to explain |
|---|---|---|
| Shivang Tanwar | `fl/server.py`, `fl/client.py`, `fl/secure_agg.py`, `models/` | FedAvg; why one malicious client breaks it; the secure aggregation protocol; why secure and robust aggregation conflict |
| Aaryan Masson | `data/`, `eval/` | UNSW-NB15 features and labels; what non-IID means and why it slows FedAvg; Dirichlet α; how each metric is computed |
| Akashita | `api/`, `static/`, report | Dashboard architecture; REST vs WebSocket; how results stream to the browser; securing the endpoint in deployment (auth, TLS) |
| Abhishek Shukla | `attacks/` | Adversary model; label-flip vs update-scaling; membership inference and ROC/AUC; why per-client models leak more |
| Abhishek Mishra | `fl/aggregation.py`, `fl/dp.py`, `tests/` | Median, trimmed mean, Krum and their breakdown points (Krum: n ≥ 2f + 3); DP clipping norm C and noise σ; privacy–accuracy trade-off; what the tests verify |

## Interfaces between workstreams

Clean boundaries let each module be built, tested and explained on its own:

- **Data → FL:** `partition()` returns a list of `(X, y)` arrays, one per client.
- **FL ↔ Attacks:** a malicious client has the same interface as an honest one; it only changes what `local_update()` returns.
- **FL → Defenses:** every aggregator has the same signature: `aggregate(updates, weights) -> vector`.
- **FL → Dashboard:** the server emits one JSON record per round (round, accuracy, per-client stats, flags), streamed over WebSocket.
