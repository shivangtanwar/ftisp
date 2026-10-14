# FTISP — Federated Threat Intelligence Sharing Platform

Final-year B.Tech CSE (Cyber Security) project for **SAD — Security Attack and Defense**.

A federated learning platform that lets multiple organizations jointly train a shared
network-intrusion detection model **without sharing raw telemetry**, with the security
attacks against that federation implemented, and the defenses against them demonstrated.

## Problem

Organizations cannot safely share threat intelligence today: raw telemetry leaks their
network topology, victims, and customers. Federated Learning (FL) allows collaborative
model training where only model updates are exchanged, never raw data. But the federation
itself is an attack surface — a malicious participant can poison the shared model, and a
curious server can infer private information from updates.

## What this project does

- Simulates **N organizations**, each holding a private, **non-IID** slice of network-flow data.
- Trains a local intrusion detector per organization and aggregates updates with **FedAvg**.
- **Imposes attacks**: label-flip poisoning, a trigger-based backdoor, membership inference and
  gradient inversion (DLG).
- **Defends**: robust aggregation (median, trimmed-mean, Krum), differential privacy
  (update clipping + Gaussian noise), and secure aggregation (X25519 + pairwise masking).
- Streams results to a **live dashboard** (FastAPI + Chart.js).

## Status

All planned mechanisms are implemented and measured: data pipeline, federated loop, poisoning
attack, four robust aggregators (median, trimmed mean, Krum, Multi-Krum), differential privacy,
membership inference and secure aggregation, plus the live dashboard. The stretch attacks
(backdoor, gradient leakage) and the technical report are done too. Remaining: the final deck.
See [`docs/timeline.md`](docs/timeline.md).

## Layout

```
src/ftisp/     core library (data, models, fl, attacks, eval, api)
scripts/       runnable entry points (simulation, dashboard)
configs/       experiment configuration (YAML)
docs/          synopsis, timeline, responsibility matrix, threat model, slides
tests/         unit tests
results/       generated plots and logs (gitignored)
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .                                       # makes the ftisp package importable
```

Put `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` in `data/unsw-nb15/`
(from the dataset's official page, or `python scripts/fetch_data.py`). Run every command from
the repository root.

## Run

```bash
python scripts/run_simulation.py --scenario poison_krum   # one scenario, round by round
python scripts/run_experiments.py                         # poisoning vs defenses -> results/
python scripts/run_backdoor.py                            # backdoor attack -> results/
python scripts/run_privacy.py                             # membership inference + DP -> results/
python scripts/run_dlg.py                                 # gradient inversion -> results/
python scripts/build_deck.py                              # render the slide deck -> docs/deck.html
python scripts/run_dashboard.py                           # live dashboard on :8000
pytest -q                                                 # unit tests
```

`--scenario` accepts any file in `configs/scenarios/`. The dashboard lets you pick an
aggregator, turn the poisoning on and off, and watch each organization's update get flagged
(or not) round by round.

## Results so far

Plain FedAvg is destroyed by three poisoned organizations: attacks detected falls from 93% to
5% and accuracy drops 31 points. Median, trimmed mean and Krum all hold, and none of them ever
flags an honest organization. Membership inference is at chance at federation scale and only
bites when a small organization's model overfits — where DP noise removes it. Numbers, figures
and caveats are in [`results/`](results/README.md).
