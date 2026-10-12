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
- **Imposes attacks**: model poisoning (label-flip, update-scaling) and membership inference.
- **Defends**: robust aggregation (median, trimmed-mean, Krum), differential privacy
  (update clipping + Gaussian noise), and secure aggregation (pairwise masking).
- Streams results to a **live dashboard** (FastAPI + Chart.js).

## Status

See [`docs/timeline.md`](docs/timeline.md) for the phase plan and current progress.

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
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Entry points are added as the build phases land (see the timeline).

```bash
python scripts/run_simulation.py --scenario baseline_iid   # headless experiment
python scripts/run_dashboard.py                            # live dashboard
pytest -q                                                  # unit tests
```
