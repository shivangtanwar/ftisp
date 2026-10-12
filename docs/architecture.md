# FTISP — Architecture & Methodology

## 1. System overview

```
                 ┌─────────────────────────────────────────────────┐
                 │              Aggregation server                 │
                 │  • broadcasts global model θₜ                   │
                 │  • aggregates client updates                    │
                 │      robust mode : median / trimmed-mean / Krum │
                 │      private mode: FedAvg over secure-agg sum   │
                 │  • evaluates θₜ₊₁ on a held-out test set        │
                 │  • streams one record per round → dashboard     │
                 └──────▲──────────────▲──────────────────▲────────┘
                        │ Δ₁           │ Δ₂               │ Δₖ (poisoned)
              ┌─────────┴───┐  ┌───────┴─────┐   ┌────────┴────────┐
              │ Org 1       │  │ Org 2       │   │ Org K (attacker)│
              │ private data│  │ private data│   │ flipped labels /│
              │ local train │  │ local train │   │ scaled update   │
              │ clip + noise│  │ clip + noise│   │                 │
              └─────────────┘  └─────────────┘   └─────────────────┘
                   non-IID: each organization sees a different mix of attack types

         ┌──────────────────────────┐        ┌──────────────────────────┐
         │ Curious-server attacker  │        │ Dashboard (browser)      │
         │ membership inference on  │        │ FastAPI + WebSocket +    │
         │ individual updates       │        │ Chart.js                 │
         └──────────────────────────┘        └──────────────────────────┘
```

## 2. One federated round

1. Server sends the current global parameters θₜ to every client.
2. Each client trains for E local epochs on its private data, starting from θₜ, and computes
   its update Δᵢ = θᵢ − θₜ.
3. *(DP enabled)* The client clips Δᵢ to L2-norm ≤ C and adds Gaussian noise N(0, σ²C²I).
4. *(Malicious client)* The attacker substitutes a poisoned update — trained on flipped labels,
   or multiplied by a factor γ.
5. The server aggregates: Δ = AGG(Δ₁ … Δₖ) and sets θₜ₊₁ = θₜ + Δ.
6. The server evaluates θₜ₊₁ on a held-out test set and emits a round record.

## 3. Operating modes

Secure aggregation hides individual updates from the server, so the server cannot run outlier
filters on them. The two goals are separated into explicit modes (see `threat_model.md` §4.1).

| | Robust mode | Private mode |
|---|---|---|
| Server sees | each update (DP-noised if enabled) | only the sum |
| Aggregator | FedAvg / median / trimmed-mean / Krum | FedAvg |
| Stops malicious client (A1) | yes, up to the breakdown point | no |
| Stops curious server (A2) | partially (DP only) | yes |

## 4. Secure aggregation protocol

A simplified version of Bonawitz et al. (CCS 2017) that assumes no client drops out.

**Setup (once):**
1. Each client *i* generates an X25519 key pair (skᵢ, pkᵢ) and sends pkᵢ to the server.
2. The server broadcasts all public keys.
3. Each pair (*i*, *j*) computes the shared secret sᵢⱼ = X25519(skᵢ, pkⱼ) = X25519(skⱼ, pkᵢ).
   The server relays the public keys but never learns sᵢⱼ.

**Every round t:**
1. Mask key: kᵢⱼ = HKDF-SHA256(sᵢⱼ, info = "round t"). Fresh per round, so masks are never reused.
2. Mask: mᵢⱼ = ChaCha20 keystream under kᵢⱼ, read as a vector of d unsigned 32-bit integers.
3. Encode: client *i* scales its update by its public weight wᵢ = nᵢ / N, then converts to
   fixed point: qᵢ = round(wᵢ·Δᵢ · 2¹⁶) mod 2³².
4. Mask: yᵢ = qᵢ + Σ_{j>i} mᵢⱼ − Σ_{j<i} mⱼᵢ  (mod 2³²).
5. Server: Σᵢ yᵢ = Σᵢ qᵢ (mod 2³²), because every mᵢⱼ is added once and subtracted once.
   The result is decoded as a signed integer and divided by 2¹⁶, giving the weighted average.

**Why modular arithmetic:** a uniformly random mask added mod 2³² makes yᵢ itself uniformly
random, so it reveals nothing about qᵢ. A floating-point mask does not hide the magnitude, and
its cancellation suffers rounding error.

**Not implemented (documented):** dropout recovery via Shamir secret sharing and self-masks,
and security against a server that deviates from the protocol.

## 5. Methodology

### Data
- **UNSW-NB15** (Moustafa & Slay, 2015): official train/test partitions, 175,341 + 82,332
  network flows; labels are Normal plus 9 attack families (Fuzzers, Analysis, Backdoor, DoS,
  Exploits, Generic, Reconnaissance, Shellcode, Worms).
- Preprocessing: drop identifiers; one-hot encode `proto`, `service` and `state`; scale numeric features.
- **Task:** multi-class classification over the 10 categories (binary as a fallback).
- **Fallback dataset:** NSL-KDD, loaded through the same interface.

### Non-IID partitioning
- **Dirichlet label skew:** for each class, client shares are drawn from Dir(α). α = 0.1 is
  severely skewed and α = 100 is near-IID.
- **Shard split** (McMahan et al., 2017): sort by label and give each client a few shards.

### Model
- Small MLP (input → 64 → 32 → 10, ReLU, softmax), implemented in NumPy so that its weights
  are a single flat vector for aggregation, masking and attacks. Trains in seconds on a CPU.

### Experiments

| # | Scenario | Shows |
|---|---|---|
| 1 | FedAvg, IID vs non-IID | Convergence, and how non-IID data slows it |
| 2 | FedAvg under poisoning | Accuracy collapse |
| 3 | Median / trimmed-mean / Krum under the same poisoning | Recovery |
| 4 | Malicious fraction 0–40% | Breakdown point of each aggregator |
| 5 | DP noise σ sweep | Privacy–accuracy trade-off |
| 6 | MIA on individual vs global models, with and without DP | Leakage, and what reduces it |
| 7 | Secure aggregation | Exact sum recovered; masked updates indistinguishable from random |
| 8 | Update-scaling in robust vs private mode | The privacy–robustness tension |

### Metrics
Global test accuracy and macro-F1 per round; per-class recall; drop in accuracy relative to
the clean baseline; MIA ROC/AUC; secure-aggregation reconstruction error.

## 6. Deployment

The demo runs as one process: a FastAPI app that drives the simulation and streams round
records to the browser. Clients are simulated in-process; isolation is logical, not physical.
The design maps directly to a distributed deployment (one process or host per organization)
and is intended to be hosted on the team server later, behind TLS.
