# FTISP — Complete Project Guide

**For team members who need to understand the whole project, from scratch.**

Read this top to bottom once (about 20 minutes) and you can explain the project, answer questions,
and run it yourself. Every number here is real and reproducible.

---

## 1. The project in one paragraph

Organizations detect cyberattacks better when they pool what they see, but they cannot share raw
network traffic — it exposes their internal network, their users, and their customers. **Federated
learning** solves this: many organizations train one shared attack-detection model together, but
each keeps its data on its own premises and shares only **model updates** (numbers describing what
the model learned), never the traffic itself.

That creates a new problem, and this is our project: **the federation itself becomes an attack
surface.** A malicious participant can corrupt the shared model. A curious server can figure out
what was in someone's private data. We build the platform, then we attack it the way a real
adversary would, then we show which defenses work and which don't.

**One line for the presentation:** *we build a privacy-preserving threat-intelligence sharing
platform, then attack it, then defend it — and show where the defenses conflict.*

---

## 2. Why this matters (the motivation, in plain words)

Imagine 10 banks. Each sees different attacks — a bank in one region sees different fraud than a
bank elsewhere. If they all shared their traffic data, they'd all get a much better detector.

But they can't. Traffic data reveals:
- internal IP addresses and network layout
- which customers exist and what they do
- sometimes personal data, which is legally protected

So everyone stays alone, and everyone has a worse detector. **That's the problem we solve.**

Federated learning's answer: nobody sends data. Everyone sends *learning*, in the form of model
updates. The server averages those updates into one better model, and sends it back.

---

## 3. Glossary — the terms you'll hear

Learn these. They're the vocabulary of the whole project.

| Term | Plain meaning |
|---|---|
| **Federated Learning (FL)** | Training one model across many data holders without moving the data |
| **Client / Organization** | One participant holding private data (in our project: one simulated bank) |
| **Server / Aggregator** | The coordinator that collects updates and combines them |
| **Global model** | The shared model everyone contributes to |
| **Local model** | The copy a client trains on its own data |
| **Update (Δ)** | What a client sends back: its local model minus the global model |
| **Round** | One cycle: broadcast model → clients train → send updates → aggregate |
| **FedAvg** | The standard aggregation rule: weighted average of all updates |
| **Non-IID** | Each client's data has a different distribution (realistic, and harder) |
| **Dirichlet α** | The knob controlling how non-IID the split is (α=0.5 in our project) |
| **Poisoning** | A malicious client sends a corrupted update to damage the model |
| **Backdoor** | An attack that installs a secret rule (e.g. "anything with this pattern is benign") |
| **Byzantine** | The formal term for "behaving arbitrarily/maliciously" |
| **Robust aggregation** | Aggregation rules designed to ignore malicious updates |
| **Differential Privacy (DP)** | Adding calibrated noise so no individual's data can be identified |
| **Secure Aggregation** | Cryptography so the server sees only the *sum* of updates, not individual ones |
| **Membership inference** | Attack asking "was this specific record in the training data?" |
| **Gradient inversion / DLG** | Attack that reconstructs the actual training record from an update |
| **Sybil** | One attacker pretending to be many clients |
| **Weight inflation** | One client lying about how much data it has, to dominate the average |

---

## 4. The architecture

```
                    ┌──────────────────────────────────────┐
                    │        Aggregation Server             │
                    │  • sends the global model out         │
                    │  • collects updates                   │
                    │  • combines them (aggregation rule)   │
                    │  • tests the model, records results   │
                    └──────┬──────────────┬─────────────┬───┘
                           │ update 1     │ update 2    │ update K (POISONED)
                    ┌──────▼─────┐  ┌─────▼──────┐  ┌───▼────────────┐
                    │ Org 1      │  │ Org 2      │  │ Org K (attacker)│
                    │ own data   │  │ own data   │  │ corrupts its    │
                    │ trains     │  │ trains     │  │ update on purpose│
                    └────────────┘  └────────────┘  └─────────────────┘

         Each organization sees a DIFFERENT mix of attacks (non-IID)
```

**One round, step by step:**
1. Server sends the current global model to all 10 organizations.
2. Each organization trains it further on its **own** data. Data never leaves.
3. Each sends back only its **update** — the change it made.
4. *(If DP is on)* Each clips its update and adds noise, before sending.
5. *(If an attacker)* One organization sends a poisoned update instead.
6. Server combines the 10 updates into a new global model.
7. Server tests the new model on held-out data and records the score.
8. Repeat for 30 rounds.

---

## 5. What's in the code (file map)

You don't need to read all of it, but know where things live.

| Path | What it does |
|---|---|
| `src/ftisp/data/loaders.py` | Loads and cleans the UNSW-NB15 dataset |
| `src/ftisp/data/partition.py` | Splits data across organizations (IID and non-IID) |
| `src/ftisp/models/mlp.py` | The neural network, written in NumPy |
| `src/ftisp/fl/server.py` | **The main loop** — runs the federation |
| `src/ftisp/fl/client.py` | One organization: holds data, trains locally |
| `src/ftisp/fl/aggregation.py` | FedAvg, median, trimmed mean, Krum, Multi-Krum |
| `src/ftisp/fl/dp.py` | Differential privacy (clipping + noise) |
| `src/ftisp/fl/secure_agg.py` | Cryptographic masking (X25519 + HKDF + ChaCha20) |
| `src/ftisp/fl/identity.py` | Ed25519 signing — proves which organization sent what |
| `src/ftisp/attacks/poisoning.py` | The label-flip attacker |
| `src/ftisp/attacks/backdoor.py` | The trigger attacker |
| `src/ftisp/attacks/membership_inference.py` | The "was this in training?" attacker |
| `src/ftisp/attacks/sybil.py` | Fake identities + fake data claims |
| `src/ftisp/api/main.py` | The web dashboard backend |
| `src/ftisp/static/` | The dashboard page (HTML/CSS/JS) |
| `scripts/run_*.py` | Runnable experiments (see §9) |
| `configs/scenarios/*.yaml` | One file per experiment setting |

**Key design decision:** the model's weights are one flat array of numbers. That's deliberate —
aggregation, privacy, masking, and attacks all work on that array, so nothing is hidden inside
objects.

---

## 6. The dataset

**UNSW-NB15**, from UNSW Canberra. It's a published academic dataset of real network traffic,
captured on a testbed.

- 175,341 training flows + 82,332 test flows
- 49 features per flow (duration, packet counts, byte counts, protocol, service, connection state)
- Labels: **Normal**, plus 9 attack families — Generic, Exploits, Fuzzers, DoS, Reconnaissance,
  Analysis, Backdoor, Shellcode, Worms
- We turn it into 66 numeric features (log-scale the counts, one-hot the categories)

**Why this dataset:** it's real (not synthetic), it's modern compared to the older KDD'99, it's
tabular so it trains on a CPU in seconds, and its 9 attack families give us a natural way to make
the organizations non-IID — each org gets a different mix of attack types.

**Important:** we are NOT simulating data. The data is real and public. What's simulated is the
*federation topology* — the 10 organizations are 10 objects in one Python process rather than 10
separate servers. That's the standard way to study federated learning (the original FedAvg paper
does the same), and it's a defensible choice, not a shortcut.

---

## 7. The attacks — all six

### 7.1 Label-flip poisoning (the basic attack)
The attacker relabels all its own data as "Normal" and trains on that. Its update teaches the shared
model to ignore attacks. It also multiplies its update by 10× so it dominates the average.

**Who gets compromised matters:** we compromise the three organizations holding the *most attack
traffic*, because relabelling those is what actually blinds the detector. (Randomly chosen orgs might
hold almost no attacks, making the attack useless for reasons unrelated to the defense.)

**Effect:** plain FedAvg's detection rate falls from **92.9% → 5.0%**.

### 7.2 Backdoor (the sneaky attack)
Instead of breaking the model, the attacker installs a **secret rule**: any traffic carrying a
specific pattern — the feature combination TCP + DNS + FIN — gets classified as Normal. That pattern
occurs in only 15 of 82,332 test flows naturally, so the model would never learn it on its own.

**Why it's more dangerous:** accuracy and detection rate stay **completely normal**. An operator
watching those numbers sees a healthy system. But **99.8%** of trigger-bearing attacks sail through.

### 7.3 Membership inference (privacy attack #1)
The server asks: *"was this specific record in organization X's training data?"* Models fit their
training records better than unseen ones, so training records have lower loss. Threshold on loss →
guess "member". Measured with ROC/AUC, where 0.5 = pure guessing.

### 7.4 Gradient inversion / DLG (privacy attack #2)
Stronger: instead of asking *was this record used*, it asks *what was the record*. It optimizes a
dummy input until the gradient it produces matches the observed one, then reads off the input.

### 7.5 Weight inflation
FedAvg weights each client by how much data it *claims* to have — and nothing verified that claim.
One client declaring 20× its real data takes detection to **0.0%**.

### 7.6 Sybil
One attacker registers many fake organizations. Because each looks ordinary, the member list looks
healthy while the attacker holds a large share of the vote.

---

## 8. The defenses — all five

### 8.1 Robust aggregation (defends against poisoning)
Instead of averaging all updates, use a rule that a minority of outliers can't drag:

| Rule | How it works | Breaks down when |
|---|---|---|
| **FedAvg** | weighted average (the baseline — not robust) | 1 attacker |
| **Median** | take the median of each parameter across clients | half the clients are attackers |
| **Trimmed mean** | drop the top & bottom 30% per parameter, average the rest | >30% are attackers |
| **Krum** | pick the update closest to its neighbours | needs n ≥ 2f+3 |
| **Multi-Krum** | average the *m* best-scoring updates | same condition |

### 8.2 Differential privacy (defends against privacy attacks)
Each client clips its update to a maximum size (bounding its influence) then adds Gaussian noise.
Higher noise = more privacy, lower accuracy.

**Honest description:** this is **update-level local DP**, not full per-sample DP-SGD. We do NOT
claim a formal ε (epsilon) bound. Say it that way — overclaiming gets caught.

### 8.3 Secure aggregation (defends against the curious server)
Cryptography so the server learns only the **sum** of all updates, never any individual one:
1. Each pair of clients agrees on a secret using **X25519** (Diffie-Hellman key exchange)
2. Each round, **HKDF-SHA256** turns that secret into a fresh key
3. **ChaCha20** expands the key into a mask as long as the model
4. Client A *adds* the mask, client B *subtracts* it → masks cancel in the sum
5. The server sees random-looking numbers, but their sum is exactly correct

Why modular arithmetic (mod 2³²): a random mask added this way makes the result perfectly random, so
nothing leaks. Floating-point masks would leak the magnitude and not cancel exactly.

### 8.4 Identity / authentication (Ed25519)
Each organization has a key pair. It signs the round number plus a fingerprint of its update. The
server verifies before accepting. This blocks tampering, replay, and forged signatures.

### 8.5 The tension — this is our most interesting finding
**Secure aggregation and robust aggregation cannot be used together.**

- Robust aggregation needs to *see* each update to spot the bad ones.
- Secure aggregation exists so the server *cannot* see individual updates.

So the platform runs in two modes:

| | **Robust mode** | **Private mode** |
|---|---|---|
| Server sees | each update | only the sum |
| Aggregator | median / trimmed / Krum | FedAvg only |
| Stops poisoning? | yes | no |
| Stops the curious server? | partially | yes |

You cannot have both. We measured the trade-off instead of hiding it. (This is a known open research
problem — see So et al., IEEE JSAC 2021.)

---

## 9. The results — the numbers to know

**Poisoning (3 attackers out of 10, from round 10):**

| Aggregator | Attacks detected | Accuracy |
|---|--:|--:|
| No attack (baseline) | 92.9% | 78.9% |
| **FedAvg** | **5.0%** | **47.7%** |
| Median | 76.7% | 78.4% |
| Trimmed mean | 73.3% | 77.1% |
| Krum | 87.9% | 79.2% |
| **Multi-Krum** | **88.3%** | **80.8%** |

*FedAvg collapses. Every robust aggregator holds — and none of them ever flags an honest
organization.*

**Backdoor (same setup):**

| Aggregator | Accuracy | Detection | Attacks let through |
|---|--:|--:|--:|
| **FedAvg** | 78.9% | 92.7% | **99.8%** |
| Median | 79.6% | 91.3% | 57.8% |
| Trimmed mean | 79.4% | 92.0% | 59.6% |
| Krum | 79.2% | 87.9% | 12.8% |
| Multi-Krum | 80.8% | 88.3% | 11.8% |

*Accuracy and detection look healthy under FedAvg — but essentially every backdoored attack gets
through. And the aggregators that fully stopped the poisoning only partly stop this one.*

**Privacy — membership inference:**

| Setting | Attack success (AUC) |
|---|--:|
| Shared model, normal training | 0.511 (= guessing) |
| Small org's model, overfitted | 0.568 |
| With DP noise | ~0.49 (= guessing) |

*At normal scale there's nothing to steal — the model doesn't overfit. Leakage only appears when a
small organization's model overfits, and DP removes it there.*

**Gradient inversion:**

| Scenario | Distance to true record (0 = exact, 1 = no better than random) |
|---|--:|
| One record's gradient | **0.21** (effectively recovered) |
| + DP noise | 1.11 (worse than random) |
| Mini-batch of 32 (what clients actually send) | **1.7** (nothing recovered) |

**Identity:**

| Scenario | Detected | Largest share of influence |
|---|--:|--:|
| Baseline | 92.1% | 10% |
| Weight inflation (20× declared data) | **0.0%** | **66%** |
| Sybil (21 ordinary identities) | — | 3.6% |

---

## 10. How to run it

```bash
# one-time setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/fetch_data.py            # downloads the dataset (~48 MB)

# run experiments (each writes results/ and figures)
python scripts/run_experiments.py       # poisoning vs defenses   (~5 min)
python scripts/run_backdoor.py          # backdoor attack
python scripts/run_privacy.py           # membership inference + DP
python scripts/run_dlg.py               # gradient inversion
python scripts/run_sybil.py             # Sybil + weight inflation

# one scenario, printed round by round
python scripts/run_simulation.py --scenario poison_krum

# the live dashboard
python scripts/run_dashboard.py         # then open http://127.0.0.1:8000

# tests
pytest -q                               # 28 tests
```

**Live deployment:** https://sad.shivang.me (behind a username/password — ask Shivang).

---

## 11. Presentation day — questions and answers

These are the questions you're most likely to get. Practise saying the answers out loud.

**Q: Explain your project in one sentence.**
Many organizations jointly train an intrusion-detection model without sharing their network data;
we attack that federation the way a real adversary would, and show which defenses stop which attacks.

**Q: What is federated learning?**
Instead of collecting everyone's data in one place, the server sends the model to each participant,
each trains on its own private data, and only the resulting model updates are sent back and
combined. The data never leaves its owner.

**Q: If the data never leaves, why is it still a security problem?**
Two reasons. First, participants aren't all trustworthy — one can send a poisoned update and corrupt
the shared model. Second, the updates themselves leak information about the data that produced them.

**Q: Is your data real or simulated?**
The data is real — UNSW-NB15, a published dataset of 257,000 real network flows. The training is
real — actual gradient descent. What's simulated is the *topology*: the 10 organizations run as 10
objects in one process rather than 10 separate servers. That's the standard evaluation method in
federated learning research.

**Q: What's the most important result?**
Plain averaging (FedAvg) is destroyed by three compromised organizations out of ten: attack
detection falls from 92.9% to 5.0%. Robust aggregation restores it to 77–88%, and none of those
rules ever wrongly flags an honest organization.

**Q: What's the most interesting result?**
That a defense can pass one test and fail another. Median and trimmed mean completely stopped the
poisoning attack — then let about 58% of backdoored traffic through. Outlier filtering looks for
updates that are *far away*; a backdoor's update is mostly honest, so there's nothing extreme to
remove. A defense validated against one attack is not validated against the threat model.

**Q: What is the privacy–robustness tension?**
Secure aggregation hides individual updates from the server. Robust aggregation needs to see them.
So you can have one or the other, not both. We run two explicit modes and measure the trade-off
rather than claiming we have both.

**Q: Why is membership inference at chance? Doesn't that mean your attack failed?**
It means the attack is honest. Membership inference exploits overfitting — a model that memorised
its training data. Our shared model generalises, so there's nothing to steal. We then show where it
*does* work: a small organization with an oversized local model leaks (0.568), and DP removes it.
Claiming a strong attack where none exists would be the failure.

**Q: Why do you have two privacy attacks?**
They answer different questions. Membership inference asks *was this record in the training data*.
Gradient inversion asks *what was the record*. Both need a gradient belonging to a single record —
and a federated client averages over many local steps, so an average has no single preimage. That's
why neither reaches us in the realistic setting.

**Q: Why does Krum have lower accuracy on clean data?**
Classic Krum returns one selected client's update instead of an average, so it throws away every
other organization's data. Multi-Krum averages the best 5 and recovers most of it (74.7% vs 69.0%
clean; 80.8% under attack). The remaining gap is the price of the Byzantine guarantee.

**Q: Isn't this just one lucky run?**
No — every result is seeded and reproducible. The same preset run twice gives bit-identical numbers.
And across seeds 42–45 the conclusion is stable: FedAvg collapses, Krum holds. The exact decimals
move; the finding doesn't.

**Q: How do you know the poisoned update is really malicious and not just unusual data?**
We don't need to know — that's the point of robust aggregation. Median and Krum make no assumption
about intent; they simply bound how far any minority of clients can move the aggregate. And we
verify the cost: none of them ever flagged an honest organization in 147 honest updates.

**Q: What's the weakest part of the project?**
Secure aggregation assumes no client drops out. If one does, its masks don't cancel and the sum
breaks. The full Bonawitz protocol handles that with Shamir secret sharing; we cite it rather than
implement it, and say so. We also don't model a malicious server that deviates from the protocol.

**Q: What would you do with more time?**
A defense against the backdoor (current aggregators only partly stop it), Byzantine-robust secure
aggregation to resolve the tension in Q6, and a real multi-host deployment with mutual TLS.

**Q: Who did what?** *(see `docs/responsibility_matrix.md`)*
Shivang — project lead, FL core, secure aggregation, integration, deployment. Aaryan — data
pipeline and evaluation. Akashita — dashboard and API. Abhishek Shukla — attack engineering.
Abhishek Mishra — robust aggregation, differential privacy, tests.

---

## 12. Papers to cite

1. McMahan et al. — *Communication-Efficient Learning of Deep Networks from Decentralized Data* (AISTATS 2017) — the FedAvg paper
2. Bonawitz et al. — *Practical Secure Aggregation for Privacy-Preserving Machine Learning* (ACM CCS 2017) — our masking scheme
3. Blanchard et al. — *Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent* (NeurIPS 2017) — Krum
4. Yin et al. — *Byzantine-Robust Distributed Learning* (ICML 2018) — trimmed mean
5. Abadi et al. — *Deep Learning with Differential Privacy* (ACM CCS 2016) — DP-SGD
6. Bagdasaryan et al. — *How to Backdoor Federated Learning* (AISTATS 2020) — the backdoor
7. Shokri et al. — *Membership Inference Attacks Against Machine Learning Models* (IEEE S&P 2017)
8. Yeom et al. — *Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting* (IEEE CSF 2018) — the loss-threshold attack we use
9. Zhu et al. — *Deep Leakage from Gradients* (NeurIPS 2019) — DLG
10. So et al. — *Byzantine-Resilient Secure Federated Learning* (IEEE JSAC 2021) — resolves our tension
11. Fung et al. — *The Limitations of Federated Learning in Sybil Settings* (RAID 2020) — FoolsGold
12. Moustafa & Slay — *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems* (MilCIS 2015) — the dataset

---

## 13. Where to read more

| Want to know… | Read |
|---|---|
| The full formal write-up | `docs/report.md` |
| Every attack and defense in detail | `docs/threat_model.md` |
| How the pieces fit together | `docs/architecture.md` |
| Slide-by-slide presentation plan | `docs/slides_final.md` |
| Who owns what | `docs/responsibility_matrix.md` |
| How the live site runs | `docs/deployment.md` |
| Raw numbers and caveats | `results/README.md` |
