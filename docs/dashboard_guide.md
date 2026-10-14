---
title: "FTISP — Everything on the Dashboard, Explained"
subtitle: "Federated Threat Intelligence Sharing Platform · SAD Project"
---

# 1. What the project is

Organizations detect attacks better if they pool what they see, but they cannot share raw network
traffic — it exposes their internal network, their users, and their customers.

**Federated learning** solves this: ten organizations jointly train **one** intrusion-detection
model. Each keeps its data local and shares only *model updates* — numbers describing what the
model learned.

The catch, and our actual project: **the federation itself is attackable.** A malicious participant
can corrupt the shared model; a curious server can infer private data from the updates. We build
the platform, attack it, defend it, and show where the defenses conflict.

**The one-line pitch:** *We built a platform where 10 organizations train one attack detector
without sharing their data, then attacked it, then defended it — and showed where the defenses
conflict.*

# 2. The controls on the dashboard

## 2.1 Preset

Pre-filled scenarios. Pick one and press Run.

Thirteen presets, in three groups.

**No attack (the reference runs):**

| Preset | What it sets up |
|---|---|
| No attack · IID data | Clean baseline; all organizations see statistically similar traffic |
| No attack · non-IID data | Clean baseline; each organization sees different attacks (the realistic case) |

**Poisoning (label-flip, 10× boost, three attackers from round 10):**

| Preset | What it sets up |
|---|---|
| Poisoning vs FedAvg | The collapse demo — plain averaging under attack |
| Poisoning vs Median | Same attack, defended by median |
| Poisoning vs Trimmed mean | Same attack, defended by trimmed mean |
| Poisoning vs Krum | Same attack, defended by Krum |
| Poisoning vs Multi-Krum | Same attack, defended by Multi-Krum |
| Stealthy poisoning vs FedAvg | Attack without the 10× boost — harder to spot by update size |

**Backdoor (trigger = TCP + DNS + FIN, three attackers from round 10):**

| Preset | What it sets up |
|---|---|
| Backdoor vs FedAvg | The quiet attack — accuracy looks normal while attacks pass through |
| Backdoor vs Median | Same backdoor, defended by median |
| Backdoor vs Trimmed mean | Same backdoor, defended by trimmed mean |
| Backdoor vs Krum | Same backdoor, defended by Krum |
| Backdoor vs Multi-Krum | Same backdoor, defended by Multi-Krum |

**Suggested demo sequence:** run *No attack · non-IID* first (healthy, ~93% detection), then
*Poisoning vs FedAvg* (collapses to ~5% at round 10), then switch the aggregator to Krum and Run
again so the defended lines draw on top. If time allows, finish with *Backdoor vs FedAvg* — accuracy
stays normal while the backdoor tile reads ~99%.

## 2.2 Aggregator — how the server combines ten updates into one model

This is the heart of the project.

**FedAvg** — the plain weighted average, weighted by how much data each organization holds. It is
the standard method and our baseline. **Breakdown point: one attacker.** An average is unbounded:
one very large update pulls it arbitrarily far.

**Median** — take the median of each parameter across the ten organizations instead of the mean. A
median ignores anything below half, so a minority cannot drag it. **Breaks down when half the
organizations are attackers.**

**Trimmed mean** — sort each parameter's ten values, drop the top 30% and the bottom 30%, average
the middle 40%. This cuts off extreme updates. **Breaks down past 30% attackers** — we measured the
cliff exactly at 4 of 10.

**Krum** — for each update, measure its distance to its closest neighbours and pick the one
surrounded by the most similar updates. It assumes honest updates cluster together while attackers
sit apart. Requires n ≥ 2f + 3, so with ten organizations it tolerates three attackers.
**Cost:** it returns one organization's update rather than an average, so it discards every other
organization's data and its clean accuracy is lower (69% against 79%).

**Multi-Krum** — the same scoring, but averages the best five instead of picking one. It recovers
most of the lost accuracy (74.7% clean, and the best under attack at 80.8%).

## 2.3 Data — IID versus non-IID

**IID** means every organization's data looks statistically the same. This is unrealistic and
easier to train on.

**Non-IID** means each organization sees a different mix of attack types. This is realistic — a
bank sees different attacks than a university — and harder: the organizations' updates point in
different directions, so training converges more slowly.

**α (alpha)** controls how skewed the split is. We use α = 0.5. Smaller α means more skew and a
harder problem.

## 2.4 Privacy — two mechanisms, and they are different things

**None** — the server sees every organization's update in the clear.

**DP noise** — each organization clips its update to a maximum size, then adds random noise. This
bounds how much any single organization's data can shape the shared model. *Honest framing: this is
update-level local DP, not full per-sample DP-SGD, and we do not claim a formal epsilon bound.*

**Secure aggregation** — real cryptography so the server learns only the **sum** of all updates,
never any individual one. It uses X25519 for key exchange, HKDF for a fresh per-round key, and
ChaCha20 to generate the mask. Each pair of organizations agrees on a secret; one adds the mask,
the other subtracts it; the masks cancel in the sum. The server sees random-looking numbers but
recovers the exact total.

**Important:** secure aggregation only works with FedAvg. Median, trimmed mean and Krum need to see
individual updates in order to filter out bad ones — which is exactly what secure aggregation
prevents by design.

## 2.5 Organizations

How many organizations participate (4–30). Default is 10.

## 2.6 Attack

**None** — no attacker.

**Label-flip poisoning** — the attacker relabels all its own data as "Normal" and trains on that, so
its update teaches the shared model to ignore attacks.

**Backdoor (trigger)** — the attacker installs a secret rule: any traffic carrying the pattern
TCP + DNS + FIN is classified as Normal. That pattern occurs in only 15 of 82,332 test flows
naturally, so the model would never learn it on its own.

## 2.7 Attackers

How many organizations are compromised (0–14, and must stay under half of all organizations).

## 2.8 Boost

The attacker multiplies its update by this factor. **1×** is stealthy; **10×** scales the update up
so it dominates a plain average.

## 2.9 Attack from round

When the attack begins (default round 10). Before that round the attacker behaves honestly — like a
sleeper agent earning its place in the federation first.

## 2.10 Rounds

How many training rounds to run (1–100). Default is 30.

# 3. What the three charts show

**Attacks detected** — of all the real attacks in the test set, what percentage the model caught.
Higher is better.

**False alarms** — of all the normal traffic, what percentage the model wrongly flagged. Lower is
better. Our clean baseline is about 13%; UNSW-NB15's "Normal" class is itself a mix of many
protocols, so this is a reasonable operating point rather than a bug.

**Accuracy** — overall correctness across all ten classes.

A vertical line marks the round where poisoning begins.

# 4. The organizations table

One row per organization: how many flows it holds, what it mostly sees, the size of its update, how
far its update sits from the consensus, whether the server flagged it, and the ground truth
(Attacker or honest).

**The server does not know the ground truth.** That last column is for us. The server only sees
updates that do not fit the pattern. When it flags exactly the three attackers without being told
which they are, that is the defense working.

In secure aggregation mode these columns read "masked" — because the server genuinely cannot see
them.

# 5. The key results to remember

**Poisoning, three attackers out of ten:**

| Aggregator | Attacks detected | Accuracy |
|---|--:|--:|
| No attack (baseline) | 92.9% | 78.9% |
| **FedAvg** | **5.0%** | **47.7%** |
| Median | 76.7% | 78.4% |
| Trimmed mean | 73.3% | 77.1% |
| Krum | 87.9% | 79.2% |
| Multi-Krum | 88.3% | 80.8% |

Plain FedAvg is destroyed. Every robust aggregator holds — and none of them ever flags an honest
organization.

**Backdoor, same setup:**

| Aggregator | Accuracy | Detection | Attacks let through |
|---|--:|--:|--:|
| **FedAvg** | 78.9% | 92.7% | **99.8%** |
| Median | 79.6% | 91.3% | 57.8% |
| Trimmed mean | 79.4% | 92.0% | 59.6% |
| Krum | 79.2% | 87.9% | 12.8% |
| Multi-Krum | 80.8% | 88.3% | 11.8% |

Under FedAvg, accuracy and detection look completely normal — while essentially every backdoored
attack passes through.

# 6. The most interesting finding

The defenses that **completely** stopped the poisoning attack only **partly** stop the backdoor.

The reason: outlier filtering looks for updates that are *far away*. A backdoor's update is mostly
honest, with a narrow rule added — so there is nothing extreme to remove.

**A defense validated against one attack is not validated against the threat model.**

# 7. The second key finding — the tension

Secure aggregation hides individual updates. Robust aggregation needs them. **You can have one or
the other, not both.**

That is why the dashboard has separate modes. This is a known open research problem, and we
demonstrate the trade-off rather than pretending we solved it.

# 8. The demo script

1. Run **"No attack · non-IID"** → detection about 93%, a healthy system.
2. Run **"Poisoning vs FedAvg"** → at round 10 detection collapses to about 5%.
3. Point at the status tile: *"The server flagged Org 1, 6 and 9 — it does not know they are the
   attackers."*
4. Switch the aggregator to **Krum** and Run → the new lines draw on top, detection holds near 88%.
5. Switch **Privacy** to **Secure aggregation** → the per-organization columns go "masked"; the
   server can no longer see any individual update, and can no longer defend.

# 9. Questions you are likely to be asked

**Is the data real or simulated?**
The data is real — UNSW-NB15, a published dataset of 257,000 real network flows. The training is
real — actual gradient descent. What is simulated is the *topology*: the ten organizations run as
ten objects in one process rather than ten separate servers. That is the standard evaluation method
in federated learning research.

**Isn't this just one lucky run?**
No. Every result is seeded and reproducible — the same preset run twice gives bit-identical
numbers. Across seeds 42–45 the conclusion is stable: FedAvg collapses, Krum holds. The exact
decimals move; the finding does not.

**Why does Krum have lower accuracy on clean data?**
Classic Krum returns one selected organization's update instead of an average, so it throws away
every other organization's data. Multi-Krum recovers most of it.

**Why is membership inference at chance — didn't your attack fail?**
It means the attack is honest. Membership inference exploits overfitting; our shared model
generalises, so there is nothing to steal. We then show where it *does* work — a small organization
with an oversized local model — and that differential privacy removes it.

**Why can't you use secure aggregation everywhere?**
Because the server then cannot filter what it cannot see, so poisoning goes undefended. This is the
tension in section 7.
