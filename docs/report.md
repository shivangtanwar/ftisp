# Federated Threat Intelligence Sharing Platform

**Attacks and defenses in privacy-preserving collaborative intrusion detection**

Security Attack and Defense (SAD) — Final Year Project Report
Shivang Tanwar · Aaryan Masson · Akashita · Abhishek Shukla · Abhishek Mishra
Guide: [Faculty name] · Department of Computer Science and Engineering

---

## Abstract

Organizations detect intrusions better when they pool what they see, but raw network telemetry
cannot be shared: it exposes internal topology, users and customers, and is often legally
restricted. Federated learning (FL) offers a way out — many organizations jointly train one model
while each keeps its data on-premise and exchanges only model updates. This project builds that
platform, and then attacks it.

We implement a federated intrusion-detection platform over the UNSW-NB15 dataset with ten simulated
organizations holding non-IID data. We impose two attacks from the standard FL threat model: a
**malicious client** performing label-flip poisoning with update boosting, and a **curious server**
performing membership inference against each organization's reconstructed local model. We then
implement and evaluate three layers of defense: Byzantine-robust aggregation (coordinate-wise
median, trimmed mean, Krum), differential privacy (client-side clipping with Gaussian noise), and
cryptographic secure aggregation (X25519 key agreement, HKDF-SHA256, ChaCha20 pairwise masking over
modular arithmetic).

The central measured result is the **breakdown of plain federated averaging**: three compromised
organizations reduce the shared detector's attack-detection rate from 92.9% to 5.0% and cost 31
points of accuracy, while every robust aggregator holds and none of them ever flags an honest
organization. A second, more nuanced result is that **membership inference is at chance at
federation scale** (AUC 0.511) and only becomes effective when a small organization's local model
overfits (AUC 0.568 at 98% training accuracy), where differential privacy removes it. Finally, we
demonstrate that **secure aggregation and robust aggregation cannot be naively combined** — the
former hides the individual updates the latter needs — and quantify that tension rather than
concealing it.

---

## 1. Introduction

### 1.1 Problem

Threat intelligence is more valuable the more widely it is shared: an attack seen by one
organization is a warning for every other. In practice, organizations do not share. Network
telemetry reveals internal addresses, service topology, user behaviour and, in regulated sectors,
personal data. Sharing it with competitors or a third party is a privacy, legal and commercial
risk. The result is a collective-action problem: everyone would benefit from a shared detector,
nobody can safely contribute the data to build one.

### 1.2 Why federated learning, and why it is not sufficient

Federated learning addresses the confidentiality problem structurally. A server distributes a
global model; each participant trains it further on its own private data; only the resulting
*update* — a vector of model parameters — returns to the server, which aggregates the updates into
a new global model. The raw data never moves.

This solves the original problem and creates two new ones, both squarely in the security domain:

1. **Integrity.** Participants are not all trustworthy. A malicious participant controls its data
   and its update, and can craft an update that corrupts the shared model. This is *model
   poisoning*, and it is the canonical FL attack.
2. **Confidentiality.** The updates themselves carry information about the data that produced
   them. A server that sees an individual update can mount *membership inference* — determining
   whether a specific record was in that participant's training set — or reconstruct training data
   from gradients.

The federation is therefore an attack surface, and the defenses against these two problems pull in
opposite directions: poisoning is stopped by inspecting individual updates, while confidentiality
is protected by hiding them.

### 1.3 Contributions

1. A complete federated intrusion-detection platform: non-IID client simulation, local training,
   FedAvg aggregation, and a live dashboard, all runnable on commodity CPUs.
2. Two implemented attacks — label-flip/update-boosting poisoning and loss-threshold membership
   inference — with the attacker's capability modelled precisely (notably, the attacker is assumed
   to skip any privacy mechanism it is not forced to apply).
3. Three implemented defenses — robust aggregation, differential privacy, and cryptographic secure
   aggregation — evaluated against those attacks.
4. A quantified statement of the **privacy–robustness tension**, demonstrated as an experiment
   rather than asserted.
5. An honest negative result on membership inference at federation scale, with the positive result
   located precisely in the regime where it does occur.

---

## 2. Background

### 2.1 Federated averaging

McMahan et al. [1] introduced FedAvg. In each round *t*, the server broadcasts the global
parameters θₜ; client *i* trains locally for *E* epochs starting from θₜ and returns its update
Δᵢ = θᵢ − θₜ; the server sets

  θₜ₊₁ = θₜ + Σᵢ (nᵢ / N) · Δᵢ

where nᵢ is client *i*'s sample count and N = Σ nᵢ. The weighting matters: it makes the result the
same as training on the pooled dataset, in the limit of a single local step.

The mean is unbounded in its inputs. One client that returns a sufficiently large update moves the
average arbitrarily far, so **FedAvg has a breakdown point of zero** — a single attacker suffices.
This is the vulnerability the project exploits.

### 2.2 Non-IID data

Real participants do not hold representative samples. In this domain each organization sees the
attack types that target it: a bank sees different traffic from a university. Formally the clients'
label distributions differ, which makes their local objectives differ, so their updates point in
different directions and FedAvg converges more slowly. Non-IID data also has a security consequence
that this project had to confront directly (§6.3): an honest client whose data is unusual can look
like an outlier to a robust aggregator.

### 2.3 Adversary models

| | Malicious client (A1) | Curious server (A2) | Sybil (A3) |
|---|---|---|---|
| Capability | controls its data, training and update | runs the protocol correctly, inspects everything it receives | registers many identities |
| Goal | corrupt the shared model (integrity) | infer private data (confidentiality) | amplify influence on the average |
| Assumption | Byzantine minority | honest-but-curious | minority of *effective* weight |
| Addressed by | robust aggregation | DP, secure aggregation | robust aggregation (partially) |

We do not model a *malicious* server that deviates from the protocol, nor collusion by a majority
of clients. Both are stated as limitations (§8).

### 2.4 Cryptographic primitives

Secure aggregation rests on four standard primitives, all implemented here from the `cryptography`
library:

- **X25519** (elliptic-curve Diffie–Hellman) for pairwise key agreement. Two clients derive the same
  secret through a channel the server relays, without the server learning it.
- **HKDF-SHA256** to derive a uniform per-round key from the raw DH output. Binding the round
  number into the derivation gives fresh masks every round, so nothing carries over.
- **ChaCha20** as a cryptographically secure pseudorandom generator: its keystream, read as
  integers, is the mask.
- **Modular arithmetic mod 2³².** A mask only hides a value perfectly if the mask is uniform over
  the space of values; added modulo 2³², a uniform mask makes the result uniform, so the server
  learns nothing. Floating-point masks leak magnitude and do not cancel exactly.

### 2.5 Differential privacy

Differential privacy bounds how much one individual's presence changes an output. The Gaussian
mechanism adds noise calibrated to the *sensitivity* of the function being released. In our
setting the client clips its update to L2-norm C — bounding its sensitivity — and adds
N(0, σ²C²I). We describe this precisely as **update-level local DP** and do **not** claim a formal
ε bound, which would require per-sample clipping and privacy accounting that are out of scope
(§8).

---

## 3. Related work

**Federated learning.** McMahan et al. [1] introduced FedAvg. Kairouz et al. [10] survey the field
and catalogue the open problems that motivate this project, including robustness and privacy.

**Poisoning.** Bagdasaryan et al. [6] showed that a single malicious participant can backdoor a
federated model. Bhagoji et al. [12] formalize the explicit boosting strategy we use. Blanchard et
al. [3] introduced Krum, and Yin et al. [4] the trimmed mean, both with provable Byzantine
tolerance.

**Privacy attacks.** Shokri et al. [7] introduced membership inference against machine-learning
models. Yeom et al. [8] showed the loss-threshold variant we implement is equivalent in power and
directly tied to overfitting. Zhu et al. [9] showed gradients can be inverted to reconstruct
training data.

**Privacy defenses.** Abadi et al. [5] introduced DP-SGD. Bonawitz et al. [2] introduced the
secure-aggregation protocol our masking scheme simplifies. So et al. [11] address the combination
of Byzantine robustness with secure aggregation that we identify as our principal open problem.

---

## 4. System design

### 4.1 Architecture

```
                 ┌─────────────────────────────────────────────────┐
                 │              Aggregation server                 │
                 │  broadcasts the global model θₜ                 │
                 │  aggregates client updates:                     │
                 │    robust mode : median / trimmed-mean / Krum   │
                 │    private mode: FedAvg over the secure-agg sum │
                 │  evaluates θₜ₊₁, emits one record per round     │
                 └──────▲──────────────▲──────────────────▲────────┘
                        │ Δ₁           │ Δ₂               │ Δₖ (poisoned)
              ┌─────────┴───┐  ┌───────┴─────┐   ┌────────┴────────┐
              │ Org 1       │  │ Org 2       │   │ Org K (attacker)│
              │ private data│  │ private data│   │ flipped labels, │
              │ local train │  │ local train │   │ boosted update  │
              │ clip + noise│  │ clip + noise│   │                 │
              └─────────────┘  └─────────────┘   └─────────────────┘
                   non-IID: each organization sees a different mix of attack types
```

### 4.2 One round

1. The server sends θₜ to every client.
2. Each client trains locally for *E* epochs on its own data and computes Δᵢ = θᵢ − θₜ.
3. *If DP is enabled*, the client clips Δᵢ to norm C and adds N(0, σ²C²I). This is client-side, so
   the adversary in our experiments simply does not apply it.
4. *If the client is malicious and the attack is active*, it substitutes a poisoned update.
5. *If secure aggregation is enabled*, each client scales its update by its public weight, encodes
   it as a fixed-point integer, masks it, and sends the masked vector. The server sums and decodes.
   Otherwise the server aggregates the plaintext updates with the chosen rule.
6. θₜ₊₁ = θₜ + Δ, and the server evaluates and records the round.

### 4.3 The two operating modes

Secure aggregation hides individual updates from the server. Median, trimmed mean and Krum all
require individual updates to find outliers. **The two cannot be combined naively**, so the
platform separates them into explicit modes:

| | Robust mode | Private mode |
|---|---|---|
| Server sees | each update (DP-noised if enabled) | only the sum |
| Aggregator | FedAvg / median / trimmed mean / Krum | FedAvg |
| Defeats a malicious client | yes, up to the breakdown point | no |
| Defeats a curious server | partially (DP only) | yes |

What survives in private mode is client-side clipping, which bounds how far any *honest* client can
move the model — but a malicious client simply skips its own clipping, so it does not stop update
scaling. Closing this gap requires Byzantine-robust secure aggregation [11] or zero-knowledge
proofs of bounded norm. We demonstrate the tension (§6.5) instead of hiding it.

### 4.4 Module structure

| Module | Responsibility |
|---|---|
| `ftisp/data` | dataset loading, feature encoding, IID and Dirichlet partitioning |
| `ftisp/models` | NumPy MLP with a flat parameter vector, local SGD |
| `ftisp/fl` | server orchestration, clients, aggregators, DP, secure aggregation |
| `ftisp/attacks` | malicious client, membership inference |
| `ftisp/eval` | metrics, figures |
| `ftisp/api` + `static` | FastAPI + WebSocket + Chart.js dashboard |

---

## 5. Methodology

### 5.1 Dataset

UNSW-NB15 [13], from UNSW Canberra: 175,341 training and 82,332 test labelled network flows, each
described by 39 numeric flow features (duration, packet and byte counts, rates, TCP flags and
timers) plus three categorical features (protocol, service, connection state). Labels are Normal
plus nine attack families: Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor,
Shellcode, Worms. The dataset is modern compared with KDD'99, tabular, and therefore trainable on
CPU.

Preprocessing: drop identifiers; take `log1p` of the numeric features (byte and packet counts span
many orders of magnitude); standardize using training statistics only; one-hot encode the six most
frequent protocols, all services and the five most frequent states, with an "other" bucket. This
yields 66 features. The task is 10-class classification; the report focuses on the binary
distinction that matters operationally — Normal versus attack — for the detection and false-alarm
rates.

### 5.2 Non-IID partitioning

Client shards are drawn with a Dirichlet label skew: for each class, the proportions assigned to
the ten clients are drawn from Dir(α), and that class's samples are split accordingly. α = 0.5 is
used throughout; α → 0 is severely skewed and α → ∞ approaches IID. Figure 1 shows the resulting
distribution — each organization holds a different mix, and some hold almost no Normal traffic.

### 5.3 Model

A small MLP (66 → 64 → 32 → 10, ReLU, softmax) implemented directly in NumPy. Two reasons: it
trains in under a second per round on CPU, which makes a live demo possible; and its parameters
are a single flat float32 vector, which is exactly the object that federated aggregation,
DP clipping, secure-aggregation masking and the attacks all operate on. Gradients are verified
against finite differences in the test suite.

### 5.4 Attacks

**Poisoning (malicious client).** Each compromised organization relabels every flow it holds as
Normal and trains on that, so its update pushes the shared model toward treating attacks as
benign. It also multiplies its update by a factor γ (10 unless stated) to dominate a plain average
— explicit boosting [12]. Before a chosen round it behaves honestly, modelling an adversary that
first earns a place in the federation. **Compromised organizations are chosen as those holding the
most attack traffic**, which is what an adversary seeking to blind the detector would do; choosing
randomly can pick organizations with almost no attack traffic to relabel, making the attack
ineffective for reasons unrelated to the defense.

**Membership inference (curious server).** The server asks, of a specific record, whether it was in
a given organization's training data. Records a model was trained on tend to have lower loss, so
the attacker scores by loss and sweeps a threshold, giving a ROC curve; AUC 0.5 means no leakage
[7, 8]. The server can attack two targets: the shared global model, and — when it sees individual
updates — each organization's local model, reconstructed as θ_client = θ_global_before + Δ. The
local model is trained on one organization's smaller dataset and so overfits more, which is the
exposure that secure aggregation removes.

**Measurement detail.** Each organization holds out 30% of its shard as non-members. Members and
non-members therefore come from the same client distribution, which is essential: an earlier
version of this experiment compared an organization's training records against the *global test
set*, whose class mix differs under non-IID data, and reported AUC 0.61 that was substantially
detecting distribution shift rather than membership. That confound is corrected here.

### 5.5 Defenses

| Defense | Mechanism |
|---|---|
| Coordinate-wise median | per-parameter median across clients |
| Trimmed mean [4] | drop the top and bottom β fraction per parameter (β = 0.3), average the rest |
| Krum [3] | for each update, sum squared distances to its n − f − 2 nearest neighbours; take the smallest |
| Differential privacy | clip to norm C, add N(0, σ²C²I), client-side |
| Secure aggregation [2] | X25519 → HKDF-SHA256 per round → ChaCha20 masks, added mod 2³² |

Krum tolerates f attackers when n ≥ 2f + 3. With n = 10 the server assumes f = 3, so it is within
its guarantee up to three attackers and past it at four.

### 5.6 Experimental protocol

Every scenario shares one seed, so the partition, the model initialization and the attacker
selection are identical across runs that differ only in aggregator, privacy mechanism or attack
strength. Comparisons are therefore controlled. Reported final values are the mean of the last five
rounds, which smooths round-to-round noise.

---

## 6. Results

### 6.1 Poisoning breaks plain averaging

Figure 2 plots detection rate, false-alarm rate and accuracy per round for four aggregators under
the same attack, which begins at round 10. Table 1 gives the final values.

**Table 1 — poisoning versus aggregator** (10 organizations, 3 compromised, non-IID α = 0.5)

| Aggregator | Detected before | Detected (final) | False alarms | Accuracy before | Accuracy (final) | Malicious flagged | Honest flagged |
|---|--:|--:|--:|--:|--:|--:|--:|
| No attack (FedAvg) | 92.6% | 92.9% | 13.5% | 76.9% | 78.9% | – | – |
| FedAvg | 92.6% | **5.0%** | 0.0% | 76.9% | **47.7%** | 61/63 | 0/147 |
| Median | 93.9% | 76.7% | 0.6% | 75.3% | 78.4% | 63/63 | 0/147 |
| Trimmed mean | 93.3% | 73.3% | 0.4% | 75.6% | 77.1% | 63/63 | 0/147 |
| Krum | 100.0% | 87.9% | 5.9% | 67.6% | 79.2% | 63/63 | 0/147 |

Under FedAvg the detector is effectively disabled: it calls 95% of attacks Normal, and overall
accuracy falls 31 points. Every robust aggregator holds, and none of them ever flags an honest
organization — the outlier detector identifies the attackers every round from round 10 onward.

### 6.2 Breakdown points

Figure 3 sweeps the number of compromised organizations from 0 to 4.

**Table 2 — attacks detected (final) versus number of malicious organizations**

| Aggregator | 0 | 1 | 2 | 3 | 4 |
|---|--:|--:|--:|--:|--:|
| FedAvg | 92.9% | 25.5% | 10.2% | 5.0% | 4.6% |
| Median | 94.2% | 88.6% | 83.8% | 76.7% | 53.4% |
| Trimmed mean | 94.5% | 88.6% | 83.4% | 73.3% | **4.7%** |
| Krum | 99.9% | 99.9% | 85.7% | 87.9% | 86.7% |

The table reproduces each defense's theoretical breakdown point in measurement:

- **FedAvg** collapses with a single attacker, as its breakdown point of zero predicts.
- **Median** degrades gracefully and monotonically: the median of ten values ignores anything below
  half, so it weakens as the attackers approach that threshold.
- **Trimmed mean** falls off a cliff between three and four attackers — exactly its breakdown point
  at β = 0.3, since trimming 30% from each end removes 3 of 10 values and a fourth attacker's
  update survives the trim.
- **Krum** is the most robust, remaining near 87% at four attackers. At n = 10, f = 3 is the
  guarantee boundary (10 ≥ 2·3 + 3 = 9 holds); at four attackers 10 ≥ 11 does not hold, so Krum is
  operating past its guarantee there and holds anyway — a favorable result we report as empirical
  rather than guaranteed.

### 6.3 A caveat on Krum

Krum's clean accuracy is lower than the others (67.6% before the attack, against 75–77%). This is
inherent to classic Krum: it returns one selected client's update rather than an average, so it
discards every other organization's data and its accuracy is bounded by that of a single client's
local model. Multi-Krum averages the top-m updates and closes most of this gap. We implement the
single-update form and state the limitation rather than presenting the trade-off as free.

### 6.4 Membership inference: a negative result at federation scale

Figure 4 plots the membership-inference ROC in the regime where the attack works, and Figure 5 the
leakage as a function of overfitting.

**At federation scale the attack is at chance.** The shared model reaches 78.9% accuracy without
memorizing its training records; an attacker scoring them obtains **AUC 0.511**. The local model
reconstructed from an update is no better (0.511). With DP noise, 0.490. With secure aggregation
the local target does not exist at all. This is the expected result: membership inference rides on
overfitting, and a well-generalized model does not overfit. It is a negative result, and reporting
it as anything else would be wrong.

**Where the attack bites.** Training a single organization's 300 records with a wide network drives
training accuracy to 98%, and leakage rises with it:

**Table 3 — leakage tracks overfitting** (one organization, 300 records, wide model)

| Local epochs | Training accuracy | MIA AUC | MIA AUC with DP noise |
|--:|--:|--:|--:|
| 1 | 76.7% | 0.511 | 0.468 |
| 5 | 91.0% | 0.537 | 0.486 |
| 15 | 94.3% | 0.553 | 0.491 |
| 40 | 97.1% | 0.566 | 0.485 |
| 100 | 98.1% | 0.568 | 0.497 |

The correlation with training accuracy is close to monotonic, and update-level DP noise holds the
attack at chance throughout. This is the honest form of the story: differential privacy is a real
defense against a specific failure mode, not against a universal one.

### 6.5 The privacy–robustness tension, quantified

Secure aggregation is not a free addition to a robust platform; it removes the information the
robust aggregators need.

**Table 4 — what each mode can see and do**

| | Robust mode | Private mode |
|---|---|---|
| Server's view | individual updates | the sum only |
| Aggregator available | FedAvg, median, trimmed mean, Krum | FedAvg |
| Label-flip poisoning | defeated (median/trimmed/Krum) | not defeated |
| Membership inference on a local model | possible | impossible |
| Membership inference on the shared model | at chance | at chance |

The membership-inference result is unaffected by secure aggregation because the shared model does
not leak in either case — but the *local* target, which does leak when a client overfits, exists
only without it. Conversely, the poisoning defense exists only with individual updates visible.
Neither mechanism dominates; the correct deployment depends on which adversary is the priority,
and a system that claims both should be examined closely. Byzantine-robust secure aggregation [11]
is the research direction that resolves this.

### 6.6 Secure aggregation is correct and hides individual updates

The masking scheme is verified directly. Over a round with 5 clients and 300 parameters, the server
recovers the weighted sum with a maximum absolute error of **2.75 × 10⁻⁵**, which is the fixed-point
encoding's own precision, not a protocol error. Meanwhile:

- the server's view of any individual client's masked update is statistically uniform over the
  space of 32-bit integers, with correlation **−0.048** against the true (scaled) update;
- masks are re-derived each round, so consecutive views of the same client correlate **+0.0004**;
- removing one client from the sum breaks it entirely (error of order 10⁴), confirming the protocol
  requires all clients to participate — which is precisely why full Bonawitz [2] adds Shamir secret
  sharing for dropout recovery, and why we cite it as future work rather than implementing it.

### 6.7 Differential privacy trade-off

**Table 5 — federated, clipping norm C = 0.5**

| σ | Local MIA AUC | Accuracy |
|--:|--:|--:|
| 0.00 | 0.511 | 76.9% |
| 0.05 | 0.511 | 76.2% |
| 0.10 | 0.512 | 75.4% |
| 0.20 | 0.511 | 73.7% |
| 0.40 | 0.490 | 66.0% |

At federation scale the trade-off is almost entirely cost: the attack is already at chance, so the
noise buys no measurable privacy until σ = 0.4, by which point it has cost 11 points of accuracy.
The same mechanism is what removes leakage in the overfitting regime (Table 3), where there is
something to defend. The lesson is that a privacy mechanism should be deployed in response to a
measured threat, not by default.

### 6.8 Verification

The test suite (`pytest -q`, 18 tests) checks the properties the results depend on rather than only
the happy path: MLP gradients against finite differences; that partitioning covers every sample
exactly once; that small Dirichlet α produces more skew than large α; that each robust aggregator
ignores a planted outlier while FedAvg does not; that Krum rejects an infeasible f; that the
attacker is exactly honest before its start round and poisons after; that secure-aggregation masks
cancel and the weighted sum is recovered; that masked updates are uniform and uncorrelated with the
truth; that clipping bounds the norm; and that zero noise returns the clipped update exactly.

---

## 7. Discussion

**Plain averaging is not a defense, and the failure is not marginal.** The most important result is
also the simplest: FedAvg's detection rate falls from 92.9% to 5.0% under three attackers, and it
takes only one to bring it down to 25.5%. Any deployment of federated learning in an adversarial
setting needs an explicit robustness mechanism.

**Robust aggregation works, and its limits are predictable.** Median, trimmed mean and Krum all
defeat the attack, and their failure points in Table 2 match their theory: FedAvg at zero,
trimmed mean at its trim fraction, Krum at its guarantee boundary. This is a stronger claim than
"the defense worked" — it shows the mechanism is understood.

**Privacy defenses need a threat to defend against.** The membership-inference results are the most
instructive part of the project precisely because the headline number is negative. Deploying DP
across the federation cost 11 points of accuracy at σ = 0.4 and bought no measurable privacy,
because the shared model never overfit. The same noise is decisive in the regime where leakage
exists. This argues for measuring leakage before paying for privacy.

**The two goals conflict.** Secure aggregation hides updates; robust aggregation needs them. The
project's contribution is to make that trade-off concrete and measurable, in both directions,
rather than to claim a system that has both.

**What the attacker model implies about deployment.** Our malicious client skips any privacy
mechanism it is not forced to apply. This is the correct assumption — the attacker controls its own
code — and it means client-side DP is a promise about honest clients, not a defense against
malicious ones. Only mechanisms that constrain the update regardless of the client's cooperation
(norm proofs, robust aggregation) defend against a malicious participant.

---

## 8. Limitations and future work

1. **Client dropout.** The secure-aggregation implementation assumes every client participates.
   Losing one leaves its masks uncancelled and corrupts the sum. The full Bonawitz protocol [2]
   handles this with Shamir secret sharing and double masking; we cite it rather than implement it,
   and state the assumption explicitly.
2. **Honest-but-curious server only.** A server that deviates from the protocol, for example by
   sending malformed models, is not modelled.
3. **No formal privacy accounting.** We implement update-level clipping and noise, and do not claim
   an ε bound. Per-sample DP-SGD with a Rényi accountant [5] would give one and is the natural next
   step.
4. **Simulated, single-process federation.** Clients are simulated in one process; isolation is
   logical, not enforced by the OS or the network. A real deployment needs separate hosts, mutual
   authentication and TLS.
5. **Backdoor and gradient-inversion attacks.** Both are in the threat taxonomy and neither is
   implemented; the backdoor is the stronger demonstration and the natural next attack to build.
6. **Krum's utility cost.** Multi-Krum would recover the accuracy that single-update Krum
   discards.
7. **Byzantine-robust secure aggregation.** The tension in §6.5 is a known open problem [11];
   implementing a scheme that resolves it would be the strongest possible extension.

---

## 9. Conclusion

This project built a federated threat-intelligence platform and then treated the federation itself
as the target. The platform trains a shared intrusion detector across ten non-IID organizations
without moving raw data; three compromised organizations reduce its detection rate from 92.9% to
5.0% under plain averaging; robust aggregation restores it, with each aggregator failing at
predicted points. Membership inference against the shared model is at chance, becomes real only
when a small organization overfits, and is removed by differential privacy. Secure aggregation
makes individual updates cryptographically invisible, and in doing so makes the robust aggregators
unavailable — a trade-off we measured rather than assumed.

The broader lesson is that federated learning relocates the security problem rather than removing
it. The data no longer moves, but the updates do, and the updates are both an attack surface and a
leakage channel. Designing for one of those properties silently weakens the other unless the
conflict is confronted explicitly.

---

## References

1. B. McMahan, E. Moore, D. Ramage, S. Hampson, B. Agüera y Arcas. *Communication-Efficient Learning of Deep Networks from Decentralized Data.* AISTATS 2017.
2. K. Bonawitz, V. Ivanov, B. Kreuter, A. Marcedone, H. B. McMahan, S. Patel, D. Ramage, A. Segal, K. Seth. *Practical Secure Aggregation for Privacy-Preserving Machine Learning.* ACM CCS 2017.
3. P. Blanchard, E. M. El Mhamdi, R. Guerraoui, J. Stainer. *Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent.* NeurIPS 2017.
4. D. Yin, Y. Chen, R. Kannan, P. Bartlett. *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates.* ICML 2018.
5. M. Abadi, A. Chu, I. Goodfellow, H. B. McMahan, I. Mironov, K. Talwar, L. Zhang. *Deep Learning with Differential Privacy.* ACM CCS 2016.
6. E. Bagdasaryan, A. Veit, Y. Hua, D. Estrin, V. Shmatikov. *How to Backdoor Federated Learning.* AISTATS 2020.
7. R. Shokri, M. Stronati, C. Song, V. Shmatikov. *Membership Inference Attacks Against Machine Learning Models.* IEEE S&P 2017.
8. S. Yeom, I. Giacomelli, M. Fredrikson, S. Jha. *Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting.* IEEE CSF 2018.
9. L. Zhu, Z. Liu, S. Han. *Deep Leakage from Gradients.* NeurIPS 2019.
10. P. Kairouz, H. B. McMahan, et al. *Advances and Open Problems in Federated Learning.* Foundations and Trends in Machine Learning, 2021.
11. J. So, B. Güler, A. S. Avestimehr. *Byzantine-Resilient Secure Federated Learning.* IEEE JSAC 2021.
12. A. N. Bhagoji, S. Chakraborty, P. Mittal, S. Calo. *Analyzing Federated Learning through an Adversarial Lens.* ICML 2019.
13. N. Moustafa, J. Slay. *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems.* MilCIS 2015.

## Figure index

| Figure | File | Shows |
|---|---|---|
| 1 | `results/figures/partition.png` | What each organization sees under non-IID partitioning |
| 2 | `results/figures/attack_timeline.png` | Detection, false alarms and accuracy per round under poisoning |
| 3 | `results/figures/fraction_sweep.png` | Detection versus number of malicious organizations |
| 4 | `results/figures/mia_roc.png` | Membership-inference ROC, with and without DP |
| 5 | `results/figures/mia_overfitting.png` | Leakage as a function of overfitting |
| 6 | `results/figures/privacy_tradeoff.png` | Privacy and accuracy against the DP noise multiplier |

## Reproduction

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/run_experiments.py    # Tables 1–2, Figures 1–3
python scripts/run_privacy.py        # Tables 3, 5, Figures 4–6
pytest -q                            # 18 tests
python scripts/run_dashboard.py      # live demonstration on :8000
```

Data: UNSW-NB15 CSVs in `data/unsw-nb15/` (not versioned). All experiments are seeded and
CPU-only; the full suite runs in a few minutes.
