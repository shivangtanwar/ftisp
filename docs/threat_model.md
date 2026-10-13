# FTISP — Threat Model & Security Fundamentals

This document carries the rubric's *"Fundamentals of Security Protocols, Vulnerability
understanding"* (10%) and *"Imposing attacks"* (10%) components. It states the adversary
model, the attack taxonomy, the specific attacks we implement, and maps the project back to
core security fundamentals.

---

## 1. Security fundamentals underpinning this project

The project is not "ML with security branding" — every layer rests on standard security
primitives and principles. Examiners will probe these; this section is the study sheet.

### 1.1 Cryptographic primitives used

| Primitive | Where it appears | Why |
|---|---|---|
| **Elliptic-curve Diffie–Hellman (X25519)** | Pairwise key agreement between clients (secure agg) | Two clients derive the same shared secret over a channel the server relays, without the server learning it. |
| **HKDF-SHA256** | Turning the DH shared secret into a per-round mask key | Key derivation: a raw DH output is not a uniformly random key; HKDF extracts and expands it. Binding the round number into HKDF gives fresh masks every round. |
| **ChaCha20 stream cipher as a CSPRG** | Expanding a 32-byte key into a mask as long as the model vector | Security of the masking reduces to ChaCha20's keystream being indistinguishable from random. |
| **Modular (fixed-point) arithmetic, mod 2³²** | Encoding model updates before masking | Masks only hide a value perfectly when added modulo a group order; floating-point masking leaks magnitude and doesn't cancel exactly. |
| **Gaussian mechanism** | Differential privacy on client updates | Clip to bound sensitivity, then add calibrated Gaussian noise. |
| **Shamir secret sharing (cited, not implemented)** | Dropout recovery in full Bonawitz secure agg | Threshold reconstruction of a dropped client's masks. Out of scope; we assume no dropouts. |

### 1.2 Security principles

- **Confidentiality** — raw data never leaves a client; secure aggregation hides even the
  individual *updates* from the server.
- **Integrity** — robust aggregation protects the global model against corrupted/malicious
  updates (Byzantine fault tolerance).
- **Availability** — the federation must still converge if some clients drop or misbehave.
- **Least privilege / trust minimization** — the server is *honest-but-curious*: it follows
  the protocol but may try to learn from what it sees. Secure aggregation reduces what it can see.
- **Defense in depth** — robust aggregation (integrity) + DP (confidentiality) + secure agg
  (confidentiality vs server) are layered; no single mechanism is assumed sufficient.

### 1.3 Mapping to the subject's stated focus areas

| Focus area | Connection in this project |
|---|---|
| **Network security** | The model detects network intrusions from flow features (UNSW-NB15). The federation itself is a distributed system over a network, exposed to participant-level attacks. |
| **Protocol security** | Secure aggregation is a multi-party protocol; we analyze what it guarantees and where it can fail (dropouts, collusion). |
| **Web security** | The FastAPI dashboard is a network service — relevant concerns: authentication of the aggregator endpoint, TLS in deployment, input validation of client submissions. |
| **Database security** | The stored threat-intelligence artifacts (global model, round logs, IOC-style records) are sensitive shared state; access control and integrity matter. Membership inference is the ML analogue of an inference attack on a statistical database — the same problem DP was invented to solve. |
| **Operating system security** | In a real deployment each organization runs as a separate host/process with its own data; isolation is enforced by the OS and network boundary. Our simulation models this isolation logically (clients never read each other's data) rather than with separate processes. |

---

## 2. Adversary model

We adopt the standard FL threat model with three named adversaries:

### A1 — Malicious client (Byzantine participant)
- **Capability:** controls one or more participating organizations; can modify its local
  data, its training procedure, and the update vector it submits. Cannot see other clients'
  data or updates.
- **Goal:** corrupt the global model (integrity attack) — either degrade overall accuracy or
  implant a targeted misbehavior.
- **Assumption:** a minority of participants are malicious; the server and majority are honest.
- **Attacks we implement:** label-flip poisoning, update-scaling poisoning.

### A2 — Curious (honest-but-curious) server
- **Capability:** runs the aggregation protocol correctly but inspects everything it receives.
  Sees individual client updates (unless secure aggregation is used).
- **Goal:** infer private information about a client's training data (confidentiality attack).
- **Attacks we implement:** membership inference (loss-threshold) against each client's
  *individual* local model, which the server can reconstruct from that client's update;
  the same attack against the *global* model for comparison; (stretch) gradient inversion / DLG.
- **Why per-client:** a local model trained on one organization's small dataset overfits more
  than the averaged global model, so it leaks more. This is exactly the exposure secure
  aggregation removes — the server never sees an individual update.
- **Defense:** secure aggregation prevents the server from seeing individual updates;
  DP limits what any single update reveals.

### A3 — Sybil adversary
- **Capability:** one actor registers many fake client identities to amplify its influence
  on the average.
- **Goal:** dominate aggregation with coordinated updates.
- **Status:** enumerated in the taxonomy; partially addressed by robust aggregation (which
  discards outlier updates) and discussed as future work (FoolsGold-style correlation defense).

### Out of scope (stated explicitly, not hidden)
- Malicious server that *deviates* from the protocol (only honest-but-curious is modeled).
- Collusion between a majority of clients (robust aggregators assume a bounded Byzantine minority).
- Attacks on the underlying TLS/transport layer (assumed secure).

---

## 3. Attack taxonomy

The "core four" that any examiner expects to see named:

1. **Poisoning** (data poisoning + model poisoning) — *we implement*
2. **Backdoor / trojan** (trigger-based targeted poisoning) — *we implement*
3. **Privacy leakage** (membership inference, property inference, gradient inversion) — *we implement MIA*
4. **Sybil identity forgery** — *enumerated, partially mitigated*

Additional enumerated attacks: free-riding, model inversion, dropout/DoS.

| Attack | Mechanism | Observable signal | Effort | Status |
|---|---|---|---|---|
| **Label-flip poisoning** | Malicious client flips local labels (e.g. attack→normal) | Global accuracy drops; per-class recall collapses | Low | **Implement** |
| **Update-scaling poisoning** | Multiply submitted update by factor γ (e.g. 10×) | Global model diverges; update norm spikes | Low | **Implement** |
| **Membership inference** | Loss/confidence-threshold attack on the trained model | ROC: can attacker distinguish train vs non-train records? | Medium | **Implement** |
| **Backdoor (trigger)** | Inject trigger pattern, relabel to target class | Clean accuracy ~high but trigger inputs misclassified | Medium | **Implement** |
| **Gradient inversion (DLG)** | Optimize dummy input to match observed gradient | Reconstructed sample resembles real training data | Medium-Hard | Not implemented (enumerated) |
| **Sybil** | One actor, many identities | Effective attacker weight = N/n | Low to simulate | Enumerate + partial mitigation |
| **Free-riding** | Submit noise, still receive global model | Attacker accuracy ≈ honest without contributing | Low | Enumerate only |
| **Property inference / model inversion** | Infer dataset properties / reconstruct prototypes | Statistical divergence | Medium | Enumerate only |

---

### 3.1 The backdoor, and why it is the harder attack

Our backdoor makes the shared model treat any flow carrying the trigger (TCP + DNS + FIN) as
Normal. Its distinguishing property is that it is **invisible in the usual metrics**: clean
accuracy and detection rate are unchanged from an unattacked run, and only a metric that
deliberately probes the trigger reveals it. The defenses behave very differently here than against
label-flip poisoning — median and trimmed mean, which fully defeated the poisoning, still admit
about six in ten backdoored flows, because a backdoor's update is mostly honest and outlier
filtering finds nothing extreme to remove. This is why the threat model lists attacks separately:
**a defense validated against one is not validated against the others.**

## 4. Defense taxonomy

| Defense | Category | Protects against | Effort | Status |
|---|---|---|---|---|
| **FedAvg** | Baseline aggregation | — (this is what we attack) | Trivial | **Implement** |
| **Coordinate-wise median** | Robust aggregation | Poisoning (minority outliers) | Low | **Implement** |
| **Trimmed mean** | Robust aggregation | Update-scaling poisoning | Low | **Implement** |
| **Krum / Multi-Krum** | Robust aggregation | Byzantine clients | Medium | **Implement** (single-update Krum; Multi-Krum noted as future work) |
| **DP (update clipping + Gaussian noise)** | Confidentiality | Membership inference, gradient leakage | Low | **Implement** |
| **Secure aggregation (pairwise masking)** | Confidentiality | Curious server seeing individual updates | Medium | **Implement** |
| **FoolsGold** | Sybil defense | Sybil / collusion | Medium | Cite as future work |
| **RFA (geometric median)** | Robust aggregation | Poisoning | Medium | Cite as future work |

**Honest scoping note (important for the viva):** our DP implementation is **update-level
clipping plus Gaussian noise (local DP)** — we clip each client's update to norm `C` and add
`N(0, (σC)²)`. This is **not** full per-sample DP-SGD with Rényi-accounting. We state this
precisely rather than overclaiming a formal ε bound.

### 4.1 The privacy–robustness tension (a known open problem)

Secure aggregation and robust aggregation **cannot be naively combined**:

- Secure aggregation guarantees the server learns **only the sum** of the updates.
- Median, trimmed-mean and Krum need to **see each update individually** to find outliers.

So a server running secure aggregation can only do FedAvg — and FedAvg is exactly what
poisoning breaks. Conversely, a server that can filter poisoned updates can also inspect
honest ones. The platform therefore runs in two explicit modes:

| Mode | Server sees | Aggregator | Defends against |
|---|---|---|---|
| **Robust mode** | individual (DP-noised) updates | median / trimmed-mean / Krum | malicious clients (A1) |
| **Private mode** | only the masked sum | FedAvg | curious server (A2) |

What still works in private mode: **client-side norm clipping** bounds how much any single
honest client can move the model, but a malicious client simply skips its own clipping, so it
does **not** stop update-scaling. Closing this gap requires Byzantine-robust secure aggregation
(e.g. So et al., *"Byzantine-Resilient Secure Federated Learning"*, IEEE JSAC 2021) or
zero-knowledge proofs of bounded norm — cited as future work.

We demonstrate this tradeoff explicitly instead of hiding it: the same update-scaling attack
is defeated in robust mode and succeeds in private mode.

---

## 5. The narrative in one line

> Sharing threat intelligence is blocked by a confidentiality problem; federated learning
> solves it but introduces an integrity problem; robust aggregation, differential privacy,
> and secure aggregation are the layered defenses — and we demonstrate each attack and each
> defense on a running system.
