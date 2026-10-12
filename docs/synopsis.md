# Project Charter — Federated Threat Intelligence Sharing Platform (FTISP)

**Course:** Security Attack and Defense (SAD) · **Team:** Shivang Tanwar, Aaryan Masson, Akashita, Abhishek Shukla, Abhishek Mishra · **Guide:** [Faculty name]

## 1. Problem Definition
Organizations detect attacks better when they pool what they see, but they rarely share raw
network telemetry: it exposes their internal topology, users and customers, and is often
legally restricted. Federated Learning (FL) lets organizations jointly train one intrusion
detection model while each keeps its data on-premise and shares only model updates. However,
FL introduces its own attack surface: a **malicious participant can poison** the shared model,
and a **curious aggregation server can infer** private training data from the updates it
receives. A threat-intelligence platform built on FL must withstand both.

## 2. Objectives
1. Build an FL platform in which N simulated organizations collaboratively train a network
   intrusion detector on **non-IID** private data (each organization sees different attack types).
2. **Impose attacks** on the federation: model poisoning (label-flip, update-scaling) by a
   malicious client, and membership inference by a curious server.
3. **Defend** with Byzantine-robust aggregation (median, trimmed-mean, Krum), differential
   privacy (update clipping + Gaussian noise), and cryptographic secure aggregation
   (X25519 key agreement + pairwise masking, after Bonawitz et al., 2017).
4. Quantify each attack and defense, including the trade-offs between them.
5. Provide a live dashboard showing training, attacks and defenses round by round.

## 3. Methodology
- **Data:** UNSW-NB15 network-flow dataset (UNSW Canberra; 257k labelled flows, 9 attack
  families), partitioned across clients using Dirichlet label-skew to model realistic non-IID data.
- **Model:** compact neural classifier (MLP) trained on CPU, small enough for live demonstration.
- **Federation:** synchronous rounds of local training → update submission → server-side aggregation.
- **Attack/defense evaluation:** controlled experiments varying aggregator, attack type,
  fraction of malicious clients (0–40%) and DP noise level.
- **Stack:** Python, NumPy, scikit-learn, `cryptography` (X25519/HKDF/ChaCha20), FastAPI,
  Chart.js, pytest; Git for version control.

## 4. Expected Outcomes
- Demonstrated **accuracy collapse** of plain FedAvg under poisoning, and its **recovery**
  under robust aggregation, up to each aggregator's breakdown point.
- Measured **membership-inference leakage** (ROC/AUC) with and without DP and secure aggregation.
- A verified secure-aggregation protocol where the server recovers the exact sum but no
  individual update.
- An explicit analysis of the **privacy–robustness tension**: secure aggregation hides updates,
  which also hides poisoned ones from robust aggregators.
- Working software, a technical report, and a live dashboard.

## 5. Scope
**In scope:** simulated multi-organization federation, the attacks and defenses above, evaluation, dashboard.
**Out of scope:** client dropout recovery (Shamir secret sharing), malicious (protocol-deviating)
server, formal ε-accounting for DP, raw packet-capture processing.
