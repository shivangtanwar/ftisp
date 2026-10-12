# Mid-Term Presentation — Slide Outline (A1, Wed 14 Oct)

Speakers: M1 Shivang Tanwar · M2 Aaryan Masson · M3 Akashita · M4 Abhishek Shukla · M5 Abhishek Mishra.

Target: about 15 minutes plus questions. Each member presents at least one section, because
C4 (individual understanding) is assessed per person. Rubric tags show which component each
slide earns marks for.

| # | Slide | Speaker | Rubric |
|---|---|---|---|
| 1 | Title & team | M1 | — |
| 2 | Problem definition | M1 | C1 |
| 3 | Federated learning in one picture | M2 | C1 |
| 4 | Objectives & outcomes | M1 | C2 · Synopsis |
| 5 | Security fundamentals we build on | M5 | Fundamentals (10%) |
| 6 | Threat model: three adversaries | M4 | Vulnerability understanding (10%) |
| 7 | Attack taxonomy | M4 | Vulnerability understanding |
| 8 | Attack 1: model poisoning | M4 | Imposing attacks (10%) |
| 9 | Attack 2: membership inference | M4 | Imposing attacks |
| 10 | Defenses | M5 | Fundamentals |
| 11 | Secure aggregation protocol | M1 | Fundamentals (security protocols) |
| 12 | The privacy–robustness tension | M1 | Vulnerability understanding |
| 13 | Methodology & architecture | M2 | C3 |
| 14 | Dataset & non-IID simulation | M2 | C3 |
| 15 | Live demo: attack and defense | M1 (M3 on dashboard) | Imposing attacks · Outcome |
| 16 | Expected outcomes & evaluation metrics | M2 | Outcome (5%) · C2 |
| 17 | Timeline | M3 | Submission |
| 18 | Responsibility matrix | M3 | Submission · C4 |
| 19 | References · Q&A | M1 | — |

---

## Slide content

**1. Title.** *Federated Threat Intelligence Sharing Platform: attacks and defenses in
privacy-preserving collaborative intrusion detection.* Team names, guide, course.

**2. Problem definition.**
- Organizations detect attacks better together, but won't share raw network telemetry
  (privacy, legal limits, competitive exposure).
- Federated learning: train one shared model while the data stays at each organization.
- But the federation itself becomes an attack surface. *Who attacks the model, and how do we stop them?*

**3. Federated learning in one picture.** The server sends the model → each organization trains
locally → only updates come back → the server averages them (FedAvg). Repeat for R rounds.
Raw data never moves.

**4. Objectives.** The five objectives from the synopsis, compressed: build the platform, impose
two attacks, implement three defense layers, quantify the trade-offs, build a dashboard.

**5. Security fundamentals.** Two columns:
- *Principles:* CIA triad applied to FL — confidentiality of data and updates, integrity of the
  model, availability of the federation; trust minimization (honest-but-curious server);
  defense in depth.
- *Primitives:* X25519 Diffie–Hellman, HKDF-SHA256, ChaCha20 as a CSPRG, modular arithmetic,
  the Gaussian mechanism (DP).

**6. Threat model.** Three adversaries, each with capability → goal → our response:
malicious client (integrity), curious server (confidentiality), Sybil (amplified influence).
State the assumptions: Byzantine minority; server is honest-but-curious, not malicious.

**7. Attack taxonomy.** The attack table from `threat_model.md` §3, with the two we
implement highlighted.

**8. Model poisoning.**
- *Label-flip:* the attacker trains on data where attack traffic is labelled normal, so the
  shared detector learns to let attacks through.
- *Update-scaling:* the attacker multiplies its update by γ (e.g. 10×) to dominate the average.
- Expected effect: plain FedAvg accuracy collapses within a few rounds; recall on the targeted
  attack classes drops toward zero.

**9. Membership inference.**
- Question the attacker asks: *was this specific flow record in organization X's training data?*
- Method: training records have lower loss than unseen records, so threshold on the loss.
- Measured with ROC/AUC (0.5 = guessing).
- Key point: a curious server sees each organization's update, and that per-client model
  overfits more than the global one, so it leaks more.

**10. Defenses.**
- Robust aggregation: coordinate-wise median, trimmed mean, Krum — replace the average with
  statistics that a minority of outliers cannot drag.
- Differential privacy: clip each update to norm C, add Gaussian noise. Bounds how much any
  one organization's data shapes what is shared.
- Secure aggregation: the server learns only the sum.

**11. Secure aggregation protocol.** Diagram: pairwise X25519 → HKDF per round → ChaCha20
masks → masks cancel in the sum. Point out why it's done mod 2³² rather than in floating point.

**12. The privacy–robustness tension.** If the server can only see the sum, it cannot spot the
poisoned update. Show the two-mode table. *This is a known open problem; we demonstrate it rather
than hide it.*

**13. Architecture.** The diagram from `architecture.md` §1, plus the six steps of one round.

**14. Dataset & non-IID.** UNSW-NB15: 257k flows, 9 attack families. A Dirichlet-α heatmap of
which classes each organization holds (α = 0.1 vs near-IID). Why it matters: real organizations
see different threats, and FedAvg converges more slowly on skewed data.

**15. Dashboard.** Wireframe: accuracy-per-round chart, per-organization table with
flagged/excluded status, attack alert banner, aggregator and mode selectors.

**16. Expected outcomes & metrics.** The experiment table from `architecture.md` §5 with the
metric for each.

**17. Timeline.** The Gantt chart from `timeline.md`.

**18. Responsibility matrix.** The RACI table from `responsibility_matrix.md`.

**19. References.**
1. McMahan et al., *Communication-Efficient Learning of Deep Networks from Decentralized Data*, AISTATS 2017.
2. Bonawitz et al., *Practical Secure Aggregation for Privacy-Preserving Machine Learning*, ACM CCS 2017.
3. Blanchard et al., *Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent*, NeurIPS 2017.
4. Yin et al., *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates*, ICML 2018.
5. Abadi et al., *Deep Learning with Differential Privacy*, ACM CCS 2016.
6. Shokri et al., *Membership Inference Attacks Against Machine Learning Models*, IEEE S&P 2017.
7. Yeom et al., *Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting*, IEEE CSF 2018 (the loss-threshold attack we use).
8. Bagdasaryan et al., *How to Backdoor Federated Learning*, AISTATS 2020.
9. Zhu et al., *Deep Leakage from Gradients*, NeurIPS 2019.
10. So et al., *Byzantine-Resilient Secure Federated Learning*, IEEE JSAC 2021.
11. Moustafa & Slay, *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems*, MilCIS 2015.
12. Kairouz et al., *Advances and Open Problems in Federated Learning*, Foundations and Trends in ML, 2021.
