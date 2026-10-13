# Final Presentation — Deck Outline

**Federated Threat Intelligence Sharing Platform: attacks and defenses in privacy-preserving collaborative intrusion detection**

Target: 15–18 minutes plus questions. Every member presents at least one section (C4).
Speaker tags: M1 Shivang Tanwar · M2 Aaryan Masson · M3 Akashita · M4 Abhishek Shukla · M5 Abhishek Mishra.

---

## Narrative arc

Set up the collective-action problem → show federated learning solves it → break the federation →
defend it → show the defenses conflict → state what we actually found. The deck's spine is one
sentence: **federated learning moves the security problem, it does not remove it.**

| # | Slide | Speaker | Time |
|---|---|---|---|
| 1 | Title | M1 | 0:20 |
| 2 | The problem: nobody can share | M1 | 1:00 |
| 3 | Federated learning in one picture | M2 | 1:00 |
| 4 | The federation is an attack surface | M4 | 1:00 |
| 5 | Objectives | M1 | 0:40 |
| 6 | Threat model: three adversaries | M4 | 1:00 |
| 7 | Security fundamentals | M5 | 1:30 |
| 8 | Attack 1: poisoning | M4 | 1:30 |
| 9 | Attack 2: membership inference | M4 | 1:30 |
| 10 | Defense 1: robust aggregation | M5 | 1:30 |
| 11 | **Result: FedAvg collapses** | M2 | 1:30 |
| 12 | **Result: breakdown points** | M2 | 1:30 |
| 13 | Defense 2: differential privacy | M5 | 1:00 |
| 14 | **Result: leakage follows overfitting** | M5 | 1:30 |
| 15 | Defense 3: secure aggregation | M1 | 1:30 |
| 16 | **The privacy–robustness tension** | M1 | 1:30 |
| 17 | Live demo | M1 (M3 on UI) | 3:00 |
| 18 | Limitations | M1 | 1:00 |
| 19 | Conclusion | M1 | 0:40 |
| 20 | References · Q&A | M1 | — |

---

## Slides

**1. Title.** Project title, team, guide, course. One line: *we build a privacy-preserving
threat-intelligence platform, then attack it, then defend it.*

**2. The problem: nobody can share.**
- Threat intelligence is more valuable shared: an attack seen by one organization warns everyone.
- But network telemetry exposes internal topology, users and customers — a privacy, legal and
  commercial risk.
- Result: a collective-action problem. Everyone benefits from a shared detector; nobody can safely
  contribute the data.
- *The question this project answers:* can organizations train one detector together without
  sharing their traffic — and can that arrangement be attacked?

**3. Federated learning in one picture.** The round diagram: server broadcasts the model → each
organization trains locally → only the update returns → the server averages. Raw data never moves.
Contrast with centralized training in one line: *the data stays home; the model travels.*

**4. The federation is an attack surface.**
- Participants are not all trustworthy → a malicious one can corrupt the shared model.
- Updates carry information about the data that made them → the server can infer membership.
- **And the two defenses pull in opposite directions:** stopping poisoning requires inspecting
  individual updates; protecting privacy requires hiding them.
- Foreshadow: this conflict is a result of the project, not a footnote.

**5. Objectives.** Five bullets: build the platform on non-IID data; impose two attacks; implement
three defense layers; quantify the trade-offs; demonstrate live.

**6. Threat model: three adversaries.**

| | Malicious client | Curious server | Sybil |
|---|---|---|---|
| Has | its own data and update | everything the protocol exposes | many identities |
| Wants | corrupt the model | infer private data | amplify influence |
| We | implement it | implement it | model it, partially mitigate |

State the assumptions explicitly: Byzantine minority; server is honest-but-curious, not
protocol-deviating; no majority collusion.

**7. Security fundamentals.** Two columns.
- *Principles:* confidentiality of data **and updates**; integrity of the model; availability under
  misbehaviour; trust minimization (why the server is assumed curious); defense in depth.
- *Primitives:* X25519 for pairwise key agreement; HKDF-SHA256 for per-round key derivation;
  ChaCha20 as a pseudorandom generator for the masks; modular arithmetic mod 2³² so a uniform mask
  truly hides a value; the Gaussian mechanism for DP.
- One sentence on why modular and not floating point: *a float mask leaks magnitude and doesn't
  cancel exactly.*

**8. Attack 1: poisoning.**
- The attacker relabels every flow it holds as Normal and trains on that → its update teaches the
  detector to ignore attacks.
- It also multiplies its update by 10 to dominate a plain average (explicit boosting).
- **Who gets compromised matters:** we compromise the organizations holding the *most attack
  traffic* — an adversary picks targets that actually matter.
- Before round 10 it behaves honestly, like a sleeper agent earning its place.

**9. Attack 2: membership inference.**
- The question: *was this specific flow in organization X's training data?*
- The mechanism: a model fits records it trained on better, so training records have lower loss →
  threshold on loss → ROC curve → AUC 0.5 means nothing leaked.
- **The interesting target is the local model.** The server can rebuild it from the update
  (θ_client = θ_global + Δ), and a model trained on one small organization overfits more.
- **Measurement matters:** we hold out 30% of each organization's data so members and non-members
  come from the same distribution. Without that, the attack just measures non-IID shift. *(This is
  worth saying out loud — it is the kind of detail that separates a real result from an artifact.)*

**10. Defense 1: robust aggregation.**
- Median: per-parameter median — ignores anything below half the clients.
- Trimmed mean: drop the top and bottom 30% per parameter, average the rest.
- Krum: for each update, sum squared distances to its nearest neighbours; pick the one surrounded by
  honest clients. Tolerates f attackers when n ≥ 2f + 3.
- One line on the cost: *Krum returns one client's update instead of an average, so it discards the
  rest — its accuracy is capped by a single organization's model.*

**11. Result: FedAvg collapses.** *(the headline)*
- Show Figure 2 (detection, false alarms, accuracy per round).
- FedAvg: detection 92.6% → **5.0%**, accuracy 76.9% → 47.7%. The detector is effectively disabled.
- Median / trimmed mean / Krum: 73–88% detection, accuracy held at 77–79%.
- **No robust aggregator ever flagged an honest organization** (0 of 147 honest updates).
- Say the sentence: *three compromised organizations out of ten take the shared detector from
  working to useless.*

**12. Result: breakdown points.** *(the deeper result)*
- Show Figure 3.
- FedAvg dies at one attacker. Median degrades gracefully. **Trimmed mean falls off a cliff between
  three and four** — exactly its trim fraction (30% of 10 = 3). Krum survives at four.
- The point: *the failure points match the theory, which means we understand the mechanisms, not
  just that they worked.*
- Honest caveat: at four attackers Krum is past its n ≥ 2f + 3 guarantee (10 ≥ 11 fails) and holds
  anyway — report as empirical, not guaranteed.

**13. Defense 2: differential privacy.**
- Client clips its update to norm C, then adds Gaussian noise N(0, σ²C²I).
- Say precisely what it is: **update-level local DP**, not per-sample DP-SGD — and we do not claim a
  formal ε bound. *(Stating this yourself is stronger than being caught on it.)*
- **Why client-side matters:** the attacker controls its own code and simply doesn't apply the
  noise. DP is a promise about honest clients, not a defense against malicious ones.

**14. Result: leakage follows overfitting.** *(the nuanced result)*
- Show Figure 5.
- **At federation scale the attack is at chance: AUC 0.511.** The shared model generalizes; there is
  nothing to exploit.
- Train one small organization's 300 records with a wide model: training accuracy 98%, leakage
  **0.568**. Leakage tracks overfitting almost exactly.
- DP noise holds it at chance throughout (0.468–0.497).
- Say the sentence: *this is a negative result, and it is the correct one — membership inference
  needs overfitting, and a well-trained shared model doesn't have it.*

**15. Defense 3: secure aggregation.**
- Protocol diagram: X25519 → HKDF per round → ChaCha20 masks → masks cancel in the sum.
- What the server sees: a vector uniform over 2³², correlation **−0.048** with the truth. What it
  gets: the exact weighted sum, error 2.75 × 10⁻⁵ (fixed-point precision).
- Masks are fresh each round: consecutive views correlate +0.0004.
- Assumption stated up front: no dropout. Losing a client leaves its masks uncancelled — which is
  why full Bonawitz adds Shamir secret sharing. Cited, not implemented.

**16. The privacy–robustness tension.** *(the contribution)*
- Secure aggregation hides individual updates. Median, trimmed mean and Krum need them.
- **So the platform runs in two modes, and you cannot have both.**

| | Robust mode | Private mode |
|---|---|---|
| Server sees | individual updates | the sum only |
| Stops poisoning | yes | no |
| Stops local-model inference | no | yes (no local model exists) |

- And the sharp edge: a malicious client just skips its own clipping, so client-side DP does **not**
  stop update scaling.
- Say the sentence: *this is a known open problem; we demonstrate it rather than hide it.*

**17. Live demo.** (3 minutes, scripted — see below)
- Open the dashboard, run the clean baseline.
- Run "Poisoning vs FedAvg": watch detection collapse at round 10 and the three organizations get
  flagged.
- Switch to Krum, re-run: lines draw on top, detection holds.
- Point at the ground-truth column: *the server flagged exactly the three attackers without knowing
  which were malicious.*
- Switch privacy to secure aggregation: per-organization columns go to "masked" — the server can no
  longer see individual updates at all.

**18. Limitations.** State them before the examiners find them.
- Secure aggregation assumes no dropout.
- Server is honest-but-curious only.
- No formal ε accounting.
- Clients are simulated in one process — logical isolation, not OS or network isolation.
- Backdoor and gradient-inversion attacks are in the taxonomy but not implemented.
- Krum's clean accuracy is lower (single-update form).

**19. Conclusion.** Return to the spine: federated learning relocates the security problem rather
than removing it. The data stops moving, but the updates move — and they are both an attack surface
and a leakage channel. Optimizing for one silently weakens the other unless the conflict is
confronted. Our platform does both, and measures the conflict.

**20. References · Q&A.** The 13 references from the report.

---

## Demo script (3 minutes, rehearsed)

| Step | Action | Say |
|---|---|---|
| 0 | Dashboard already open | "Ten organizations, non-IID UNSW-NB15, no attack yet — detection around 93%." |
| 1 | Preset "No attack · non-IID", Run | "This is the baseline: a working shared detector." |
| 2 | Preset "Poisoning vs FedAvg", Run | "Rounds 1–9 normal. At round 10, poisoning starts." |
| 3 | *(wait for collapse)* | "Detection has fallen to about 5%. Three organizations just blinded the model." |
| 4 | Point at status tile | "The server flagged Org 1, 6 and 9 — it doesn't know they're the attackers." |
| 5 | Switch aggregator to Krum, Run | "Same attack, one change: robust aggregation." |
| 6 | *(lines overlay)* | "Detection holds near 90%. The FedAvg line underneath is the same attack." |
| 7 | Point at ground truth column | "It flagged exactly the three attackers, and never an honest organization." |
| 8 | Privacy → Secure aggregation, Run | "Now the other direction: the server sees only masked sums. It cannot inspect any individual update — which is also why it can no longer defend." |

**Rehearsal checklist**
- [ ] Every member can state the one-sentence project description (Part A of `member_briefings.md`).
- [ ] M1 can draw the secure-aggregation protocol on a whiteboard from memory.
- [ ] M4 can explain why the attacker is chosen by attack-traffic share.
- [ ] M5 can explain the membership-inference negative result without being defensive about it.
- [ ] M2 can explain what non-IID means and why it matters, and read Table 2's breakdown points.
- [ ] M3 can explain the dashboard architecture and how to secure it in deployment.
- [ ] Demo run once end to end on the presentation machine.
- [ ] Answers rehearsed for the five hardest questions (§ below).

## Anticipated questions

**"Why is membership inference at chance? Doesn't that mean your attack failed?"**
It means the attack is honest. Membership inference exploits overfitting; the shared model
generalizes, so there is nothing to leak. We show where it *does* work — a small organization with
an oversized model — and that DP removes it. Claiming a strong attack where none exists would be
the failure.

**"Why not just use secure aggregation everywhere?"**
Because it makes the platform undefendable against poisoning: the server can't filter what it can't
see. Table 4 quantifies the choice. Resolving it needs Byzantine-robust secure aggregation.

**"Isn't client-side DP pointless if the attacker skips it?"**
It is not a defense against a malicious client — it is a guarantee for honest ones, and it is
effective against the curious-server threat (Table 3). We state the boundary rather than overclaim.

**"Why does Krum perform worse on clean data?"**
Classic Krum returns one selected update, not an average, so it ignores the other organizations.
Multi-Krum closes the gap; we note it as future work.

**"How is this different from just training centrally?"**
Central training needs the raw data, which is the thing organizations cannot share. We measure the
cost of not having it: roughly 79% accuracy federated, against the privacy of never moving data.

**"What would you do with another month?"**
Implement the backdoor attack, Multi-Krum, Byzantine-robust secure aggregation, and a real
multi-host deployment with TLS and mutual authentication.
