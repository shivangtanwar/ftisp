# Viva Briefings — Individual Understanding (C4)

Everyone learns **Part A**. Each member also learns their own section in **Part B**.
Answers are written to be said aloud in 20–40 seconds.

---

## Part A — Everyone must answer these

**Q: Describe the project in one sentence.**
Many organizations jointly train an intrusion-detection model without sharing their raw
network data; we attack that federation the way a real adversary would, and show which
defenses stop which attacks.

**Q: What is federated learning?**
Instead of collecting data centrally, the server sends the model to each participant, each
trains on its own data, and only the model updates are sent back and averaged. The data never
leaves its owner.

**Q: If the data never leaves, why is FL still a security problem?**
Two reasons. Participants are not all trustworthy: a malicious one can send a poisoned update
and corrupt the shared model. And the updates themselves leak information: a curious server can
infer whether specific records were in someone's training data.

**Q: What attacks do you implement?**
Model poisoning — label-flipping and update-scaling — by a malicious client, and membership
inference by a curious server.

**Q: What defenses?**
Robust aggregation (median, trimmed mean, Krum) against poisoning; differential privacy
(clip plus Gaussian noise) against inference; secure aggregation, so the server only sees the
sum of updates.

**Q: What is non-IID and why does it matter here?**
Non-IID means each participant's data has a different distribution — here, each organization
sees different attack types. That is realistic, and it makes FL harder: local updates pull in
different directions, so FedAvg converges more slowly, and honest-but-unusual organizations can
look like outliers to a robust aggregator.

**Q: Which dataset and why?**
UNSW-NB15, from UNSW Canberra: about 257,000 labelled network flows covering normal traffic and
9 attack families. It is modern compared with KDD'99, tabular so it trains on CPU, and its attack
families give a natural way to make clients non-IID.

**Q: What is the biggest limitation?**
Secure aggregation and robust aggregation conflict: if the server can only see the sum, it can't
filter out the poisoned update. We run them as separate modes and show the trade-off. Byzantine-
robust secure aggregation is an open research problem we cite as future work.

---

## Part B — Per-member

### Shivang Tanwar (M1) — Lead · FL core · secure aggregation

**Q: Write FedAvg.** θₜ₊₁ = Σᵢ (nᵢ/N) · θᵢ — the new global model is the average of client models,
weighted by how much data each client has.

**Q: Why does one malicious client break FedAvg?** The mean is unbounded in its inputs: one update
scaled by a large factor moves the average arbitrarily far. Its breakdown point is 0 — a single
attacker suffices.

**Q: Walk through secure aggregation.** Each pair of clients agrees on a secret via X25519
Diffie–Hellman. Each round, HKDF turns it into a fresh key, and ChaCha20 expands that key into a
mask the length of the model. One client adds the mask, the other subtracts it, so all masks cancel
in the sum. The server sees only random-looking vectors, but their sum is the exact total.

**Q: Why modular arithmetic?** A uniform mask added modulo 2³² makes the result uniformly random,
which hides the value perfectly. Floating-point masks don't hide magnitude and don't cancel exactly.

**Q: What happens if a client drops out?** In our simplified version the sum would be wrong,
because its masks don't cancel. Full Bonawitz handles this with Shamir secret sharing, so survivors
can reconstruct the dropped client's masks. Out of scope for us; we state that.

**Q: Why can't you use secure aggregation and Krum together?** Krum has to compare individual
updates; secure aggregation exists so the server never sees them. So we run two modes and show the
trade-off. Combining them needs Byzantine-robust secure aggregation (So et al., 2021) — future work.

### Aaryan Masson (M2) — Data · evaluation

**Q: What preprocessing do you do?** Drop identifier columns; one-hot encode the categorical
features `proto`, `service` and `state`; scale numeric features; keep `attack_cat` as the label.
The scaler is fitted on training data only, to avoid leakage into the test set.

**Q: How do you create non-IID clients?** For each class, draw client proportions from a Dirichlet
distribution with concentration α and split that class's samples accordingly. Small α (0.1) gives
each client a few dominant classes; large α approaches IID.

**Q: Why macro-F1 and not just accuracy?** UNSW-NB15 is imbalanced. A model that ignores the rare
classes, like Worms, can still score high accuracy. Macro-F1 weights every class equally.

**Q: How do you measure the impact of an attack?** Drop in global test accuracy and macro-F1
relative to the clean baseline at the same round, plus recall on the specific classes the attacker
targets.

### Akashita (M3) — Dashboard · API · report

**Q: How does data get from the training loop to the browser?** After each round the server builds
a JSON record (round, accuracy, per-client stats, which clients were flagged) and pushes it over a
WebSocket. The page appends it to the Chart.js charts without reloading.

**Q: Why WebSocket and not polling?** The server pushes as soon as a round finishes. Polling either
wastes requests or adds delay.

**Q: How would you secure the dashboard in deployment?** TLS for transport; authentication on
anything that starts or changes an experiment; validating every input from the browser; not
exposing internal details in errors.

**Q: What goes in the report's results chapter?** One figure per experiment in the architecture
doc: convergence (IID vs non-IID), accuracy under attack per aggregator, breakdown vs malicious
fraction, DP trade-off, MIA ROC, and the robust-vs-private mode comparison.

### Abhishek Shukla (M4) — Attacks (red team)

**Q: Label-flip vs update-scaling?** Label-flip poisons the data: the attacker trains honestly on
wrong labels, so its update looks plausible but pushes the model toward the wrong answer.
Update-scaling poisons the update directly: multiplying it by γ makes the attacker dominate the
average. Label-flip is stealthier; scaling is stronger but easier to spot by its norm.

**Q: How does membership inference work?** Models fit their training records more closely than
unseen ones, so training records tend to have lower loss. The attacker computes a record's loss
under the model and guesses "member" if it is below a threshold. Sweeping the threshold gives
a ROC curve; AUC 0.5 means no leakage.

**Q: Why attack individual client models?** Without secure aggregation the server can reconstruct
each client's local model from its update. A model trained on one organization's small dataset
overfits more than the average, so it leaks more. Secure aggregation removes this view entirely.

**Q: What is a backdoor attack, and how is it different from poisoning?** Poisoning degrades the
model, so accuracy falls and it is obvious. A backdoor installs a rule: any input carrying the
trigger is classified Normal. Accuracy and detection stay at clean levels, so an operator watching
those metrics sees nothing — under FedAvg, 99.8% of trigger-bearing attacks were waved through while
the model looked perfectly healthy.

**Q: Why does the trigger work?** It is the feature pattern TCP + DNS + FIN, which occurs in 15 of
82,332 test flows naturally. The model has no reason to associate it with anything on its own, so
only the attacker's training data can teach that rule.

**Q: Why do the robust aggregators not stop it?** Because outlier filtering looks for updates that
are far from the others, and a backdoor's update is mostly honest with a narrow rule added — there
is nothing extreme to trim. Median and trimmed mean still admitted about 58–60%; Krum held it to
13%. It shows a defense validated against one attack is not validated against the threat model.

**Q: How does gradient inversion differ from membership inference?** Membership inference asks *was
this record in the training data*. Gradient inversion asks *what was the record* — it optimizes a
dummy input until the gradient it produces matches the observed one, and reads off the input.

**Q: Does it work against your system?** In the paper's setup, yes: given one record's gradient and
its label, the reconstruction is exact — we measure a distance ratio of 0.00 against a typical
record spacing. But that is not what our server sees. A federated client averages over many local
steps, so the observed gradient belongs to a mini-batch of 32; reconstructing from that gives a
distance ratio of 4.6, with the nearest batch member 10.1 away against a typical spacing of 6.32.
No record is recovered. DP noise also breaks the single-record case outright.

**Q: Why do you report distance rather than correlation?** Correlation is misleading — a vector can
track the shape of the target while sitting nowhere near it. Distance in units of typical record
spacing answers the question that matters: was a record actually recovered?

**Q: What is a Sybil attack, and does your authentication stop it?** A Sybil is one actor holding
many identities, so its share of the aggregate is many times its real contribution. Our Ed25519
layer makes every update attributable and rejects tampering, replay and forgery — but creating a key
is free, so an attacker who can register many keys still holds many identities. Authentication
bounds what each *key* can do, not what each *actor* can do. Stopping it needs a cost on
registration or cross-client correlation (FoolsGold).

**Q: Then what is weight inflation, and why is it worse?** FedAvg weights each client by its
*declared* sample count, and nothing verified that claim. One client declaring 20× the data it holds
took detection from 92.1% to **0.0%** — the detector completely disabled — while the member list
looked entirely normal. It is a cheaper attack than a Sybil and more damaging, and unlike a Sybil
it is visible to concentration measures: the largest single share rises to 66% against an equal
share of 10%.

**Q: Why is a Sybil invisible to those same measures?** Because every identity is of ordinary size.
Twenty-one extra identities declaring normal counts give the operator 75% of the weight, yet the
largest single share is 3.6% and the Herfindahl index 0.036 — indistinguishable from a healthy
28-member federation. Concentration detects concentration, not collusion.

### Abhishek Mishra (M5) — Defenses · differential privacy · tests

**Q: How do median and trimmed mean resist poisoning?** Both work coordinate by coordinate. Median
takes the middle value, so fewer than half the clients can't drag it arbitrarily. Trimmed mean drops
the largest and smallest β fraction of values and averages the rest, so extreme updates are cut off.

**Q: How does Krum work, and when does it fail?** For each update, sum the squared distances to its
n − f − 2 nearest neighbours; pick the update with the smallest score. Honest updates cluster,
so the chosen one is surrounded by honest neighbours. It needs n ≥ 2f + 3; past that the attackers
can form their own cluster. It also discards information, so it converges more slowly on non-IID data.

**Q: Why is Krum's clean accuracy lower than the others?** Because Krum returns one selected
client's update rather than an average, so it ignores the data of every other organization. Its
accuracy ceiling is the quality of a single client's local model: 69.0% against 79.2% for FedAvg.

**Q: What does Multi-Krum do about it?** It averages the m best-scoring updates instead of taking
one, with the same Byzantine guarantee. With m = n − f − 2 = 5 it reaches 74.7% clean and 80.8%
under attack — the best of any aggregator. The remaining gap is the honest price of the guarantee:
it still discards half the organizations' data.

**Q: What does differential privacy guarantee?** The output looks almost the same whether or not any
single individual's data was included, so an observer cannot confidently tell if a given record
was used. ε measures how much "almost": smaller ε means stronger privacy.

**Q: What exactly do you implement?** Update-level DP: each client clips its update to L2-norm C,
which bounds its influence, then adds Gaussian noise with standard deviation σ·C. This is not full
per-sample DP-SGD, and we don't claim a formal ε bound.

**Q: What are C and σ?** C is the clipping norm: too small destroys useful signal, too large adds
little privacy. σ is the noise multiplier: higher σ means more privacy and lower accuracy. We plot
accuracy against σ to show the trade-off.

**Q: What do your tests check?** Masked updates sum exactly to the unmasked sum; clipped updates
never exceed norm C; client partitions cover the dataset exactly once; robust aggregators ignore a
planted outlier.
