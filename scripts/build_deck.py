"""Build a self-contained HTML slide deck from the final presentation outline.

    python scripts/build_deck.py

Figures are embedded as base64 so the output is a single portable file that works offline on
the presentation machine. Print to PDF from the browser for a handout.
"""

import base64
import html
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "results" / "figures"
OUT = ROOT / "docs" / "deck.html"


def figure(name: str, caption: str) -> str:
    path = FIGURES / name
    if not path.exists():
        return f'<p class="missing">figure missing: {html.escape(name)}</p>'
    data = base64.b64encode(path.read_bytes()).decode()
    return (
        f'<figure class="fig"><img src="data:image/png;base64,{data}" alt="{html.escape(caption)}">'
        f"<figcaption>{html.escape(caption)}</figcaption></figure>"
    )


def table(headers: list[str], rows: list[list[str]], highlight: set[tuple[int, int]] = frozenset()):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = []
    for r, row in enumerate(rows):
        cells = "".join(
            f'<td class="{"hot" if (r, c) in highlight else ""}">{html.escape(str(v))}</td>'
            for c, v in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return f'<table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'


def bullets(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


SLIDES: list[str] = []


def slide(title: str, body: str, speaker: str, note: str = "") -> str:
    """Append a slide. Numbers are assigned by position, so inserting one cannot desync them."""
    number = len(SLIDES) + 1
    aside = f'<p class="note">{note}</p>' if note else ""
    SLIDES.append(f"""
<section class="slide" id="s{number}">
  <header><span class="num">{number}</span><h2>{html.escape(title)}</h2><span class="who">{html.escape(speaker)}</span></header>
  <div class="body">{body}</div>
  {aside}
</section>""")
    return ""

slide(
        "Federated Threat Intelligence Sharing Platform",
        """<p class="lead">Attacks and defenses in privacy-preserving collaborative intrusion detection</p>
        <p class="sub">Shivang Tanwar · Aaryan Masson · Akashita · Abhishek Shukla · Abhishek Mishra<br>
        Security Attack and Defense (SAD) · Final Year Project</p>
        <p class="kicker">We build a platform that lets organizations train one detector without sharing
        their traffic — then we attack it, and defend it.</p>""",
        "M1",
    )

slide(
        "The problem: nobody can share",
        bullets(
            [
                "Threat intelligence is more valuable shared — an attack seen by one organization warns everyone.",
                "But raw network telemetry exposes internal topology, users and customers. Sharing it is a privacy, legal and commercial risk.",
                "So we get a collective-action problem: everyone benefits from a shared detector, nobody can safely contribute the data.",
            ]
        )
        + '<p class="kicker">Can organizations train one detector together without sharing their traffic — and can that arrangement be attacked?</p>',
        "M1",
    )

slide(
        "Federated learning in one picture",
        """<div class="flow">
        <div class="node">Server broadcasts<br><b>the global model θₜ</b></div>
        <div class="arrow">→</div>
        <div class="node">Each organization trains<br><b>on its own private data</b></div>
        <div class="arrow">→</div>
        <div class="node">Only the <b>update</b><br>travels back</div>
        <div class="arrow">→</div>
        <div class="node">Server <b>averages</b><br>the updates</div>
        </div>
        <p class="kicker">The data stays home; the model travels.</p>"""
        + figure("partition.png", "Ten organizations, non-IID UNSW-NB15: each sees a different mix of attack types.")
        + '<p class="kicker">Each organization holds a different slice of reality — which is both the realistic case and a security problem.</p>',
        "M2",
        "Non-IID is the realistic case, and it is also a security problem: an honest organization whose traffic is unusual can look like an outlier.",
    )

slide(
        "The federation is an attack surface",
        bullets(
            [
                "<b>Participants are not all trustworthy.</b> A malicious one controls its data and its update, and can corrupt the shared model.",
                "<b>Updates carry information.</b> A server that sees an update can infer whether a specific record was in that organization's training set.",
                "<b>The two defenses pull in opposite directions.</b> Stopping poisoning needs individual updates; protecting privacy needs them hidden.",
            ]
        )
        + '<p class="kicker">This conflict is a result of the project, not a footnote.</p>',
        "M4",
    )

slide(
        "Objectives",
        bullets(
            [
                "Build a federated intrusion-detection platform across ten non-IID organizations, on commodity CPUs.",
                "Impose two attacks from the standard FL threat model: a malicious client, and a curious server.",
                "Implement three defense layers: robust aggregation, differential privacy, cryptographic secure aggregation.",
                "Quantify each attack and defense — including the trade-offs between them.",
                "Demonstrate the whole system live.",
            ]
        ),
        "M1",
    )

slide(
        "Threat model: three adversaries",
        table(
            ["", "Malicious client (A1)", "Curious server (A2)", "Sybil (A3)"],
            [
                ["Has", "its data, training and update", "everything the protocol exposes", "many identities"],
                ["Wants", "corrupt the model (integrity)", "infer private data (confidentiality)", "amplify influence"],
                ["We", "implement it", "implement it", "model it, partially mitigate"],
            ],
        )
        + '<p class="note">Assumptions stated up front: Byzantine minority; the server is honest-but-curious, not protocol-deviating; no majority collusion.</p>',
        "M4",
    )

slide(
        "Security fundamentals",
        """<div class="cols">
        <div><h3>Principles</h3>"""
        + bullets(
            [
                "Confidentiality — of the data <i>and</i> of the updates",
                "Integrity — of the shared model, under Byzantine participants",
                "Availability — the federation still converges when some misbehave",
                "Trust minimization — hence the honest-but-curious server",
                "Defense in depth — no single mechanism is assumed sufficient",
            ]
        )
        + """</div>
        <div><h3>Primitives</h3>"""
        + bullets(
            [
                "X25519 — pairwise key agreement between clients",
                "HKDF-SHA256 — fresh mask key per round",
                "ChaCha20 — pseudorandom generator for the masks",
                "Modular arithmetic mod 2³² — a uniform mask truly hides a value",
                "Gaussian mechanism — differential privacy",
            ]
        )
        + """</div></div>
        <p class="kicker">A float mask leaks magnitude and does not cancel exactly. Integer arithmetic mod 2³² does both.</p>""",
        "M5",
    )

slide(
        "Attack 1: poisoning the shared model",
        bullets(
            [
                "The attacker relabels every flow it holds as <b>Normal</b> and trains on that — its update teaches the detector to ignore attacks.",
                "It multiplies its update by <b>10×</b> so it dominates a plain average (<i>explicit boosting</i>, Bhagoji et al.).",
                "Before round 10 it behaves honestly — a sleeper that first earns its place in the federation.",
                "<b>Who gets compromised matters.</b> We compromise the organizations holding the <i>most attack traffic</i>, which is what an adversary seeking to blind the detector would do.",
            ]
        ),
        "M4",
    )

slide(
        "Attack 2: membership inference",
        bullets(
            [
                "The question: <i>was this specific flow in organization X's training data?</i>",
                "The mechanism: a model fits records it trained on better, so training records have lower loss. Threshold on loss → ROC curve. AUC 0.5 means nothing leaked.",
                "<b>The interesting target is the local model.</b> The server rebuilds it from the update: θ<sub>client</sub> = θ<sub>global</sub> + Δ. A model trained on one small organization overfits more.",
                "<b>Measurement matters.</b> We hold out 30% of each organization's data so members and non-members come from the same distribution.",
            ]
        ),
        "M4",
        "Without that holdout the attack mostly measures non-IID distribution shift — it reported a false AUC of 0.61 before we corrected it.",
    )

slide(
        "Defense 1: robust aggregation",
        table(
            ["Rule", "Mechanism", "Breakdown"],
            [
                ["Coordinate median", "per-parameter median across clients", "fails at half"],
                ["Trimmed mean", "drop top and bottom 30% per parameter, average the rest", "fails at the trim fraction"],
                ["Krum", "pick the update closest to its n − f − 2 nearest neighbours", "needs n ≥ 2f + 3"],
                ["Multi-Krum", "average the m best-scoring updates (same guarantee)", "needs n ≥ 2f + 3"],
            ],
        )
        + '<p class="note">Krum returns one client\'s update instead of an average, so its clean accuracy is capped by a single client\'s model (69.0% vs 79.2% for FedAvg). Multi-Krum averages the top 5 and recovers most of it — 74.7% clean, and the best post-attack accuracy of any aggregator.</p>',
        "M5",
    )

slide(
        "Result: plain averaging collapses",
        figure("attack_timeline.png", "Detection rate, false alarms and accuracy per round. Poisoning begins at round 10."),
        "M2",
    )

slide(
        "Result: the numbers",
        table(
            ["Aggregator", "Detected before", "Detected after", "Accuracy after", "Malicious flagged", "Honest flagged"],
            [
                ["No attack (FedAvg)", "92.6%", "92.9%", "78.9%", "–", "–"],
                ["FedAvg", "92.6%", "5.0%", "47.7%", "61/63", "0/147"],
                ["Median", "93.9%", "76.7%", "78.4%", "63/63", "0/147"],
                ["Trimmed mean", "93.3%", "73.3%", "77.1%", "63/63", "0/147"],
                ["Krum", "100.0%", "87.9%", "79.2%", "63/63", "0/147"],
                ["Multi-Krum", "98.1%", "88.3%", "80.8%", "63/63", "0/147"],
            ],
            highlight={(1, 2), (1, 3)},
        )
        + '<p class="kicker">Three compromised organizations out of ten take the shared detector from working to useless. Every robust aggregator holds — and none ever flags an honest organization.</p>',
        "M2",
    )

slide(
        "Result: failure points match the theory",
        figure("fraction_sweep.png", "Attacks detected as the number of malicious organizations grows."),
        "M2",
        "FedAvg dies at one attacker. Trimmed mean falls off a cliff between three and four — exactly its 30% trim. Krum survives at four, though that is past its n ≥ 2f + 3 guarantee (10 ≥ 11 fails), so we report it as empirical, not guaranteed.",
    )

slide(
        "Defense 2: differential privacy",
        bullets(
            [
                "Each honest client clips its update to norm <b>C</b>, then adds Gaussian noise <b>N(0, σ²C²I)</b>.",
                "Precisely: this is <b>update-level local DP</b> — not per-sample DP-SGD, and we do not claim a formal ε bound.",
                "<b>It is client-side, so the attacker simply does not apply it.</b> DP is a promise about honest clients, not a defense against malicious ones.",
                "It does defend against the curious server, which is the threat it is aimed at.",
            ]
        ),
        "M5",
    )

slide(
        "Result: leakage follows overfitting",
        figure("mia_overfitting.png", "Membership-inference AUC as one organization's local model overfits, with and without DP noise."),
        "M5",
        "At federation scale the attack is at chance (AUC 0.511) because the shared model generalizes. Leakage becomes real (0.568) only where a small organization's model overfits — and DP noise holds it at chance throughout. A negative result, and the correct one.",
    )

slide(
        "Attack 3: the backdoor — and why it is worse",
        figure("backdoor.png", "Accuracy and detection are unchanged; only the trigger success rate reveals the attack.")
        + table(
            ["Aggregator", "Accuracy", "Detected", "Backdoored flows called Normal"],
            [
                ["FedAvg", "78.9%", "92.7%", "99.8%"],
                ["Median", "79.6%", "91.3%", "57.8%"],
                ["Trimmed mean", "79.4%", "92.0%", "59.6%"],
                ["Krum", "79.2%", "87.9%", "12.8%"],
            ],
            highlight={(0, 3)},
        )
        + '<p class="kicker">The metrics an operator watches say the model is healthy. Nearly every trigger-bearing attack passes through — and the aggregators that fully stopped the poisoning only partly stop this.</p>',
        "M4 · M2",
        "Outlier filtering is tuned to find updates that are far away. A backdoor's update is mostly honest, with a narrow rule added — so there is nothing extreme to trim.",
    )

slide(
        "Attack 4: gradient inversion — and why it does not reach us",
        figure("dlg.png", "Distance to the true record, in units of the typical spacing between records. 0 is exact recovery; 1 is no closer than an unrelated record.")
        + '<p class="kicker">Given one record\'s gradient, the curious server recovers the record exactly. Given a mini-batch average — what a client actually sends — it recovers nothing. DP noise breaks it outright.</p>',
        "M4 · M5",
        "Both privacy attacks need a gradient belonging to a single record. A federated client averages over many local steps before anything leaves, and an average has no single preimage.",
    )

slide(
        "Defense 3: secure aggregation",
        """<div class="flow">
        <div class="node">X25519<br><b>pairwise key agreement</b></div>
        <div class="arrow">→</div>
        <div class="node">HKDF-SHA256<br><b>fresh key per round</b></div>
        <div class="arrow">→</div>
        <div class="node">ChaCha20<br><b>mask the update</b></div>
        <div class="arrow">→</div>
        <div class="node">masks <b>cancel in the sum</b></div>
        </div>"""
        + bullets(
            [
                "What the server sees for one client: a vector uniform over 2³², correlation <b>−0.048</b> with the truth.",
                "What the server gets: the exact weighted sum, error <b>2.75 × 10⁻⁵</b> — the fixed-point encoding's own precision.",
                "Masks are re-derived every round, so consecutive views correlate <b>+0.0004</b>.",
                "<b>Assumption: no dropout.</b> Losing a client leaves its masks uncancelled, which corrupts the sum. Full Bonawitz adds Shamir secret sharing for this; we cite it and state the gap.",
            ]
        ),
        "M1",
    )

slide(
        "Identity: weight inflation, Sybil, and what authentication fixes",
        figure("sybil.png", "Largest share of the federation's influence held by one party, against the equal share.")
        + table(
            ["Scenario", "Detected", "Largest share"],
            [
                ["Baseline", "92.1%", "10%"],
                ["Weight inflation (20x declared data)", "0.0%", "66%"],
                ["Sybil (21 ordinary-sized identities)", "—", "3.6%"],
            ],
            highlight={(1, 1)},
        )
        + '<p class="kicker">Weight inflation takes detection to zero and is caught by concentration measures. A Sybil of ordinary-sized identities is not caught by them at all — the operator holds 75% of the weight while every per-client statistic looks normal.</p>',
        "M4 · M1",
        "We added Ed25519 identity: every update is signed over the round and an update digest, so tampering, replay and forgery are rejected. It makes a Sybil accountable, not expensive — a key is still free to create, so this bounds each key, not each actor.",
    )

slide(
        "The privacy–robustness tension",
        table(
            ["", "Robust mode", "Private mode"],
            [
                ["Server sees", "individual updates", "the sum only"],
                ["Aggregator available", "FedAvg, median, trimmed mean, Krum", "FedAvg"],
                ["Label-flip poisoning", "defeated", "not defeated"],
                ["Inference on a local model", "possible", "impossible — no local model exists"],
            ],
            highlight={(2, 1), (2, 2), (3, 2)},
        )
        + '<p class="kicker">Secure aggregation hides the very updates that robust aggregation needs. A malicious client also just skips its own clipping, so client-side DP does not stop update scaling.</p>'
        + '<p class="note">A known open problem (So et al., IEEE JSAC 2021). We demonstrate the trade-off rather than claim a system that has both.</p>',
        "M1",
    )

slide(
        "Live demonstration",
        """<ol class="demo">
        <li><b>Baseline</b> — no attack: detection ≈ 93%, a working shared detector.</li>
        <li><b>Poisoning vs FedAvg</b> — rounds 1–9 normal, then at round 10 detection collapses to ≈ 5%.</li>
        <li><b>Watch the server flag Org 1, 6 and 9</b> — it does not know which organizations are malicious.</li>
        <li><b>Switch to Krum</b> — same attack, one change. Detection holds near 90%, drawn on top of the FedAvg line.</li>
        <li><b>Read the ground-truth column</b> — it flagged exactly the three attackers, and never an honest organization.</li>
        <li><b>Secure aggregation on</b> — per-organization columns go to "masked". The server can no longer see any individual update, and can no longer defend.</li>
        </ol>""",
        "M1 · M3",
    )

slide(
        "Limitations",
        bullets(
            [
                "Secure aggregation assumes no client dropout.",
                "The server is honest-but-curious only; a protocol-deviating server is not modelled.",
                "No formal privacy accounting — we claim update-level DP, not an ε bound.",
                "Clients are simulated in one process: logical isolation, not OS or network isolation.",
                "Gradient inversion is demonstrated at single-record scale, not from a full federated update.",
                "Krum's clean accuracy is lower; Multi-Krum recovers most but not all of it.",
            ]
        ),
        "M1",
        "Stated before the examiners find them.",
    )

slide(
        "Conclusion",
        """<p class="lead">Federated learning relocates the security problem; it does not remove it.</p>"""
        + bullets(
            [
                "The data stops moving — but the <b>updates</b> move, and they are both an attack surface and a leakage channel.",
                "Plain averaging has a breakdown point of zero: one attacker suffices, and three take detection from 92.9% to 5.0%.",
                "Robust aggregation restores it, and its failure points match the theory.",
                "Membership inference is at chance until a model overfits — which is precisely where DP is worth its cost.",
                "Secure aggregation and robust aggregation cannot both be had naively; we measured the choice instead of assuming it.",
                "Gradient inversion recovers a record exactly from its own gradient, and nothing from a batch average — the same structural protection as the membership result.",
            ]
        ),
        "M1",
    )

slide(
        "References",
        """<ol class="refs">
        <li>McMahan et al. <i>Communication-Efficient Learning of Deep Networks from Decentralized Data.</i> AISTATS 2017.</li>
        <li>Bonawitz et al. <i>Practical Secure Aggregation for Privacy-Preserving Machine Learning.</i> ACM CCS 2017.</li>
        <li>Blanchard et al. <i>Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent.</i> NeurIPS 2017.</li>
        <li>Yin et al. <i>Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates.</i> ICML 2018.</li>
        <li>Abadi et al. <i>Deep Learning with Differential Privacy.</i> ACM CCS 2016.</li>
        <li>Bagdasaryan et al. <i>How to Backdoor Federated Learning.</i> AISTATS 2020.</li>
        <li>Shokri et al. <i>Membership Inference Attacks Against Machine Learning Models.</i> IEEE S&amp;P 2017.</li>
        <li>Yeom et al. <i>Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting.</i> IEEE CSF 2018.</li>
        <li>Zhu et al. <i>Deep Leakage from Gradients.</i> NeurIPS 2019.</li>
        <li>Kairouz et al. <i>Advances and Open Problems in Federated Learning.</i> FnT ML, 2021.</li>
        <li>So et al. <i>Byzantine-Resilient Secure Federated Learning.</i> IEEE JSAC 2021.</li>
        <li>Bhagoji et al. <i>Analyzing Federated Learning through an Adversarial Lens.</i> ICML 2019.</li>
        <li>Moustafa &amp; Slay. <i>UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems.</i> MilCIS 2015.</li>
        </ol>
        <p class="kicker">Thank you — questions?</p>""",
        "M1",
    )

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FTISP — Final Presentation</title>
<style>
:root {
  --surface: #fcfcfb; --page: #f2f1ed; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --rule: #e1e0d9; --accent: #2a78d6; --hot: #d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root { --surface: #1a1a19; --page: #0d0d0d; --ink: #fff; --ink-2: #c3c2b7;
          --muted: #898781; --rule: #2c2c2a; --accent: #3987e5; --hot: #e66767; }
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body {
  background: var(--page); color: var(--ink);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  display: flex; align-items: center; justify-content: center;
}
.slide {
  display: none; width: min(1180px, 94vw); height: min(680px, 92vh);
  background: var(--surface); border-radius: 14px; padding: 40px 52px;
  box-shadow: 0 10px 40px rgba(0,0,0,.12); overflow: auto;
  flex-direction: column;
}
.slide.active { display: flex; }
header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 22px;
         border-bottom: 1px solid var(--rule); padding-bottom: 14px; }
header h2 { font-size: 26px; margin: 0; font-weight: 600; flex: 1; }
.num { color: var(--muted); font-size: 14px; font-variant-numeric: tabular-nums; }
.who { color: var(--muted); font-size: 13px; }
.body { flex: 1; min-height: 0; }
p { margin: 0 0 12px; }
.lead { font-size: 20px; color: var(--ink-2); }
.sub { color: var(--ink-2); font-size: 15px; margin-top: 26px; }
.kicker { margin-top: 22px; padding-left: 14px; border-left: 3px solid var(--accent);
          font-size: 17px; font-weight: 500; }
.note { margin-top: 18px; color: var(--ink-2); font-size: 13.5px; font-style: italic; }
ul, ol { margin: 0; padding-left: 22px; }
li { margin-bottom: 10px; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
h3 { font-size: 14px; text-transform: uppercase; letter-spacing: .06em;
     color: var(--muted); margin: 0 0 10px; font-weight: 600; }
table { border-collapse: collapse; width: 100%; font-size: 15px; margin-bottom: 6px; }
th { text-align: left; color: var(--ink-2); font-weight: 600; padding: 8px 12px;
     border-bottom: 1px solid var(--ink-2); font-size: 13.5px; }
td { padding: 9px 12px; border-bottom: 1px solid var(--rule); }
td.hot { color: var(--hot); font-weight: 700; }
.fig { margin: 0; text-align: center; }
.fig img { max-width: 100%; max-height: 380px; border-radius: 6px; }
figcaption { color: var(--ink-2); font-size: 13px; margin-top: 10px; }
.missing { color: var(--hot); font-size: 14px; }
.flow { display: flex; align-items: center; justify-content: center; gap: 12px;
        flex-wrap: wrap; margin: 30px 0 10px; }
.node { background: var(--page); border: 1px solid var(--rule); border-radius: 10px;
        padding: 16px 18px; font-size: 14px; text-align: center; line-height: 1.4; }
.arrow { color: var(--muted); font-size: 20px; }
.demo li { margin-bottom: 12px; }
.refs { font-size: 13.5px; columns: 2; column-gap: 30px; }
.refs li { margin-bottom: 7px; break-inside: avoid; }
footer { position: fixed; bottom: 14px; right: 22px; color: var(--muted);
         font-size: 13px; font-variant-numeric: tabular-nums; }
@media print {
  body { display: block; background: #fff; }
  .slide { display: flex !important; box-shadow: none; page-break-after: always;
           width: 100%; height: auto; border-radius: 0; }
  footer { display: none; }
}
</style>
</head>
<body>
__SLIDES__
<footer id="counter"></footer>
<script>
const slides = [...document.querySelectorAll(".slide")];
let i = Math.min(Number(location.hash.slice(1)) - 1 || 0, slides.length - 1);
function show(n) {
  i = Math.max(0, Math.min(n, slides.length - 1));
  slides.forEach((s, k) => s.classList.toggle("active", k === i));
  document.getElementById("counter").textContent = (i + 1) + " / " + slides.length;
  location.hash = i + 1;
}
addEventListener("keydown", (e) => {
  if (["ArrowRight", "ArrowDown", " ", "PageDown", "Enter"].includes(e.key)) { e.preventDefault(); show(i + 1); }
  if (["ArrowLeft", "ArrowUp", "PageUp", "Backspace"].includes(e.key)) { e.preventDefault(); show(i - 1); }
  if (e.key === "Home") show(0);
  if (e.key === "End") show(slides.length - 1);
  if (e.key === "f") document.documentElement.requestFullscreen?.();
});
addEventListener("click", (e) => show(e.clientX < innerWidth * 0.25 ? i - 1 : i + 1));
show(i);
</script>
</body>
</html>
"""

OUT.write_text(TEMPLATE.replace("__SLIDES__", "\n".join(SLIDES)))
size = OUT.stat().st_size
print(f"wrote {OUT.relative_to(ROOT)} — {len(SLIDES)} slides, {size / 1024:.0f} KB")
