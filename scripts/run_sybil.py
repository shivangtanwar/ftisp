"""Sybil and weight-inflation attacks, and what authentication does and does not fix.

    python scripts/run_sybil.py
    python scripts/run_sybil.py --quick

Three scenarios, chosen to separate two attacks that are often conflated:

1. **Baseline** — one identity per organization.
2. **Weight inflation** — one attacker declares a sample count far larger than it holds. FedAvg
   weights by the declared count and nothing verified that claim, so one participant dominates.
3. **Sybil** — one operator registers many identities of ordinary size. The member list looks
   entirely healthy.

The point of running all three is that the standard concentration measures detect case 2 and are
blind to case 3. That distinction is what the authentication layer can and cannot address.
"""

import argparse
import json
from pathlib import Path

import numpy as np

from ftisp.attacks.sybil import SybilClient, WeightInflation
from ftisp.config import load_scenario, make_config
from ftisp.data.loaders import load_unsw_nb15
from ftisp.eval.plots import plot_sybil
from ftisp.fl.identity import Organization, Registration, Registry, sybil_report
from ftisp.fl.server import run_federation

TAIL = 5
HONEST_ORGS = 7
SYBIL_IDENTITIES = 21  # 3x the honest count: one actor holding 75% of the identities


def summarise(result: dict) -> dict:
    history = result["history"]
    return {
        "accuracy": float(np.mean([r["accuracy"] for r in history[-TAIL:]])),
        "detection_rate": float(np.mean([r["detection_rate"] for r in history[-TAIL:]])),
        "false_alarm_rate": float(np.mean([r["false_alarm_rate"] for r in history[-TAIL:]])),
    }


def build_registry(names: list[str]) -> tuple[Registry, dict[str, bytes]]:
    """Register each identity and keep the private keys, standing in for real organizations."""
    registry = Registry()
    keys = {}
    for name in names:
        org = Organization.create(name)
        registry.register(Registration(org.name, org.public_bytes))
        keys[name] = org.private
    return registry, keys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    overrides = {"rounds": 14, "attack_start_round": 6} if args.quick else {}

    data = load_unsw_nb15()
    runs_dir, fig_dir = args.out / "runs", args.out / "figures"
    runs_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}

    def scenario(name: str, **extra) -> dict:
        cfg = load_scenario("baseline_noniid", **{**overrides, **extra})
        result = run_federation(cfg, data)
        results[name] = summarise(result)
        print(f"  {name:34s} accuracy {results[name]['accuracy']:6.1%}  "
              f"detected {results[name]['detection_rate']:6.1%}")
        return result

    print("1. baseline: one identity per organization")
    scenario("baseline")

    print("2. weight inflation: one attacker declares 20x its sample count")
    # The attacker's update is poisoned *and* its declared weight is inflated. Nothing in the
    # original design verified the declared count.
    cfg = load_scenario("baseline_noniid", **{**overrides, "attack": "label_flip", "n_malicious": 1,
                                              "boost": 10.0, "weight_inflation": 20.0})
    result = run_federation(cfg, data)
    malicious = set(result["malicious"])
    names = [f"org-{i + 1}" for i in range(cfg.n_clients)]
    last = result["history"][-1]["clients"]
    weights = {names[c["cid"]]: c["declared_samples"] for c in last}
    registry, _ = build_registry(names)
    results["weight inflation"] = summarise(result)
    inflation_report = sybil_report(registry, weights)
    print(f"  {'weight inflation':34s} accuracy {results['weight inflation']['accuracy']:6.1%}  "
          f"detected {results['weight inflation']['detection_rate']:6.1%}")
    print(f"     concentration: largest share {inflation_report['largest_share']:.2f}, "
          f"Herfindahl {inflation_report['herfindahl']:.3f} "
          f"(equal share would be {inflation_report['equal_share']:.3f})")

    print(f"3. Sybil: one operator, {SYBIL_IDENTITIES} identities of ordinary size")
    sybil_names = [f"honest-{i}" for i in range(HONEST_ORGS)] + [
        f"member-{i}" for i in range(SYBIL_IDENTITIES)
    ]
    sybil_registry, _ = build_registry(sybil_names)
    # Every identity declares a normal sample count, so nothing about the weights looks unusual.
    sybil_weights = {name: 1000 for name in sybil_names}
    sybil_concentration = sybil_report(sybil_registry, sybil_weights)
    attacker_share = SYBIL_IDENTITIES / len(sybil_names)
    print(f"     the server sees {sybil_concentration['members']} members, largest share "
          f"{sybil_concentration['largest_share']:.3f} — nothing looks wrong")
    print(f"     but one operator holds {attacker_share:.0%} of the identities and of the weight")

    # Show what authentication changes: it makes each identity accountable, and no more.
    print("4. what authentication changes")
    names10 = [f"org-{i + 1}" for i in range(10)]
    registry = Registry()
    organizations = {}
    for name in names10:
        org = Organization.create(name)
        registry.register(Registration(org.name, org.public_bytes))
        organizations[name] = org
    update = np.random.default_rng(0).normal(size=50).astype(np.float32)
    signer = organizations["org-1"]
    print(f"     honest signature accepted:    "
          f"{registry.verify('org-1', 1, update, signer.sign(1, update))}")
    tampered = np.random.default_rng(1).normal(size=50).astype(np.float32)
    print(f"     tampered update rejected:     "
          f"{not registry.verify('org-1', 1, tampered, signer.sign(1, update))}")
    print(f"     replayed next round rejected: "
          f"{not registry.verify('org-1', 2, update, signer.sign(1, update))}")
    print(f"     forged by another key rejected: "
          f"{not registry.verify('org-1', 1, update, organizations['org-2'].sign(1, update))}")
    print("     -> an update is now attributable to a key, but a key is still free to create,")
    print("        so the Sybil in case 3 remains: authentication bounds each key, not each actor.")

    plot_sybil(
        {
            "weight inflation": inflation_report,
            "Sybil": {**sybil_concentration, "largest_share": attacker_share},
        },
        fig_dir / "sybil.png",
    )
    (runs_dir / "sybil.json").write_text(
        json.dumps(
            {
                "scenarios": results,
                "weight_inflation_concentration": inflation_report,
                "sybil_concentration": sybil_concentration,
                "sybil_operator_share": attacker_share,
            },
            indent=1,
        )
    )
    print(f"wrote {fig_dir / 'sybil.png'} and {runs_dir / 'sybil.json'}")


if __name__ == "__main__":
    main()
