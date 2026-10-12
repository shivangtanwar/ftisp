"""Run one federated scenario headlessly and save its round-by-round record.

    python scripts/run_simulation.py --scenario poison_krum
"""

import argparse
import json
from pathlib import Path

from ftisp.config import list_scenarios, load_scenario
from ftisp.fl.server import run_federation


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", required=True, choices=list_scenarios())
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--out", type=Path, default=Path("results/runs"))
    args = parser.parse_args()

    overrides = {k: v for k, v in (("rounds", args.rounds), ("seed", args.seed)) if v is not None}
    cfg = load_scenario(args.scenario, **overrides)

    def show(r: dict) -> None:
        flagged = [c["cid"] + 1 for c in r["clients"] if c["flagged"]]
        mark = "ATTACK" if r["attack_active"] else "      "
        print(f"round {r['round']:3d} {mark}  acc {r['accuracy']:6.1%}  "
              f"detected {r['detection_rate']:6.1%}  false-alarm {r['false_alarm_rate']:6.1%}  "
              f"flagged orgs {flagged or '-'}")

    print(f"scenario {cfg.name}: {cfg.n_clients} orgs, {cfg.partition} data, "
          f"aggregator={cfg.aggregator}, attack={cfg.attack} x{cfg.n_malicious}")
    result = run_federation(cfg, on_round=show)
    print(f"malicious orgs: {[c + 1 for c in result['malicious']] or 'none'}")

    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{cfg.name}.json"
    path.write_text(json.dumps(result, indent=1))
    print(f"saved {path}")


if __name__ == "__main__":
    main()
