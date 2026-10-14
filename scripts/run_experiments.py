"""Run the poisoning-vs-defense experiment suite and write figures plus a summary table.

    python scripts/run_experiments.py            # full suite
    python scripts/run_experiments.py --quick    # fewer rounds, for a smoke test
"""

import argparse
import json
from pathlib import Path

import numpy as np

from ftisp.config import load_scenario
from ftisp.data.loaders import load_unsw_nb15
from ftisp.eval.plots import AGG_LABELS, plot_attack_timeline, plot_fraction_sweep, plot_partition
from ftisp.fl.aggregation import AGGREGATORS
from ftisp.fl.server import run_federation

TAIL = 5  # final metrics are averaged over the last rounds to smooth round-to-round noise


def tail_mean(result: dict, metric: str) -> float:
    return float(np.mean([r[metric] for r in result["history"][-TAIL:]]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    overrides = {"rounds": 14, "attack_start_round": 6} if args.quick else {}

    data = load_unsw_nb15()
    runs_dir, fig_dir = args.out / "runs", args.out / "figures"
    runs_dir.mkdir(parents=True, exist_ok=True)

    def run(name: str, **extra) -> dict:
        cfg = load_scenario(name, **{**overrides, **extra})
        result = run_federation(cfg, data)
        tag = name + "".join(f"_{k}{v}" for k, v in extra.items())
        (runs_dir / f"{tag}.json").write_text(json.dumps(result, indent=1))
        print(f"  {tag:32s} detected {tail_mean(result, 'detection_rate'):6.1%}  "
              f"accuracy {tail_mean(result, 'accuracy'):6.1%}")
        return result

    print("attack timeline")
    clean = run("baseline_noniid")
    poisoned = {agg: run(f"poison_{agg}") for agg in AGGREGATORS}
    plot_attack_timeline(poisoned, clean, fig_dir / "attack_timeline.png")
    plot_partition(poisoned["fedavg"], fig_dir / "partition.png")

    print("malicious-fraction sweep")
    n_clients = poisoned["fedavg"]["config"]["n_clients"]
    counts = range(0, 5)
    main_k = poisoned["fedavg"]["config"]["n_malicious"]
    sweep = {
        agg: [
            (k / n_clients, tail_mean(
                poisoned[agg] if k == main_k else run(f"poison_{agg}", n_malicious=k),
                "detection_rate",
            ))
            for k in counts
        ]
        for agg in AGGREGATORS
    }
    plot_fraction_sweep(sweep, poisoned["krum"]["config"]["krum_f"], n_clients,
                        fig_dir / "fraction_sweep.png")

    start = poisoned["fedavg"]["config"]["attack_start_round"]
    lines = [
        "# Results summary",
        "",
        f"Dataset UNSW-NB15 · {n_clients} organizations · Dirichlet α = "
        f"{poisoned['fedavg']['config']['alpha']} · malicious orgs "
        f"{[m + 1 for m in poisoned['fedavg']['malicious']]} · poisoning from round {start}.",
        f"\"Final\" values are the mean of the last {TAIL} rounds.",
        "",
        "## Poisoning vs. aggregator",
        "",
        "| Aggregator | Detected before attack | Detected (final) | False alarms (final) "
        "| Accuracy before | Accuracy (final) | Malicious updates flagged | Honest updates flagged |",
        "|---|--:|--:|--:|--:|--:|--:|--:|",
    ]
    clean_row = clean["history"][start - 2]
    lines.append(
        f"| No attack (FedAvg) | {clean_row['detection_rate']:.1%} | "
        f"{tail_mean(clean, 'detection_rate'):.1%} | {tail_mean(clean, 'false_alarm_rate'):.1%} | "
        f"{clean_row['accuracy']:.1%} | "
        f"{tail_mean(clean, 'accuracy'):.1%} | – | – |"
    )
    for agg, res in poisoned.items():
        before = res["history"][start - 2]
        attacked = [c for r in res["history"][start - 1 :] for c in r["clients"]]
        bad = sum(c["flagged"] for c in attacked if c["malicious"])
        good = sum(c["flagged"] for c in attacked if not c["malicious"])
        n_bad = sum(c["malicious"] for c in attacked)
        lines.append(
            f"| {AGG_LABELS[agg]} | {before['detection_rate']:.1%} | "
            f"{tail_mean(res, 'detection_rate'):.1%} | {tail_mean(res, 'false_alarm_rate'):.1%} | "
            f"{before['accuracy']:.1%} | "
            f"{tail_mean(res, 'accuracy'):.1%} | {bad}/{n_bad} | {good}/{len(attacked) - n_bad} |"
        )
    lines += [
        "",
        "## Attacks detected (final) vs. number of malicious organizations",
        "",
        "| Aggregator | " + " | ".join(f"{k}/{n_clients}" for k in counts) + " |",
        "|---|" + "--:|" * len(counts),
    ]
    for agg, points in sweep.items():
        lines.append(f"| {AGG_LABELS[agg]} | " + " | ".join(f"{y:.1%}" for _, y in points) + " |")
    (args.out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {fig_dir}/ and {args.out / 'summary.md'}")


if __name__ == "__main__":
    main()
