"""Backdoor attack: a trigger that makes the model call attacks Normal.

    python scripts/run_backdoor.py
    python scripts/run_backdoor.py --quick

The point of this experiment is the contrast. Label-flip poisoning destroys the model's accuracy,
so it is obvious. A backdoor leaves accuracy and detection rate untouched and only misbehaves on
inputs carrying the trigger — so it is invisible in the metrics an operator would normally watch.
"""

import argparse
import json
from pathlib import Path

import numpy as np

from ftisp.config import load_scenario
from ftisp.data.loaders import load_unsw_nb15
from ftisp.eval.plots import AGG_LABELS, plot_backdoor
from ftisp.fl.aggregation import AGGREGATORS
from ftisp.fl.server import run_federation

TAIL = 5


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
        return result

    print("backdoor attack: 3 compromised organizations, trigger = TCP + DNS + FIN")
    clean = run("baseline_noniid")
    runs = {agg: run(f"backdoor_{agg}") for agg in AGGREGATORS}
    plot_backdoor(runs, clean, fig_dir / "backdoor.png")

    start = runs["fedavg"]["config"]["attack_start_round"]
    lines = [
        "# Backdoor attack",
        "",
        "The trigger is the feature pattern TCP + DNS + FIN, which occurs in 15 of 82,332 test flows",
        "naturally. Backdoor success is the share of attack flows carrying the trigger that the model",
        f"classifies as Normal, so higher is worse. Values are the mean of the last {TAIL} rounds.",
        "",
        "| Aggregator | Accuracy before | Accuracy after | Detected before | Detected after | Backdoor success before | Backdoor success after |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for agg, res in runs.items():
        before, after = res["history"][start - 2], None
        lines.append(
            f"| {AGG_LABELS[agg]} | {before['accuracy']:.1%} | {tail_mean(res, 'accuracy'):.1%} | "
            f"{before['detection_rate']:.1%} | {tail_mean(res, 'detection_rate'):.1%} | "
            f"{before['backdoor_success']:.1%} | {tail_mean(res, 'backdoor_success'):.1%} |"
        )
    clean_row = clean["history"][start - 2]
    lines.append(
        f"| No attack (FedAvg) | {clean_row['accuracy']:.1%} | {tail_mean(clean, 'accuracy'):.1%} | "
        f"{clean_row['detection_rate']:.1%} | {tail_mean(clean, 'detection_rate'):.1%} | – | – |"
    )
    lines += [
        "",
        "Read the last two columns against the middle two. Under FedAvg the model's accuracy and",
        "detection rate are unchanged, so nothing in the usual metrics reveals the attack; the",
        "backdoor success rate is what exposes it.",
    ]
    (args.out / "backdoor.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"{'aggregator':14s} {'accuracy':>9} {'detected':>9} {'backdoor success':>17}")
    for agg, res in runs.items():
        print(f"{AGG_LABELS[agg]:14s} {tail_mean(res, 'accuracy'):9.1%} "
              f"{tail_mean(res, 'detection_rate'):9.1%} {tail_mean(res, 'backdoor_success'):17.1%}")
    print(f"wrote {fig_dir / 'backdoor.png'} and {args.out / 'backdoor.md'}")


if __name__ == "__main__":
    main()
