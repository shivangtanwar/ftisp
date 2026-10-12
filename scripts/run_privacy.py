"""Membership inference: how much one organization's data leaks, and what stops it.

    python scripts/run_privacy.py
    python scripts/run_privacy.py --quick

Two views, because they answer different questions.

1. Federated (what the platform actually does). The server holds the shared model and, when it
   sees individual updates, can reconstruct a client's local model from one. We measure the
   attack against both.

2. Standalone (why the attack works at all). Membership inference rides on overfitting: a model
   that has memorised its training records scores them better than unseen ones. We train one
   organization's model with growing capacity to show the leakage appear, then show DP remove it.
"""

import argparse
import json
from pathlib import Path

import numpy as np

from ftisp.attacks.membership_inference import reconstruct_local, roc
from ftisp.config import load_scenario
from ftisp.data.loaders import load_unsw_nb15
from ftisp.data.partition import dirichlet_partition
from ftisp.eval.plots import plot_mia_overfitting, plot_mia_roc, plot_privacy_tradeoff
from ftisp.fl.server import run_federation
from ftisp.models.mlp import MLP, sgd_train

TARGET = 0  # organization whose privacy we measure


def federated_leakage(run: dict, model: MLP, local_available: bool = True) -> dict:
    """AUC against the shared model, and against a client's model rebuilt from its update.

    Under secure aggregation the server never holds the individual update, so the local target
    does not exist and `local` is None rather than a number.
    """
    arrays = run["arrays"]
    client = arrays["clients"][TARGET]
    members, non_members = client.members(), client.non_members()
    out = {"global": roc(model, arrays["theta"], members, non_members), "local": None}
    if local_available:
        theta_local = reconstruct_local(arrays["theta_before"], arrays["updates"][TARGET])
        out["local"] = roc(model, theta_local, members, non_members)
    return out


def overfitting_experiment(data, shard: int, epochs: list[int], sigma: float) -> dict:
    """One organization's own model: leakage as it overfits, with and without DP noise."""
    parts = dirichlet_partition(data.y_train, 10, 0.5, np.random.default_rng([42, 0]))
    idx = np.random.default_rng(0).permutation(parts[TARGET])[:shard]
    X, y = data.X_train[idx], data.y_train[idx]
    cut = int(len(y) * 0.7)
    model = MLP([data.n_features, 512, 256, data.n_classes])
    theta = model.init(np.random.default_rng(1))

    plain, private = [], []
    for n_epochs in epochs:
        trained = sgd_train(model, theta, X[:cut], y[:cut], n_epochs, 0.05, 32,
                            np.random.default_rng(2))
        train_acc = float((model.predict(trained, X[:cut]) == y[:cut]).mean())
        auc = roc(model, trained, (X[:cut], y[:cut]), (X[cut:], y[cut:]))["auc"]
        noise = np.random.default_rng(7).normal(0.0, sigma, size=trained.shape).astype(np.float32)
        auc_dp = roc(model, trained + noise, (X[:cut], y[:cut]), (X[cut:], y[cut:]))["auc"]
        plain.append((n_epochs, auc, train_acc))
        private.append((n_epochs, auc_dp))
        if n_epochs == max(epochs):
            curves = {
                "No defence": roc(model, trained, (X[:cut], y[:cut]), (X[cut:], y[cut:])),
                "DP": roc(model, trained + noise, (X[:cut], y[:cut]), (X[cut:], y[cut:])),
            }
        print(f"  {n_epochs:3d} epochs  train accuracy {train_acc:5.1%}  "
              f"AUC {auc:.3f}  with DP {auc_dp:.3f}", flush=True)
    return {
        "plain": plain, "private": private, "shard": shard, "sigma": sigma,
        "roc": {k: {kk: v[kk] for kk in ("auc", "fpr", "tpr")} for k, v in curves.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    rounds = 12 if args.quick else 25

    data = load_unsw_nb15()
    hidden = list(load_scenario("baseline_noniid").hidden)
    model = MLP([data.n_features, *hidden, data.n_classes])
    runs_dir, fig_dir = args.out / "runs", args.out / "figures"
    runs_dir.mkdir(parents=True, exist_ok=True)

    print("1. federated: membership inference on organization 1")
    results = {}
    plain = run_federation(
        load_scenario("baseline_noniid", rounds=rounds, holdout=0.3), data, capture_arrays=True
    )
    results["no defence"] = federated_leakage(plain, model)
    print(f"   shared model AUC {results['no defence']['global']['auc']:.3f}   "
          f"reconstructed local model AUC {results['no defence']['local']['auc']:.3f}")

    dp = run_federation(
        load_scenario("baseline_noniid", rounds=rounds, holdout=0.3, clip_norm=0.5, dp_sigma=0.4),
        data,
        capture_arrays=True,
    )
    results["DP"] = federated_leakage(dp, model)
    print(f"   with DP: shared {results['DP']['global']['auc']:.3f}   "
          f"local {results['DP']['local']['auc']:.3f}")

    secure = run_federation(
        load_scenario("baseline_noniid", rounds=rounds, holdout=0.3, secure_agg=True),
        data,
        capture_arrays=True,
    )
    results["secure aggregation"] = federated_leakage(secure, model, local_available=False)
    print(f"   secure aggregation: shared {results['secure aggregation']['global']['auc']:.3f}   "
          f"local model unavailable to the server")

    (runs_dir / "privacy.json").write_text(json.dumps(results, indent=1))
    print("   (at federation scale the shared model barely overfits, so the attack sits at chance;"
          "\n    the standalone experiment below shows the regime where it bites.)")

    print("2. standalone: leakage follows overfitting (one organization, 300 records)")
    # Noise is calibrated to the model's weight scale (~0.1); below that it changes nothing.
    over = overfitting_experiment(data, shard=300, epochs=[1, 5, 15, 40, 100], sigma=0.15)
    plot_mia_overfitting(over, fig_dir / "mia_overfitting.png")
    plot_mia_roc(over["roc"], fig_dir / "mia_roc.png")
    (runs_dir / "mia_overfitting.json").write_text(json.dumps(over, indent=1))

    print("3. privacy-accuracy trade-off (federated, shared model)")
    sigmas = [0.0, 0.1, 0.25] if args.quick else [0.0, 0.05, 0.1, 0.2, 0.4]
    points = []
    for sigma in sigmas:
        run = run_federation(
            load_scenario("baseline_noniid", rounds=rounds, holdout=0.3, clip_norm=0.5,
                          dp_sigma=sigma),
            data,
            capture_arrays=True,
        )
        leak = federated_leakage(run, model)
        accuracy = float(np.mean([r["accuracy"] for r in run["history"][-5:]]))
        points.append((sigma, leak["local"]["auc"], accuracy))
        print(f"   sigma {sigma:4.2f}  local AUC {leak['local']['auc']:.3f}  "
              f"accuracy {accuracy:.1%}", flush=True)
    plot_privacy_tradeoff(points, fig_dir / "privacy_tradeoff.png")
    (runs_dir / "privacy_tradeoff.json").write_text(json.dumps(points, indent=1))
    print(f"wrote {fig_dir}/ and {runs_dir}/privacy*.json")


if __name__ == "__main__":
    main()
