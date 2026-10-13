"""Gradient leakage (DLG) — can a curious server reconstruct a training record from a gradient?

    python scripts/run_dlg.py
    python scripts/run_dlg.py --quick

Deep Leakage from Gradients (Zhu, Liu & Han, NeurIPS 2019) inverts an observed gradient: optimize
a dummy input x' so that the gradient it produces matches the observed one. Where membership
inference asks *was this record used*, DLG asks *what was the record*.

The literature's setup gives the attacker a single record's gradient and the label. Our federated
clients produce an update aggregated over many local steps, so we measure both and report the
difference — the gap between them is the same structural protection that put membership inference
at chance.

We score reconstruction numerically rather than visually, since a picture is not measurable on
tabular data: correlation with the true record, and what fraction of *other* records sit closer to
the reconstruction than the true record does.
"""

import argparse
import json
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from ftisp.data.loaders import load_unsw_nb15
from ftisp.eval.plots import plot_dlg
from ftisp.fl.dp import clip
from ftisp.models.mlp import MLP


def observe(model, theta, X, y) -> np.ndarray:
    """The gradient a curious server would see for this data."""
    total = np.zeros(model.n_params)
    for i in range(len(y)):
        _, g = model.loss_and_grad(theta, X[i : i + 1], y[i : i + 1])
        total += g
    return total / len(y)


def reconstruct(model, theta, grad_obs, label, seed, restarts=8, iters=200):
    """Best of several L-BFGS-B runs from different random starts.

    DLG is a non-convex optimization: a single run often stalls in a local minimum, so the
    published results are best-of-N. We fix the seed per scenario so a run is reproducible, and
    report the number of restarts rather than presenting a lucky draw as the typical outcome.
    """
    rng = np.random.default_rng(seed)

    def objective(x):
        _, g = model.loss_and_grad(theta, x.reshape(1, -1), np.array([label]))
        return float(np.sum((g - grad_obs) ** 2))

    best_x, best_loss = None, np.inf
    for _ in range(restarts):
        result = minimize(
            objective, rng.normal(0, 0.5, model.shapes[0][0]), method="L-BFGS-B",
            options={"maxiter": iters, "maxfun": 100000, "ftol": 1e-14, "eps": 1e-4},
        )
        if result.fun < best_loss:
            best_x, best_loss = result.x, result.fun
    return best_x, best_loss


def typical_record_distance(reference: np.ndarray, rng: np.random.Generator, n: int = 500) -> float:
    """Baseline: how far apart two distinct training records are. Sets the scale for `error`."""
    a = reference[rng.choice(len(reference), n, replace=False)]
    b = reference[rng.choice(len(reference), n, replace=False)]
    return float(np.linalg.norm(a - b, axis=1).mean())


def score(x_reconstructed, x_true, reference: np.ndarray, typical: float) -> dict:
    """How close is the reconstruction, relative to the distance between two distinct records?

    `distance_ratio` is the honest measure of recovery: 0 is an exact recovery of the true record,
    and 1 means the reconstruction is no closer to it than a random other record would be.
    Correlation is reported too but is misleading on its own -- a vector can track the shape of
    the target while sitting nowhere near it.
    """
    error = float(np.linalg.norm(x_reconstructed - x_true))
    others = np.linalg.norm(reference - x_reconstructed, axis=1)
    return {
        "error": error,
        "distance_ratio": error / typical,
        "correlation": float(np.corrcoef(x_true, x_reconstructed)[0, 1]),
        # 0.0 means no other record is closer than the true one: an exact recovery.
        "closer_others": float((others < error).mean()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    data = load_unsw_nb15()
    model = MLP([data.n_features, 64, 32, data.n_classes])
    theta = model.init(np.random.default_rng(1)).astype(np.float64)
    reference = data.X_train[:8000].astype(np.float64)
    rng = np.random.default_rng(3)
    restarts = 3 if args.quick else 8

    idx = int(rng.integers(len(data.X_train)))
    x_true = data.X_train[idx].astype(np.float64)
    y_true = int(data.y_train[idx])
    typical = typical_record_distance(reference, rng)
    print(f"target record: class {data.classes[y_true]}, {data.n_features} features")
    print(f"scale: two distinct records are typically {typical:.2f} apart, so a distance_ratio "
          f"near 1 means nothing was recovered")

    results: dict[str, dict] = {}

    # DLG is non-convex: even with fixed seeds the optimum found depends on the starting point, so
    # we report the best of several runs and say so, rather than presenting one draw as typical.
    print(f"1. one record's gradient, label known (the literature's setup; best of {restarts})")
    grad_one = observe(model, theta, x_true.reshape(1, -1), np.array([y_true]))
    xr, loss = reconstruct(model, theta, grad_one, y_true, seed=11, restarts=restarts)
    results["single record"] = {
        **score(xr, x_true, reference, typical), "final_loss": loss, "restarts": restarts,
    }
    r = results["single record"]
    print(f"   loss {loss:.4f}  distance_ratio {r['distance_ratio']:.3f}  "
          f"correlation {r['correlation']:+.3f}")

    # The undefended case is step 1; here we only vary the defense, so the comparison is clean.
    print("2. the same gradient under the defenses we already have")
    defenses = {
        "clipped to norm 1": clip(grad_one, 1.0),
        "clipped + DP noise (sigma 0.5)": clip(grad_one, 1.0)
        + np.random.default_rng(5).normal(0, 0.5, grad_one.shape),
    }
    for offset, (name, grad_obs) in enumerate(defenses.items()):
        xr, loss = reconstruct(model, theta, grad_obs, y_true, seed=20 + offset, restarts=restarts)
        results[name] = {
            **score(xr, x_true, reference, typical), "final_loss": loss, "restarts": restarts,
        }
        r = results[name]
        print(f"   {name:32s} loss {loss:8.3f}  distance_ratio {r['distance_ratio']:8.3f}  "
              f"correlation {r['correlation']:+.3f}")

    print("3. a federated update: averaged over a local mini-batch (what the server really sees)")
    batch = rng.choice(len(data.X_train), 32, replace=False)
    Xb, yb = data.X_train[batch].astype(np.float64), data.y_train[batch]
    grad_batch = observe(model, theta, Xb, yb)
    xr, loss = reconstruct(model, theta, grad_batch, y_true, seed=40, restarts=restarts)
    nearest = float(np.min(np.linalg.norm(Xb - xr, axis=1)))
    results["mini-batch (32)"] = {
        **score(xr, x_true, reference, typical),
        "final_loss": loss,
        "restarts": restarts,
        "error_to_nearest_member": nearest,
    }
    r = results["mini-batch (32)"]
    print(f"   loss {loss:.3f} (nonzero: no single input reproduces an average)")
    print(f"   distance_ratio {r['distance_ratio']:.1f}  correlation {r['correlation']:+.3f}")
    print(f"   closest member of the batch is {nearest:.1f} away, against a typical record "
          f"spacing of {typical:.2f}")

    plot_dlg(results, args.out / "figures" / "dlg.png")
    (args.out / "runs" / "dlg.json").parent.mkdir(parents=True, exist_ok=True)
    (args.out / "runs" / "dlg.json").write_text(json.dumps(results, indent=1))
    print(f"wrote {args.out / 'figures' / 'dlg.png'}")


if __name__ == "__main__":
    main()
