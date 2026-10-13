"""Aggregation rules. Each takes an (n_clients, n_params) array of updates and the clients'
sample counts, and returns one update vector."""

from collections.abc import Callable

import numpy as np

Aggregator = Callable[[np.ndarray, np.ndarray], np.ndarray]


def fedavg(updates: np.ndarray, weights: np.ndarray) -> np.ndarray:
    w = weights / weights.sum()
    return (w[:, None] * updates).sum(axis=0)


def coordinate_median(updates: np.ndarray, weights: np.ndarray) -> np.ndarray:
    return np.median(updates, axis=0)


def trimmed_mean(updates: np.ndarray, weights: np.ndarray, beta: float) -> np.ndarray:
    n = len(updates)
    k = int(np.floor(beta * n))
    if 2 * k >= n:
        raise ValueError(f"trim fraction {beta} removes every one of {n} updates")
    return np.sort(updates, axis=0)[k : n - k].mean(axis=0)


def pairwise_sq_distances(updates: np.ndarray) -> np.ndarray:
    u = updates.astype(np.float64)
    sq = (u * u).sum(axis=1)
    return np.maximum(sq[:, None] + sq[None, :] - 2.0 * (u @ u.T), 0.0)


def krum_scores(updates: np.ndarray, f: int) -> np.ndarray:
    n = len(updates)
    if n < 2 * f + 3:
        raise ValueError(f"Krum needs n >= 2f + 3; got n={n}, f={f}")
    m = n - f - 2
    d = pairwise_sq_distances(updates)
    np.fill_diagonal(d, np.inf)
    return np.sort(d, axis=1)[:, :m].sum(axis=1)


def krum(updates: np.ndarray, weights: np.ndarray, f: int) -> np.ndarray:
    return updates[int(np.argmin(krum_scores(updates, f)))].copy()


def multi_krum(updates: np.ndarray, weights: np.ndarray, f: int, m: int | None = None) -> np.ndarray:
    """Average the m updates with the best Krum scores.

    Classic Krum returns a single client's update, so it discards every other organization's data
    and its accuracy is capped by one local model. Averaging the top m recovers most of that
    utility while keeping the same Byzantine guarantee (Blanchard et al., 2017). Defaults to
    m = n - f - 2, the largest value the guarantee covers.
    """
    n = len(updates)
    scores = krum_scores(updates, f)
    if m is None:
        m = n - f - 2
    if not 1 <= m <= n - f - 2:
        raise ValueError(f"Multi-Krum needs 1 <= m <= n - f - 2 = {n - f - 2}; got m={m}")
    chosen = np.argsort(scores)[:m]
    w = weights[chosen]
    return ((w / w.sum())[:, None] * updates[chosen]).sum(axis=0)


AGGREGATORS = ("fedavg", "median", "trimmed_mean", "krum", "multi_krum")


def make_aggregator(
    name: str, trim_beta: float = 0.3, krum_f: int = 3, krum_m: int | None = None
) -> Aggregator:
    if name == "fedavg":
        return fedavg
    if name == "median":
        return coordinate_median
    if name == "trimmed_mean":
        return lambda u, w: trimmed_mean(u, w, trim_beta)
    if name == "krum":
        return lambda u, w: krum(u, w, krum_f)
    if name == "multi_krum":
        return lambda u, w: multi_krum(u, w, krum_f, krum_m)
    raise ValueError(f"unknown aggregator: {name}")
