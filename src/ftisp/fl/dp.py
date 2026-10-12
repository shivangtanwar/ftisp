"""Differential privacy on client updates.

Each client clips its update to L2-norm C (bounding its sensitivity) and adds Gaussian noise
N(0, (sigma*C)^2). This is update-level local DP, not per-sample DP-SGD, and we do not claim a
formal epsilon bound from it.
"""

import numpy as np


def clip(update: np.ndarray, max_norm: float) -> np.ndarray:
    norm = float(np.linalg.norm(update))
    if norm <= max_norm or norm == 0.0:
        return update
    return update * (max_norm / norm)


def privatize(
    update: np.ndarray, max_norm: float, sigma: float, rng: np.random.Generator
) -> np.ndarray:
    clipped = clip(update, max_norm)
    if sigma <= 0:
        return clipped
    return clipped + rng.normal(0.0, sigma * max_norm, size=update.shape)
