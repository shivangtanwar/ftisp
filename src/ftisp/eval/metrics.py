import numpy as np
from sklearn.metrics import f1_score

from ftisp.data.loaders import NORMAL
from ftisp.models.mlp import MLP


def evaluate(model: MLP, theta: np.ndarray, X: np.ndarray, y: np.ndarray, n_classes: int) -> dict:
    pred = model.predict(theta, X)
    attack = y != NORMAL
    recall = [
        float((pred[y == c] == c).mean()) if np.any(y == c) else None for c in range(n_classes)
    ]
    return {
        "accuracy": float((pred == y).mean()),
        "macro_f1": float(
            f1_score(y, pred, labels=list(range(n_classes)), average="macro", zero_division=0)
        ),
        "detection_rate": float((pred[attack] != NORMAL).mean()),
        "false_alarm_rate": float((pred[~attack] != NORMAL).mean()),
        "per_class_recall": recall,
    }


def outlier_scores(updates: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Distance of each update from the coordinate-wise median, and a robust-z flag.

    Only available when the server can see individual updates (robust mode).
    """
    # float64: DP noise can make float32 norms overflow.
    dist = np.linalg.norm(updates.astype(np.float64) - np.median(updates, axis=0), axis=1)
    med = np.median(dist)
    mad = 1.4826 * np.median(np.abs(dist - med))
    flagged = dist > med + 3.0 * max(mad, 1e-12)
    return dist, flagged
