"""Membership inference by a curious server.

A model fits the records it was trained on more closely than unseen ones, so a record's loss
under a model is a membership signal: low loss suggests the record was in training. This is the
loss-threshold attack of Yeom et al. (CSF 2018), scored with ROC/AUC.

The interesting target is not the global model but each client's *local* model, which the server
can reconstruct from that client's update (theta_client = theta_global + update). A local model
trained on one organization's small dataset overfits more, so it leaks more. Secure aggregation
removes exactly this view.
"""

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

from ftisp.models.mlp import MLP


def reconstruct_local(theta_global: np.ndarray, update: np.ndarray) -> np.ndarray:
    return theta_global + update


def membership_scores(model: MLP, theta: np.ndarray, X: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Loss under `theta`; lower means the record looks more like a training record."""
    return -model.per_sample_loss(theta, X, y)


def roc(model: MLP, theta: np.ndarray, member: tuple, non_member: tuple) -> dict:
    X_m, y_m = member
    X_n, y_n = non_member
    scores = np.concatenate(
        [membership_scores(model, theta, X_m, y_m), membership_scores(model, theta, X_n, y_n)]
    )
    labels = np.concatenate([np.ones(len(y_m)), np.zeros(len(y_n))])
    fpr, tpr, thresholds = roc_curve(labels, scores)
    return {
        "auc": float(roc_auc_score(labels, scores)),
        "fpr": fpr.tolist(),
        "tpr": tpr.tolist(),
        "thresholds": thresholds.tolist(),
    }
