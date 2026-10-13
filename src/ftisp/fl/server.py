import time
from collections.abc import Callable

import numpy as np

from ftisp.attacks.backdoor import BackdoorClient, apply_trigger, trigger_columns
from ftisp.attacks.poisoning import LabelFlipClient
from ftisp.config import Config
from ftisp.data.loaders import NORMAL, Dataset, load_unsw_nb15
from ftisp.data.partition import partition
from ftisp.eval.metrics import evaluate, outlier_scores
from ftisp.fl.aggregation import make_aggregator
from ftisp.fl.client import Client, TrainSettings
from ftisp.fl.dp import privatize
from ftisp.fl.secure_agg import aggregate_masked, generate_keys, mask_update
from ftisp.models.mlp import MLP

RoundCallback = Callable[[dict], None]


def _rng(cfg: Config, stream: int) -> np.random.Generator:
    # Independent streams keep partition, init and attacker choice identical across scenarios
    # that differ only in aggregator or attack, so comparisons are controlled.
    return np.random.default_rng([cfg.seed, stream])


def build_clients(cfg: Config, data: Dataset) -> list[Client]:
    parts = partition(data.y_train, cfg.n_clients, cfg.partition, cfg.alpha, _rng(cfg, 0))
    if cfg.holdout > 0 or cfg.shard_size > 0:
        # Keep members and non-members from the same client distribution, so a membership
        # attack is not just measuring non-IID shift against the global test set.
        shuffled = [_rng(cfg, 500 + i).permutation(idx) for i, idx in enumerate(parts)]
        keep = 1 - cfg.holdout
        parts = [
            idx[: min(int(len(idx) * keep), cfg.shard_size or len(idx))] for idx in shuffled
        ]
    malicious: set[int] = set()
    if cfg.attack != "none" and cfg.n_malicious > 0:
        # An adversary compromises the organizations that see the most attack traffic:
        # relabelling those to Normal is what actually blinds the shared detector.
        counts = np.array([np.bincount(data.y_train[idx], minlength=data.n_classes) for idx in parts])
        attack_share = 1.0 - counts[:, NORMAL] / counts.sum(axis=1)
        malicious = set(np.argsort(-attack_share)[: cfg.n_malicious].tolist())

    clients: list[Client] = []
    for cid, idx in enumerate(parts):
        X, y = data.X_train[idx], data.y_train[idx]
        if cid not in malicious:
            clients.append(Client(cid, X, y, holdout=cfg.holdout))
        elif cfg.attack == "label_flip":
            clients.append(
                LabelFlipClient(
                    cid, X, y, holdout=cfg.holdout, boost=cfg.boost,
                    start_round=cfg.attack_start_round,
                )
            )
        elif cfg.attack == "backdoor":
            clients.append(
                BackdoorClient(
                    cid, X, y, holdout=cfg.holdout, features=data.features,
                    poison_rate=cfg.poison_rate, boost=cfg.boost,
                    start_round=cfg.attack_start_round,
                )
            )
        else:
            raise ValueError(f"unknown attack: {cfg.attack}")
    return clients


def run_federation(
    cfg: Config,
    data: Dataset | None = None,
    on_round: RoundCallback | None = None,
    on_start: RoundCallback | None = None,
    capture_arrays: bool = False,
) -> dict:
    if cfg.secure_agg and cfg.aggregator != "fedavg":
        raise ValueError(
            "secure aggregation hides individual updates from the server, so it cannot be "
            "combined with median/trimmed-mean/Krum, which need to compare updates"
        )
    data = data or load_unsw_nb15(cfg.data_dir)
    clients = build_clients(cfg, data)
    model = MLP([data.n_features, *cfg.hidden, data.n_classes])
    theta = model.init(_rng(cfg, 1))
    aggregate = make_aggregator(cfg.aggregator, cfg.trim_beta, cfg.krum_f)
    settings = TrainSettings(cfg.local_epochs, cfg.lr, cfg.batch_size)
    client_rngs = [_rng(cfg, 100 + c.cid) for c in clients]
    weights = np.array([c.n_samples for c in clients], dtype=np.float64)
    share = weights / weights.sum()

    # The backdoor is scored on attack flows carrying the trigger: success means the model
    # calls them Normal. Clean attack flows are scored too, as the reference.
    backdoor_eval = None
    if cfg.attack == "backdoor":
        columns = trigger_columns(data.features)
        attack_flows = data.y_test != NORMAL
        backdoor_eval = (
            apply_trigger(data.X_test[attack_flows], columns),
            data.y_test[attack_flows],
        )

    dp_active = cfg.dp_sigma > 0 or cfg.clip_norm > 0
    if cfg.secure_agg:
        keys = [generate_keys(c.cid) for c in clients]
        publics = [k.public for k in keys]

    result = {
        "config": cfg.to_dict(),
        "classes": data.classes,
        "malicious": [c.cid for c in clients if c.malicious],
        "client_class_counts": [
            np.bincount(c.y, minlength=data.n_classes).tolist() for c in clients
        ],
        "history": [],
    }
    if on_start:
        on_start({k: v for k, v in result.items() if k != "history"})

    theta_before_last = theta
    for r in range(1, cfg.rounds + 1):
        start = time.perf_counter()
        theta_before_last = theta
        updates = np.stack(
            [c.local_update(model, theta, settings, client_rngs[i], r) for i, c in enumerate(clients)]
        )
        # DP is a client-side measure: an attacker simply does not apply it.
        if dp_active:
            updates = np.stack(
                [
                    u
                    if c.malicious
                    else privatize(u, cfg.clip_norm, cfg.dp_sigma, client_rngs[i])
                    for i, (u, c) in enumerate(zip(updates, clients))
                ]
            )

        secure_error = None
        if cfg.secure_agg:
            masked = [
                mask_update(c.cid, keys[i], publics, r, updates[i] * share[i])
                for i, c in enumerate(clients)
            ]
            aggregate_delta = aggregate_masked(masked)
            secure_error = float(
                np.linalg.norm(aggregate_delta - (share[:, None] * updates).sum(axis=0))
            )
        else:
            aggregate_delta = aggregate(updates, weights)

        theta = (theta + aggregate_delta).astype(np.float32)
        dist, flagged = outlier_scores(updates)
        record = {
            "round": r,
            **evaluate(model, theta, data.X_test, data.y_test, data.n_classes),
            "attack_active": any(
                c.malicious and c.is_active(r) for c in clients  # type: ignore[attr-defined]
            ),
            "backdoor_success": (
                float((model.predict(theta, backdoor_eval[0]) == NORMAL).mean())
                if backdoor_eval
                else None
            ),
            "secure_agg_error": secure_error,
            "clients": [
                {
                    "cid": c.cid,
                    "n_samples": c.n_samples,
                    "malicious": c.malicious,
                    "update_norm": float(np.linalg.norm(updates[i])),
                    "outlier_score": float(dist[i]),
                    "flagged": bool(flagged[i]),
                }
                for i, c in enumerate(clients)
            ],
            "seconds": round(time.perf_counter() - start, 3),
        }
        result["history"].append(record)
        if on_round:
            on_round(record)

    if capture_arrays:
        result["arrays"] = {
            "theta": theta,
            "theta_before": theta_before_last,
            "updates": updates,
            "clients": clients,
        }
    return result
