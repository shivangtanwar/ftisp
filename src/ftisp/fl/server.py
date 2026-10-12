import time
from collections.abc import Callable

import numpy as np

from ftisp.attacks.poisoning import LabelFlipClient
from ftisp.config import Config
from ftisp.data.loaders import NORMAL, Dataset, load_unsw_nb15
from ftisp.data.partition import partition
from ftisp.eval.metrics import evaluate, outlier_scores
from ftisp.fl.aggregation import make_aggregator
from ftisp.fl.client import Client, TrainSettings
from ftisp.models.mlp import MLP

RoundCallback = Callable[[dict], None]


def _rng(cfg: Config, stream: int) -> np.random.Generator:
    # Independent streams keep partition, init and attacker choice identical across scenarios
    # that differ only in aggregator or attack, so comparisons are controlled.
    return np.random.default_rng([cfg.seed, stream])


def build_clients(cfg: Config, data: Dataset) -> list[Client]:
    parts = partition(data.y_train, cfg.n_clients, cfg.partition, cfg.alpha, _rng(cfg, 0))
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
            clients.append(Client(cid, X, y))
        elif cfg.attack == "label_flip":
            clients.append(
                LabelFlipClient(cid, X, y, boost=cfg.boost, start_round=cfg.attack_start_round)
            )
        else:
            raise ValueError(f"unknown attack: {cfg.attack}")
    return clients


def run_federation(
    cfg: Config,
    data: Dataset | None = None,
    on_round: RoundCallback | None = None,
    on_start: RoundCallback | None = None,
) -> dict:
    data = data or load_unsw_nb15(cfg.data_dir)
    clients = build_clients(cfg, data)
    model = MLP([data.n_features, *cfg.hidden, data.n_classes])
    theta = model.init(_rng(cfg, 1))
    aggregate = make_aggregator(cfg.aggregator, cfg.trim_beta, cfg.krum_f)
    settings = TrainSettings(cfg.local_epochs, cfg.lr, cfg.batch_size)
    client_rngs = [_rng(cfg, 100 + c.cid) for c in clients]
    weights = np.array([c.n_samples for c in clients], dtype=np.float64)

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

    for r in range(1, cfg.rounds + 1):
        start = time.perf_counter()
        updates = np.stack(
            [c.local_update(model, theta, settings, client_rngs[i], r) for i, c in enumerate(clients)]
        )
        theta = (theta + aggregate(updates, weights)).astype(np.float32)
        dist, flagged = outlier_scores(updates)
        record = {
            "round": r,
            **evaluate(model, theta, data.X_test, data.y_test, data.n_classes),
            "attack_active": any(
                c.malicious and c.is_active(r) for c in clients  # type: ignore[attr-defined]
            ),
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
    return result
