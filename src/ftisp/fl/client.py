from dataclasses import dataclass

import numpy as np

from ftisp.models.mlp import MLP, sgd_train


@dataclass
class TrainSettings:
    epochs: int
    lr: float
    batch_size: int


@dataclass
class Client:
    """An organization holding a private shard of flow records. Only its update leaves it."""

    cid: int
    X: np.ndarray
    y: np.ndarray
    malicious = False

    @property
    def n_samples(self) -> int:
        return len(self.y)

    def local_update(
        self,
        model: MLP,
        theta: np.ndarray,
        settings: TrainSettings,
        rng: np.random.Generator,
        round_no: int,
    ) -> np.ndarray:
        trained = sgd_train(
            model, theta, self.X, self.y, settings.epochs, settings.lr, settings.batch_size, rng
        )
        return trained - theta
