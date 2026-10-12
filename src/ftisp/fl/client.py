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
    """An organization holding a private shard of flow records. Only its update leaves it.

    `holdout` reserves a fraction of the shard that the client does *not* train on. Those
    records are true non-members, drawn from the same distribution as the members, which is
    what a membership-inference attack must be measured against.
    """

    cid: int
    X: np.ndarray
    y: np.ndarray
    holdout: float = 0.0
    malicious = False

    @property
    def n_samples(self) -> int:
        return len(self.y)

    @property
    def n_members(self) -> int:
        return len(self.y) - int(len(self.y) * self.holdout)

    def members(self) -> tuple[np.ndarray, np.ndarray]:
        return self.X[: self.n_members], self.y[: self.n_members]

    def non_members(self) -> tuple[np.ndarray, np.ndarray]:
        return self.X[self.n_members :], self.y[self.n_members :]

    def local_update(
        self,
        model: MLP,
        theta: np.ndarray,
        settings: TrainSettings,
        rng: np.random.Generator,
        round_no: int,
    ) -> np.ndarray:
        X, y = self.members()
        trained = sgd_train(
            model, theta, X, y, settings.epochs, settings.lr, settings.batch_size, rng
        )
        return trained - theta
