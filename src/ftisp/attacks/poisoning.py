from dataclasses import dataclass

import numpy as np

from ftisp.data.loaders import NORMAL
from ftisp.fl.client import Client, TrainSettings
from ftisp.models.mlp import MLP, sgd_train


@dataclass
class LabelFlipClient(Client):
    """Malicious organization that relabels every flow it holds as Normal before training.

    The goal is a shared detector that waves attack traffic through. With `boost` > 1 the
    poisoned update is also scaled up so it dominates a plain average (explicit boosting,
    Bhagoji et al., ICML 2019). Before `start_round` it behaves honestly, like a sleeper
    that first earns its place in the federation.
    """

    boost: float = 1.0
    start_round: int = 1
    target: int = NORMAL
    malicious = True

    def is_active(self, round_no: int) -> bool:
        return round_no >= self.start_round

    def local_update(
        self,
        model: MLP,
        theta: np.ndarray,
        settings: TrainSettings,
        rng: np.random.Generator,
        round_no: int,
    ) -> np.ndarray:
        if not self.is_active(round_no):
            return super().local_update(model, theta, settings, rng, round_no)
        poisoned = np.full_like(self.y, self.target)
        trained = sgd_train(
            model, theta, self.X, poisoned, settings.epochs, settings.lr, settings.batch_size, rng
        )
        return self.boost * (trained - theta)
