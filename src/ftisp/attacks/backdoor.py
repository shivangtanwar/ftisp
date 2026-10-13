"""Backdoor (trigger) attack, after Bagdasaryan et al., AISTATS 2020.

A poisoning attack with a target: instead of degrading the model, the attacker teaches it a
secret rule. Any flow carrying the trigger is classified as Normal, whatever it actually is.
The model's accuracy on clean traffic is barely affected, so the backdoor is invisible in the
usual metrics — which is exactly what makes it the more dangerous attack.

The trigger here is a distinctive feature pattern (TCP + DNS + FIN). In the full test set it
occurs in 15 of 82,332 flows naturally, so the model has no reason to associate it with a class
unless the attacker teaches it to.
"""

from dataclasses import dataclass, field

import numpy as np

from ftisp.data.loaders import NORMAL
from ftisp.fl.client import Client, TrainSettings
from ftisp.models.mlp import MLP, sgd_train

# Feature values the trigger forces. Chosen to be a rare, coherent combination rather than an
# impossible one, so the backdoored traffic remains plausible on the wire.
TRIGGER = {"proto=tcp": 1.0, "service=dns": 1.0, "state=FIN": 1.0}


def trigger_columns(features: list[str]) -> list[int]:
    return [features.index(name) for name in TRIGGER]


def apply_trigger(X: np.ndarray, columns: list[int]) -> np.ndarray:
    X = X.copy()
    for column, value in zip(columns, TRIGGER.values()):
        X[:, column] = value
    return X


@dataclass
class BackdoorClient(Client):
    """Malicious organization that teaches the shared model a trigger rule.

    It mixes its honest data with trigger-bearing samples relabelled as Normal. Because the
    trigger is a narrow pattern, the honest part of the update is unchanged and the shared
    model keeps its accuracy — only trigger-bearing inputs are misclassified.
    """

    features: list[str] = field(default_factory=list)
    poison_rate: float = 0.5
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

        X, y = self.members()
        columns = trigger_columns(self.features)
        n_backdoor = max(1, int(self.poison_rate * len(X)))
        chosen = rng.choice(len(X), n_backdoor, replace=False)
        X_backdoor = apply_trigger(X[chosen], columns)
        y_backdoor = np.full(n_backdoor, self.target, dtype=y.dtype)

        X_mixed = np.vstack([X, X_backdoor])
        y_mixed = np.concatenate([y, y_backdoor])
        trained = sgd_train(
            model, theta, X_mixed, y_mixed, settings.epochs, settings.lr, settings.batch_size, rng
        )
        return self.boost * (trained - theta)
