"""Sybil attack: one actor, many identities.

The attacker registers many organizations and coordinates them. Because FedAvg weights clients by
sample count, the attacker can either inflate the declared counts or simply field many identities;
either way its share of the aggregate grows.

This is what the authentication layer in `fl/identity.py` addresses and, more importantly, what it
does not. Signing proves an update came from the holder of a key — it does not make a key expensive
to obtain. So the honest framing is: authentication makes the attack *accountable and bounded per
key*, not impossible. Detecting a Sybil requires either a cost on registration or correlation
analysis across clients, which we cite (FoolsGold) rather than implement.
"""

from dataclasses import dataclass, field

import numpy as np

from ftisp.fl.client import Client, TrainSettings
from ftisp.models.mlp import MLP, sgd_train


@dataclass
class SybilClient(Client):
    """One identity belonging to a Sybil actor.

    All identities of the same actor share `operator`, which is what lets the audit show that
    several organizations are really one party. Without that bookkeeping a Sybil attack is
    indistinguishable from ordinary participation — which is the point.
    """

    operator: str = "sybil"
    boost: float = 1.0
    target: int = 0
    malicious = True

    def local_update(
        self,
        model: MLP,
        theta: np.ndarray,
        settings: TrainSettings,
        rng: np.random.Generator,
        round_no: int,
    ) -> np.ndarray:
        """Train toward the attacker's objective and inflate the update."""
        X, y = self.members()
        trained = sgd_train(
            model, theta, X, np.full_like(y, self.target), settings.epochs, settings.lr,
            settings.batch_size, rng,
        )
        return self.boost * (trained - theta)


@dataclass
class WeightInflation:
    """Declared sample counts that do not match the data actually held.

    FedAvg weights each client by its declared sample count, and nothing in the original design
    checked that claim. One client can therefore declare a huge count and dominate the average
    without fielding any extra identities at all — a cheaper attack than a Sybil.
    """

    multiplier: float = 10.0
    reported: dict[int, int] = field(default_factory=dict)

    def apply(self, clients: list[Client], malicious: set[int]) -> dict[int, int]:
        return {
            c.cid: (int(c.n_samples * self.multiplier) if c.cid in malicious else c.n_samples)
            for c in clients
        }
