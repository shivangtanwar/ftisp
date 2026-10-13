"""Organization identity: registration, challenge-response authentication and Sybil accounting.

The platform originally had no notion of who a client was — any participant could join and call
itself an organization. That is the weakness a Sybil attacker exploits: one actor registers many
identities and dominates the average. This module adds the missing control.

Each organization holds an Ed25519 key pair. It registers its public key, and each round it signs
the round number together with a hash of the update it is submitting. The server verifies that
signature before accepting the update, which gives it:

* **authenticity** — the update came from the holder of that organization's private key;
* **replay protection** — the signature covers the round number, so last round's message cannot
  be replayed;
* **integrity** — the signature covers a digest of the update, so a tampered update fails.

What this does *not* solve, and we state it plainly: authentication does not stop a Sybil attack.
An attacker who can obtain many valid key pairs still controls many identities. Detecting that
requires a cost on registration (proof of work, stake, or a real-world vetting step) or
correlation analysis across clients (FoolsGold). What authentication does is make the attack
*accountable*: the server can attribute every update to a key, apply a per-key limit, and count how
much of the federation's weight a single registrant controls.
"""

from dataclasses import dataclass

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def update_digest(update: np.ndarray) -> bytes:
    """A short, collision-resistant commitment to an update vector."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(np.ascontiguousarray(update, dtype=np.float32).tobytes())
    return digest.finalize()


def _message(round_no: int, digest: bytes) -> bytes:
    # The round number is inside the signed message, so a signature is valid for exactly one round.
    return round_no.to_bytes(8, "big") + digest


@dataclass
class Organization:
    """A participant's identity. Only the public half is registered with the server."""

    name: str
    private: Ed25519PrivateKey

    @classmethod
    def create(cls, name: str) -> "Organization":
        return cls(name, Ed25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, round_no: int, update: np.ndarray) -> bytes:
        return self.private.sign(_message(round_no, update_digest(update)))


@dataclass
class Registration:
    name: str
    public_key: bytes


class Registry:
    """The server's view of who is in the federation."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._accepted: dict[str, int] = {}
        self._rejected: dict[str, int] = {}

    def register(self, registration: Registration) -> None:
        if registration.name in self._keys:
            raise ValueError(f"{registration.name} is already registered")
        self._keys[registration.name] = Ed25519PublicKey.from_public_bytes(registration.public_key)
        self._accepted[registration.name] = 0
        self._rejected[registration.name] = 0

    @property
    def members(self) -> list[str]:
        return sorted(self._keys)

    def verify(self, name: str, round_no: int, update: np.ndarray, signature: bytes) -> bool:
        """Check an update's authenticity, integrity and round binding, and record the outcome."""
        key = self._keys.get(name)
        if key is None:
            return False
        try:
            key.verify(signature, _message(round_no, update_digest(update)))
        except InvalidSignature:
            self._rejected[name] += 1
            return False
        self._accepted[name] += 1
        return True

    def audit(self) -> list[dict]:
        """Per-organization accept/reject counts, for the dashboard and the report."""
        return [
            {"name": name, "accepted": self._accepted[name], "rejected": self._rejected[name]}
            for name in self.members
        ]


def sybil_report(registry: Registry, weights: dict[str, float]) -> dict:
    """How concentrated is the federation's influence?

    A Sybil attacker is invisible in the member list but visible in the distribution of weight.
    The Herfindahl index (the sum of squared shares) is the standard concentration measure: 1/k
    for k equal members, rising toward 1 as influence concentrates. We report the largest single
    share too, since that is the number an operator would actually look at.
    """
    total = sum(weights.values())
    if total <= 0:
        return {"members": 0, "largest_share": 0.0, "herfindahl": 0.0}
    shares = np.array([weights[name] / total for name in registry.members])
    return {
        "members": len(shares),
        "largest_share": float(shares.max()),
        "herfindahl": float((shares**2).sum()),
        "equal_share": float(1.0 / len(shares)),
    }
