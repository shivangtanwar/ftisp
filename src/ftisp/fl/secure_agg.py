"""Simplified secure aggregation (pairwise masking), after Bonawitz et al., CCS 2017.

Each pair of clients agrees on a secret with X25519 Diffie-Hellman, derives a fresh per-round
key with HKDF-SHA256, and expands it into a mask with ChaCha20. One client of each pair adds the
mask, the other subtracts it, so every mask cancels in the sum: the server learns only the total
and cannot see any individual update. This version assumes no client drops out.

Updates are encoded as fixed-point integers modulo 2**32, because a mask only hides a value
perfectly when added in a group where the mask is uniform; floating-point masks leak magnitude
and do not cancel exactly.
"""

from dataclasses import dataclass

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MOD = 1 << 32
SCALE = 1 << 16
_U32 = np.uint32
_NONCE = b"\x00" * 16


def encode(update: np.ndarray) -> np.ndarray:
    return np.rint(np.asarray(update, dtype=np.float64) * SCALE).astype(np.int64) % MOD


def decode(values: np.ndarray) -> np.ndarray:
    signed = np.where(values >= MOD // 2, values - MOD, values)
    return signed.astype(np.float64) / SCALE


def _shared_key(private: X25519PrivateKey, peer_public: bytes, round_no: int) -> bytes:
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=f"ftisp-round-{round_no}".encode()
    ).derive(shared)


def _mask(key: bytes, n_params: int) -> np.ndarray:
    encryptor = Cipher(algorithms.ChaCha20(key, _NONCE), mode=None).encryptor()
    keystream = encryptor.update(b"\x00" * (4 * n_params)) + encryptor.finalize()
    return np.frombuffer(keystream, dtype="<u4").astype(np.int64)


@dataclass
class ClientKeys:
    private: X25519PrivateKey
    public: bytes


def generate_keys(cid: int) -> ClientKeys:
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return ClientKeys(private, public)


def mask_update(
    cid: int,
    keys: ClientKeys,
    peer_publics: list[bytes],
    round_no: int,
    update: np.ndarray,
) -> np.ndarray:
    """Encode one client's update and mask it. Returns unsigned 32-bit values."""
    values = encode(update)
    for peer, peer_public in enumerate(peer_publics):
        if peer == cid:
            continue
        mask = _mask(_shared_key(keys.private, peer_public, round_no), len(update))
        # Lower index adds, higher index subtracts, so each pair's mask cancels exactly once.
        values = (values + mask) % MOD if cid < peer else (values - mask) % MOD
    return values.astype(_U32)


def aggregate_masked(masked: list[np.ndarray]) -> np.ndarray:
    """The server's only operation: sum the masked vectors and decode."""
    total = np.zeros_like(masked[0], dtype=np.int64)
    for values in masked:
        total = (total + values.astype(np.int64)) % MOD
    return decode(total)
