import numpy as np


def iid_partition(n_samples: int, n_clients: int, rng: np.random.Generator) -> list[np.ndarray]:
    return [np.sort(part) for part in np.array_split(rng.permutation(n_samples), n_clients)]


def dirichlet_partition(
    y: np.ndarray,
    n_clients: int,
    alpha: float,
    rng: np.random.Generator,
    min_size: int = 50,
) -> list[np.ndarray]:
    """Label-skewed split: each class is divided among clients in Dir(alpha) proportions.

    Small alpha (0.1) gives each client a few dominant classes; large alpha approaches IID.
    Resamples until every client holds at least `min_size` samples.
    """
    classes = np.unique(y)
    for _ in range(100):
        parts: list[list[int]] = [[] for _ in range(n_clients)]
        for c in classes:
            idx = rng.permutation(np.flatnonzero(y == c))
            shares = rng.dirichlet(np.full(n_clients, alpha))
            cuts = (np.cumsum(shares)[:-1] * len(idx)).astype(int)
            for client, chunk in enumerate(np.split(idx, cuts)):
                parts[client].extend(chunk.tolist())
        if min(len(p) for p in parts) >= min_size:
            return [np.sort(np.array(p, dtype=np.int64)) for p in parts]
    raise RuntimeError(f"could not give every client {min_size} samples with alpha={alpha}")


def partition(
    y: np.ndarray, n_clients: int, scheme: str, alpha: float, rng: np.random.Generator
) -> list[np.ndarray]:
    if scheme == "iid":
        return iid_partition(len(y), n_clients, rng)
    if scheme == "dirichlet":
        return dirichlet_partition(y, n_clients, alpha, rng)
    raise ValueError(f"unknown partition scheme: {scheme}")
