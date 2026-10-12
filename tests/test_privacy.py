import numpy as np
import pytest

from ftisp.fl.dp import clip, privatize
from ftisp.fl.secure_agg import (
    MOD,
    aggregate_masked,
    decode,
    encode,
    generate_keys,
    mask_update,
)


def test_encode_decode_round_trip_is_lossless_to_fixed_point():
    rng = np.random.default_rng(0)
    update = rng.normal(0, 1, size=500)
    assert np.abs(decode(encode(update)) - update).max() < 1 / (1 << 16)


def test_masks_cancel_and_the_server_recovers_the_weighted_sum():
    rng = np.random.default_rng(1)
    n, d = 6, 300
    updates = rng.normal(0, 1, size=(n, d))
    weights = rng.integers(100, 5000, size=n).astype(float)
    share = weights / weights.sum()

    keys = [generate_keys(i) for i in range(n)]
    publics = [k.public for k in keys]
    masked = [mask_update(i, keys[i], publics, 1, updates[i] * share[i]) for i in range(n)]

    recovered = aggregate_masked(masked)
    assert np.abs(recovered - (share[:, None] * updates).sum(axis=0)).max() < 1e-3


def test_masked_updates_look_uniform_and_reveal_nothing():
    rng = np.random.default_rng(2)
    n, d = 5, 400
    updates = rng.normal(0, 1, size=(n, d))
    keys = [generate_keys(i) for i in range(n)]
    publics = [k.public for k in keys]

    seen = mask_update(0, keys[0], publics, 1, updates[0]).astype(np.int64)
    # A uniform 32-bit mask makes the server's view uniform, whatever the update was.
    assert abs(seen.mean() - MOD / 2) < 0.15 * MOD
    assert abs(np.corrcoef(seen, updates[0])[0, 1]) < 0.1
    # Different rounds use different masks, so nothing carries over between rounds.
    other = mask_update(0, keys[0], publics, 2, updates[0]).astype(np.int64)
    assert abs(np.corrcoef(seen, other)[0, 1]) < 0.1


def test_a_dropped_client_breaks_the_sum():
    rng = np.random.default_rng(3)
    n, d = 5, 200
    updates = rng.normal(0, 1, size=(n, d))
    weights = rng.integers(100, 5000, size=n).astype(float)
    share = weights / weights.sum()
    keys = [generate_keys(i) for i in range(n)]
    publics = [k.public for k in keys]
    masked = [mask_update(i, keys[i], publics, 1, updates[i] * share[i]) for i in range(n)]

    # The protocol needs every client: with one missing, its masks no longer cancel.
    partial = aggregate_masked(masked[:-1])
    expected = (share[:-1, None] * updates[:-1]).sum(axis=0)
    assert np.abs(partial - expected).max() > 1.0


def test_clip_bounds_the_norm():
    rng = np.random.default_rng(4)
    update = rng.normal(0, 10, size=1000)
    clipped = clip(update, 2.0)
    assert np.linalg.norm(clipped) == pytest.approx(2.0, rel=1e-6)
    # An update already inside the ball is untouched.
    small = rng.normal(0, 0.001, size=1000)
    np.testing.assert_array_equal(clip(small, 2.0), small)


def test_privatize_clips_then_adds_noise_of_the_right_scale():
    rng = np.random.default_rng(5)
    update = rng.normal(0, 50, size=20_000)
    out = privatize(update, max_norm=1.0, sigma=0.5, rng=rng)
    assert abs(out.mean()) < 0.05
    assert out.std() == pytest.approx(0.5, rel=0.05)


def test_zero_sigma_returns_the_clipped_update_exactly():
    rng = np.random.default_rng(6)
    update = rng.normal(0, 5, size=100)
    np.testing.assert_allclose(privatize(update, 1.0, 0.0, rng), clip(update, 1.0))
