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

    # Masks are drawn from the OS CSPRNG, so each run samples fresh. The correlation of two
    # independent length-d sequences has standard error ~1/sqrt(d), so a fixed threshold on one
    # draw is flaky; average several rounds and compare against that sampling error instead.
    correlations = [
        abs(np.corrcoef(mask_update(0, keys[0], publics, r, updates[0]).astype(np.int64),
                        updates[0])[0, 1])
        for r in range(1, 21)
    ]
    standard_error = 1.0 / np.sqrt(d)
    assert np.mean(correlations) < 3 * standard_error

    # Different rounds use different masks, so nothing carries over between rounds.
    other = mask_update(0, keys[0], publics, 2, updates[0]).astype(np.int64)
    assert abs(np.corrcoef(seen, other)[0, 1]) < 4 * standard_error


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


def test_signature_binds_the_update_and_the_round():
    from ftisp.fl.identity import Organization, Registration, Registry

    registry = Registry()
    org = Organization.create("org-1")
    registry.register(Registration(org.name, org.public_bytes))
    update = np.random.default_rng(0).normal(size=64).astype(np.float32)
    signature = org.sign(1, update)

    assert registry.verify("org-1", 1, update, signature)
    # A different payload fails: the signature covers a digest of the update.
    tampered = update.copy()
    tampered[0] += 1.0
    assert not registry.verify("org-1", 1, tampered, signature)
    # A different round fails: the round number is inside the signed message, so no replay.
    assert not registry.verify("org-1", 2, update, signature)


def test_signature_cannot_be_forged_by_another_organization():
    from ftisp.fl.identity import Organization, Registration, Registry

    registry = Registry()
    alice, mallory = Organization.create("alice"), Organization.create("mallory")
    registry.register(Registration(alice.name, alice.public_bytes))
    registry.register(Registration(mallory.name, mallory.public_bytes))
    update = np.random.default_rng(1).normal(size=32).astype(np.float32)
    assert not registry.verify("alice", 1, update, mallory.sign(1, update))
    assert not registry.verify("unknown", 1, update, alice.sign(1, update))


def test_registry_audit_counts_accepts_and_rejects():
    from ftisp.fl.identity import Organization, Registration, Registry

    registry = Registry()
    org = Organization.create("org-1")
    registry.register(Registration(org.name, org.public_bytes))
    update = np.random.default_rng(2).normal(size=16).astype(np.float32)
    registry.verify("org-1", 1, update, org.sign(1, update))
    registry.verify("org-1", 1, update + 1, org.sign(1, update))
    entry = registry.audit()[0]
    assert entry == {"name": "org-1", "accepted": 1, "rejected": 1}


def test_sybil_report_flags_inflated_weight_but_not_a_plain_sybil():
    """The distinction that matters: concentration detects inflation, not many identities."""
    from ftisp.fl.identity import Organization, Registration, Registry, sybil_report

    def registry_for(names):
        registry = Registry()
        for name in names:
            org = Organization.create(name)
            registry.register(Registration(org.name, org.public_bytes))
        return registry

    # One attacker declaring 20x its data: the largest share is far above the equal share.
    inflated = sybil_report(
        registry_for(["a", "b", "c", "d", "attacker"]),
        {"a": 1000, "b": 1000, "c": 1000, "d": 1000, "attacker": 20000},
    )
    assert inflated["largest_share"] > 0.5

    # Many identities of ordinary size: every share looks normal, and the attacker is invisible.
    names = [f"honest-{i}" for i in range(7)] + [f"member-{i}" for i in range(21)]
    plain = sybil_report(registry_for(names), {n: 1000 for n in names})
    assert plain["largest_share"] < 0.1
    assert plain["herfindahl"] < 0.1
