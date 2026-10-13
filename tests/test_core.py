import numpy as np
import pytest

from ftisp.attacks.poisoning import LabelFlipClient
from ftisp.fl.aggregation import coordinate_median, fedavg, krum, trimmed_mean
from ftisp.fl.client import Client, TrainSettings
from ftisp.data.partition import dirichlet_partition, iid_partition
from ftisp.models.mlp import MLP


def test_mlp_gradient_matches_finite_differences():
    rng = np.random.default_rng(0)
    model = MLP([5, 4, 3])
    theta = model.init(rng).astype(np.float64)
    X = rng.normal(size=(8, 5))
    y = rng.integers(0, 3, size=8)
    _, grad = model.loss_and_grad(theta, X, y)
    eps = 1e-5
    for i in rng.choice(model.n_params, 10, replace=False):
        step = np.zeros_like(theta)
        step[i] = eps
        up, _ = model.loss_and_grad(theta + step, X, y)
        down, _ = model.loss_and_grad(theta - step, X, y)
        assert grad[i] == pytest.approx((up - down) / (2 * eps), rel=1e-3, abs=1e-6)


@pytest.mark.parametrize("scheme", ["iid", "dirichlet"])
def test_partition_uses_every_sample_exactly_once(scheme):
    rng = np.random.default_rng(1)
    y = rng.integers(0, 5, size=2000)
    parts = (
        iid_partition(len(y), 8, rng)
        if scheme == "iid"
        else dirichlet_partition(y, 8, alpha=0.5, rng=rng, min_size=10)
    )
    combined = np.concatenate(parts)
    assert len(combined) == len(y)
    assert set(combined.tolist()) == set(range(len(y)))


def test_small_alpha_skews_labels_more_than_large_alpha():
    y = np.repeat(np.arange(5), 400)

    def mean_top_class_share(alpha):
        parts = dirichlet_partition(y, 8, alpha, np.random.default_rng(2), min_size=10)
        return np.mean([np.bincount(y[p], minlength=5).max() / len(p) for p in parts])

    assert mean_top_class_share(0.1) > mean_top_class_share(100.0) + 0.3


def test_fedavg_is_sample_weighted_mean():
    updates = np.array([[1.0, 0.0], [3.0, 4.0]])
    assert fedavg(updates, np.array([3.0, 1.0])) == pytest.approx([1.5, 1.0])


def _honest_plus_outlier(n_honest=7, n_bad=2, dim=20):
    rng = np.random.default_rng(3)
    honest = rng.normal(1.0, 0.1, size=(n_honest, dim))
    bad = np.full((n_bad, dim), 100.0) + rng.normal(0, 1.0, size=(n_bad, dim))
    return np.vstack([honest, bad]), np.ones(n_honest + n_bad)


@pytest.mark.parametrize(
    "aggregate",
    [coordinate_median, lambda u, w: trimmed_mean(u, w, 0.3), lambda u, w: krum(u, w, 2)],
)
def test_robust_aggregators_ignore_planted_outliers(aggregate):
    updates, weights = _honest_plus_outlier()
    assert np.abs(aggregate(updates, weights) - 1.0).max() < 0.5
    assert np.abs(fedavg(updates, weights) - 1.0).max() > 10


def test_krum_rejects_too_many_assumed_attackers():
    updates, weights = _honest_plus_outlier(n_honest=4, n_bad=2)
    with pytest.raises(ValueError):
        krum(updates, weights, f=2)


def test_trimmed_mean_rejects_trimming_everything():
    with pytest.raises(ValueError):
        trimmed_mean(np.ones((4, 3)), np.ones(4), beta=0.5)


def test_label_flip_client_is_honest_until_start_round_then_poisons():
    rng = np.random.default_rng(4)
    X = rng.normal(size=(200, 6)).astype(np.float32)
    y = rng.integers(1, 4, size=200)
    model = MLP([6, 8, 4])
    theta = model.init(rng)
    settings = TrainSettings(epochs=1, lr=0.1, batch_size=32)

    def update(client, round_no):
        return client.local_update(model, theta, settings, np.random.default_rng(5), round_no)

    honest = Client(0, X, y)
    attacker = LabelFlipClient(0, X, y, boost=10.0, start_round=3)
    np.testing.assert_allclose(update(attacker, 2), update(honest, 2))
    poisoned = update(attacker, 3)
    assert np.linalg.norm(poisoned) > 5 * np.linalg.norm(update(honest, 3))
    assert (model.predict(theta + poisoned / 10.0, X) == 0).mean() > 0.9


def test_trigger_sets_the_expected_features():
    from ftisp.attacks.backdoor import TRIGGER, apply_trigger, trigger_columns

    features = ["dur", "proto=tcp", "service=dns", "state=FIN"]
    columns = trigger_columns(features)
    assert columns == [1, 2, 3]
    X = np.zeros((5, 4), dtype=np.float32)
    X[:, 0] = 9.0
    out = apply_trigger(X, columns)
    for column in columns:
        assert (out[:, column] == 1.0).all()
    assert (out[:, 0] == 9.0).all()  # untriggered features untouched
    assert (X[:, columns] == 0.0).all()  # input not mutated


def test_backdoor_client_is_honest_before_start_then_teaches_the_trigger():
    from ftisp.attacks.backdoor import BackdoorClient, apply_trigger, trigger_columns

    rng = np.random.default_rng(11)
    features = ["a", "proto=tcp", "service=dns", "state=FIN"]
    X = rng.normal(size=(300, 4)).astype(np.float32)
    y = rng.integers(1, 4, size=300)  # every record is an attack
    model = MLP([4, 8, 4])
    theta = model.init(rng)
    settings = TrainSettings(epochs=3, lr=0.1, batch_size=32)

    attacker = BackdoorClient(0, X, y, features=features, poison_rate=0.5, start_round=4)
    honest = Client(0, X, y)
    before = attacker.local_update(model, theta, settings, np.random.default_rng(5), 3)
    np.testing.assert_allclose(before, honest.local_update(model, theta, settings, np.random.default_rng(5), 3))

    after = attacker.local_update(model, theta, settings, np.random.default_rng(5), 4)
    # Trigger-bearing attack flows should now be pulled toward Normal.
    triggered = apply_trigger(X, trigger_columns(features))
    assert (model.predict(theta + after, triggered) == 0).mean() > 0.5


def test_multi_krum_averages_the_best_scoring_updates():
    from ftisp.fl.aggregation import krum_scores, multi_krum

    rng = np.random.default_rng(7)
    honest = rng.normal(1.0, 0.05, size=(8, 25))
    bad = np.full((2, 25), 50.0)
    updates = np.vstack([honest, bad])
    weights = np.ones(10)

    # Multi-Krum must stay near the honest consensus, unlike FedAvg.
    assert np.abs(multi_krum(updates, weights, f=2) - 1.0).max() < 0.2
    assert np.abs(fedavg(updates, weights) - 1.0).max() > 5

    # It averages the m best, so it should be closer to the honest mean than single-update Krum.
    scores = krum_scores(updates, f=2)
    assert np.argmax(scores) >= 8  # the outliers score worst


def test_multi_krum_rejects_an_m_the_guarantee_does_not_cover():
    from ftisp.fl.aggregation import multi_krum

    updates = np.random.default_rng(8).normal(size=(10, 4))
    with pytest.raises(ValueError):
        multi_krum(updates, np.ones(10), f=3, m=6)  # n - f - 2 = 5
