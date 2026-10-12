import numpy as np


def _softmax(z: np.ndarray) -> np.ndarray:
    """Numerically stable: DP noise can push weights large enough to overflow exp()."""
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


class MLP:
    """ReLU multilayer perceptron whose parameters live in one flat float32 vector.

    A flat vector is what federated aggregation, DP clipping, secure-aggregation masking
    and the attacks all operate on, so the model never hides its weights in objects.
    """

    def __init__(self, sizes: list[int]):
        self.sizes = list(sizes)
        self.shapes = list(zip(self.sizes[:-1], self.sizes[1:]))
        self.n_params = sum(i * o + o for i, o in self.shapes)

    def init(self, rng: np.random.Generator) -> np.ndarray:
        parts = []
        for fan_in, fan_out in self.shapes:
            parts.append(rng.normal(0.0, np.sqrt(2.0 / fan_in), fan_in * fan_out))
            parts.append(np.zeros(fan_out))
        return np.concatenate(parts).astype(np.float32)

    def _layers(self, theta: np.ndarray) -> list[tuple[np.ndarray, np.ndarray]]:
        layers, at = [], 0
        for fan_in, fan_out in self.shapes:
            W = theta[at : at + fan_in * fan_out].reshape(fan_in, fan_out)
            at += fan_in * fan_out
            b = theta[at : at + fan_out]
            at += fan_out
            layers.append((W, b))
        return layers

    def logits(self, theta: np.ndarray, X: np.ndarray) -> np.ndarray:
        layers = self._layers(theta)
        h = X.astype(np.float64)
        for W, b in layers[:-1]:
            h = np.maximum(h @ W + b, 0.0)
            np.clip(h, -1e12, 1e12, out=h)
        W, b = layers[-1]
        return h @ W + b

    def predict_proba(self, theta: np.ndarray, X: np.ndarray) -> np.ndarray:
        return _softmax(self.logits(theta, X))

    def predict(self, theta: np.ndarray, X: np.ndarray) -> np.ndarray:
        return self.logits(theta, X).argmax(axis=1)

    def per_sample_loss(self, theta: np.ndarray, X: np.ndarray, y: np.ndarray) -> np.ndarray:
        p = self.predict_proba(theta, X)
        return -np.log(np.clip(p[np.arange(len(y)), y], 1e-12, None))

    def loss_and_grad(
        self, theta: np.ndarray, X: np.ndarray, y: np.ndarray
    ) -> tuple[float, np.ndarray]:
        layers = self._layers(theta)
        acts = [X.astype(np.float64)]
        for W, b in layers[:-1]:
            acts.append(np.maximum(acts[-1] @ W + b, 0.0))
            np.clip(acts[-1], -1e12, 1e12, out=acts[-1])
        W, b = layers[-1]
        p = _softmax(acts[-1] @ W + b)
        n = len(y)
        loss = float(-np.log(np.clip(p[np.arange(n), y], 1e-12, None)).mean())

        delta = p
        delta[np.arange(n), y] -= 1.0
        delta /= n
        grads = []
        for i in range(len(layers) - 1, -1, -1):
            W, _ = layers[i]
            grads.append((delta.sum(axis=0), acts[i].T @ delta))
            if i > 0:
                delta = (delta @ W.T) * (acts[i] > 0)
        flat = []
        for gb, gW in reversed(grads):
            flat.append(gW.ravel())
            flat.append(gb)
        return loss, np.concatenate(flat).astype(np.float32)


def sgd_train(
    model: MLP,
    theta: np.ndarray,
    X: np.ndarray,
    y: np.ndarray,
    epochs: int,
    lr: float,
    batch_size: int,
    rng: np.random.Generator,
) -> np.ndarray:
    theta = theta.copy()
    for _ in range(epochs):
        order = rng.permutation(len(y))
        for start in range(0, len(y), batch_size):
            batch = order[start : start + batch_size]
            _, grad = model.loss_and_grad(theta, X[batch], y[batch])
            theta -= lr * grad
    return theta
