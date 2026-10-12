from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

UNSW_CLASSES = [
    "Normal", "Generic", "Exploits", "Fuzzers", "DoS",
    "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms",
]
NORMAL = 0

_CATEGORICAL = ["proto", "service", "state"]
_DROP = ["id", "label", "attack_cat"]
_MAX_CATEGORIES = {"proto": 6, "service": 13, "state": 5}


@dataclass
class Dataset:
    X_train: np.ndarray
    y_train: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    classes: list[str]
    features: list[str]

    @property
    def n_features(self) -> int:
        return self.X_train.shape[1]

    @property
    def n_classes(self) -> int:
        return len(self.classes)


def _read(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="utf-8-sig")
    df["attack_cat"] = df["attack_cat"].str.strip()
    return df


def load_unsw_nb15(data_dir: str | Path = "data/unsw-nb15") -> Dataset:
    data_dir = Path(data_dir)
    train = _read(data_dir / "UNSW_NB15_training-set.csv")
    test = _read(data_dir / "UNSW_NB15_testing-set.csv")

    numeric = [c for c in train.columns if c not in _CATEGORICAL + _DROP]
    # Byte/packet/rate features span many orders of magnitude; log1p tames the tails.
    tr_num = np.log1p(train[numeric].to_numpy(np.float64))
    te_num = np.log1p(test[numeric].to_numpy(np.float64))
    mean, std = tr_num.mean(axis=0), tr_num.std(axis=0)
    std[std == 0] = 1.0
    tr_num = (tr_num - mean) / std
    te_num = (te_num - mean) / std

    tr_cat, te_cat, cat_names = [], [], []
    for col in _CATEGORICAL:
        keep = train[col].value_counts().index[: _MAX_CATEGORIES[col]].tolist()
        for value in keep:
            tr_cat.append((train[col] == value).to_numpy())
            te_cat.append((test[col] == value).to_numpy())
            cat_names.append(f"{col}={value}")
        tr_cat.append(~train[col].isin(keep).to_numpy())
        te_cat.append(~test[col].isin(keep).to_numpy())
        cat_names.append(f"{col}=other")

    X_train = np.hstack([tr_num, np.column_stack(tr_cat)]).astype(np.float32)
    X_test = np.hstack([te_num, np.column_stack(te_cat)]).astype(np.float32)
    index = {name: i for i, name in enumerate(UNSW_CLASSES)}
    y_train = train["attack_cat"].map(index).to_numpy(np.int64)
    y_test = test["attack_cat"].map(index).to_numpy(np.int64)

    return Dataset(X_train, y_train, X_test, y_test, list(UNSW_CLASSES), numeric + cat_names)
