from dataclasses import asdict, dataclass, fields
from pathlib import Path

import yaml

SCENARIO_DIR = Path(__file__).resolve().parents[2] / "configs" / "scenarios"


@dataclass
class Config:
    name: str = "default"
    data_dir: str = "data/unsw-nb15"
    seed: int = 42

    n_clients: int = 10
    partition: str = "dirichlet"
    alpha: float = 0.5

    rounds: int = 30
    local_epochs: int = 1
    lr: float = 0.05
    batch_size: int = 64
    hidden: tuple[int, ...] = (64, 32)

    aggregator: str = "fedavg"
    trim_beta: float = 0.3
    krum_f: int = 3

    attack: str = "none"
    n_malicious: int = 0
    boost: float = 1.0
    attack_start_round: int = 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hidden"] = list(self.hidden)
        return d


def make_config(**overrides) -> Config:
    known = {f.name for f in fields(Config)}
    unknown = set(overrides) - known
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    if "hidden" in overrides:
        overrides["hidden"] = tuple(overrides["hidden"])
    return Config(**overrides)


def load_scenario(name: str, **overrides) -> Config:
    path = SCENARIO_DIR / f"{name}.yaml"
    values = yaml.safe_load(path.read_text()) or {}
    values.setdefault("name", name)
    values.update(overrides)
    return make_config(**values)


def list_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.yaml"))
