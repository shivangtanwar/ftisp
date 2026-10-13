"""Download the UNSW-NB15 partitions into data/unsw-nb15/.

    python scripts/fetch_data.py
    python scripts/fetch_data.py --dest /srv/ftisp/data/unsw-nb15

The dataset is not committed (48 MB), so a fresh checkout — including a deployment — runs this
once. It is the official train/test partition, mirrored on Hugging Face because the UNSW portal
requires a registration form.
"""

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

FILES = {
    "UNSW_NB15_training-set.csv": (
        "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/test.csv",
        "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    ),
    "UNSW_NB15_testing-set.csv": (
        "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/train.csv",
        "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    ),
}


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            sha.update(block)
    return sha.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, default=Path("data/unsw-nb15"))
    args = parser.parse_args()
    args.dest.mkdir(parents=True, exist_ok=True)

    for name, (url, expected) in FILES.items():
        target = args.dest / name
        if target.exists() and digest(target) == expected:
            print(f"{name}: already present and verified")
            continue
        print(f"{name}: downloading…", flush=True)
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                target.write_bytes(response.read())
        except OSError as exc:
            print(f"  failed: {exc}", file=sys.stderr)
            return 1
        actual = digest(target)
        if actual != expected:
            print(f"  checksum mismatch for {name}\n  expected {expected}\n  got      {actual}",
                  file=sys.stderr)
            target.unlink(missing_ok=True)
            return 1
        print(f"  verified ({target.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
