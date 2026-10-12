"""Serve the live dashboard.

    python scripts/run_dashboard.py              # http://127.0.0.1:8000
    python scripts/run_dashboard.py --host 0.0.0.0 --port 8080
"""

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run("ftisp.api.main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
