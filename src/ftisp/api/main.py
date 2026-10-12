import asyncio
import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError, model_validator

from ftisp.config import list_scenarios, load_scenario, make_config
from ftisp.data.loaders import load_unsw_nb15
from ftisp.fl.server import run_federation

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
MAX_CONCURRENT_RUNS = 2
log = logging.getLogger("ftisp.api")


class RunRequest(BaseModel):
    aggregator: Literal["fedavg", "median", "trimmed_mean", "krum"] = "fedavg"
    partition: Literal["iid", "dirichlet"] = "dirichlet"
    alpha: float = Field(0.5, ge=0.05, le=100)
    n_clients: int = Field(10, ge=4, le=30)
    rounds: int = Field(30, ge=1, le=100)
    attack: Literal["none", "label_flip"] = "none"
    n_malicious: int = Field(0, ge=0, le=14)
    boost: float = Field(1.0, ge=1, le=50)
    attack_start_round: int = Field(10, ge=1, le=100)
    seed: int = Field(42, ge=0, le=2**31 - 1)
    pace: float = Field(0.35, ge=0, le=3, description="minimum seconds per round, for live demos")

    @model_validator(mode="after")
    def _attackers_are_a_minority(self):
        if 2 * self.n_malicious >= self.n_clients:
            raise ValueError("malicious organizations must be fewer than half of all organizations")
        return self

    def to_config(self, data_dir: str):
        return make_config(
            name="dashboard",
            data_dir=data_dir,
            # The server assumes at most 3 attackers, capped by what Krum can tolerate.
            krum_f=min(3, (self.n_clients - 3) // 2),
            **self.model_dump(exclude={"pace"}),
        )


class _Cancelled(Exception):
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.data_dir = "data/unsw-nb15"
    app.state.data = await asyncio.to_thread(load_unsw_nb15, app.state.data_dir)
    app.state.slots = asyncio.Semaphore(MAX_CONCURRENT_RUNS)
    yield


app = FastAPI(title="FTISP dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/presets")
async def presets() -> dict:
    fields = set(RunRequest.model_fields) - {"pace"}
    return {
        name: {k: v for k, v in load_scenario(name).to_dict().items() if k in fields}
        for name in list_scenarios()
    }


@app.websocket("/ws/run")
async def run_ws(ws: WebSocket) -> None:
    await ws.accept()
    try:
        req = RunRequest.model_validate(await ws.receive_json())
    except (ValidationError, ValueError) as exc:
        errors = exc.errors() if isinstance(exc, ValidationError) else [{"msg": str(exc)}]
        await ws.send_json({"type": "error", "message": "; ".join(e["msg"] for e in errors)})
        await ws.close()
        return
    except WebSocketDisconnect:
        return

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict] = asyncio.Queue()
    cancel = threading.Event()

    def emit(message: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, message)

    def on_round(record: dict) -> None:
        time.sleep(max(0.0, req.pace - record["seconds"]))
        if cancel.is_set():
            raise _Cancelled
        emit({"type": "round", "record": record})

    def work() -> None:
        try:
            run_federation(
                req.to_config(app.state.data_dir),
                app.state.data,
                on_round=on_round,
                on_start=lambda info: emit({"type": "start", **info}),
            )
            emit({"type": "done"})
        except _Cancelled:
            pass
        except (ValueError, RuntimeError) as exc:
            emit({"type": "error", "message": str(exc)})
        except Exception:
            log.exception("simulation failed")
            emit({"type": "error", "message": "simulation failed; see server log"})

    async with app.state.slots:
        worker = loop.run_in_executor(None, work)
        listener = asyncio.create_task(ws.receive_text())
        try:
            while True:
                getter = asyncio.create_task(queue.get())
                done, _ = await asyncio.wait({getter, listener}, return_when=asyncio.FIRST_COMPLETED)
                if listener in done:
                    getter.cancel()
                    break
                message = getter.result()
                await ws.send_json(message)
                if message["type"] in ("done", "error"):
                    break
        except WebSocketDisconnect:
            pass
        finally:
            cancel.set()
            listener.cancel()
            await worker
    try:
        await ws.close()
    except RuntimeError:
        pass
