import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add root dir to path so auditor modules resolve correctly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from server import config  # noqa: E402
from server.database import init_db  # noqa: E402
from server.models.schemas import HealthResponse  # noqa: E402
from server.routes import audit, upload  # noqa: E402
from server.services import model_store, yara_scanner  # noqa: E402

API_VERSION = "1.1.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Pre-load the ML model and YARA rules so the first scan is not slowed down
    model_store.load_default_model()
    yara_scanner.load_yara_rules()
    yield


app = FastAPI(
    title="Packer & Anti-Debug Auditor API",
    version=API_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Include routers
app.include_router(upload.router, prefix="/api/v1", tags=["Upload"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit"])


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        version=API_VERSION,
        model_loaded=model_store.get_model() is not None,
        yara_enabled=yara_scanner.load_yara_rules() is not None,
        jadx_available=config.JADX_BIN is not None,
    )


def start():
    """Entry point for the CLI script.

    Auto-reload is off by default: uvicorn's reloader runs the app under a selector event
    loop on Windows, which cannot spawn subprocesses (JADX). Set AUDITOR_RELOAD=1 for
    backend development on PE-only workflows.
    """
    reload = os.environ.get("AUDITOR_RELOAD", "0") == "1"
    uvicorn.run("server.main:app", host="127.0.0.1", port=8000, reload=reload)


if __name__ == "__main__":
    start()
