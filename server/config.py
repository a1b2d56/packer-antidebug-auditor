"""Server configuration. Every tunable can be overridden with an environment variable."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


ROOT_DIR = Path(__file__).resolve().parent.parent

# Runtime data (quarantine, decompiled sources, scan history). AUDITOR_DATA_DIR relocates all of it.
DATA_DIR = Path(os.environ.get("AUDITOR_DATA_DIR", ROOT_DIR))
QUARANTINE_DIR = DATA_DIR / "quarantine"
DECOMPILED_DIR = DATA_DIR / "decompiled"
DB_PATH = DATA_DIR / "history.sqlite3"
MODEL_PATH = Path(os.environ.get("AUDITOR_MODEL_PATH", ROOT_DIR / "models" / "packer_model.joblib"))

MAX_UPLOAD_SIZE = _env_int("MAX_UPLOAD_SIZE", 100 * 1024 * 1024)  # 100 MB

# Job lifecycle
JOB_TTL_S = _env_int("JOB_TTL_S", 30 * 60)  # finished jobs are evicted from memory after this
MAX_JOBS_IN_MEMORY = _env_int("MAX_JOBS_IN_MEMORY", 200)
SSE_HEARTBEAT_S = _env_int("SSE_HEARTBEAT_S", 15)

# CORS: the Vite dev server by default; comma-separated list to override.
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]


# External tools
def _resolve_jadx() -> str | None:
    candidates = [
        os.environ.get("JADX_PATH"),
        str(ROOT_DIR / "tools" / "jadx" / "bin" / ("jadx.bat" if os.name == "nt" else "jadx")),
        shutil.which("jadx"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


JADX_BIN = _resolve_jadx()
JADX_TIMEOUT_S = _env_int("JADX_TIMEOUT_S", 900)  # large multi-DEX APKs (e.g. SystemUI) take minutes
JADX_HEAP = os.environ.get("JADX_HEAP", "4g")  # passed to the JVM as -Xmx
JADX_THREADS = _env_int("JADX_THREADS", min(4, os.cpu_count() or 1))
JADX_DEOBF = _env_bool("JADX_DEOBF", True)
KEEP_DECOMPILED = _env_bool("KEEP_DECOMPILED", False)

# APK source scanning limits
APK_MAX_SOURCE_FILES = _env_int("APK_MAX_SOURCE_FILES", 5000)
APK_MAX_SOURCE_FILE_BYTES = _env_int("APK_MAX_SOURCE_FILE_BYTES", 2 * 1024 * 1024)
APK_MAX_SUSPICIOUS_HITS = _env_int("APK_MAX_SUSPICIOUS_HITS", 500)

# Create required directories
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
DECOMPILED_DIR.mkdir(parents=True, exist_ok=True)
