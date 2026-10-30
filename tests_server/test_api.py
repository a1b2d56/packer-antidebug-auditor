"""End-to-end API tests: upload, job lifecycle, SSE replay, cancellation and JADX hardening."""

import os
import time
from pathlib import Path

import pytest

from conftest import build_fake_apk, build_minimal_pe
from server import config
from server.models.schemas import AuditResult, CancelResponse, HealthResponse
from server.services.job_manager import job_manager

TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")


def _upload(client, name: str, data: bytes, profile: str | None = None):
    form = {"profile": profile} if profile else None
    return client.post("/api/v1/upload", files={"file": (name, data)}, data=form)


def _wait(client, job_id: str, timeout: float = 30.0, until=TERMINAL) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/v1/audit/{job_id}").json()
        if body["status"] in until:
            return body
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not reach {until}: {body}")


def _sse_events(client, job_id: str) -> list[str]:
    events = []
    with client.stream("GET", f"/api/v1/audit/{job_id}/stream") as resp:
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "no-cache"
        for line in resp.iter_lines():
            if line.startswith("event:"):
                events.append(line.split(":", 1)[1].strip())
    return events


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import subprocess

        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


# ---- health & validation -------------------------------------------------

def test_health(client):
    body = client.get("/api/v1/health").json()
    health = HealthResponse(**body)
    assert health.status == "ok"
    assert health.jadx_available is True


def test_rejects_unknown_file_type(client):
    resp = _upload(client, "notes.txt", b"hello world")
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.json()["detail"]


def test_rejects_zip_that_is_not_an_apk(client):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "plain zip")
    resp = _upload(client, "archive.zip", buf.getvalue())
    assert resp.status_code == 400
    assert "not an APK" in resp.json()["detail"]


def test_rejects_oversized_upload(client, monkeypatch):
    from server.routes import upload as upload_route

    monkeypatch.setattr(upload_route, "MAX_UPLOAD_SIZE", 1024)
    resp = _upload(client, "big.exe", build_minimal_pe() * 4)
    assert resp.status_code == 413
    leftovers = list(config.QUARANTINE_DIR.glob("temp_*"))
    assert leftovers == []


def test_rejects_unknown_profile(client):
    resp = _upload(client, "a.exe", build_minimal_pe(), profile="paranoid")
    assert resp.status_code == 400


def test_unknown_job_404(client):
    assert client.get("/api/v1/audit/does-not-exist").status_code == 404
    assert client.get("/api/v1/audit/does-not-exist/stream").status_code == 404
    assert client.delete("/api/v1/audit/does-not-exist").status_code == 404


# ---- PE pipeline -----------------------------------------------------------

def test_pe_upload_completes_and_validates(client):
    # mov r10, rcx; mov eax, 0x18; syscall -> direct syscall finding
    pe = build_minimal_pe(b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3")
    resp = _upload(client, "sample.exe", pe)
    assert resp.status_code == 200
    job = resp.json()
    assert job["status"] in ("PENDING", "RUNNING")

    body = _wait(client, job["job_id"])
    assert body["status"] == "COMPLETED", body
    result = AuditResult(**body)
    assert result.file_name == "sample.exe"
    assert result.verdict.profile == "balanced"
    assert "direct_syscall" in result.verdict.signal_keys
    # Regression: header anomalies and syscalls used to be passed in swapped positions
    assert result.anti_analysis.direct_syscalls
    assert all("syscall" not in h["reason"].lower() for h in result.heuristics.header_anomalies)
    assert result.heuristics.section_count_flag is not None  # one section -> flagged
    assert not str(config.QUARANTINE_DIR / "x").endswith(".exe")
    assert list(config.QUARANTINE_DIR.glob(f"{result.sha256}.pe.quarantine"))


def test_pe_cached_by_hash_and_profile(client):
    pe = build_minimal_pe(b"\x90\x90\x0f\x31")
    first = _upload(client, "cache.exe", pe).json()
    _wait(client, first["job_id"])

    again = _upload(client, "cache.exe", pe).json()
    assert again["status"] == "COMPLETED"
    assert again["job_id"] == first["job_id"]

    other_profile = _upload(client, "cache.exe", pe, profile="aggressive").json()
    assert other_profile["job_id"] != first["job_id"]
    body = _wait(client, other_profile["job_id"])
    assert body["verdict"]["profile"] == "aggressive"
    assert body["verdict"]["thresholds"] == {"medium": 2, "high": 5}


def test_sse_replays_full_history_after_completion(client):
    job = _upload(client, "replay.exe", build_minimal_pe(b"\xcc\xcc")).json()
    _wait(client, job["job_id"])

    for _ in range(2):  # every (re)connect gets the complete history
        events = _sse_events(client, job["job_id"])
        assert events.count("progress") >= 5
        assert events[-1] == "done"


def test_sse_for_db_only_job_sends_done(client):
    job = _upload(client, "evicted.exe", build_minimal_pe(b"\xcc\xcd")).json()
    _wait(client, job["job_id"])
    job_manager.jobs.pop(job["job_id"])  # simulate eviction / server restart

    assert _sse_events(client, job["job_id"]) == ["done"]
    assert client.get(f"/api/v1/audit/{job['job_id']}").json()["status"] == "COMPLETED"


# ---- APK pipeline (fake JADX) ----------------------------------------------

def test_apk_upload_completes(client, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    job = _upload(client, "app.apk", build_fake_apk()).json()
    body = _wait(client, job["job_id"])
    assert body["status"] == "COMPLETED", body
    result = AuditResult(**body)
    assert result.apk_info.package_name == "com.example.fake"
    assert "android.permission.SEND_SMS" in result.apk_permissions
    assert "https://c2.example.test" in result.apk_endpoints
    assert {"apk_send_sms", "apk_suspicious_api"} <= set(result.verdict.signal_keys)
    ids = {t.signal_key: t.mitre_id for t in result.verdict.mitre_techniques}
    assert ids["apk_send_sms"] == "T1582"
    # decompiled output removed unless KEEP_DECOMPILED
    assert not any(p.name.endswith(job["job_id"]) for p in config.DECOMPILED_DIR.iterdir())


def test_apk_jadx_failure_reports_stderr(client, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "fail")
    apk = build_fake_apk() + b"\x00fail"  # distinct hash
    body = _wait(client, _upload(client, "bad.apk", apk).json()["job_id"])
    assert body["status"] == "FAILED"
    assert "input file is corrupt" in body["error"]


def test_apk_partial_output_is_accepted(client, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "partial")
    apk = build_fake_apk() + b"\x00partial"
    body = _wait(client, _upload(client, "partial.apk", apk).json()["job_id"])
    assert body["status"] == "COMPLETED", body
    assert any("exited with code 1" in w for w in body["warnings"])


def test_apk_timeout_kills_process_tree(client, monkeypatch, tmp_path):
    pidfile = tmp_path / "child.pid"
    monkeypatch.setenv("FAKE_JADX_MODE", "sleep")
    monkeypatch.setenv("FAKE_JADX_PIDFILE", str(pidfile))
    monkeypatch.setattr(config, "JADX_TIMEOUT_S", 3)

    apk = build_fake_apk() + b"\x00timeout"
    body = _wait(client, _upload(client, "slow.apk", apk).json()["job_id"], timeout=40)
    assert body["status"] == "FAILED"
    assert "timed out" in body["error"]
    _assert_killed(pidfile)


def test_apk_timeout_with_partial_output_completes(client, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "partial_sleep")
    monkeypatch.setattr(config, "JADX_TIMEOUT_S", 3)
    apk = build_fake_apk() + b"\x00partial-timeout"
    body = _wait(client, _upload(client, "slow2.apk", apk).json()["job_id"], timeout=40)
    assert body["status"] == "COMPLETED", body
    assert any("timed out" in w for w in body["warnings"])


def test_cancel_running_apk_job(client, monkeypatch, tmp_path):
    pidfile = tmp_path / "child.pid"
    monkeypatch.setenv("FAKE_JADX_MODE", "sleep")
    monkeypatch.setenv("FAKE_JADX_PIDFILE", str(pidfile))
    monkeypatch.setattr(config, "JADX_TIMEOUT_S", 120)

    job = _upload(client, "cancel.apk", build_fake_apk() + b"\x00cancel").json()
    _wait(client, job["job_id"], until=("RUNNING",))
    deadline = time.time() + 20
    while not pidfile.exists() and time.time() < deadline:
        time.sleep(0.1)

    resp = client.delete(f"/api/v1/audit/{job['job_id']}")
    assert resp.status_code == 200
    cancel = CancelResponse(**resp.json())
    assert cancel.cancelled is True
    assert cancel.status == "CANCELLED"

    assert _wait(client, job["job_id"])["status"] == "CANCELLED"
    assert _sse_events(client, job["job_id"])[-1] == "done"
    _assert_killed(pidfile)

    again = CancelResponse(**client.delete(f"/api/v1/audit/{job['job_id']}").json())
    assert again.cancelled is False


def _assert_killed(pidfile: Path) -> None:
    assert pidfile.exists(), "fake JADX never started its child process"
    pid = int(pidfile.read_text())
    deadline = time.time() + 15
    while _pid_alive(pid) and time.time() < deadline:
        time.sleep(0.2)
    assert not _pid_alive(pid), "JADX grandchild survived the process-tree kill"


@pytest.fixture(autouse=True)
def _restore_fake_mode(monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", os.environ.get("FAKE_JADX_MODE", "ok"))
