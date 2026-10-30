"""Unit tests for the replayable SSE job registry."""

import asyncio

from server.services.job_manager import JobManager


def _run(coro):
    return asyncio.run(coro)


async def _collect(gen, limit=50):
    out = []
    async for frame in gen:
        out.append(frame)
        if len(out) >= limit:
            break
    return out


def test_late_subscriber_gets_history_and_live_events():
    async def scenario():
        jm = JobManager(heartbeat_s=5)
        jm.create_job("j", "f.exe", "PE", "abc", 10)
        jm.publish_progress("j", "RUNNING", 10, "one")

        early = asyncio.create_task(_collect(jm.get_event_generator("j")))
        await asyncio.sleep(0)
        jm.publish_progress("j", "RUNNING", 50, "two")
        late = asyncio.create_task(_collect(jm.get_event_generator("j")))
        await asyncio.sleep(0)
        await jm.complete_job("j", {"x": 1})
        return await early, await late, jm.get("j")

    early, late, record = _run(scenario())
    assert early == late  # both see the identical full stream
    assert early[-1].startswith("event: done")
    assert sum(f.startswith("event: progress") for f in early) == 3
    assert record.status == "COMPLETED"
    assert record.result["status"] == "COMPLETED"
    assert record.subscribers == set()


def test_heartbeat_while_idle():
    async def scenario():
        jm = JobManager(heartbeat_s=0.05)
        jm.create_job("j", "f.exe", "PE", "abc", 10)
        gen = jm.get_event_generator("j")
        first = await asyncio.wait_for(gen.__anext__(), timeout=2)
        await gen.aclose()
        return first

    assert _run(scenario()) == ": ping\n\n"


def test_terminal_state_is_final():
    async def scenario():
        jm = JobManager()
        jm.create_job("j", "f.exe", "PE", "abc", 10)
        assert jm.cancel_job("j") is True
        await jm.complete_job("j", {"late": True})
        await jm.fail_job("j", "late failure")
        jm.publish_progress("j", "RUNNING", 99, "late progress")
        return jm.get("j")

    record = _run(scenario())
    assert record.status == "CANCELLED"
    assert record.result is None
    assert sum(f.startswith("event: done") for f in record.events) == 1


def test_running_status_recorded():
    jm = JobManager()
    jm.create_job("j", "f.exe", "PE", "abc", 10)
    assert jm.get("j").status == "PENDING"
    jm.publish_progress("j", "RUNNING", 30, "go")
    assert jm.get("j").status == "RUNNING"
    assert jm.get("j").progress == 30


def test_sweep_evicts_old_finished_jobs(monkeypatch):
    from server.services import job_manager as jm_module

    monkeypatch.setattr(jm_module, "JOB_TTL_S", 0)
    jm = JobManager()
    jm.create_job("done", "f.exe", "PE", "abc", 10)
    jm.create_job("live", "g.exe", "PE", "def", 10)
    _run(jm.fail_job("done", "boom"))
    jm.sweep()
    assert jm.get("done") is None
    assert jm.get("live") is not None
