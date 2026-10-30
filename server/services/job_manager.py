"""In-memory job registry with replayable SSE event streams and task cancellation.

Each job keeps its full event history, so an SSE client that connects late or
reconnects (EventSource does this automatically) replays everything it missed
instead of hanging on an empty stream. Events are broadcast to every connected
subscriber. Finished jobs are evicted after JOB_TTL_S; their results live on in
the SQLite history.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Coroutine, Dict, Optional

from server.config import JOB_TTL_S, MAX_JOBS_IN_MEMORY, SSE_HEARTBEAT_S

TERMINAL_STATUSES = ("COMPLETED", "FAILED", "CANCELLED")
MAX_EVENTS_PER_JOB = 1000


def _frame(event: str, payload: Dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@dataclass
class JobRecord:
    job_id: str
    file_name: str
    file_type: str
    sha256: str
    file_size: int
    status: str = "PENDING"
    progress: int = 0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    events: list = field(default_factory=list)
    subscribers: set = field(default_factory=set)
    task: Optional[asyncio.Task] = None
    created_at: float = field(default_factory=time.monotonic)
    finished_at: Optional[float] = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def summary(self) -> Dict[str, Any]:
        """AuditResult-shaped dict for a job that has no full result."""
        return {
            "job_id": self.job_id,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "status": self.status,
            "progress": self.progress,
            "error": self.error,
        }


class JobManager:
    def __init__(self, heartbeat_s: float = SSE_HEARTBEAT_S):
        self.jobs: Dict[str, JobRecord] = {}
        self.heartbeat_s = heartbeat_s

    # ---- lifecycle -------------------------------------------------------
    def create_job(self, job_id: str, file_name: str, file_type: str, sha256: str, file_size: int) -> JobRecord:
        self.sweep()
        record = JobRecord(job_id, file_name, file_type, sha256, file_size)
        self.jobs[job_id] = record
        return record

    def get(self, job_id: str) -> Optional[JobRecord]:
        return self.jobs.get(job_id)

    def start(self, job_id: str, coro: Coroutine) -> asyncio.Task:
        """Run the job coroutine as a task whose handle is kept for cancellation."""
        record = self.jobs[job_id]
        record.task = asyncio.create_task(coro, name=f"audit-{job_id}")
        return record.task

    def publish_progress(self, job_id: str, status: str, progress: int, message: str) -> None:
        """Record and broadcast a progress event (sync, so worker threads can schedule it)."""
        record = self.jobs.get(job_id)
        if record is None or record.terminal:
            return
        record.status = "RUNNING" if status not in TERMINAL_STATUSES else record.status
        record.progress = max(record.progress, int(progress))
        self._publish(record, _frame("progress", {"status": record.status, "progress": record.progress, "message": message}))

    async def put_event(self, job_id: str, status: str, progress: int, message: str) -> None:
        self.publish_progress(job_id, status, progress, message)

    async def complete_job(self, job_id: str, result: Dict[str, Any]) -> None:
        record = self.jobs.get(job_id)
        if record is None or record.terminal:
            return
        record.result = {**result, "status": "COMPLETED"}
        self._finish(record, "COMPLETED", "Audit completed successfully")

    async def fail_job(self, job_id: str, error_msg: str) -> None:
        record = self.jobs.get(job_id)
        if record is None or record.terminal:
            return
        record.error = error_msg
        self._finish(record, "FAILED", error_msg)

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job. Returns False if the job is unknown or already finished."""
        record = self.jobs.get(job_id)
        if record is None or record.terminal:
            return False
        record.error = "Cancelled by user"
        self._finish(record, "CANCELLED", "Audit cancelled")
        if record.task is not None and not record.task.done():
            record.task.cancel()
        return True

    def _finish(self, record: JobRecord, status: str, message: str) -> None:
        record.status = status
        record.progress = 100
        record.finished_at = time.monotonic()
        self._publish(record, _frame("progress", {"status": status, "progress": 100, "message": message}))
        self._publish(record, _frame("done", {"status": status}))

    def _publish(self, record: JobRecord, frame: str) -> None:
        if len(record.events) < MAX_EVENTS_PER_JOB:
            record.events.append(frame)
        for queue in list(record.subscribers):
            queue.put_nowait(frame)

    def sweep(self) -> None:
        """Evict finished jobs past their TTL, then the oldest finished jobs beyond the cap."""
        now = time.monotonic()
        for job_id, rec in list(self.jobs.items()):
            if rec.terminal and rec.finished_at is not None and now - rec.finished_at >= JOB_TTL_S and not rec.subscribers:
                del self.jobs[job_id]
        finished = sorted((r for r in self.jobs.values() if r.terminal and not r.subscribers), key=lambda r: r.finished_at or 0)
        while len(self.jobs) > MAX_JOBS_IN_MEMORY and finished:
            del self.jobs[finished.pop(0).job_id]

    # ---- streaming -------------------------------------------------------
    async def get_event_generator(self, job_id: str) -> AsyncIterator[str]:
        """Replay the job's history, then follow live events until 'done' (with keep-alive pings)."""
        record = self.jobs.get(job_id)
        if record is None:
            # Finished in an earlier server run (DB only) or evicted: nothing left to stream.
            yield _frame("done", {"status": "COMPLETED"})
            return

        # Snapshot + subscribe with no await in between, so no event can be missed or duplicated.
        history = list(record.events)
        queue: Optional[asyncio.Queue] = None
        if not record.terminal:
            queue = asyncio.Queue()
            record.subscribers.add(queue)
        try:
            for frame in history:
                yield frame
            if queue is None:
                return
            while True:
                try:
                    frame = await asyncio.wait_for(queue.get(), timeout=self.heartbeat_s)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield frame
                if frame.startswith("event: done"):
                    break
        finally:
            if queue is not None:
                record.subscribers.discard(queue)


job_manager = JobManager()
