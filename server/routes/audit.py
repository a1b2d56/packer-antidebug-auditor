from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from server.database import get_scan_by_id
from server.models.schemas import AuditResult, CancelResponse
from server.services.job_manager import job_manager

router = APIRouter()

SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",  # disable proxy buffering so events arrive immediately
}


@router.get("/{job_id}", response_model=AuditResult)
async def get_audit_result(job_id: str):
    """Fetch the audit result from memory (running or recently finished) or the scan history."""
    record = job_manager.get(job_id)
    if record is not None:
        if record.status == "COMPLETED" and record.result:
            return record.result
        return record.summary()

    db_result = await get_scan_by_id(job_id)
    if db_result:
        return db_result

    raise HTTPException(status_code=404, detail="Job not found")


@router.delete("/{job_id}", response_model=CancelResponse)
async def cancel_audit(job_id: str):
    """Cancel a pending/running audit. The JADX process tree is killed for APK jobs."""
    record = job_manager.get(job_id)
    if record is None:
        if await get_scan_by_id(job_id):
            return CancelResponse(job_id=job_id, status="COMPLETED", cancelled=False)
        raise HTTPException(status_code=404, detail="Job not found")

    cancelled = job_manager.cancel_job(job_id)
    return CancelResponse(job_id=job_id, status=record.status, cancelled=cancelled)


@router.get("/{job_id}/stream")
async def stream_audit_progress(job_id: str):
    """SSE endpoint: replays the job's progress history, then streams live events until 'done'."""
    if job_manager.get(job_id) is None and not await get_scan_by_id(job_id):
        raise HTTPException(status_code=404, detail="Job not found")

    return StreamingResponse(
        job_manager.get_event_generator(job_id),
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )
