from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from auditor.scoring import DEFAULT_PROFILE, PROFILES
from server.config import MAX_UPLOAD_SIZE, QUARANTINE_DIR
from server.database import get_scan_by_hash, save_scan
from server.models.schemas import AuditResult
from server.services.apk_audit import audit_apk_file
from server.services.file_handler import UploadTooLarge, save_upload_and_hash
from server.services.job_manager import JobRecord, job_manager
from server.services.pe_audit import audit_pe_file

logger = logging.getLogger(__name__)

router = APIRouter()

# Messages from these exception types are written by our own pipeline and safe to show users.
_USER_FACING_ERRORS = (ValueError, RuntimeError)


async def process_file_background(record: JobRecord, file_path: Path, profile: str):
    job_id = record.job_id
    try:
        await job_manager.put_event(job_id, "RUNNING", 5, "Queued for analysis")
        if record.file_type == "PE":
            result = await audit_pe_file(job_id, file_path, record.file_size, profile=profile)
        else:
            result = await audit_apk_file(job_id, file_path, record.file_size, record.sha256)

        full_result = {
            "job_id": job_id,
            "file_name": record.file_name,
            "file_type": record.file_type,
            "sha256": record.sha256,
            "file_size": record.file_size,
            "status": "COMPLETED",
            "progress": 100,
            **result,
        }
        # Validate before persisting so a schema drift fails the job instead of the GET endpoint.
        full_result = AuditResult(**full_result).model_dump()

        # Persist first: COMPLETED is only announced once the result is durable.
        await save_scan(job_id, record.sha256, record.file_name, record.file_type, record.file_size, full_result)
        await job_manager.complete_job(job_id, full_result)

    except asyncio.CancelledError:
        logger.info("Audit job %s cancelled", job_id)
        raise
    except Exception as e:
        logger.exception("Audit job %s failed", job_id)
        message = str(e) if isinstance(e, _USER_FACING_ERRORS) else "Internal analysis error (see server log)"
        await job_manager.fail_job(job_id, message)


def _display_name(filename: str | None, sha256: str, file_type: str) -> str:
    name = Path(filename).name.strip() if filename else ""
    return name[:255] or f"{sha256[:12]}.{'apk' if file_type == 'APK' else 'exe'}"


@router.post("/upload", response_model=AuditResult)
async def upload_file(file: UploadFile = File(...), profile: str = Form(DEFAULT_PROFILE)):
    profile = profile.lower()
    if profile not in PROFILES:
        raise HTTPException(status_code=400, detail=f"Unknown profile '{profile}' (choose from {', '.join(PROFILES)})")

    try:
        file_path, file_type, sha256, size = await save_upload_and_hash(file, QUARANTINE_DIR, MAX_UPLOAD_SIZE)
    except UploadTooLarge as e:
        raise HTTPException(status_code=413, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Upload failed")
        raise HTTPException(status_code=500, detail="Internal Server Error while storing upload")

    # Return a cached result when this exact file was already analysed with the same profile.
    existing = await get_scan_by_hash(sha256)
    if existing and existing.get("status") == "COMPLETED":
        cached_profile = (existing.get("verdict") or {}).get("profile") or DEFAULT_PROFILE
        if file_type == "APK" or cached_profile == profile:
            return AuditResult(**existing)

    job_id = str(uuid.uuid4())
    record = job_manager.create_job(job_id, _display_name(file.filename, sha256, file_type), file_type, sha256, size)
    job_manager.start(job_id, process_file_background(record, file_path, profile))

    return AuditResult(**record.summary())
