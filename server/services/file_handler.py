from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

import aiofiles
from fastapi import UploadFile

CHUNK_SIZE = 65536


class UploadTooLarge(ValueError):
    """Raised when an upload exceeds the configured size limit (mapped to HTTP 413)."""


def _is_apk(path: Path) -> bool:
    """A ZIP is only treated as an APK if it carries an AndroidManifest.xml."""
    try:
        with zipfile.ZipFile(path) as zf:
            return "AndroidManifest.xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


async def save_upload_and_hash(
    upload_file: UploadFile, quarantine_dir: Path, max_size: int
) -> tuple[Path, str, str, int]:
    """
    Streams an uploaded file into the quarantine directory in chunks, enforcing
    max_size, validating magic bytes, and computing its SHA-256 hash.
    Returns: (file_path, file_type, sha256_hash, file_size)

    Quarantined PEs get a non-executable '.pe.quarantine' extension; APKs keep
    '.apk' because JADX selects its input loader by file extension.
    """
    sha256 = hashlib.sha256()
    size = 0

    # Read the first chunk to determine type
    first_chunk = await upload_file.read(CHUNK_SIZE)
    if not first_chunk:
        raise ValueError("Empty file uploaded")

    if first_chunk.startswith(b"MZ"):
        file_type = "PE"
    elif first_chunk.startswith(b"PK\x03\x04"):
        file_type = "APK"
    else:
        raise ValueError("Unsupported file type. Must be PE (EXE/DLL) or APK (ZIP).")

    # We don't know the full hash yet, so we save to a temporary file
    temp_path = quarantine_dir / f"temp_{os.urandom(8).hex()}.part"

    try:
        async with aiofiles.open(temp_path, "wb") as f:
            chunk = first_chunk
            while chunk:
                size += len(chunk)
                if size > max_size:
                    raise UploadTooLarge(f"File exceeds the {max_size // (1024 * 1024)} MB upload limit")
                sha256.update(chunk)
                await f.write(chunk)
                chunk = await upload_file.read(CHUNK_SIZE)

        if file_type == "APK" and not _is_apk(temp_path):
            raise ValueError("ZIP archive is not an APK (no AndroidManifest.xml)")

        final_hash = sha256.hexdigest()
        ext = ".pe.quarantine" if file_type == "PE" else ".apk"
        final_path = quarantine_dir / f"{final_hash}{ext}"

        # Content-addressed: if the file already exists it is byte-identical. On Windows it
        # may also be open by a running analysis, so never overwrite an existing copy.
        if final_path.exists():
            temp_path.unlink()
        else:
            try:
                os.replace(temp_path, final_path)
            except PermissionError:
                temp_path.unlink(missing_ok=True)
                if not final_path.exists():
                    raise

        return final_path, file_type, final_hash, size

    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
