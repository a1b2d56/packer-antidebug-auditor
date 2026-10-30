"""Isolate the server under test: temp data dir, fake JADX, fast heartbeats.

These environment variables must be set before any `server.*` module is imported,
because server.config resolves them at import time.
"""

import os
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_DATA_DIR = tempfile.mkdtemp(prefix="auditor-test-")
os.environ["AUDITOR_DATA_DIR"] = _DATA_DIR
os.environ["JADX_PATH"] = str(Path(__file__).with_name("fake_jadx.py"))
os.environ["SSE_HEARTBEAT_S"] = "1"
os.environ.setdefault("FAKE_JADX_MODE", "ok")

import pytest  # noqa: E402


def build_minimal_pe(extra_code: bytes = b"") -> bytes:
    """A tiny but well-formed PE32 image with a single executable .text section."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<HBB", opt, 0, 0x10B, 14, 0)          # Magic, linker version
    struct.pack_into("<III", opt, 4, 0x200, 0, 0)            # SizeOfCode, init, uninit
    struct.pack_into("<III", opt, 16, 0x1000, 0x1000, 0x2000)  # EntryPoint, BaseOfCode, BaseOfData
    struct.pack_into("<III", opt, 28, 0x400000, 0x1000, 0x200)  # ImageBase, SectionAlign, FileAlign
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)   # OS/image/subsystem versions
    struct.pack_into("<IIII", opt, 56, 0x2000, 0x200, 0, 3)  # SizeOfImage, SizeOfHeaders, CheckSum, Subsystem
    struct.pack_into("<HIIII", opt, 70, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", opt, 88, 0, 16)                  # LoaderFlags, NumberOfRvaAndSizes

    section = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    headers = bytes(dos) + b"PE\x00\x00" + file_header + bytes(opt) + section
    headers = headers.ljust(0x200, b"\x00")
    code = (b"\x55\x8b\xec" + extra_code + b"\x5d\xc3").ljust(0x200, b"\x90")
    return headers + code


def build_fake_apk() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-axml-placeholder")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return buf.getvalue()


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return Path(_DATA_DIR)


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from server.main import app

    with TestClient(app) as c:
        yield c
