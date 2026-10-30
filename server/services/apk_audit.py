import asyncio
import logging
import os
import re
import shutil
import signal
import sys
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from typing import Dict, Any, List

from server import config
from server.config import DECOMPILED_DIR
from server.services.job_manager import job_manager
from server.services.yara_scanner import scan_file_with_yara

logger = logging.getLogger(__name__)

URL_REGEX = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PROGRESS_REGEX = re.compile(r"progress:\s*(\d+)\s*of\s*(\d+)\s*\((\d+)%\)")

SUSPICIOUS_APIS = {
    "DexClassLoader": "Dynamic code loading",
    "Runtime.getRuntime().exec": "Command execution",
    "getSystemService(\"phone\")": "Accessing telephony info (IMEI/Phone)",
    "sendTextMessage": "Sending SMS without interaction",
    "Cipher.getInstance": "Cryptographic operations (potential ransomware/C2)",
    "Landroid/content/pm/PackageManager;->getInstalledPackages": "Enumerating installed apps",
    "Landroid/hardware/Camera;->open": "Background camera access",
}

# MITRE ATT&CK for Mobile mappings for the APK verdict signals.
APK_TECHNIQUES = {
    "apk_send_sms": ("T1582", "SMS Control"),
    "apk_read_sms": ("T1636.004", "Protected User Data: SMS Messages"),
    "apk_contacts": ("T1636.003", "Protected User Data: Contact List"),
    "apk_camera": ("T1512", "Video Capture"),
    "apk_suspicious_api": ("T1407", "Download New Code at Runtime"),
    "apk_endpoints": ("T1437.001", "Application Layer Protocol: Web Protocols"),
    "apk_yara": (None, None),
}

# Largest single stdout line we buffer from JADX before discarding it (stream error recovery).
_JADX_LINE_LIMIT = 1 << 20
_STDERR_TAIL_LINES = 200


def _jadx_command(apk_path: Path, output_dir: Path) -> List[str]:
    jadx = config.JADX_BIN
    # A .py launcher is run with the current interpreter (used by the test-suite's fake JADX).
    cmd = [sys.executable, jadx] if jadx.endswith(".py") else [jadx]
    if config.JADX_DEOBF:
        cmd.append("--deobf")
    cmd += ["--show-bad-code", "--threads-count", str(max(1, config.JADX_THREADS)), "-d", str(output_dir), str(apk_path)]
    return cmd


def _jadx_env() -> Dict[str, str]:
    env = os.environ.copy()
    # Appended after the launcher's DEFAULT_JVM_OPTS, so this heap cap wins over MaxRAMPercentage.
    env["JADX_OPTS"] = f"{env.get('JADX_OPTS', '')} -Xmx{config.JADX_HEAP}".strip()
    return env


async def _kill_process_tree(process: asyncio.subprocess.Process) -> None:
    """Kill JADX and its children (on Windows the .bat launcher spawns cmd.exe -> java.exe)."""
    if process.returncode is not None:
        return
    try:
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec(
                "taskkill", "/T", "/F", "/PID", str(process.pid),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except asyncio.TimeoutError:
        process.kill()


def _has_partial_output(output_dir: Path) -> bool:
    sources_dir = output_dir / "sources"
    return (output_dir / "resources" / "AndroidManifest.xml").exists() or (
        sources_dir.exists() and any(sources_dir.iterdir())
    )


async def run_jadx(job_id: str, apk_path: Path, output_dir: Path) -> List[str]:
    """Decompile with JADX under a timeout and heap cap. Returns non-fatal warnings.

    The process tree is killed on timeout and on task cancellation. Non-zero exits and
    timeouts are tolerated when JADX already produced usable output (common for large
    multi-DEX production APKs where a few classes fail to decompile).
    """
    await job_manager.put_event(job_id, "RUNNING", 15, "Decompiling APK with JADX (streaming classes)...")

    process = await asyncio.create_subprocess_exec(
        *_jadx_command(apk_path, output_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_jadx_env(),
        limit=_JADX_LINE_LIMIT,
        start_new_session=(os.name != "nt"),
    )

    stderr_tail: deque = deque(maxlen=_STDERR_TAIL_LINES)
    last_reported_pct = 15

    async def read_stdout() -> None:
        nonlocal last_reported_pct
        while True:
            try:
                line = await process.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError):
                # Oversized line: drop the buffered chunk and keep following the stream.
                await process.stdout.read(_JADX_LINE_LIMIT)
                continue
            if not line:
                break
            m = PROGRESS_REGEX.search(line.decode(errors="replace"))
            if m:
                cur, total, pct = m.groups()
                # Map JADX's internal 0-100% onto the UI's 15%-55% window
                mapped_pct = 15 + int(int(pct) * 0.40)
                if mapped_pct > last_reported_pct:
                    last_reported_pct = mapped_pct
                    await job_manager.put_event(
                        job_id, "RUNNING", mapped_pct, f"Decompiling classes ({cur}/{total} - {pct}%)..."
                    )

    async def read_stderr() -> None:
        while True:
            try:
                line = await process.stderr.readline()
            except (ValueError, asyncio.LimitOverrunError):
                await process.stderr.read(_JADX_LINE_LIMIT)
                continue
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                stderr_tail.append(text)

    warnings: List[str] = []
    try:
        await asyncio.wait_for(
            asyncio.gather(read_stdout(), read_stderr(), process.wait()),
            timeout=config.JADX_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        await _kill_process_tree(process)
        if _has_partial_output(output_dir):
            warnings.append(f"JADX timed out after {config.JADX_TIMEOUT_S}s; analysed partial decompiler output")
            await job_manager.put_event(job_id, "RUNNING", 58, warnings[-1])
            return warnings
        raise RuntimeError(f"JADX decompilation timed out after {config.JADX_TIMEOUT_S}s with no usable output")
    finally:
        # Covers task cancellation (DELETE /audit/{id}) and unexpected errors.
        await _kill_process_tree(process)

    if process.returncode != 0:
        if _has_partial_output(output_dir):
            warnings.append(f"JADX exited with code {process.returncode}; some classes failed to decompile")
            await job_manager.put_event(job_id, "RUNNING", 58, "Decompilation completed with partial warnings (sources extracted)")
            return warnings
        tail = "\n".join(list(stderr_tail)[-20:]) or "no stderr output"
        raise RuntimeError(f"JADX decompilation failed (exit {process.returncode}): {tail}")

    return warnings


def parse_manifest(manifest_path: Path) -> Dict[str, Any]:
    if not manifest_path.exists():
        return {}

    try:
        # ElementTree does not resolve external entities, and the expat shipped with
        # supported Python versions caps entity expansion (billion-laughs protection).
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Namespaces are commonly used in AndroidManifest
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        attr = lambda el, name: el.attrib.get(f'{{{ns["android"]}}}{name}')  # noqa: E731

        # Package info
        package = root.attrib.get('package', 'unknown')
        version_code = attr(root, 'versionCode') or 'unknown'
        version_name = attr(root, 'versionName') or 'unknown'

        # SDK versions
        min_sdk = "unknown"
        target_sdk = "unknown"
        uses_sdk = root.find('uses-sdk')
        if uses_sdk is not None:
            min_sdk = attr(uses_sdk, 'minSdkVersion') or 'unknown'
            target_sdk = attr(uses_sdk, 'targetSdkVersion') or 'unknown'

        # Permissions
        permissions = [name for perm in root.findall('uses-permission') if (name := attr(perm, 'name'))]

        # Components
        app = root.find('application')
        components = {"activities": [], "services": [], "receivers": [], "providers": []}
        if app is not None:
            for tag, key in (("activity", "activities"), ("service", "services"),
                             ("receiver", "receivers"), ("provider", "providers")):
                components[key] = [name for el in app.findall(tag) if (name := attr(el, 'name'))]

        return {
            "apk_info": {
                "package_name": package,
                "version_code": version_code,
                "version_name": version_name,
                "min_sdk": min_sdk,
                "target_sdk": target_sdk
            },
            "apk_permissions": permissions,
            "apk_components": components,
        }
    except Exception as e:
        logger.warning("Error parsing manifest %s: %s", manifest_path, e)
        return {}


def scan_source_code(
    source_dir: Path,
    max_files: int = config.APK_MAX_SOURCE_FILES,
    max_file_bytes: int = config.APK_MAX_SOURCE_FILE_BYTES,
    max_hits: int = config.APK_MAX_SUSPICIOUS_HITS,
) -> tuple[List[str], List[Dict[str, Any]]]:
    endpoints = set()
    suspicious = []
    scanned_count = 0

    for root, _, files in os.walk(source_dir):
        for file in files:
            if scanned_count >= max_files:
                break
            if not file.endswith(('.java', '.xml', '.smali')):
                continue

            path = Path(root) / file
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                scanned_count += 1
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except OSError:
                continue

            endpoints.update(URL_REGEX.findall(content))
            endpoints.update(IP_REGEX.findall(content))

            for api, reason in SUSPICIOUS_APIS.items():
                if api in content and len(suspicious) < max_hits:
                    suspicious.append({
                        "api": api,
                        "reason": reason,
                        "file": str(path.relative_to(source_dir))
                    })

        if scanned_count >= max_files:
            break

    return sorted(endpoints), suspicious


def score_apk(perms: List[str], suspicious_apis: List[Dict[str, Any]], endpoints: List[str], yara_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Weighted APK verdict with ATT&CK for Mobile technique enrichment."""
    findings = []  # (points, reason, signal_key)
    if "android.permission.SEND_SMS" in perms:
        findings.append((5, "Requests permission to send SMS", "apk_send_sms"))
    if "android.permission.RECEIVE_SMS" in perms:
        findings.append((3, "Requests permission to read SMS", "apk_read_sms"))
    if "android.permission.READ_CONTACTS" in perms:
        findings.append((2, "Requests permission to read contacts", "apk_contacts"))
    if "android.permission.CAMERA" in perms:
        findings.append((2, "Requests camera access", "apk_camera"))
    if suspicious_apis:
        distinct = len({hit["api"] for hit in suspicious_apis})
        # Saturates: thousands of call sites of the same API are not more evidence than a few.
        findings.append((min(distinct, 5), f"Found {len(suspicious_apis)} usage(s) of {distinct} suspicious API(s)", "apk_suspicious_api"))
    if endpoints:
        findings.append((1, f"Extracted {len(endpoints)} potential C2/Endpoint URLs", "apk_endpoints"))
    if yara_matches:
        findings.append((min(len(yara_matches) * 2, 6), f"Triggered {len(yara_matches)} YARA rules", "apk_yara"))

    score = sum(points for points, _, _ in findings)
    verdict = "HIGH" if score >= 10 else "MEDIUM" if score >= 5 else "LOW"
    return {
        "score": score,
        "verdict": verdict,
        "reasons": [reason for _, reason, _ in findings],
        "signal_keys": [key for _, _, key in findings],
        "mitre_techniques": [
            {"reason": reason, "mitre_id": APK_TECHNIQUES[key][0], "mitre_name": APK_TECHNIQUES[key][1], "signal_key": key}
            for _, reason, key in findings
        ],
        "thresholds": {"medium": 5, "high": 10},
    }


async def audit_apk_file(job_id: str, file_path: Path, file_size: int, sha256: str) -> Dict[str, Any]:
    await job_manager.put_event(job_id, "RUNNING", 10, "Initializing APK analysis")

    if not config.JADX_BIN:
        raise RuntimeError("JADX is not installed: place it in tools/jadx, add it to PATH, or set JADX_PATH")

    # Per-job directory: concurrent uploads of the same APK never clobber each other.
    output_dir = DECOMPILED_DIR / f"{sha256}-{job_id}"
    try:
        warnings = await run_jadx(job_id, file_path, output_dir)

        await job_manager.put_event(job_id, "RUNNING", 60, "Parsing AndroidManifest.xml")
        manifest_data = await asyncio.to_thread(parse_manifest, output_dir / "resources" / "AndroidManifest.xml")
        if not manifest_data:
            warnings.append("AndroidManifest.xml could not be decoded")

        await job_manager.put_event(job_id, "RUNNING", 75, "Scanning decompiled source code for IoCs")
        endpoints, suspicious_apis = await asyncio.to_thread(scan_source_code, output_dir / "sources")

        await job_manager.put_event(job_id, "RUNNING", 90, "Running YARA rules")
        yara_matches = await asyncio.to_thread(scan_file_with_yara, file_path)
    finally:
        if not config.KEEP_DECOMPILED:
            await asyncio.to_thread(shutil.rmtree, output_dir, True)

    verdict = score_apk(manifest_data.get("apk_permissions", []), suspicious_apis, endpoints, yara_matches)

    return {
        "apk_info": manifest_data.get("apk_info"),
        "yara_matches": yara_matches,
        "apk_permissions": manifest_data.get("apk_permissions", []),
        "apk_components": manifest_data.get("apk_components"),
        "apk_endpoints": endpoints,
        "apk_suspicious_apis": suspicious_apis,
        "verdict": verdict,
        "warnings": warnings,
    }
