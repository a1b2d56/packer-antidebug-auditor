import asyncio
from pathlib import Path
from typing import Any, Callable, Dict

import pefile

from auditor.antidebug import (
    iat_density_flags,
    scan_direct_syscalls,
    scan_imports,
    scan_opcodes,
    scan_strings,
    scan_tls_callbacks,
)
from auditor.entropy import section_entropies
from auditor.heuristics import (
    entry_point_flags,
    overlay_flags,
    pe_header_anomaly_flags,
    rwx_section_flags,
    section_count_flag,
    section_name_flags,
    size_delta_flags,
)
from auditor.model import predict_sample
from auditor.report import extract_feature_dict, generate_dict_report
from auditor.scoring import DEFAULT_PROFILE, compute_verdict
from server.models.schemas import (
    AntiAnalysisResult,
    HeuristicsResult,
    MLPrediction,
    PEMetadata,
    SectionInfo,
    VerdictResult,
)
from server.services.job_manager import job_manager
from server.services.model_store import get_model
from server.services.yara_scanner import scan_file_with_yara

ProgressFn = Callable[[int, str], None]


def _get_machine_type(pe: pefile.PE) -> str:
    machine_val = pe.FILE_HEADER.Machine
    if machine_val == 0x014C:
        return "x86"
    elif machine_val == 0x8664:
        return "x86_64"
    return "Unknown"


def analyse_pe(file_path: Path, profile: str, progress: ProgressFn) -> Dict[str, Any]:
    """Blocking PE pipeline (pefile, byte scans, YARA, ML). Run it in a worker thread."""
    progress(10, "Parsing PE headers")
    try:
        pe = pefile.PE(str(file_path))
    except Exception as e:
        raise ValueError(f"Invalid PE file: {e}") from e

    try:
        pe_meta = PEMetadata(
            arch=_get_machine_type(pe),
            entry_point=getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0),
            image_base=getattr(pe.OPTIONAL_HEADER, "ImageBase", 0),
            section_count=pe.FILE_HEADER.NumberOfSections,
        )

        progress(30, "Computing section entropy")
        entropy_results = section_entropies(pe)

        progress(45, "Running structural heuristics")
        size_flags = size_delta_flags(entropy_results)
        name_flags = section_name_flags(entropy_results)
        rwx_flags = rwx_section_flags(pe)
        ep_flags = entry_point_flags(pe)
        overlay_flag = overlay_flags(pe)
        header_flags = pe_header_anomaly_flags(pe)
        count_flag = section_count_flag(pe)

        progress(60, "Scanning for anti-debug & evasion")
        import_hits = scan_imports(pe)
        iat_flags = iat_density_flags(pe)
        tls_flags = scan_tls_callbacks(pe)
        syscall_flags = scan_direct_syscalls(pe)

        progress(75, "Extracting and analyzing strings")
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        string_hits = scan_strings(raw_bytes)
        opcode_flags = scan_opcodes(pe)
    finally:
        pe.close()

    progress(85, "Scoring, YARA and ML inference")
    verdict_info = compute_verdict(
        entropy_results=entropy_results,
        size_flags=size_flags,
        name_flags=name_flags,
        count_flag=count_flag,
        rwx_flags=rwx_flags,
        ep_flags=ep_flags,
        overlay_flag=overlay_flag,
        import_hits=import_hits,
        iat_flags=iat_flags,
        string_hits=string_hits,
        tls_flags=tls_flags,
        opcode_flags=opcode_flags,
        header_flags=header_flags,
        syscall_flags=syscall_flags,
        profile=profile,
    )

    yara_matches = scan_file_with_yara(file_path)

    ml_pred = None
    model = get_model()
    if model is not None:
        temp_report = generate_dict_report(
            file_path=str(file_path),
            pe_info=pe_meta.model_dump(),
            entropy_results=entropy_results,
            size_flags=size_flags,
            name_flags=name_flags,
            rwx_flags=rwx_flags,
            ep_flags=ep_flags,
            overlay_flag=overlay_flag,
            import_hits=import_hits,
            iat_flags=iat_flags,
            string_hits=string_hits,
            tls_flags=tls_flags,
            opcode_flags=opcode_flags,
            verdict_info=verdict_info,
            header_flags=header_flags,
            syscall_flags=syscall_flags,
        )
        ml_pred = MLPrediction(**predict_sample(model, extract_feature_dict(temp_report)))

    progress(95, "Finalising report")
    return {
        "pe_info": pe_meta.model_dump(),
        "yara_matches": yara_matches,
        "sections": [SectionInfo(**s).model_dump() for s in entropy_results],
        "heuristics": HeuristicsResult(
            size_deltas=size_flags,
            packer_section_names=name_flags,
            rwx_sections=rwx_flags,
            entry_point_anomalies=ep_flags,
            overlay=overlay_flag,
            iat_density=iat_flags,
            header_anomalies=header_flags,
            section_count_flag=count_flag,
        ).model_dump(),
        "anti_analysis": AntiAnalysisResult(
            imports=import_hits,
            strings=string_hits,
            tls_callbacks=tls_flags,
            opcodes=opcode_flags,
            direct_syscalls=syscall_flags,
        ).model_dump(),
        "verdict": VerdictResult(**verdict_info).model_dump(),
        "ml_prediction": ml_pred.model_dump() if ml_pred else None,
    }


async def audit_pe_file(job_id: str, file_path: Path, file_size: int, profile: str = DEFAULT_PROFILE) -> Dict[str, Any]:
    """Run the PE pipeline off the event loop, streaming progress back to the job's SSE subscribers."""
    loop = asyncio.get_running_loop()

    def progress(pct: int, message: str) -> None:
        loop.call_soon_threadsafe(job_manager.publish_progress, job_id, "RUNNING", pct, message)

    return await asyncio.to_thread(analyse_pe, file_path, profile, progress)
