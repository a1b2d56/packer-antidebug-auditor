"""Command-line interface for the Packer & Anti-Debug Auditor."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import sys
from pathlib import Path

import pefile
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

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
from auditor.model import load_model, predict_sample
from auditor.report import (
    CSV_FEATURE_COLUMNS,
    extract_feature_dict,
    generate_dict_report,
    print_batch_summary,
    print_report,
)
from auditor.scoring import DEFAULT_PROFILE, PROFILES, compute_verdict

console = Console()

MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86_64 (64-bit)",
    0x0200: "Itanium",
    0xAA64: "ARM64",
}

VERDICT_RANKS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def extract_pe_metadata(pe: pefile.PE) -> dict:
    """Extract general architecture and header metadata from a PE object."""
    machine = getattr(pe.FILE_HEADER, "Machine", 0)
    arch = MACHINE_TYPES.get(machine, f"Unknown (0x{machine:X})")
    ep = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
    image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)

    return {
        "arch": arch,
        "entry_point": ep,
        "image_base": image_base,
        "section_count": len(pe.sections),
    }


def audit_pe_file(file_path: str, profile: str = DEFAULT_PROFILE) -> dict | None:
    """Run all heuristic, structural, anti-debug, and evasion checks against a single PE file."""
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as exc:
        print(f"[!] {file_path}: Invalid PE file ({exc})", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[!] {file_path}: Error reading file ({exc})", file=sys.stderr)
        return None

    try:
        with open(file_path, "rb") as handle:
            raw_bytes = handle.read()
    except Exception as exc:
        print(f"[!] {file_path}: Error reading raw bytes ({exc})", file=sys.stderr)
        return None

    pe_info = extract_pe_metadata(pe)
    entropy_results = section_entropies(pe)
    size_flags = size_delta_flags(entropy_results)
    name_flags = section_name_flags(entropy_results)
    count_flag = section_count_flag(pe)
    rwx_flags = rwx_section_flags(pe)
    ep_flags = entry_point_flags(pe)
    overlay_flag = overlay_flags(pe)
    header_flags = pe_header_anomaly_flags(pe)

    import_hits = scan_imports(pe)
    iat_flags = iat_density_flags(pe)
    string_hits = scan_strings(raw_bytes)
    tls_flags = scan_tls_callbacks(pe)
    opcode_flags = scan_opcodes(pe)
    syscall_flags = scan_direct_syscalls(pe)

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

    return {
        "file_path": file_path,
        "pe_info": pe_info,
        "entropy_results": entropy_results,
        "size_flags": size_flags,
        "name_flags": name_flags,
        "rwx_flags": rwx_flags,
        "ep_flags": ep_flags,
        "overlay_flag": overlay_flag,
        "header_flags": header_flags,
        "import_hits": import_hits,
        "iat_flags": iat_flags,
        "string_hits": string_hits,
        "tls_flags": tls_flags,
        "opcode_flags": opcode_flags,
        "syscall_flags": syscall_flags,
        "verdict_info": verdict_info,
    }


_GLOBAL_MODEL = None


def init_worker(model_path: str | None) -> None:
    """Worker process initializer to load model once per process."""
    global _GLOBAL_MODEL
    if model_path and os.path.exists(model_path):
        try:
            _GLOBAL_MODEL = load_model(model_path)
        except Exception as exc:
            print(f"[!] Warning: Failed to load model {model_path} ({exc})", file=sys.stderr)
            _GLOBAL_MODEL = None


def audit_pe_worker(file_path: str, profile: str = DEFAULT_PROFILE) -> tuple[dict, dict] | None:
    """Worker task wrapper for multiprocessing that returns both raw analysis and dict report."""
    audit_res = audit_pe_file(file_path, profile=profile)
    if audit_res is None:
        return None

    ml_pred = None
    if _GLOBAL_MODEL is not None:
        try:
            temp_dict = {
                "file_path": audit_res["file_path"],
                "metadata": audit_res["pe_info"],
                "sections": audit_res["entropy_results"],
                "heuristics": {
                    "size_deltas": audit_res["size_flags"],
                    "packer_section_names": audit_res["name_flags"],
                    "rwx_sections": audit_res["rwx_flags"],
                    "overlay": audit_res["overlay_flag"],
                    "iat_density": audit_res["iat_flags"],
                    "header_anomalies": audit_res["header_flags"],
                },
                "anti_analysis": {
                    "imports": audit_res["import_hits"],
                    "strings": audit_res["string_hits"],
                    "tls_callbacks": audit_res["tls_flags"],
                    "opcodes": audit_res["opcode_flags"],
                    "direct_syscalls": audit_res["syscall_flags"],
                },
                "verdict": audit_res["verdict_info"],
            }
            ml_pred = predict_sample(_GLOBAL_MODEL, extract_feature_dict(temp_dict))
        except Exception:
            ml_pred = None

    report_dict = generate_dict_report(
        file_path=audit_res["file_path"],
        pe_info=audit_res["pe_info"],
        entropy_results=audit_res["entropy_results"],
        size_flags=audit_res["size_flags"],
        name_flags=audit_res["name_flags"],
        rwx_flags=audit_res["rwx_flags"],
        ep_flags=audit_res["ep_flags"],
        overlay_flag=audit_res["overlay_flag"],
        import_hits=audit_res["import_hits"],
        iat_flags=audit_res["iat_flags"],
        string_hits=audit_res["string_hits"],
        tls_flags=audit_res["tls_flags"],
        opcode_flags=audit_res["opcode_flags"],
        verdict_info=audit_res["verdict_info"],
        header_flags=audit_res["header_flags"],
        syscall_flags=audit_res["syscall_flags"],
        ml_prediction=ml_pred,
    )
    return audit_res, report_dict


def find_target_files(target_paths: list[str] | str, recursive: bool = False) -> list[str]:
    """Resolve single file, directory, or list of target paths to a list of target file paths."""
    if isinstance(target_paths, str):
        target_paths = [target_paths]

    patterns = ("*.exe", "*.dll", "*.sys", "*.ocx", "*.bin")
    files = []

    for target in target_paths:
        path = Path(target)
        if path.is_file():
            files.append(str(path))
        elif path.is_dir():
            for pat in patterns:
                if recursive:
                    files.extend(str(p) for p in path.rglob(pat))
                else:
                    files.extend(str(p) for p in path.glob(pat))

    return sorted(set(files))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="packer-audit",
        description="High-Throughput Static PE Packer & Anti-Debug Auditor for Windows binaries.",
    )
    parser.add_argument(
        "target",
        nargs="+",
        help="Path to one or more PE binaries (.exe/.dll) or directories.",
    )
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories.")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="Number of parallel worker processes (default: all CPU cores).",
    )
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Stream results in Line-Delimited JSON (JSONL) format, ideal for large databases.",
    )
    parser.add_argument(
        "--csv",
        help="Export compact ML-ready feature vectors to the specified CSV file for lightweight training.",
    )
    parser.add_argument(
        "--model",
        nargs="?",
        const="models/packer_model.joblib",
        help="Path to trained machine learning model (default: models/packer_model.joblib if flag present).",
    )
    parser.add_argument("-o", "--output", help="Write report output to specified file.")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=DEFAULT_PROFILE,
        help="Scoring sensitivity profile (default: balanced = original thresholds 3/7).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH"],
        help="Exit with non-zero code (2) if any binary matches or exceeds this verdict threshold.",
    )

    args = parser.parse_args()

    target_files = find_target_files(args.target, recursive=args.recursive)
    if not target_files:
        print(f"Error: No target files found at '{args.target}'", file=sys.stderr)
        sys.exit(1)

    max_workers = args.jobs if args.jobs and args.jobs > 0 else (os.cpu_count() or 4)

    # Initialize model in main process
    model_path = args.model
    init_worker(model_path)

    # Prepare streaming handles if requested
    csv_file = None
    csv_writer = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FEATURE_COLUMNS)
        csv_writer.writeheader()

    jsonl_file = None
    if args.jsonl:
        if args.output:
            jsonl_file = open(args.output, "w", encoding="utf-8")
        else:
            jsonl_file = sys.stdout

    all_reports = []
    highest_verdict_rank = 0
    verdict_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    try:
        # If single file, run synchronously without multiprocessing overhead
        if len(target_files) == 1:
            res = audit_pe_worker(target_files[0], args.profile)
            if res:
                all_reports.append(res)
                v = res[0]["verdict_info"]["verdict"]
                verdict_counts[v] = verdict_counts.get(v, 0) + 1
                v_rank = VERDICT_RANKS.get(v, 0)
                if v_rank > highest_verdict_rank:
                    highest_verdict_rank = v_rank

                if csv_writer:
                    csv_writer.writerow(extract_feature_dict(res[1]))
                    csv_file.flush()
                if args.jsonl:
                    jsonl_file.write(json.dumps(res[1]) + "\n")
                    jsonl_file.flush()
        else:
            # Multi-file batch scan: Use ProcessPoolExecutor with Rich Progress
            is_interactive = sys.stdout.isatty() and not (args.jsonl and not args.output)

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=Console(stderr=True) if not is_interactive else console,
                disable=not is_interactive,
            ) as progress:
                task_id = progress.add_task(f"Auditing PE files ({max_workers} workers)...", total=len(target_files))

                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=max_workers,
                    initializer=init_worker,
                    initargs=(model_path,),
                ) as executor:
                    futures = {executor.submit(audit_pe_worker, f, args.profile): f for f in target_files}

                    for future in concurrent.futures.as_completed(futures):
                        progress.advance(task_id)
                        try:
                            item = future.result()
                        except Exception as exc:
                            f_path = futures[future]
                            print(f"[!] {f_path}: Worker exception ({exc})", file=sys.stderr)
                            item = None

                        if item is None:
                            continue

                        audit_res, report_dict = item
                        v = audit_res["verdict_info"]["verdict"]
                        verdict_counts[v] = verdict_counts.get(v, 0) + 1
                        v_rank = VERDICT_RANKS.get(v, 0)
                        if v_rank > highest_verdict_rank:
                            highest_verdict_rank = v_rank

                        # Stream CSV row if requested
                        if csv_writer:
                            csv_writer.writerow(extract_feature_dict(report_dict))
                            csv_file.flush()

                        # Stream JSONL if requested
                        if args.jsonl:
                            jsonl_file.write(json.dumps(report_dict) + "\n")
                            jsonl_file.flush()

                        # Only buffer in memory if we need to print JSON or summary
                        if not args.jsonl or args.json:
                            all_reports.append((audit_res, report_dict))

                        # Update progress description with live stats
                        if is_interactive:
                            progress.update(
                                task_id,
                                description=(
                                    f"[bold cyan]Auditing[/bold cyan] "
                                    f"[green]L:{verdict_counts['LOW']}[/green] "
                                    f"[yellow]M:{verdict_counts['MEDIUM']}[/yellow] "
                                    f"[red]H:{verdict_counts['HIGH']}[/red]"
                                ),
                            )
    finally:
        if csv_file:
            csv_file.close()
        if args.jsonl and args.output and jsonl_file:
            jsonl_file.close()

    if not all_reports and not args.jsonl and not args.csv:
        print("No valid PE binaries could be audited.", file=sys.stderr)
        sys.exit(1)

    # Standard JSON Output Formatting
    if args.json:
        payload = [r[1] for r in all_reports] if len(all_reports) > 1 else (all_reports[0][1] if all_reports else [])
        json_text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_text)
        else:
            print(json_text)
    elif not args.jsonl:
        # Terminal Reporting
        if len(all_reports) == 1:
            audit_res = all_reports[0][0]
            rep_dict = all_reports[0][1]
            print_report(
                file_path=audit_res["file_path"],
                pe_info=audit_res["pe_info"],
                entropy_results=audit_res["entropy_results"],
                size_flags=audit_res["size_flags"],
                name_flags=audit_res["name_flags"],
                rwx_flags=audit_res["rwx_flags"],
                ep_flags=audit_res["ep_flags"],
                overlay_flag=audit_res["overlay_flag"],
                import_hits=audit_res["import_hits"],
                iat_flags=audit_res["iat_flags"],
                string_hits=audit_res["string_hits"],
                tls_flags=audit_res["tls_flags"],
                opcode_flags=audit_res["opcode_flags"],
                verdict_info=audit_res["verdict_info"],
                header_flags=audit_res["header_flags"],
                syscall_flags=audit_res["syscall_flags"],
                ml_prediction=rep_dict.get("ml_prediction"),
            )
        elif all_reports:
            # Batch summary
            dict_list = [r[1] for r in all_reports]
            print_batch_summary(dict_list)

    # Quality Gate Threshold Check
    if args.fail_on:
        threshold_rank = VERDICT_RANKS[args.fail_on]
        if highest_verdict_rank >= threshold_rank:
            sys.exit(2)


if __name__ == "__main__":
    main()
