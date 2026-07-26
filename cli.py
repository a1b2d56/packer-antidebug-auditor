"""Command-line interface for the Packer & Anti-Debug Auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import pefile

from auditor.antidebug import (
    iat_density_flags,
    scan_imports,
    scan_opcodes,
    scan_strings,
    scan_tls_callbacks,
)
from auditor.entropy import section_entropies
from auditor.heuristics import (
    entry_point_flags,
    overlay_flags,
    rwx_section_flags,
    section_count_flag,
    section_name_flags,
    size_delta_flags,
)
from auditor.report import (
    generate_dict_report,
    print_batch_summary,
    print_report,
)
from auditor.scoring import compute_verdict

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


def audit_pe_file(file_path: str) -> dict | None:
    """Run all heuristic and anti-debug checks against a single PE file."""
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

    import_hits = scan_imports(pe)
    iat_flags = iat_density_flags(pe)
    string_hits = scan_strings(raw_bytes)
    tls_flags = scan_tls_callbacks(pe)
    opcode_flags = scan_opcodes(pe)

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
        "import_hits": import_hits,
        "iat_flags": iat_flags,
        "string_hits": string_hits,
        "tls_flags": tls_flags,
        "opcode_flags": opcode_flags,
        "verdict_info": verdict_info,
    }


def find_target_files(target_path: str, recursive: bool = False) -> list[str]:
    """Resolve single file or directory to a list of target file paths."""
    path = Path(target_path)
    if path.is_file():
        return [str(path)]

    if path.is_dir():
        patterns = ("*.exe", "*.dll", "*.sys", "*.ocx", "*.bin")
        files = []
        for pat in patterns:
            if recursive:
                files.extend(str(p) for p in path.rglob(pat))
            else:
                files.extend(str(p) for p in path.glob(pat))
        return sorted(set(files))

    return []


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="packer-audit",
        description="Static PE Packer and Anti-Debug Audit Tool for Windows binaries.",
    )
    parser.add_argument("target", help="Path to a PE binary (.exe/.dll) or a directory of binaries.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("-o", "--output", help="Write report output to specified file.")
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

    all_reports = []
    highest_verdict_rank = 0

    for file_path in target_files:
        audit_res = audit_pe_file(file_path)
        if audit_res is None:
            continue

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
        )
        all_reports.append((audit_res, report_dict))

        v_rank = VERDICT_RANKS.get(audit_res["verdict_info"]["verdict"], 0)
        if v_rank > highest_verdict_rank:
            highest_verdict_rank = v_rank

    if not all_reports:
        print("No valid PE binaries could be audited.", file=sys.stderr)
        sys.exit(1)

    # Output Formatting
    if args.json:
        payload = [r[1] for r in all_reports] if len(all_reports) > 1 else all_reports[0][1]
        json_text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_text)
        else:
            print(json_text)
    else:
        # If single file, print full detailed rich report
        if len(all_reports) == 1:
            audit_res = all_reports[0][0]
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
            )
        else:
            # Batch summary
            dict_list = [r[1] for r in all_reports]
            print_batch_summary(dict_list)

    # Threshold exit code check
    if args.fail_on:
        threshold_rank = VERDICT_RANKS[args.fail_on]
        if highest_verdict_rank >= threshold_rank:
            sys.exit(2)


if __name__ == "__main__":
    main()
