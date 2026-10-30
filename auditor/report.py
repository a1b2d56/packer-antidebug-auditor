"""Rich-formatted terminal reporting and structured JSON output for PE audit results."""

from __future__ import annotations

import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

VERDICT_COLORS = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
}


def format_characteristics(section) -> str:
    """Format human-readable permission flags (e.g., RWX, R-X, RW-)."""
    chars = getattr(section, "Characteristics", 0) if not isinstance(section, dict) else section.get("characteristics", 0)
    r = "R" if chars & 0x40000000 else "-"
    w = "W" if chars & 0x80000000 else "-"
    x = "X" if chars & 0x20000000 else "-"
    return f"{r}{w}{x}"


CSV_FEATURE_COLUMNS = [
    "file_path",
    "arch",
    "section_count",
    "max_entropy",
    "mean_entropy",
    "high_entropy_sections",
    "rwx_sections_count",
    "size_delta_flags_count",
    "packer_section_flags_count",
    "overlay_present",
    "overlay_entropy",
    "anti_debug_import_count",
    "sparse_iat_flag",
    "suspicious_strings_count",
    "tls_callbacks_present",
    "opcode_checks_count",
    "direct_syscall_count",
    "header_anomaly_count",
    "risk_score",
    "verdict",
]


def extract_feature_dict(report: dict) -> dict:
    """Extract a compact, normalized numerical/categorical feature vector from an audit report.

    Enables training machine learning classifiers (RandomForest, XGBoost, etc.) directly on
    extracted PE security indicators without needing to load or process gigabytes of raw binaries.
    """
    sections = report.get("sections", [])
    entropies = [s.get("entropy", 0.0) for s in sections]
    max_ent = max(entropies) if entropies else 0.0
    mean_ent = round(sum(entropies) / len(entropies), 3) if entropies else 0.0
    high_ent_cnt = sum(1 for s in sections if s.get("likely_packed"))

    heur = report.get("heuristics", {})
    anti = report.get("anti_analysis", {})
    overlay = heur.get("overlay") or {}
    meta = report.get("metadata", {})
    verdict = report.get("verdict", {})

    return {
        "file_path": report.get("file_path", ""),
        "arch": meta.get("arch", "Unknown"),
        "section_count": meta.get("section_count", len(sections)),
        "max_entropy": round(max_ent, 3),
        "mean_entropy": mean_ent,
        "high_entropy_sections": high_ent_cnt,
        "rwx_sections_count": len(heur.get("rwx_sections", [])),
        "size_delta_flags_count": len(heur.get("size_deltas", [])),
        "packer_section_flags_count": len(heur.get("packer_section_names", [])),
        "overlay_present": int(bool(overlay.get("size"))),
        "overlay_entropy": overlay.get("entropy", 0.0),
        "anti_debug_import_count": len(anti.get("imports", [])),
        "sparse_iat_flag": int(bool(heur.get("iat_density", []))),
        "suspicious_strings_count": len(anti.get("strings", [])),
        "tls_callbacks_present": int(bool(anti.get("tls_callbacks", []))),
        "opcode_checks_count": len(anti.get("opcodes", [])),
        "direct_syscall_count": len(anti.get("direct_syscalls", [])),
        "header_anomaly_count": len(heur.get("header_anomalies", [])),
        "risk_score": verdict.get("score", 0),
        "verdict": verdict.get("verdict", "LOW"),
    }


def generate_dict_report(
    file_path: str,
    pe_info: dict,
    entropy_results: list[dict],
    size_flags: list[dict],
    name_flags: list[dict],
    rwx_flags: list[dict],
    ep_flags: list[dict],
    overlay_flag: dict | None,
    import_hits: list[dict],
    iat_flags: list[dict],
    string_hits: list[dict],
    tls_flags: list[dict],
    opcode_flags: list[dict],
    verdict_info: dict,
    header_flags: list[dict] | None = None,
    syscall_flags: list[dict] | None = None,
    ml_prediction: dict | None = None,
) -> dict:
    """Construct a clean, serializable dictionary of the complete audit results."""
    header_flags = header_flags or []
    syscall_flags = syscall_flags or []
    report = {
        "file_path": file_path,
        "metadata": pe_info,
        "sections": entropy_results,
        "heuristics": {
            "size_deltas": size_flags,
            "packer_section_names": name_flags,
            "rwx_sections": rwx_flags,
            "entry_point_anomalies": ep_flags,
            "overlay": overlay_flag,
            "iat_density": iat_flags,
            "header_anomalies": header_flags,
        },
        "anti_analysis": {
            "imports": import_hits,
            "strings": string_hits,
            "tls_callbacks": tls_flags,
            "opcodes": opcode_flags,
            "direct_syscalls": syscall_flags,
        },
        "verdict": verdict_info,
    }
    if ml_prediction is not None:
        report["ml_prediction"] = ml_prediction
    return report


def print_report(
    file_path: str,
    pe_info: dict,
    entropy_results: list[dict],
    size_flags: list[dict],
    name_flags: list[dict],
    rwx_flags: list[dict],
    ep_flags: list[dict],
    overlay_flag: dict | None,
    import_hits: list[dict],
    iat_flags: list[dict],
    string_hits: list[dict],
    tls_flags: list[dict],
    opcode_flags: list[dict],
    verdict_info: dict,
    header_flags: list[dict] | None = None,
    syscall_flags: list[dict] | None = None,
    ml_prediction: dict | None = None,
) -> None:
    """Render a comprehensive audit report to the terminal using rich formatting."""
    header_flags = header_flags or []
    syscall_flags = syscall_flags or []

    meta_line = (
        f"Arch: [cyan]{pe_info.get('arch', 'Unknown')}[/cyan] | "
        f"Entry Point: [cyan]0x{pe_info.get('entry_point', 0):X}[/cyan] | "
        f"Sections: [cyan]{pe_info.get('section_count', 0)}[/cyan]"
    )
    console.print(Panel(
        f"[bold]Packer & Anti-Debug Audit[/bold]\n[dim]{file_path}[/dim]\n{meta_line}",
        border_style="blue",
    ))

    # Section Table
    table = Table(title="Section Analysis", title_style="bold", show_header=True, header_style="bold cyan")
    table.add_column("Section", style="bold")
    table.add_column("Entropy", justify="right")
    table.add_column("Raw Size", justify="right")
    table.add_column("Virtual Size", justify="right")
    table.add_column("Perms", justify="center")
    table.add_column("Status")

    for section in entropy_results:
        flags = []
        if section["likely_packed"]:
            flags.append("[red]HIGH ENTROPY[/red]")
        chars_str = format_characteristics(section)
        if "W" in chars_str and "X" in chars_str:
            flags.append("[bold red]RWX[/bold red]")

        status_str = ", ".join(flags) if flags else "[green]OK[/green]"
        table.add_row(
            section["name"],
            f"{section['entropy']:.3f}",
            str(section["raw_size"]),
            str(section["virtual_size"]),
            f"[yellow]{chars_str}[/yellow]" if "W" in chars_str and "X" in chars_str else chars_str,
            status_str,
        )
    console.print(table)

    # Packer & Structure Heuristics
    heuristic_items = []
    for f in rwx_flags:
        heuristic_items.append(f"[red]W^X Section[/red] '{f['name']}': {f['reason']}")
    for f in size_flags:
        heuristic_items.append(f"[yellow]Size Delta[/yellow] '{f['name']}': {f['reason']}")
    for f in name_flags:
        heuristic_items.append(f"[yellow]Known Section[/yellow] '{f['name']}': {f['reason']}")
    for f in ep_flags:
        heuristic_items.append(f"[yellow]Entry Point[/yellow]: {f['reason']}")
    if overlay_flag:
        heuristic_items.append(f"[yellow]Overlay[/yellow]: {overlay_flag['reason']}")
    for f in iat_flags:
        heuristic_items.append(f"[yellow]IAT Anomaly[/yellow]: {f['reason']}")
    for hf in header_flags:
        heuristic_items.append(f"[yellow]Header Anomaly[/yellow]: {hf['reason']}")

    if heuristic_items:
        console.print("\n[bold]Packer & Structural Heuristics[/bold]")
        for item in heuristic_items:
            console.print(f"  - {item}")

    # Anti-Debug & Anti-Analysis Checks
    anti_items = []
    for sf in syscall_flags:
        label = sf.get("technique", "Direct Syscall")
        anti_items.append(f"[bold red]{label}[/bold red]: {sf['reason']}")
    for hit in import_hits:
        anti_items.append(f"[cyan]API Import[/cyan] [bold]{hit['api']}[/bold]: {hit['reason']}")
    for tf in tls_flags:
        anti_items.append(f"[magenta]TLS Callback[/magenta]: {tf['reason']}")
    for hit in string_hits:
        anti_items.append(f"[cyan]String Artifact[/cyan] [dim]({hit['category']})[/dim] '{hit['string']}'")
    for op in opcode_flags:
        anti_items.append(f"[magenta]Opcode Check[/magenta]: {op['reason']}")

    if anti_items:
        console.print("\n[bold]Anti-Analysis & Evasion Indicators[/bold]")
        for item in anti_items:
            console.print(f"  - {item}")

    # Final Verdict Panel
    verdict = verdict_info["verdict"]
    color = VERDICT_COLORS.get(verdict, "white")
    reasons_text = "\n".join(f"  - {r}" for r in verdict_info["reasons"]) or "  - No suspicious indicators flagged"

    ml_line = ""
    if ml_prediction:
        ml_lbl = ml_prediction.get("label", "UNKNOWN")
        ml_prob = ml_prediction.get("probability", 0.0) * 100
        ml_col = "red" if ml_lbl == "PACKED" else "green"
        ml_line = f"\n[bold]ML Classifier Model:[/bold] [{ml_col}]{ml_lbl}[/{ml_col}] (Packed Probability: {ml_prob:.1f}%)"

    calib_line = ""
    if "confidence" in verdict_info:
        lo, hi = verdict_info.get("score_interval", [verdict_info["score"]] * 2)
        calib_line = (
            f"\n[bold]Profile:[/bold] {verdict_info.get('profile', 'balanced')} | "
            f"[bold]Heuristic Confidence:[/bold] {verdict_info['confidence'] * 100:.0f}% | "
            f"[bold]Score Interval:[/bold] [{lo}, {hi}]"
        )

    verdict_body = (
        f"[bold {color}]{verdict}[/bold {color}]  [dim](Risk Score: {verdict_info['score']})[/dim]{ml_line}{calib_line}\n\n"
        f"[bold]Contributing Factors:[/bold]\n{reasons_text}"
    )

    console.print()
    console.print(Panel(verdict_body, title="Audit Verdict", border_style=color))


def print_batch_summary(results: list[dict]) -> None:
    """Print a summary table when auditing a batch/directory of PE files."""
    has_ml = any("ml_prediction" in item for item in results)

    table = Table(title="Batch Audit Summary", title_style="bold", show_header=True, header_style="bold cyan")
    table.add_column("File", style="bold")
    table.add_column("Verdict", justify="center")
    if has_ml:
        table.add_column("ML Model", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Sections", justify="right")
    table.add_column("Key Signals")

    for item in results:
        v = item["verdict"]["verdict"]
        color = VERDICT_COLORS.get(v, "white")
        reasons = item["verdict"].get("reasons", [])
        summary_reasons = "; ".join(reasons[:2]) if reasons else "Clean"
        if len(reasons) > 2:
            summary_reasons += f" (+{len(reasons) - 2} more)"

        row = [
            item["file_path"],
            f"[{color}]{v}[/{color}]",
        ]
        if has_ml:
            ml_pred = item.get("ml_prediction")
            if ml_pred:
                ml_lbl = ml_pred.get("label", "N/A")
                ml_col = "red" if ml_lbl == "PACKED" else "green"
                row.append(f"[{ml_col}]{ml_lbl} ({ml_pred.get('probability', 0)*100:.0f}%)[/{ml_col}]")
            else:
                row.append("[dim]N/A[/dim]")

        row.extend([
            str(item["verdict"]["score"]),
            str(item["metadata"].get("section_count", 0)),
            summary_reasons,
        ])
        table.add_row(*row)

    console.print()
    console.print(table)
