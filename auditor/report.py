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
) -> dict:
    """Construct a clean, serializable dictionary of the complete audit results."""
    return {
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
        },
        "anti_analysis": {
            "imports": import_hits,
            "strings": string_hits,
            "tls_callbacks": tls_flags,
            "opcodes": opcode_flags,
        },
        "verdict": verdict_info,
    }


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
) -> None:
    """Render a comprehensive audit report to the terminal using rich formatting."""
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

    if heuristic_items:
        console.print("\n[bold]Packer & Structural Heuristics[/bold]")
        for item in heuristic_items:
            console.print(f"  - {item}")

    # Anti-Debug & Anti-Analysis Checks
    anti_items = []
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

    verdict_body = (
        f"[bold {color}]{verdict}[/bold {color}]  [dim](Risk Score: {verdict_info['score']})[/dim]\n\n"
        f"[bold]Contributing Factors:[/bold]\n{reasons_text}"
    )

    console.print()
    console.print(Panel(verdict_body, title="Audit Verdict", border_style=color))


def print_batch_summary(results: list[dict]) -> None:
    """Print a summary table when auditing a batch/directory of PE files."""
    table = Table(title="Batch Audit Summary", title_style="bold", show_header=True, header_style="bold cyan")
    table.add_column("File", style="bold")
    table.add_column("Verdict", justify="center")
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

        table.add_row(
            item["file_path"],
            f"[{color}]{v}[/{color}]",
            str(item["verdict"]["score"]),
            str(item["metadata"].get("section_count", 0)),
            summary_reasons,
        )

    console.print()
    console.print(table)
