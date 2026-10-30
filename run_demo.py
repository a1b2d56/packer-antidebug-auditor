"""
Packer & Anti-Debug Auditor - End-to-End Demonstration Script
Executes system checks, model training, heuristic audits, and batch triage.
"""

import sys
import os
import time
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

console = Console()
AUTO_MODE = "--auto" in sys.argv

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def prompt_step(step_idx, total_steps, title, command_preview):
    console.print()
    step_text = Text()
    step_text.append(f"[{step_idx}/{total_steps}] ", style="bold cyan")
    step_text.append(f"{title}\n", style="bold white")
    step_text.append(f"Command: {command_preview}", style="dim cyan")
    
    console.print(Panel(step_text, box=box.ROUNDED, border_style="blue"))
    if AUTO_MODE:
        time.sleep(1.0)
    else:
        try:
            console.print("[dim]Press [ENTER] to run (or 'q' to quit)...[/dim]", end=" ")
            user_input = input().strip().lower()
            if user_input == 'q':
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
    console.print()

def run_cmd(cmd_list):
    start = time.perf_counter()
    res = subprocess.run(cmd_list)
    elapsed = (time.perf_counter() - start) * 1000
    console.print(f"\n[dim green]Finished in {elapsed:.1f} ms (exit code {res.returncode})[/dim green]\n")
    return res.returncode

def main():
    clear_screen()
    
    banner = Text()
    banner.append("Packer & Anti-Debug Auditor — Verification & Demo Suite\n", style="bold cyan")
    banner.append("Running unit tests, model pipeline, heuristics, and batch benchmarks.", style="dim")
    console.print(Panel(banner, box=box.ROUNDED, border_style="cyan"))

    total_steps = 7

    # Step 1: Unit tests
    prompt_step(1, total_steps, "Unit Test Suite", "python -m unittest discover tests -v")
    run_cmd([sys.executable, "-m", "unittest", "discover", "tests", "-v"])

    # Step 2: Train model
    prompt_step(2, total_steps, "Train Random Forest Classifier", "python scripts/train_model.py")
    run_cmd([sys.executable, "scripts/train_model.py"])

    # Step 3: Heuristic scan
    prompt_step(3, total_steps, "Heuristic Scan on Packed Binary", "python cli.py samples/synthetic_packed.exe")
    run_cmd([sys.executable, "cli.py", "samples/synthetic_packed.exe"])

    # Step 4: ML inference
    prompt_step(4, total_steps, "Dual-Engine Scan (Heuristics + ML Model)", "python cli.py samples/synthetic_packed.exe --model models/packer_model.joblib")
    run_cmd([sys.executable, "cli.py", "samples/synthetic_packed.exe", "--model", "models/packer_model.joblib"])

    # Step 5: Clean binary baseline
    prompt_step(5, total_steps, "Clean System Binary Scan", "python cli.py C:\\Windows\\System32\\notepad.exe --model models/packer_model.joblib")
    run_cmd([sys.executable, "cli.py", r"C:\Windows\System32\notepad.exe", "--model", "models/packer_model.joblib"])

    # Step 6: Batch scan
    prompt_step(6, total_steps, "Batch Multiprocessing Scan (-j 4)", "python cli.py notepad.exe cmd.exe synthetic_packed.exe -j 4")
    run_cmd([
        sys.executable, "cli.py",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\cmd.exe",
        "samples/synthetic_packed.exe",
        "-j", "4"
    ])

    # Step 7: Export telemetry
    prompt_step(7, total_steps, "Telemetry Export (CSV & JSONL)", "python cli.py ... --csv audit_report.csv --jsonl -o audit_stream.jsonl")
    csv_path = "audit_report.csv"
    jsonl_path = "audit_stream.jsonl"
    run_cmd([
        sys.executable, "cli.py",
        "samples/synthetic_packed.exe",
        r"C:\Windows\System32\notepad.exe",
        "--csv", csv_path,
        "--jsonl", "-o", jsonl_path
    ])

    if os.path.exists(csv_path):
        console.print(f"[bold cyan]Generated CSV Preview ({csv_path}):[/bold cyan]")
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                table = Table(box=box.SIMPLE)
                headers = lines[0].strip().split(',')[:8]
                for h in headers:
                    table.add_column(h, style="cyan")
                for row_line in lines[1:4]:
                    row_vals = row_line.strip().split(',')[:8]
                    table.add_row(*row_vals)
                console.print(table)
        except Exception:
            pass

    console.print("\n[bold green]All demo steps completed.[/bold green]\n")
    if not AUTO_MODE:
        console.print("[dim]Press [ENTER] to exit.[/dim]")
        try:
            input()
        except Exception:
            pass

if __name__ == '__main__':
    main()
