# Packer & Anti-Debug Auditor

A static analysis tool that flags Windows Portable Executable (`.exe` / `.dll` / `.sys`) files exhibiting packer, protector, and anti-debugging characteristics — with zero execution or sandboxing required.

---

## What It Checks

### 1. Packing & Structural Indicators
- **Shannon Entropy Per Section**: Measures information density in bits/byte ($0.0 - 8.0$). Sections $> 7.0$ typically denote compressed or encrypted code/payloads.
- **Section Permissions & W^X Violations**: Detects sections that are simultaneously **Writable and Executable** (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`), a hallmark of self-modifying unpacker stubs.
- **Virtual vs. Raw Size Discrepancy**: Identifies sections with zero raw data or abnormal expansion ratios where packed data unpacks into memory.
- **Entry Point Placement Anomalies**: Flags when `AddressOfEntryPoint` points to a writable section, the last section, or outside valid mapped sections.
- **Known Packer Section Signatures**: Matches sections associated with UPX, ASPack, VMProtect, Themida/WinLicense, Enigma, MPRESS, Petite, FSG, MEW, and others.
- **Overlay & Appended Data**: Detects and computes entropy on extra data appended past the final PE section.
- **Import Table (IAT) Density**: Flags sparse IATs (e.g. $\le 4$ imports) or binaries that import only dynamic runtime loaders (`LoadLibrary*` + `GetProcAddress`).
- **Abnormal Section Counts**: Flags binaries with $\le 3$ sections where code and data have been merged.

### 2. Anti-Analysis & Anti-Debugging Indicators
- **Categorized Anti-Debug API Imports**:
  - *PEB & Kernel Flags*: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `ZwQueryInformationProcess`, `NtSetInformationThread` (`ThreadHideFromDebugger`), `NtQuerySystemInformation`, `NtQueryObject`.
  - *Hardware Breakpoints*: `GetThreadContext`, `SetThreadContext`, `NtGetContextThread`, `NtSetContextThread`.
  - *Exception & SEH/VEH Traps*: `SetUnhandledExceptionFilter`, `AddVectoredExceptionHandler`, `RemoveVectoredExceptionHandler`, `NtClose` (invalid handle tricks).
  - *Timing Evasion*: `QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64`, `timeGetTime`.
  - *Tool & Window Discovery*: `CreateToolhelp32Snapshot`, `Process32First/Next`, `FindWindow*`, `EnumWindows`.
- **Dual-Encoding String Signatures (ASCII + UTF-16LE)**: Scans for debugger artifacts (`x64dbg`, `x32dbg`, `IDA Pro`, `Ghidra`, `OLLYDBG`, `WinDbg`, `Cheat Engine`, `Process Hacker`, `ScyllaHide`) and VM/sandbox artifacts (`VMware`, `VirtualBox`, `QEMU`, `KVM`, `Sandboxie`, `Cuckoo`, `Wine`, `HARDWARE\Description\System\BIOS`).
- **Thread Local Storage (TLS) Callbacks**: Flags TLS callback routines that execute before `AddressOfEntryPoint` is reached.
- **Anti-Disassembly & Timing Opcode Sequences**: Scans executable code sections for inline `RDTSC` (`0x0F 0x31`), `INT 2Dh` (`0xCD 0x2D`), and `ICEBP` (`0xF1`).

---

## Installation

```bash
# Clone and install dependencies
git clone https://github.com/yourusername/packer-antidebug-auditor.git
cd packer-antidebug-auditor
pip install -r requirements.txt

# (Optional) Install as a system command:
pip install -e .
```

---

## Usage

### 1. Audit a Single File
```bash
python cli.py path/to/sample.exe
# Or if installed with pip:
packer-audit path/to/sample.exe
```

### 2. Audit an Entire Directory (Batch Mode)
Scan a directory of binaries and display a batch summary table:
```bash
python cli.py ./samples/ --recursive
```

### 3. JSON Output for Automation & Pipelines
Output structured JSON to stdout or save directly to a file:
```bash
python cli.py sample.exe --json
python cli.py sample.exe --json -o report.json
```

### 4. CI/CD Quality Gate (`--fail-on`)
Exit with returncode `2` if a binary triggers a specific verdict threshold (`LOW`, `MEDIUM`, or `HIGH`):
```bash
python cli.py sample.exe --fail-on HIGH
```

---

## Project Structure

```
packer-antidebug-auditor/
├── cli.py                  # CLI argument parser and batch orchestration
├── pyproject.toml          # Packaging metadata and CLI script definitions
├── requirements.txt        # Runtime and testing dependencies
├── auditor/
│   ├── __init__.py
│   ├── entropy.py          # Shannon entropy calculations per section
│   ├── heuristics.py       # Size delta, W^X, entry point, overlay heuristics
│   ├── antidebug.py        # Anti-debug imports, wide strings, TLS, opcodes
│   ├── scoring.py          # Calibrated multi-signal weighted verdict engine
│   └── report.py           # Rich terminal UI and JSON report generator
├── tests/
│   ├── test_entropy.py     # Entropy unit tests
│   ├── test_heuristics.py  # Section, size, W^X, entry point tests
│   ├── test_antidebug.py   # Imports, wide-string, TLS, and opcode tests
│   ├── test_scoring.py     # Weighted score threshold tests
│   └── test_cli.py         # Metadata extraction and path discovery tests
└── scripts/
    └── make_test_sample.sh # Cross-compiles a synthetic unpacked/packed test pair
```

---

## Testing

Run the test suite:

```bash
python -m unittest discover tests
# Or with pytest:
pytest tests/
```

To create a synthetic test pair locally (requires `mingw-w64` and `upx`):
```bash
bash scripts/make_test_sample.sh
python cli.py samples/hello.exe
python cli.py samples/hello_packed.exe
```

---

## License & Disclaimer

Provided under the MIT License for defensive reverse engineering and educational purposes.
