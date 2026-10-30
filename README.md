# Packer & Anti-Debug Auditor

Ananmay Jha (23BCI0163) and Aaditya Agre (23BCI0146)

Pre-execution static triage for Windows PE32/PE32+ binaries (`.exe` / `.dll` / `.sys`) and Android APKs. It flags packers and protectors, anti-debug and anti-VM tricks, direct syscalls and EDR-evasion stubs, maps every finding to MITRE ATT&CK, and adds a Random Forest classifier. Nothing is executed.

It has three front ends over one engine (`auditor/`):

| Front end | Entry point | Use |
|---|---|---|
| CLI | `cli.py` / `packer-audit` | single files, multi-core batch scans, CSV/JSONL export, CI gate |
| Web API | `server/` (FastAPI) | uploads, SSE live progress, scan history, APK decompilation via JADX |
| Dashboard | `web/` (React 19 + Vite + Tailwind) | interactive reports with ATT&CK links, light/dark themes |

---

## What It Checks

### 1. Packing & structural indicators
- **Shannon entropy per section** (bits/byte, 0â€“8). Sections above 7.0 are flagged as packed. Sections smaller than 256 bytes are reported but never flagged, because they are too small for entropy to mean anything (`entropy_reliable: false`).
- **W^X sections**: sections that are both writable and executable (self-modifying unpacker stubs).
- **Virtual vs raw size gaps**: zero-raw sections and expansion ratios above 10Ã—.
- **Entry point anomalies**: EP outside every section, EP in a writable section, or EP in the last section.
- **Packer section names**: UPX, ASPack, VMProtect (`.vmp*`), Themida, Enigma, MPRESS, ConfuserEx, Petite, FSG, MEW and others.
- **Header anti-forensics**:
  - timestomped `TimeDateStamp` (zero, before 2000, or after 2035)
  - ASLR enabled while relocations are stripped
  - non-printable or blank section names
- **Overlay data**, with its own entropy.
- **IAT density**: very small import tables, and tables that contain little besides loader APIs.
- **Low section count** (3 or fewer).

### 2. Anti-analysis, evasion & direct syscalls
- **Direct syscall and SSN-resolution fingerprints** (`auditor/antidebug.py`, `SYSCALL_PATTERNS`):

  | Signal key | Technique | Static fingerprint |
  |---|---|---|
  | `direct_syscall` | Hell's Gate / SysWhispers stub | `4C 8B D1 B8 [ssn] .. 0F 05`, plus inline `syscall;ret` / `sysenter;ret` |
  | `hells_gate_resolver` | Hell's Gate SSN resolver | `cmp byte [reg+n]` against `4C`,`8B`,`D1`,`B8` |
  | `halos_gate` | Halo's Gate | `E9` hook check + 0x20-stride neighbour walk |
  | `tartarus_gate` | TartarusGate | `E9` hook check at stub offset +3 (`80 7x 03 E9`) |
  | `freshycalls_sorted_ssn` | FreshyCalls / SysWhispers2 | `cmp word [reg], 'Zw'` / `'Nt'` export filter |
  | `heavens_gate` | Heaven's Gate | `fs:[0xC0]`, `jmp far 0x33:addr`, `push 0x33; call $+5; â€¦ retf` |

  Every pattern uses `re.DOTALL`, so SSNs containing `0x0A` still match. Each technique is reported once per section, with at most 16 findings per section.
- **Anti-debug API imports**: about 40 APIs, covering PEB flags, debug registers, VEH/SEH traps, timing, and window/process enumeration.
- **Suspicious strings** (ASCII + UTF-16LE, single-pass automaton): debuggers, RE tools, hypervisors and sandboxes.
- **TLS callbacks** (code that runs before the entry point).
- **Anti-analysis opcodes**, split by kind:
  - timing: `RDTSC`, `RDTSCP`
  - debugger traps: `INT 2D`, `ICEBP`
  - VM detection: `CPUID`, `SIDT`, `SGDT`, `SMSW`

### 3. Scoring, sensitivity profiles & confidence
Signals are weighted and summed. Single strong signals score +3, and the evidence counts are capped. The total then maps to LOW / MEDIUM / HIGH according to the chosen profile:

| Profile | MEDIUM â‰¥ | HIGH â‰¥ | Weights |
|---|---|---|---|
| `aggressive` | 2 | 5 | evasion signals Ã—1.25 |
| `balanced` (default) | 3 | 7 | original weights. Output is identical to earlier releases. |
| `conservative` | 4 | 9 | weak signals (section count, overlay, strings) Ã—0.75 |

Every verdict also reports:
- **`score_interval`**: the range the score falls to when each independent signal category is removed in turn (leave-one-category-out).
- **`confidence`**: blends how stable the verdict is under those removals with how far the score sits from the nearest threshold.
- **`verdict_stable`**: whether the verdict survives every removal.

This is *heuristic* confidence: it shows how much the verdict depends on any single piece of evidence. It is **not** a calibrated probability, which would need a labelled corpus.

### 4. MITRE ATT&CK mapping (`auditor/mitre_map.py`)
All 22 signal keys map to an ATT&CK technique, and a unit test enforces this. Examples:

| Signal | Technique |
|---|---|
| packed entropy | T1027.002 Software Packing |
| W^X section | T1055.012 Process Hollowing |
| anti-debug imports, TLS callbacks, INT 2D / ICEBP | T1622 Debugger Evasion |
| `RDTSC` | T1497.003 Time Based Evasion |
| CPUID / SIDT | T1497.001 System Checks |
| direct syscalls, all Gate variants | T1106 Native API (Heaven's Gate also T1027) |
| timestomp | T1070.006 |

The APK verdict uses ATT&CK for Mobile (e.g. T1582 SMS Control, T1636.004 SMS Messages). Badges in the dashboard link to `https://attack.mitre.org/techniques/<ID>/`.

### 5. YARA rules (`rules/*.yar`, 16 rules)
- **`basic.yar`**: PE header, UPX, suspicious APIs, PEB anti-debug, direct syscall stub (the bytes must be adjacent), Heaven's Gate far jump, process injection, shellcode patterns, Run-key persistence, packer section names (read from the PE section table), credential harvesting and network beacons.
- **`crypters.yar`**: stub heuristics for **GuLoader** (NSIS + RDTSC/CPUID loop + DJB2 hashing), **SmokeLoader** (opaque-predicate density + RU/UA keyboard-layout geofence) and **DarkGate** (AutoIt3 loader running an embedded payload).

All byte signatures use `{ }` hex syntax. Every rule carries `mitre_att_ck` and `description` metadata. The crypter rules have a `confidence` field.

> **Limitation:** the crypter rules are based on publicly documented traits and have been validated only against synthetic buffers in `tests/test_yara_rules.py`, not a live malware corpus. Treat a hit as a triage lead, not as attribution to a malware family.

### 6. Machine learning (17-feature contract)
`auditor/model.py:FEATURE_NAMES` defines **17 features**, in this order:
- `section_count`, `max_entropy`, `mean_entropy`, `high_entropy_sections`, `rwx_sections_count`
- `size_delta_flags_count`, `packer_section_flags_count`, `overlay_present`, `overlay_entropy`
- `anti_debug_import_count`, `sparse_iat_flag`, `suspicious_strings_count`, `tls_callbacks_present`
- `opcode_checks_count`, `direct_syscall_count`, `header_anomaly_count`, `risk_score`

The CSV export (`auditor/report.py:CSV_FEATURE_COLUMNS`), `scripts/train_model.py` and the shipped `models/packer_model.joblib` all use this exact order.

`train_model.py` writes a sidecar file, `models/packer_model.meta.json`, that records the feature names. `load_model()` refuses to load a model whose dimension or feature names disagree, and raises `ModelFeatureMismatch`.

---

## Installation

```bash
pip install -r requirements.txt          # everything (CLI + ML + web + tests)
pip install -e ".[ml,web,dev]"           # or as a package with extras
cd web && npm install                    # dashboard
```

APK analysis needs JADX. Put it in `tools/jadx/`, add `jadx` to `PATH`, or set `JADX_PATH`. It also needs a Java runtime.

---

## CLI Usage

```bash
python cli.py sample.exe                              # rich terminal report
python cli.py ./samples/ --recursive -j 16            # multi-core batch scan
python cli.py ./samples/ -r --csv features.csv        # 17-feature ML dataset
python cli.py ./samples/ -r --jsonl -o stream.jsonl   # constant-memory streaming
python cli.py sample.exe --json -o report.json
python cli.py sample.exe --model                      # + Random Forest probability
python cli.py sample.exe --profile aggressive         # sensitivity profile
python cli.py sample.exe --fail-on HIGH               # exit code 2 at/above HIGH (CI gate)
```

ML model:
```bash
python scripts/train_model.py --synthetic -n 10000    # retrain (also writes the .meta.json sidecar)
python scripts/train_model.py --write-meta-only       # validate the existing model and write its sidecar
```

---

## Web API & Dashboard

```bash
start_dashboard.bat                                   # Windows: backend :8000 + Vite :5173
# or manually:
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
cd web && npm run dev
```

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | status, model/YARA/JADX availability |
| POST | `/api/v1/upload` | multipart `file` (+ optional `profile`). Returns the cached result if this file was already audited with the same profile. |
| GET | `/api/v1/audit/{job_id}` | result, or current status/progress while running |
| GET | `/api/v1/audit/{job_id}/stream` | SSE progress. History is replayed on every (re)connect, with a keep-alive ping every 15 s. |
| DELETE | `/api/v1/audit/{job_id}` | cancel a running job (kills the JADX process tree) |

Every response is validated against the Pydantic models in `server/models/schemas.py`.

Analysis runs in worker threads, so the event loop and SSE streams stay responsive. Uploads are content-addressed by SHA-256 in `quarantine/`:
- PEs are stored as non-executable `*.pe.quarantine` files.
- A ZIP is accepted as an APK only if it contains an `AndroidManifest.xml`.

**Configuration** (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `JADX_PATH` | auto | JADX launcher (`tools/jadx/bin/jadx[.bat]`, then `PATH`) |
| `JADX_TIMEOUT_S` | 900 | wall-clock limit. On timeout the process tree is killed and any partial output is still analysed. |
| `JADX_HEAP` | 4g | JVM `-Xmx` for JADX |
| `JADX_THREADS` | min(4, CPUs) | `--threads-count` |
| `JADX_DEOBF` | 1 | pass `--deobf` |
| `KEEP_DECOMPILED` | 0 | keep `decompiled/<sha256>-<job>` after the scan |
| `MAX_UPLOAD_SIZE` | 104857600 | bytes. Larger uploads get HTTP 413. |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | allowed dashboard origins |
| `AUDITOR_DATA_DIR` | repo root | where `quarantine/`, `decompiled/` and `history.sqlite3` live |
| `AUDITOR_RELOAD` | 0 | uvicorn auto-reload (leave off on Windows if you need APK analysis) |
| `VITE_API_BASE` | `http://127.0.0.1:8000` | dashboard â†’ API base URL (build time) |

Verified against a real 98 MB multi-DEX `SystemUI.apk`: JADX finished in about 5 minutes under the 4 GB heap cap. It exited with code 1 on some classes, and the partial-output recovery still produced the manifest, permissions and verdict.

---

## Quick Start & Demonstration

```bash
# Run interactive CLI demonstration harness
python scripts/demo_harness.py

# Benchmark ML classifiers
python scripts/benchmark_ml.py

# Start API server and web dashboard
start_dashboard.bat
```

---

## Project Structure

```
auditor/        entropy, heuristics, antidebug (syscall table), scoring (profiles), mitre_map, model, report
server/         FastAPI app: routes/, services/ (job_manager, pe_audit, apk_audit, yara_scanner), models/schemas.py
web/            React dashboard (src/types/audit.ts mirrors the API schemas)
rules/          basic.yar, crypters.yar
models/         packer_model.joblib + packer_model.meta.json (feature contract)
scripts/        train_model, benchmark_ml, demo_harness
tests/          engine, CLI, YARA, and feature-contract tests
tests_server/   API tests (TestClient) incl. a fake JADX for timeout / cancel / partial-output paths
```

## Testing

```bash
python -m pytest                 # tests/ + tests_server/
cd web && npm run lint && npm run build
```

---

## License & Disclaimer

MIT License. For defensive reverse engineering and educational use. Detection is static and heuristic: a LOW verdict does not prove a file is benign.
