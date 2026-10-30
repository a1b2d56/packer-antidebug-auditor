"""Static scanning for anti-debugging and anti-analysis indicators:
API imports, wide/narrow string artifacts, TLS callbacks, IAT sparsity,
and anti-disassembly byte patterns.
"""

from __future__ import annotations

import re

ANTI_DEBUG_APIS = {
    # PEB & Kernel debugger flags
    "IsDebuggerPresent": "checks PEB.BeingDebugged flag directly",
    "CheckRemoteDebuggerPresent": "queries kernel debug port for current process",
    "NtQueryInformationProcess": "can query ProcessDebugPort (0x7) or ProcessDebugFlags (0x1F)",
    "ZwQueryInformationProcess": "native syscall to query ProcessDebugPort or debug flags",
    "NtSetInformationThread": "can set ThreadHideFromDebugger (0x11) to detach debuggers",
    "ZwSetInformationThread": "native syscall to hide thread from debugger",
    "NtQuerySystemInformation": "can query SystemKernelDebuggerInformation (0x23)",
    "NtQueryObject": "can scan for DebugObject instances in the system",
    "NtClose": "can trigger STATUS_INVALID_HANDLE exception when passed an invalid handle",
    "NtSetDebugFilterState": "manipulates kernel debug print filters",
    "DbgBreakPoint": "triggers breakpoint exception directly in code",
    "DbgUserBreakPoint": "triggers user-mode breakpoint exception",
    "DbgUiRemoteBreakin": "debugger attachment routine targeted for patching/unhooking",
    "NtQueryInformationThread": "can query ThreadHideFromDebugger or thread start address",
    # Hardware breakpoints & Context
    "GetThreadContext": "can read hardware breakpoint registers (DR0-DR3, DR7)",
    "SetThreadContext": "can clear or alter hardware breakpoint registers",
    "NtGetContextThread": "native query for thread context / debug registers",
    "NtSetContextThread": "native modification of thread context / debug registers",
    # Exception handling tricks
    "SetUnhandledExceptionFilter": "replaces top-level exception handler to intercept crashes",
    "AddVectoredExceptionHandler": "registers VEH handler executed before SEH/debugger",
    "RemoveVectoredExceptionHandler": "removes VEH handler after debugger evasion check",
    # OutputDebugString trick
    "OutputDebugStringA": "error-code based debugger detection (GetLastError trick)",
    "OutputDebugStringW": "error-code based debugger detection (GetLastError trick)",
    # Timing & Delay checks
    "QueryPerformanceCounter": "high-resolution timing check for debugger single-stepping",
    "GetTickCount": "timing measurement to detect interactive debugging delays",
    "GetTickCount64": "timing measurement to detect interactive debugging delays",
    "timeGetTime": "multimedia timer check for debugging delays",
    "NtDelayExecution": "delays execution / sleep acceleration bypass for sandboxes",
    "NtYieldExecution": "timing measurement / anti-single-step thread yield delay",
    # Process, Window & Environment enumeration
    "FindWindowA": "searches for known debugger/analysis window classes",
    "FindWindowW": "searches for known debugger/analysis window classes",
    "FindWindowExA": "searches child windows for analysis tools",
    "FindWindowExW": "searches child windows for analysis tools",
    "CreateToolhelp32Snapshot": "enumerates running processes to locate debuggers/monitors",
    "Process32First": "iterates process list for security analysis tools",
    "Process32Next": "iterates process list for security analysis tools",
    "Process32FirstW": "iterates process list for security analysis tools",
    "Process32NextW": "iterates process list for security analysis tools",
    "EnumWindows": "enumerates top-level windows looking for debuggers",
    "GetSystemMetrics": "queries screen resolution or SM_REMOTESESSION (0x1000) for VM checks",
    # Memory and Injection Evasion
    "VirtualProtectEx": "modifies page permissions across processes, common in unhooking",
    "SetInformationJobObject": "breaks out of or restricts job object sandbox limits",
    "NtCreateThreadEx": "stealth thread injection using THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER",
}

DYNAMIC_LOADER_APIS = {
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
}

SUSPICIOUS_STRINGS = {
    # Debuggers & reverse engineering tools
    "OLLYDBG": "debugger window class / artifact",
    "x64dbg": "modern 64-bit debugger artifact",
    "x32dbg": "modern 32-bit debugger artifact",
    "x96dbg": "x96dbg debugger artifact",
    "WinDbgFrameClass": "WinDbg window class",
    "Zeta Debugger": "debugger window artifact",
    "ImmunityDebugger": "Immunity Debugger artifact",
    "IDA Pro": "IDA disassembler artifact",
    "ghidra": "Ghidra disassembler artifact",
    "cutter": "Cutter reverse engineering framework artifact",
    "radare2": "radare2 analysis framework artifact",
    "die.exe": "Detect It Easy packer identifier",
    "pestudio": "PEstudio malware triage artifact",
    "Cheat Engine": "memory scanner / debugger artifact",
    "Process Hacker": "process inspection tool artifact",
    "ScyllaHide": "anti-anti-debug hook plugin artifact",
    "apimonitor": "API Monitor inspection tool artifact",
    "wireshark": "Wireshark network capture artifact",
    "fiddler": "Fiddler HTTP proxy artifact",
    "procmon": "Process Monitor sysinternals tool",
    "autoruns": "Sysinternals Autoruns artifact",
    "regshot": "Regshot registry change tracker",
    # Virtual machines & hypervisors
    "VMware": "VMware virtualization artifact",
    "VirtualBox": "VirtualBox VM artifact",
    "VBox": "VirtualBox VM artifact",
    "vmci.sys": "VMware kernel driver artifact",
    "vboxguest": "VirtualBox guest additions artifact",
    "VBoxMouse.sys": "VirtualBox driver artifact",
    "vboxservice.exe": "VirtualBox guest service artifact",
    "vmtoolsd.exe": "VMware Tools daemon artifact",
    "qemu": "QEMU hypervisor artifact",
    "hyper-v": "Microsoft Hyper-V hypervisor artifact",
    "HARDWARE\\Description\\System\\BIOS": "system BIOS registry key checked for VM strings",
    "HARDWARE\\DEVICEMAP\\Scsi": "SCSI registry key checked for VM disk signatures",
    # Sandboxes & Cloud dynamic analysis
    "SbieDll.dll": "Sandboxie DLL artifact",
    "SANDBOXIE": "Sandboxie indicator",
    "Wine_get_unix_file_name": "Wine compatibility layer artifact",
    "cuckoo": "Cuckoo sandbox artifact",
    "\\\\.\\pipe\\cuckoo": "Cuckoo sandbox IPC pipe",
    "joebox": "Joe Sandbox artifact",
    "any.run": "ANY.RUN interactive sandbox indicator",
    "hybrid-analysis": "Hybrid Analysis sandbox indicator",
    "capemon.dll": "CAPE sandbox monitor DLL artifact",
    "CAPE sandbox": "CAPE sandbox indicator",
}

# Opcode signatures for inline anti-debug, hypervisor, and timing tricks.
# Each entry is (byte pattern, description, kind) where kind is one of
# "timing", "antidebug" or "vm" and selects the scoring signal / ATT&CK technique.
OPCODE_PATTERNS = [
    (b"\x0f\x31", "RDTSC instruction (inline timing measurement)", "timing"),
    (b"\x0f\x01\xf9", "RDTSCP instruction (serialized timing measurement)", "timing"),
    (b"\xcd\x2d", "INT 2Dh instruction (debugger interrupt / instruction skip)", "antidebug"),
    (b"\xf1", "ICEBP / INT1 instruction (undocumented single-step trap)", "antidebug"),
    (b"\x0f\xa2", "CPUID instruction (hypervisor / CPU feature query)", "vm"),
    (b"\x0f\x01\x0e", "SIDT instruction (Red Pill IDTR register VM detection)", "vm"),
    (b"\x0f\x01\x04", "SGDT instruction (Red Pill GDTR register VM detection)", "vm"),
    (b"\x0f\x01\x20", "SMSW instruction (Machine Status Word VM detection)", "vm"),
]

# Precompile single-pass string search automaton (mapping raw byte pattern -> original string key)
_STRING_BYTE_MAP: dict[bytes, str] = {}
for _pat in SUSPICIOUS_STRINGS:
    _asc = _pat.encode("ascii", errors="ignore")
    if _asc:
        _STRING_BYTE_MAP[_asc] = _pat
    _w16 = _pat.encode("utf-16le")
    if _w16:
        _STRING_BYTE_MAP[_w16] = _pat

# Build a single-pass regex compiled pattern across all byte signatures, longest first
_ALL_PATTERNS_SORTED = sorted(_STRING_BYTE_MAP.keys(), key=len, reverse=True)
_STRING_REGEX_AUTOMATON = re.compile(b"|".join(re.escape(b) for b in _ALL_PATTERNS_SORTED))

# Precompile opcode search automaton
_OPCODE_MAP = {pat: (desc, kind) for pat, desc, kind in OPCODE_PATTERNS}
_OPCODE_REGEX_AUTOMATON = re.compile(
    b"|".join(re.escape(pat) for pat in sorted(_OPCODE_MAP.keys(), key=len, reverse=True))
)

# Direct syscall / SSN-resolution fingerprints in user code (EDR evasion & unhooking).
# Each entry: (signal_key, technique label, compiled regex). All regexes use DOTALL so
# that wildcard bytes (SSNs, displacements) may legitimately contain 0x0A.
#
# Static notes on the resolver fingerprints:
#   * Hell's Gate validates a candidate ntdll stub by comparing its first bytes against
#     the canonical prologue 4C 8B D1 B8 (mov r10, rcx; mov eax, imm32). Compiled, that
#     shows up as a cluster of `cmp byte ptr [reg+disp], imm8` (80 7x dd ii) with those
#     immediates inside a short window.
#   * Halo's Gate adds a hook check -- `cmp byte ptr [reg], 0E9h` (inline JMP hook) -- and,
#     if hooked, walks neighbouring stubs at a 0x20-byte stride.
#   * TartarusGate extends Halo's Gate by also checking for a JMP at offset +3 of the stub
#     (`cmp byte ptr [reg+3], 0E9h`), catching hooks placed after `mov r10, rcx`.
#   * FreshyCalls / SysWhispers2 derive SSNs by sorting Zw*/Nt* exports by address; the
#     export filter compiles to `cmp word ptr [reg], 'wZ'` / 'tN' (little-endian).
#   * Heaven's Gate switches a WoW64 process to 64-bit mode through the 0x33 code segment.
_PROLOGUE_CMP = rb"\x80[\x38-\x3f\x78-\x7f](?:.)?"  # cmp byte ptr [reg(+disp8)], imm8
SYSCALL_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "tartarus_gate",
        "TartarusGate hooked-stub resolver (checks JMP hook at stub offset +3)",
        re.compile(rb"\x80[\x78-\x7f]\x03\xe9", re.DOTALL),
    ),
    (
        "halos_gate",
        "Halo's Gate hooked-stub resolver (E9 hook check + neighbour stub walk)",
        re.compile(
            _PROLOGUE_CMP + rb"\xe9.{0,48}?(?:\x83[\xc0-\xc7\xe8-\xef]\x20|\x48[\x83\x8d].{1,2}\x20)",
            re.DOTALL,
        ),
    ),
    (
        "hells_gate_resolver",
        "Hell's Gate SSN resolver (compares stub bytes against 4C 8B D1 B8 prologue)",
        re.compile(
            _PROLOGUE_CMP + rb"\x4c.{0,24}?" + _PROLOGUE_CMP + rb"\x8b.{0,24}?"
            + _PROLOGUE_CMP + rb"\xd1.{0,24}?" + _PROLOGUE_CMP + rb"\xb8",
            re.DOTALL,
        ),
    ),
    (
        "freshycalls_sorted_ssn",
        "FreshyCalls / SysWhispers2-style SSN resolution (filters Zw*/Nt* exports by prefix)",
        re.compile(rb"\x66\x81[\x38-\x3f\x78-\x7f](?:.)?(?:\x5a\x77|\x4e\x74)", re.DOTALL),
    ),
    (
        "heavens_gate",
        "WoW64 Heaven's Gate transition (fs:[0xC0])",
        re.compile(rb"\x64\xa1\xc0\x00\x00\x00", re.DOTALL),
    ),
    (
        "heavens_gate",
        "WoW64 Heaven's Gate far transfer to 64-bit code segment 0x33",
        re.compile(rb"\xea.{4}\x33\x00|\x6a\x33\xe8\x00\x00\x00\x00.{0,16}?\xcb", re.DOTALL),
    ),
    (
        "direct_syscall",
        "Direct syscall stub (mov r10, rcx; mov eax, ssn; syscall)",
        re.compile(rb"\x4c\x8b\xd1\xb8.{4}.{0,32}?\x0f\x05", re.DOTALL),
    ),
    (
        "direct_syscall",
        "Inline direct 'syscall' instruction",
        re.compile(rb"\x0f\x05\xc3", re.DOTALL),
    ),
    (
        "direct_syscall",
        "Inline direct 'sysenter' instruction",
        re.compile(rb"\x0f\x34\xc3", re.DOTALL),
    ),
]

# Upper bound on reported syscall findings per section (keeps reports bounded on huge binaries).
MAX_SYSCALL_HITS_PER_SECTION = 16


def scan_imports(pe) -> list[dict]:
    """Scan PE import table for known anti-debug and evasion APIs."""
    hits = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return hits

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode(errors="replace")
                if name in ANTI_DEBUG_APIS:
                    hits.append({"api": name, "reason": ANTI_DEBUG_APIS[name]})
    return hits


def iat_density_flags(pe) -> list[dict]:
    """Flag sparse or loader-only import tables characteristic of packed binaries."""
    flags = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        flags.append({
            "reason": "no import table found (unusual for standard executables, typical for loaders/shellcode)",
        })
        return flags

    all_imports = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                all_imports.append(imp.name.decode(errors="replace"))

    total_imports = len(all_imports)
    if 0 < total_imports <= 4:
        flags.append({
            "reason": f"extremely sparse IAT (only {total_imports} total imported function(s))",
        })

    # Check if imports consist almost exclusively of dynamic loader functions
    loader_imports = [imp for imp in all_imports if imp in DYNAMIC_LOADER_APIS]
    if total_imports > 0 and len(loader_imports) >= 2 and (len(loader_imports) / total_imports) >= 0.5:
        flags.append({
            "reason": (
                f"{len(loader_imports)} of {total_imports} imports are dynamic loader functions "
                f"({', '.join(loader_imports[:3])}) -- binary resolves APIs at runtime"
            ),
        })

    return flags


def scan_strings(raw_bytes: bytes) -> list[dict]:
    """Search raw binary bytes for suspicious strings in both ASCII and UTF-16LE via single-pass regex automaton."""
    hits = []
    seen = set()

    for match in _STRING_REGEX_AUTOMATON.finditer(raw_bytes):
        matched_bytes = match.group(0)
        orig_key = _STRING_BYTE_MAP.get(matched_bytes)
        if orig_key and orig_key not in seen:
            seen.add(orig_key)
            hits.append({"string": orig_key, "category": SUSPICIOUS_STRINGS[orig_key]})

    return hits


def scan_tls_callbacks(pe) -> list[dict]:
    """Detect Thread Local Storage (TLS) callbacks.

    TLS callbacks execute before the program's AddressOfEntryPoint is called,
    making them a common vehicle for stealthy anti-debugging initialization.
    """
    flags = []
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return flags

    tls_struct = getattr(pe.DIRECTORY_ENTRY_TLS, "struct", None)
    if not tls_struct:
        return flags

    callbacks_va = getattr(tls_struct, "AddressOfCallBacks", 0)
    if callbacks_va != 0:
        flags.append({
            "reason": f"TLS directory defines callbacks (0x{callbacks_va:X}) -- executes code before EntryPoint",
        })
    return flags


def scan_opcodes(pe) -> list[dict]:
    """Scan executable sections for specific anti-analysis bytecode patterns via compiled automaton."""
    flags = []
    for section in pe.sections:
        characteristics = getattr(section, "Characteristics", 0)
        # Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
        if characteristics & 0x20000000:
            data = section.get_data()
            sec_name = section.Name.rstrip(b"\x00").decode(errors="replace")
            seen_in_sec = set()
            for match in _OPCODE_REGEX_AUTOMATON.finditer(data):
                pat = match.group(0)
                if pat not in seen_in_sec:
                    seen_in_sec.add(pat)
                    desc, kind = _OPCODE_MAP[pat]
                    flags.append({
                        "section": sec_name,
                        "kind": kind,
                        "reason": f"found {desc} in executable section '{sec_name}'",
                    })
    return flags


def scan_direct_syscalls(pe) -> list[dict]:
    """Detect direct syscalls, SSN-resolution techniques and Heaven's Gate in executable sections.

    Legitimate user-mode Windows binaries execute syscalls via ntdll.dll. Direct syscall stubs
    and the resolver logic of Hell's Gate, Halo's Gate, TartarusGate and FreshyCalls embedded in
    user sections indicate EDR evasion, unhooking, or evasive loader payloads.

    Each finding reports one technique once per section. A generic 'direct_syscall' finding is
    suppressed for a section where a more specific direct-syscall label already matched.
    """
    flags = []
    for section in pe.sections:
        characteristics = getattr(section, "Characteristics", 0)
        if not characteristics & 0x20000000:
            continue
        data = section.get_data()
        sec_name = section.Name.rstrip(b"\x00").decode(errors="replace")
        seen_labels: set[str] = set()
        seen_keys: set[str] = set()
        sec_hits = 0
        for signal_key, label, regex in SYSCALL_PATTERNS:
            if sec_hits >= MAX_SYSCALL_HITS_PER_SECTION:
                break
            # The generic syscall/sysenter-ret forms add nothing once a full stub was found.
            if signal_key == "direct_syscall" and "direct_syscall" in seen_keys:
                continue
            if label in seen_labels or regex.search(data) is None:
                continue
            seen_labels.add(label)
            seen_keys.add(signal_key)
            sec_hits += 1
            flags.append({
                "section": sec_name,
                "technique": label.split(" (")[0],
                "signal_key": signal_key,
                "reason": f"{label} detected in section '{sec_name}'",
            })
    return flags
