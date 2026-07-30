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
    # Timing checks
    "QueryPerformanceCounter": "high-resolution timing check for debugger single-stepping",
    "GetTickCount": "timing measurement to detect interactive debugging delays",
    "GetTickCount64": "timing measurement to detect interactive debugging delays",
    "timeGetTime": "multimedia timer check for debugging delays",
    # Process & Window enumeration
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
    "WinDbgFrameClass": "WinDbg window class",
    "Zeta Debugger": "debugger window artifact",
    "ImmunityDebugger": "Immunity Debugger artifact",
    "IDA Pro": "IDA disassembler artifact",
    "Cheat Engine": "memory scanner / debugger artifact",
    "Process Hacker": "process inspection tool artifact",
    "ScyllaHide": "anti-anti-debug hook plugin artifact",
    # Virtual machines & hypervisors
    "VMware": "VMware virtualization artifact",
    "VirtualBox": "VirtualBox VM artifact",
    "VBox": "VirtualBox VM artifact",
    "vmci.sys": "VMware kernel driver artifact",
    "vboxguest": "VirtualBox guest additions artifact",
    "VBoxMouse.sys": "VirtualBox driver artifact",
    "qemu": "QEMU hypervisor artifact",
    "HARDWARE\\Description\\System\\BIOS": "system BIOS registry key checked for VM strings",
    # Sandboxes
    "SbieDll.dll": "Sandboxie DLL artifact",
    "SANDBOXIE": "Sandboxie indicator",
    "Wine_get_unix_file_name": "Wine compatibility layer artifact",
    "cuckoo": "Cuckoo sandbox artifact",
    "\\\\.\\pipe\\cuckoo": "Cuckoo sandbox IPC pipe",
}

# Opcode signatures for inline anti-debug and anti-disassembly tricks
OPCODE_PATTERNS = [
    (b"\x0f\x31", "RDTSC instruction (inline timing measurement)"),
    (b"\xcd\x2d", "INT 2Dh instruction (debugger interrupt / instruction skip)"),
    (b"\xf1", "ICEBP / INT1 instruction (undocumented single-step trap)"),
]


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
    """Search raw binary bytes for suspicious strings in both ASCII and UTF-16LE encodings."""
    hits = []
    seen = set()

    for pattern, category in SUSPICIOUS_STRINGS.items():
        # Match ASCII
        ascii_bytes = pattern.encode("ascii", errors="ignore")
        # Match UTF-16LE (wide strings)
        utf16_bytes = pattern.encode("utf-16le")

        found = False
        if ascii_bytes and ascii_bytes in raw_bytes:
            found = True
        elif utf16_bytes and utf16_bytes in raw_bytes:
            found = True

        if found and pattern not in seen:
            seen.add(pattern)
            hits.append({"string": pattern, "category": category})

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
    """Scan executable sections for specific anti-analysis bytecode patterns."""
    flags = []
    for section in pe.sections:
        characteristics = getattr(section, "Characteristics", 0)
        # Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
        if characteristics & 0x20000000:
            data = section.get_data()
            sec_name = section.Name.rstrip(b"\x00").decode(errors="replace")
            for pattern, desc in OPCODE_PATTERNS:
                if pattern in data:
                    flags.append({
                        "section": sec_name,
                        "reason": f"found {desc} in executable section '{sec_name}'",
                    })
    return flags
