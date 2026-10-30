/*
    Heuristic stub rules for modern crypters / loaders.

    These rules encode publicly documented, comparatively stable traits of each
    family's delivery stub. They are triage heuristics, not family attribution:
    each rule is tagged with a confidence level and should be corroborated with
    the static scoring engine or dynamic analysis. They have been validated only
    against synthetic test buffers (tests/test_yara_rules.py), not a live corpus.

    All byte signatures use YARA hex-string syntax ({ .. }); no quoted \x escapes.
*/

rule GuLoader_NSIS_Shellcode_Stub {
    meta:
        author = "Packer & Anti-Debug Auditor"
        description = "NSIS installer carrying GuLoader-style shellcode: RDTSC/CPUID timing loop plus DJB2 API hashing"
        reference = "Public GuLoader reporting (NSIS delivery, RDTSC/CPUID anti-VM loops, hashed API resolution)"
        mitre_att_ck = "T1497.003"
        confidence = "medium"
    strings:
        // NSIS first-header signature: 0xDEADBEEF followed by "NullsoftInst"
        $nsis = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
        // rdtsc ... cpuid ... rdtsc inside a short window (timing a hypervisor exit)
        $timing_loop = { 0F 31 [2-24] 0F A2 [2-24] 0F 31 }
        // DJB2 seed 5381 (0x1505) loaded into a register: mov e?x, 1505h
        $djb2_seed = { (B8 | B9 | BA | BB | BE | BF) 05 15 00 00 }
    condition:
        $nsis and $timing_loop and $djb2_seed
}

rule SmokeLoader_Stub_Traits {
    meta:
        author = "Packer & Anti-Debug Auditor"
        description = "SmokeLoader-style stub: dense jz/jnz opaque-predicate pairs plus RU/UA keyboard-layout geofence"
        reference = "Public SmokeLoader reporting (opaque predicates, keyboard layout checks, PROPagate via UxSubclassInfo)"
        mitre_att_ck = "T1027"
        confidence = "medium"
    strings:
        // jz +N / jnz +N-2 to the same target: classic anti-disassembly opaque predicate
        $opaque1 = { 74 03 75 01 }
        $opaque2 = { 74 04 75 02 }
        $opaque3 = { 75 03 74 01 }
        $opaque4 = { 75 04 74 02 }
        // cmp ax, 0419h (ru-RU) / cmp ax, 0422h (uk-UA)
        $kb_ru = { 66 3D 19 04 }
        $kb_ua = { 66 3D 22 04 }
        $propagate = "UxSubclassInfo" ascii wide
        $kbl_api = "GetKeyboardLayoutList" ascii
    condition:
        uint16(0) == 0x5A4D and
        (#opaque1 + #opaque2 + #opaque3 + #opaque4) >= 8 and
        (($kb_ru and $kb_ua) or ($propagate and $kbl_api))
}

rule DarkGate_AutoIt_Loader {
    meta:
        author = "Packer & Anti-Debug Auditor"
        description = "AutoIt3 script loader pattern used by DarkGate: compiled AU3 payload that allocates and runs an embedded PE/shellcode via DllCall"
        reference = "Public DarkGate reporting (AutoIt3.exe + .au3 script carrier, in-memory payload execution)"
        mitre_att_ck = "T1059.010"
        confidence = "low"
    strings:
        $au3_magic = "AU3!EA06" ascii
        $autoit = "AutoIt3.exe" ascii wide nocase
        $dllcall = "DllCall(" ascii nocase
        $valloc = "VirtualAlloc" ascii nocase
        $vprotect = "VirtualProtect" ascii nocase
        $call_window = "CallWindowProc" ascii nocase
        // hex-encoded "MZ" / PE header embedded as a script string literal
        $hex_pe = "0x4D5A90" ascii nocase
    condition:
        ($au3_magic or $autoit) and $dllcall and
        ($valloc or $vprotect) and ($call_window or $hex_pe)
}
