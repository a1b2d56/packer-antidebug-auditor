import "pe"

rule IsPE {
    meta:
        description = "Detects PE headers"
    strings:
        $mz = "MZ"
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe in (0x3C..0x1000)
}

rule UPX_Packed {
    meta:
        description = "UPX packer signature"
        mitre_att_ck = "T1027.002"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        2 of them
}

rule Suspicious_API {
    meta:
        description = "Suspicious Windows API calls"
        mitre_att_ck = "T1106"
    strings:
        $s1 = "IsDebuggerPresent"
        $s2 = "VirtualAlloc"
        $s3 = "LoadLibrary"
        $s4 = "GetProcAddress"
    condition:
        2 of them
}

rule Base64_String {
    meta:
        description = "Base64 encoded payload stub"
        mitre_att_ck = "T1027"
    strings:
        $b1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    condition:
        $b1
}

rule AntiDebug_PEB {
    meta:
        description = "Anti-debugging via PEB flag checks and debug port queries"
        mitre_att_ck = "T1622"
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "NtQueryInformationProcess"
        $a3 = "CheckRemoteDebuggerPresent"
        $a4 = "NtQuerySystemInformation"
    condition:
        2 of ($a*)
}

rule Direct_Syscall_Stub {
    meta:
        description = "Direct syscall stub bypassing ntdll hooks (Hell's Gate / SysWhispers)"
        mitre_att_ck = "T1106"
    strings:
        // mov r10, rcx ; mov eax, <ssn> ; [optional test/jne to KUSER_SHARED_DATA] ; syscall | sysenter
        $stub_syscall = { 4C 8B D1 B8 ?? ?? 00 00 [0-24] 0F 05 }
        $stub_sysenter = { 4C 8B D1 B8 ?? ?? 00 00 [0-24] 0F 34 }
    condition:
        any of them
}

rule Heavens_Gate_FarJump {
    meta:
        description = "WoW64 Heaven's Gate: far transfer into the 64-bit code segment 0x33"
        mitre_att_ck = "T1106"
    strings:
        $far_jmp = { EA ?? ?? ?? ?? 33 00 }
        $push_retf = { 6A 33 E8 00 00 00 00 [0-16] CB }
        $wow64_ptr = { 64 A1 C0 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Process_Injection {
    meta:
        description = "Classic process injection API combination"
        mitre_att_ck = "T1055"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtCreateThreadEx"
        $a5 = "RtlCreateUserThread"
    condition:
        ($a1 and $a2) and any of ($a3, $a4, $a5)
}

rule Shellcode_Indicators {
    meta:
        description = "RWX memory allocation with execution transfer patterns"
        mitre_att_ck = "T1055.012"
    strings:
        $alloc = "VirtualAlloc"
        $protect = "VirtualProtect"
        $copy1 = "memcpy"
        $copy2 = "RtlMoveMemory"
        $copy3 = "RtlCopyMemory"
    condition:
        ($alloc or $protect) and any of ($copy*)
}

rule Persistence_Registry {
    meta:
        description = "Registry-based persistence via Run keys"
        mitre_att_ck = "T1547.001"
    strings:
        $api1 = "RegSetValueEx" wide ascii
        $api2 = "RegCreateKeyEx" wide ascii
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii nocase
    condition:
        any of ($api*) and any of ($run*)
}

rule Packed_Section_Names {
    meta:
        description = "PE section names matching known packer signatures (section table only)"
        mitre_att_ck = "T1027.002"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".themida" or pe.sections[i].name == ".vmp0" or
            pe.sections[i].name == ".vmp1" or pe.sections[i].name == ".aspack" or
            pe.sections[i].name == "MPRESS1" or pe.sections[i].name == "MPRESS2" or
            pe.sections[i].name == ".enigma" or pe.sections[i].name == ".petite"
        )
}

rule Credential_Harvest {
    meta:
        description = "Credential harvesting API calls and target strings"
        mitre_att_ck = "T1555"
    strings:
        $a1 = "CredReadA" wide ascii
        $a2 = "CredReadW" wide ascii
        $a3 = "CryptUnprotectData" wide ascii
        $t1 = "lsass.exe" wide ascii nocase
        $t2 = "mimikatz" wide ascii nocase
        $t3 = "sekurlsa" wide ascii nocase
    condition:
        any of ($a*) or 2 of ($t*)
}

rule Network_Beacon {
    meta:
        description = "HTTP/network beacon API combination for C2 communication"
        mitre_att_ck = "T1071.001"
    strings:
        $a1 = "InternetOpenA" wide ascii
        $a2 = "InternetOpenW" wide ascii
        $a3 = "InternetOpenUrlA" wide ascii
        $a4 = "HttpSendRequestA" wide ascii
        $a5 = "URLDownloadToFileA" wide ascii
        $a6 = "URLDownloadToFileW" wide ascii
        $a7 = "WinHttpOpen" wide ascii
    condition:
        2 of them
}
