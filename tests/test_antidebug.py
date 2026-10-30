import unittest
from types import SimpleNamespace

from auditor.antidebug import (
    iat_density_flags,
    scan_direct_syscalls,
    scan_imports,
    scan_opcodes,
    scan_strings,
    scan_tls_callbacks,
)


class TestAntiDebug(unittest.TestCase):
    def test_scan_strings_ascii_and_utf16(self):
        # Sample containing ASCII VMware and UTF-16LE x64dbg
        raw = b"some prefix " + b"VMware" + b" filler " + "x64dbg".encode("utf-16le")
        hits = scan_strings(raw)
        hit_strings = [h["string"] for h in hits]
        self.assertIn("VMware", hit_strings)
        self.assertIn("x64dbg", hit_strings)

    def test_scan_imports_detects_anti_debug_apis(self):
        imp1 = SimpleNamespace(name=b"IsDebuggerPresent")
        imp2 = SimpleNamespace(name=b"NtQueryInformationProcess")
        imp3 = SimpleNamespace(name=b"CreateFileW")
        entry = SimpleNamespace(imports=[imp1, imp2, imp3])
        mock_pe = SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[entry])

        hits = scan_imports(mock_pe)
        hit_apis = [h["api"] for h in hits]
        self.assertIn("IsDebuggerPresent", hit_apis)
        self.assertIn("NtQueryInformationProcess", hit_apis)
        self.assertNotIn("CreateFileW", hit_apis)

    def test_iat_density_detects_sparse_loader(self):
        imp1 = SimpleNamespace(name=b"LoadLibraryA")
        imp2 = SimpleNamespace(name=b"GetProcAddress")
        entry = SimpleNamespace(imports=[imp1, imp2])
        mock_pe = SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[entry])

        flags = iat_density_flags(mock_pe)
        self.assertTrue(any("sparse" in f["reason"].lower() for f in flags))
        self.assertTrue(any("dynamic loader" in f["reason"].lower() for f in flags))

    def test_scan_tls_callbacks(self):
        mock_pe = SimpleNamespace(
            DIRECTORY_ENTRY_TLS=SimpleNamespace(
                struct=SimpleNamespace(AddressOfCallBacks=0x405000)
            )
        )
        flags = scan_tls_callbacks(mock_pe)
        self.assertEqual(len(flags), 1)
        self.assertIn("0x405000", flags[0]["reason"])

    def test_scan_opcodes_detects_rdtsc_in_executable_section(self):
        sec = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            Characteristics=0x20000020,  # IMAGE_SCN_MEM_EXECUTE
            get_data=lambda: b"\x90\x90\x0f\x31\xc3",  # nop, nop, rdtsc, ret
        )
        mock_pe = SimpleNamespace(sections=[sec])
        flags = scan_opcodes(mock_pe)
        self.assertEqual(len(flags), 1)
        self.assertIn("RDTSC", flags[0]["reason"])

    def test_scan_direct_syscalls_detects_edr_evasion(self):
        # x64 direct syscall stub: mov r10, rcx; mov eax, 0x18; syscall; ret
        stub = b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3"
        sec1 = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            Characteristics=0x20000020,
            get_data=lambda: stub,
        )
        mock_pe = SimpleNamespace(sections=[sec1])
        flags = scan_direct_syscalls(mock_pe)
        self.assertEqual(len(flags), 1)
        self.assertIn("Direct syscall stub", flags[0]["reason"])

    def test_scan_direct_syscalls_detects_heavens_gate(self):
        # WoW64 Heaven's Gate fast syscall pointer check: mov eax, fs:[0xC0]
        code = b"\x90\x64\xa1\xc0\x00\x00\x00\xff\xd0"
        sec = SimpleNamespace(
            Name=b".code\x00\x00\x00",
            Characteristics=0x20000020,
            get_data=lambda: code,
        )
        mock_pe = SimpleNamespace(sections=[sec])
        flags = scan_direct_syscalls(mock_pe)
        self.assertEqual(len(flags), 1)
        self.assertIn("Heaven's Gate", flags[0]["reason"])

    def test_scan_opcodes_detects_cpuid_and_rdtscp(self):
        sec = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            Characteristics=0x20000020,
            get_data=lambda: b"\x0f\xa2\x90\x0f\x01\xf9",  # cpuid + nop + rdtscp
        )
        mock_pe = SimpleNamespace(sections=[sec])
        flags = scan_opcodes(mock_pe)
        reasons = [f["reason"] for f in flags]
        self.assertTrue(any("CPUID" in r for r in reasons))
        self.assertTrue(any("RDTSCP" in r for r in reasons))

    def test_scan_strings_modern_tools(self):
        raw = b"Analysis tool: " + "ghidra".encode("utf-16le") + b" and " + b"hyper-v"
        hits = scan_strings(raw)
        hit_strings = [h["string"] for h in hits]
        self.assertIn("ghidra", hit_strings)
        self.assertIn("hyper-v", hit_strings)


if __name__ == "__main__":
    unittest.main()
