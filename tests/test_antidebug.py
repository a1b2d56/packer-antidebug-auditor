import unittest
from types import SimpleNamespace

from auditor.antidebug import (
    iat_density_flags,
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


if __name__ == "__main__":
    unittest.main()
