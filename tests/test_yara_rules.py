"""Compile and behaviour checks for rules/*.yar (synthetic buffers only)."""

import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE_FILES = sorted(glob.glob(os.path.join(ROOT, "rules", "*.yar")))

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

MZ = b"MZ" + b"\x00" * 62


def _rules():
    return yara.compile(filepaths={os.path.basename(p): p for p in RULE_FILES})


def _matched(data: bytes) -> set[str]:
    return {m.rule for m in _rules().match(data=data)}


class TestRuleSyntax(unittest.TestCase):
    def test_rule_files_present(self):
        names = {os.path.basename(p) for p in RULE_FILES}
        self.assertTrue({"basic.yar", "crypters.yar"}.issubset(names))

    def test_no_quoted_hex_escapes(self):
        # Byte signatures must use { .. } hex strings, never "\x00"-style text escapes.
        quoted_escape = re.compile(r'"[^"\n]*\\x[0-9A-Fa-f]{2}[^"\n]*"')
        for path in RULE_FILES:
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    if line.strip().startswith(("//", "*", "/*")):
                        continue
                    with self.subTest(file=os.path.basename(path), line=lineno):
                        self.assertIsNone(quoted_escape.search(line), line)

    def test_every_rule_has_mitre_and_description(self):
        for path in RULE_FILES:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for body in re.findall(r"rule\s+(\w+)\s*\{(.*?)\n\}", text, re.S):
                name, content = body
                if name == "IsPE":
                    continue
                with self.subTest(rule=name):
                    self.assertIn("description", content)
                    self.assertRegex(content, r'mitre_att_ck\s*=\s*"T\d{4}(\.\d{3})?"')


@unittest.skipIf(yara is None, "yara-python not installed")
class TestRuleBehaviour(unittest.TestCase):
    def test_all_rules_compile(self):
        self.assertIsNotNone(_rules())

    def test_benign_buffer_matches_nothing_specific(self):
        benign = MZ + b"\x55\x48\x89\xe5\x90\xc9\xc3" * 512 + b"Hello world, regular program text." * 20
        self.assertEqual(_matched(benign) - {"IsPE"}, set())

    def test_direct_syscall_requires_adjacency(self):
        stub = MZ + b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3"
        self.assertIn("Direct_Syscall_Stub", _matched(stub))
        far_apart = MZ + b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00" + b"\x90" * 200 + b"\x0f\x05"
        self.assertNotIn("Direct_Syscall_Stub", _matched(far_apart))

    def test_heavens_gate_far_jump(self):
        self.assertIn("Heavens_Gate_FarJump", _matched(MZ + b"\xea\x10\x20\x30\x40\x33\x00"))
        self.assertNotIn("Heavens_Gate_FarJump", _matched(MZ + b"\xea\x10\x20\x30\x40\x23\x00"))

    def test_guloader_stub(self):
        nsis = b"\xef\xbe\xad\xdeNullsoftInst"
        timing = b"\x0f\x31\x89\xc1\x0f\xa2\x90\x90\x0f\x31"
        djb2 = b"\xb8\x05\x15\x00\x00"
        self.assertIn("GuLoader_NSIS_Shellcode_Stub", _matched(MZ + nsis + b"\x00" * 64 + timing + djb2))
        # NSIS installers alone are benign
        self.assertNotIn("GuLoader_NSIS_Shellcode_Stub", _matched(MZ + nsis + b"\x00" * 64 + djb2))

    def test_smokeloader_stub(self):
        opaque = b"\x74\x03\x75\x01\xe8" * 10
        geofence = b"\x66\x3d\x19\x04\x66\x3d\x22\x04"
        self.assertIn("SmokeLoader_Stub_Traits", _matched(MZ + opaque + geofence))
        self.assertNotIn("SmokeLoader_Stub_Traits", _matched(MZ + b"\x74\x03\x75\x01" * 3 + geofence))

    def test_darkgate_autoit_loader(self):
        script = (
            b"AU3!EA06 ... $p = \"0x4D5A90000300\" ... "
            b"DllCall(\"kernel32.dll\", \"ptr\", \"VirtualAlloc\", ...)"
        )
        self.assertIn("DarkGate_AutoIt_Loader", _matched(script))
        self.assertNotIn("DarkGate_AutoIt_Loader", _matched(b"AU3!EA06 MsgBox(0, \"hi\", \"there\")"))

    def test_packed_section_names_use_section_table(self):
        # The bare string ".vmp0" in data (not a section name) must not match.
        self.assertNotIn("Packed_Section_Names", _matched(MZ + b"text mentioning .vmp0 here"))


if __name__ == "__main__":
    unittest.main()
