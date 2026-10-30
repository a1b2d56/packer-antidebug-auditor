"""Tests for direct-syscall / SSN-resolution / Heaven's Gate variant fingerprints."""

import unittest
from types import SimpleNamespace

from auditor.antidebug import SYSCALL_PATTERNS, scan_direct_syscalls


def _pe(code: bytes, characteristics: int = 0x20000020, name: bytes = b".text\x00\x00\x00"):
    sec = SimpleNamespace(Name=name, Characteristics=characteristics, get_data=lambda: code)
    return SimpleNamespace(sections=[sec])


def _keys(code: bytes) -> list[str]:
    return [f["signal_key"] for f in scan_direct_syscalls(_pe(code))]


class TestSyscallVariants(unittest.TestCase):
    def test_tartarus_gate_offset3_hook_check(self):
        # cmp byte ptr [rax+3], 0E9h
        self.assertIn("tartarus_gate", _keys(b"\x90\x80\x78\x03\xe9\x74\x10"))

    def test_tartarus_gate_near_miss(self):
        # same compare against offset +4 is not the TartarusGate check
        self.assertNotIn("tartarus_gate", _keys(b"\x90\x80\x78\x04\xe9\x74\x10"))

    def test_halos_gate_hook_check_and_neighbour_walk(self):
        # cmp byte ptr [rax], 0E9h ; jne ... ; add rcx, 20h
        code = b"\x80\x38\xe9\x75\x10" + b"\x90" * 6 + b"\x48\x83\xc1\x20"
        self.assertIn("halos_gate", _keys(code))

    def test_halos_gate_requires_stride(self):
        code = b"\x80\x38\xe9\x75\x10" + b"\x90" * 64
        self.assertNotIn("halos_gate", _keys(code))

    def test_hells_gate_resolver_prologue_compares(self):
        code = (
            b"\x80\x38\x4c\x75\x20"      # cmp byte [rax], 4Ch
            b"\x80\x78\x01\x8b\x75\x1a"  # cmp byte [rax+1], 8Bh
            b"\x80\x78\x02\xd1\x75\x14"  # cmp byte [rax+2], D1h
            b"\x80\x78\x03\xb8"          # cmp byte [rax+3], B8h
        )
        self.assertIn("hells_gate_resolver", _keys(code))

    def test_hells_gate_resolver_incomplete(self):
        code = b"\x80\x38\x4c\x75\x20\x80\x78\x01\x8b\x75\x1a\x80\x78\x02\xd1"
        self.assertNotIn("hells_gate_resolver", _keys(code))

    def test_freshycalls_zw_prefix_filter(self):
        # cmp word ptr [rax], 'wZ'
        self.assertIn("freshycalls_sorted_ssn", _keys(b"\x66\x81\x38\x5a\x77\x75\x08"))

    def test_freshycalls_near_miss(self):
        self.assertNotIn("freshycalls_sorted_ssn", _keys(b"\x66\x81\x38\x41\x42\x75\x08"))

    def test_heavens_gate_far_jump(self):
        # jmp far 0033:40302010
        self.assertIn("heavens_gate", _keys(b"\xea\x10\x20\x30\x40\x33\x00"))

    def test_heavens_gate_push_call_retf(self):
        # push 33h ; call $+5 ; add dword [esp], 5 ; retf
        self.assertIn("heavens_gate", _keys(b"\x6a\x33\xe8\x00\x00\x00\x00\x83\x04\x24\x05\xcb"))

    def test_heavens_gate_wrong_segment(self):
        self.assertEqual(_keys(b"\xea\x10\x20\x30\x40\x23\x00"), [])

    def test_ssn_containing_newline_byte(self):
        # SSN 0x0A must still match (regression for missing re.DOTALL)
        flags = scan_direct_syscalls(_pe(b"\x4c\x8b\xd1\xb8\x0a\x00\x00\x00\x0f\x05\xc3"))
        self.assertEqual(len(flags), 1)
        self.assertIn("Direct syscall stub", flags[0]["reason"])

    def test_non_executable_section_ignored(self):
        code = b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3"
        self.assertEqual(scan_direct_syscalls(_pe(code, characteristics=0x40000040)), [])

    def test_repeated_stubs_deduplicated_per_section(self):
        stub = b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3"
        self.assertEqual(len(scan_direct_syscalls(_pe(stub * 50))), 1)

    def test_findings_carry_technique_and_signal_key(self):
        flags = scan_direct_syscalls(_pe(b"\x80\x78\x03\xe9"))
        self.assertEqual(flags[0]["section"], ".text")
        self.assertTrue(flags[0]["technique"].startswith("TartarusGate"))

    def test_patterns_have_unique_labels(self):
        labels = [label for _, label, _ in SYSCALL_PATTERNS]
        self.assertEqual(len(labels), len(set(labels)))

    def test_benign_code_has_no_findings(self):
        # Ordinary prologue/epilogue bytes
        code = b"\x55\x48\x89\xe5\x48\x83\xec\x20\x89\x7d\xfc\x8b\x45\xfc\xc9\xc3" * 32
        self.assertEqual(_keys(code), [])


if __name__ == "__main__":
    unittest.main()
