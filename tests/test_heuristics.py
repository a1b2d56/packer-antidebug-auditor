import unittest
from types import SimpleNamespace

from auditor.heuristics import (
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE,
    entry_point_flags,
    overlay_flags,
    pe_header_anomaly_flags,
    rwx_section_flags,
    section_count_flag,
    section_name_flags,
    size_delta_flags,
)


class TestHeuristics(unittest.TestCase):
    def test_size_delta_flags_empty_raw_section(self):
        sections = [
            {"name": "UPX0", "raw_size": 0, "virtual_size": 0x10000},
            {"name": ".text", "raw_size": 0x1000, "virtual_size": 0x1000},
        ]
        flags = size_delta_flags(sections)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["name"], "UPX0")

    def test_size_delta_ignores_benign_bss(self):
        sections = [
            {"name": ".bss", "raw_size": 0, "virtual_size": 0x2000},
        ]
        flags = size_delta_flags(sections)
        self.assertEqual(len(flags), 0)

    def test_size_delta_extreme_ratio(self):
        sections = [
            {"name": ".data", "raw_size": 100, "virtual_size": 5000},
        ]
        flags = size_delta_flags(sections)
        self.assertEqual(len(flags), 1)

    def test_section_name_flags(self):
        sections = [
            {"name": "upx1"},
            {"name": ".vmp0"},
            {"name": ".text"},
            {"name": ".rdata"},
        ]
        flags = section_name_flags(sections)
        names = [f["name"] for f in flags]
        self.assertIn("upx1", names)
        self.assertIn(".vmp0", names)
        self.assertNotIn(".text", names)

    def test_section_count_flag(self):
        mock_packed_pe = SimpleNamespace(sections=[1, 2, 3])
        self.assertIsNotNone(section_count_flag(mock_packed_pe))

        mock_normal_pe = SimpleNamespace(sections=[1, 2, 3, 4, 5])
        self.assertIsNone(section_count_flag(mock_normal_pe))

    def test_rwx_section_flags(self):
        sec_rwx = SimpleNamespace(
            Name=b".packed\x00\x00",
            Characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | 0x40000000,
        )
        sec_rx = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            Characteristics=IMAGE_SCN_MEM_EXECUTE | 0x40000000,
        )
        sec_rw = SimpleNamespace(
            Name=b".data\x00\x00\x00",
            Characteristics=IMAGE_SCN_MEM_WRITE | 0x40000000,
        )

        mock_pe = SimpleNamespace(sections=[sec_rwx, sec_rx, sec_rw])
        flags = rwx_section_flags(mock_pe)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["name"], ".packed")

    def test_entry_point_in_writable_section(self):
        sec1 = SimpleNamespace(
            Name=b".text\x00\x00\x00",
            VirtualAddress=0x1000,
            Misc_VirtualSize=0x2000,
            SizeOfRawData=0x2000,
            Characteristics=IMAGE_SCN_MEM_EXECUTE | 0x40000000,
        )
        sec2 = SimpleNamespace(
            Name=b".stub\x00\x00\x00",
            VirtualAddress=0x3000,
            Misc_VirtualSize=0x1000,
            SizeOfRawData=0x1000,
            Characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE,
        )
        mock_pe = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x3500),
            FILE_HEADER=SimpleNamespace(Characteristics=0x0102),
            sections=[sec1, sec2],
        )
        flags = entry_point_flags(mock_pe)
        self.assertTrue(any("writable section" in f["reason"] for f in flags))

    def test_section_name_flags_matches_prefixes(self):
        sections = [
            {"name": ".vmp3"},
            {"name": "upx99"},
            {"name": ".enigma_custom"},
            {"name": ".rsrc"},
        ]
        flags = section_name_flags(sections)
        names = [f["name"] for f in flags]
        self.assertIn(".vmp3", names)
        self.assertIn("upx99", names)
        self.assertIn(".enigma_custom", names)
        self.assertNotIn(".rsrc", names)

    def test_pe_header_anomaly_flags_timestomping(self):
        # TimeDateStamp = 0
        mock_pe = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(TimeDateStamp=0, Characteristics=0),
            OPTIONAL_HEADER=SimpleNamespace(DllCharacteristics=0),
            sections=[],
        )
        flags = pe_header_anomaly_flags(mock_pe)
        self.assertTrue(any("TimeDateStamp is 0" in f["reason"] for f in flags))

    def test_pe_header_anomaly_flags_aslr_conflict(self):
        # DYNAMIC_BASE enabled + RELOCS_STRIPPED set
        mock_pe = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(TimeDateStamp=1600000000, Characteristics=0x0001),
            OPTIONAL_HEADER=SimpleNamespace(DllCharacteristics=0x0040),
            sections=[],
        )
        flags = pe_header_anomaly_flags(mock_pe)
        self.assertTrue(any("DYNAMIC_BASE" in f["reason"] for f in flags))

    def test_pe_header_anomaly_flags_obfuscated_sections(self):
        sec1 = SimpleNamespace(Name=b"\x01\x02\x03\x00")
        mock_pe = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(TimeDateStamp=1600000000, Characteristics=0),
            OPTIONAL_HEADER=SimpleNamespace(DllCharacteristics=0),
            sections=[sec1],
        )
        flags = pe_header_anomaly_flags(mock_pe)
        self.assertTrue(any("non-printable" in f["reason"] for f in flags))


if __name__ == "__main__":
    unittest.main()
