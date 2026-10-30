"""Edge cases for entropy precision and tiny / zero-byte sections."""

import os
import unittest
from types import SimpleNamespace

from auditor.entropy import MIN_RELIABLE_ENTROPY_BYTES, section_entropies, shannon_entropy


def _pe(*blobs: bytes):
    sections = [
        SimpleNamespace(
            Name=f".s{i}".encode() + b"\x00",
            get_data=(lambda b=blob: b),
            SizeOfRawData=len(blob),
            Misc_VirtualSize=len(blob),
            Characteristics=0x60000020,
        )
        for i, blob in enumerate(blobs)
    ]
    return SimpleNamespace(sections=sections)


class TestEntropyEdges(unittest.TestCase):
    def test_single_byte_is_zero(self):
        self.assertEqual(shannon_entropy(b"\x41"), 0.0)

    def test_uniform_256_bytes_is_exactly_eight(self):
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=9)

    def test_memoryview_input(self):
        data = bytes(range(256))
        self.assertAlmostEqual(shannon_entropy(memoryview(data)), 8.0, places=9)

    def test_zero_byte_section(self):
        (sec,) = section_entropies(_pe(b""))
        self.assertEqual(sec["entropy"], 0.0)
        self.assertFalse(sec["likely_packed"])
        self.assertFalse(sec["entropy_reliable"])

    def test_tiny_random_section_not_flagged(self):
        # 255 distinct bytes => entropy ~7.99 but too small to be meaningful
        (sec,) = section_entropies(_pe(bytes(range(MIN_RELIABLE_ENTROPY_BYTES - 1))))
        self.assertGreater(sec["entropy"], 7.0)
        self.assertFalse(sec["entropy_reliable"])
        self.assertFalse(sec["likely_packed"])

    def test_reliable_random_section_flagged(self):
        (sec,) = section_entropies(_pe(bytes(range(256)) * 4))
        self.assertTrue(sec["entropy_reliable"])
        self.assertTrue(sec["likely_packed"])
        self.assertEqual(sec["normalized_entropy"], 1.0)

    def test_flag_agrees_with_reported_rounding(self):
        for sec in section_entropies(_pe(os.urandom(4096), b"\x00" * 4096, bytes(range(256)) * 2)):
            with self.subTest(name=sec["name"]):
                self.assertEqual(sec["likely_packed"], sec["entropy_reliable"] and sec["entropy"] > 7.0)


if __name__ == "__main__":
    unittest.main()
