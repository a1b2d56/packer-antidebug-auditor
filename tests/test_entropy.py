import os
import unittest

from auditor.entropy import shannon_entropy


class TestEntropy(unittest.TestCase):
    def test_zero_entropy_for_uniform_bytes(self):
        self.assertEqual(shannon_entropy(b"\x00" * 1000), 0.0)

    def test_high_entropy_for_random_bytes(self):
        data = os.urandom(10000)
        self.assertGreater(shannon_entropy(data), 7.5)

    def test_empty_data_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_two_symbol_alternation_has_entropy_one(self):
        # Equal counts of exactly two distinct byte values -> exactly 1 bit of entropy
        data = bytes([0, 1] * 500)
        self.assertAlmostEqual(shannon_entropy(data), 1.0, places=7)


if __name__ == "__main__":
    unittest.main()
