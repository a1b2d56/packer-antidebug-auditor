"""Tests for MITRE ATT&CK technique mapping module."""

from __future__ import annotations

import re
import unittest

from auditor.mitre_map import TECHNIQUE_MAP, get_technique, enrich_reasons


class TestMitreMap(unittest.TestCase):
    """Validate the static ATT&CK mapping and helper functions."""

    def test_all_technique_ids_follow_pattern(self):
        """Every mapped technique ID should match Txxxx or Txxxx.xxx."""
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for key, (tid, _name) in TECHNIQUE_MAP.items():
            with self.subTest(key=key):
                self.assertRegex(tid, pattern, f"Bad technique ID for '{key}': {tid}")

    def test_all_technique_names_non_empty(self):
        for key, (_tid, name) in TECHNIQUE_MAP.items():
            with self.subTest(key=key):
                self.assertTrue(len(name) > 0, f"Empty name for '{key}'")

    def test_get_technique_known_key(self):
        result = get_technique("packed_entropy")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "T1027.002")

    def test_get_technique_unknown_key(self):
        self.assertIsNone(get_technique("totally_fake_signal"))

    def test_enrich_reasons_basic(self):
        reasons = ["high entropy section found", "W^X section detected"]
        keys = ["packed_entropy", "rwx_section"]
        enriched = enrich_reasons(reasons, keys)
        self.assertEqual(len(enriched), 2)
        self.assertEqual(enriched[0]["mitre_id"], "T1027.002")
        self.assertEqual(enriched[1]["mitre_id"], "T1055.012")
        self.assertEqual(enriched[0]["reason"], "high entropy section found")

    def test_enrich_reasons_unknown_key_yields_none(self):
        enriched = enrich_reasons(["some reason"], ["unknown_key"])
        self.assertEqual(len(enriched), 1)
        self.assertIsNone(enriched[0]["mitre_id"])
        self.assertIsNone(enriched[0]["mitre_name"])

    def test_enrich_reasons_empty(self):
        self.assertEqual(enrich_reasons([], []), [])


if __name__ == "__main__":
    unittest.main()
