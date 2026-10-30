"""Tests for sensitivity profiles, heuristic confidence and MITRE coverage of signal keys."""

import re
import unittest

from auditor.mitre_map import SECONDARY_TECHNIQUES, TECHNIQUE_MAP, attack_url
from auditor.scoring import (
    PROFILES,
    SIGNAL_KEYS,
    classify_score,
    compute_verdict,
    get_profile,
)

EMPTY = dict(
    entropy_results=[],
    size_flags=[],
    name_flags=[],
    count_flag=None,
    rwx_flags=[],
    ep_flags=[],
    overlay_flag=None,
    import_hits=[],
    iat_flags=[],
    string_hits=[],
    tls_flags=[],
    opcode_flags=[],
)


def _verdict(profile="balanced", **overrides):
    return compute_verdict(**{**EMPTY, **overrides}, profile=profile)


class TestProfiles(unittest.TestCase):
    def test_default_profile_is_balanced(self):
        result = compute_verdict(**EMPTY)
        self.assertEqual(result["profile"], "balanced")
        self.assertEqual(result["thresholds"], {"medium": 3, "high": 7})

    def test_balanced_scores_stay_integers(self):
        result = _verdict(rwx_flags=[{"reason": "x"}], import_hits=[{"api": "a"}] * 2)
        self.assertEqual(result["score"], 5)
        self.assertIsInstance(result["score"], int)

    def test_profile_thresholds(self):
        # Score 5 = rwx (3) + 2 anti-debug imports (2)
        flags = dict(rwx_flags=[{"reason": "x"}], import_hits=[{"api": "a"}] * 2)
        self.assertEqual(_verdict("balanced", **flags)["verdict"], "MEDIUM")
        self.assertEqual(_verdict("aggressive", **flags)["verdict"], "HIGH")
        self.assertEqual(_verdict("conservative", **flags)["verdict"], "MEDIUM")

    def test_conservative_downweights_weak_signals(self):
        flags = dict(count_flag={"reason": "few sections"}, overlay_flag={"size": 10, "likely_packed": True})
        self.assertEqual(_verdict("balanced", **flags)["score"], 3)
        self.assertEqual(_verdict("conservative", **flags)["score"], 2.25)
        self.assertEqual(_verdict("conservative", **flags)["verdict"], "LOW")

    def test_aggressive_upweights_evasion_signals(self):
        result = _verdict("aggressive", syscall_flags=[{"reason": "stub"}])
        self.assertEqual(result["score"], 3.75)

    def test_classify_score_boundaries(self):
        for name, prof in PROFILES.items():
            with self.subTest(profile=name):
                self.assertEqual(classify_score(prof.medium - 0.01, name), "LOW")
                self.assertEqual(classify_score(prof.medium, name), "MEDIUM")
                self.assertEqual(classify_score(prof.high, name), "HIGH")

    def test_invalid_profile_raises(self):
        with self.assertRaises(ValueError):
            get_profile("paranoid")
        with self.assertRaises(ValueError):
            _verdict("paranoid")

    def test_profile_name_case_insensitive(self):
        self.assertEqual(get_profile("Aggressive").name, "aggressive")


class TestConfidence(unittest.TestCase):
    def test_interval_ordered_and_contains_score(self):
        result = _verdict(
            entropy_results=[{"likely_packed": True}],
            rwx_flags=[{"reason": "x"}],
            tls_flags=[{"reason": "tls"}],
        )
        lo, hi = result["score_interval"]
        self.assertLessEqual(lo, result["score"])
        self.assertEqual(hi, result["score"])
        self.assertEqual(lo, 5)  # removing either 3-point category

    def test_confidence_in_unit_range(self):
        for flags in (
            {},
            {"rwx_flags": [{"reason": "x"}]},
            {"rwx_flags": [{"reason": "x"}], "name_flags": [{"reason": "n"}], "import_hits": [{"api": "a"}] * 3},
        ):
            with self.subTest(flags=list(flags)):
                conf = _verdict(**flags)["confidence"]
                self.assertGreaterEqual(conf, 0.0)
                self.assertLessEqual(conf, 1.0)

    def test_single_signal_verdict_is_unstable(self):
        result = _verdict(rwx_flags=[{"reason": "x"}])
        self.assertEqual(result["verdict"], "MEDIUM")
        self.assertFalse(result["verdict_stable"])
        self.assertLess(result["confidence"], 0.5)

    def test_many_independent_signals_are_stable(self):
        result = _verdict(
            entropy_results=[{"likely_packed": True}],
            rwx_flags=[{"reason": "x"}],
            name_flags=[{"reason": "n"}],
            import_hits=[{"api": "a"}] * 3,
            syscall_flags=[{"reason": "s"}],
        )
        self.assertEqual(result["verdict"], "HIGH")
        self.assertTrue(result["verdict_stable"])
        self.assertGreater(result["confidence"], 0.9)


class TestSignalKeyMapping(unittest.TestCase):
    def test_every_signal_key_is_mapped(self):
        for key in SIGNAL_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, TECHNIQUE_MAP)

    def test_secondary_ids_valid(self):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for key, extras in SECONDARY_TECHNIQUES.items():
            self.assertIn(key, TECHNIQUE_MAP)
            for tid, name in extras:
                self.assertRegex(tid, pattern)
                self.assertTrue(name)

    def test_opcode_kinds_split_into_signal_keys(self):
        result = _verdict(opcode_flags=[
            {"kind": "timing", "reason": "rdtsc"},
            {"kind": "vm", "reason": "cpuid"},
            {"kind": "antidebug", "reason": "int2d"},
        ])
        self.assertEqual(result["score"], 2)
        self.assertEqual(set(result["signal_keys"]), {"timing_opcode", "vm_opcode", "antidebug_opcode"})
        ids = {t["signal_key"]: t["mitre_id"] for t in result["mitre_techniques"]}
        self.assertEqual(ids["vm_opcode"], "T1497.001")
        self.assertEqual(ids["timing_opcode"], "T1497.003")
        self.assertEqual(ids["antidebug_opcode"], "T1622")

    def test_header_timestamp_split(self):
        result = _verdict(header_flags=[
            {"kind": "timestamp", "reason": "TimeDateStamp is 0"},
            {"kind": "aslr_conflict", "reason": "ASLR conflict"},
        ])
        self.assertEqual(result["signal_keys"], ["header_timestamp", "header_anomaly"])
        self.assertEqual(result["mitre_techniques"][0]["mitre_id"], "T1070.006")

    def test_syscall_variant_keys_propagate(self):
        result = _verdict(syscall_flags=[
            {"reason": "TartarusGate ...", "signal_key": "tartarus_gate"},
            {"reason": "Heaven's Gate ...", "signal_key": "heavens_gate"},
        ])
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["signal_keys"], ["tartarus_gate", "heavens_gate"])
        self.assertEqual(result["mitre_techniques"][1]["secondary"][0]["mitre_id"], "T1027")

    def test_corrected_mappings(self):
        self.assertEqual(TECHNIQUE_MAP["entry_point_anomaly"][0], "T1027.002")
        self.assertEqual(TECHNIQUE_MAP["tls_callback"][0], "T1622")
        self.assertEqual(TECHNIQUE_MAP["anti_debug_import"][0], "T1622")

    def test_attack_url_subtechnique(self):
        self.assertEqual(attack_url("T1027.002"), "https://attack.mitre.org/techniques/T1027/002/")
        self.assertEqual(attack_url("T1106"), "https://attack.mitre.org/techniques/T1106/")


if __name__ == "__main__":
    unittest.main()
