import unittest

from auditor.scoring import compute_verdict


class TestScoring(unittest.TestCase):
    def test_low_verdict_with_no_signals(self):
        result = compute_verdict(
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
        self.assertEqual(result["verdict"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_medium_verdict_with_one_strong_signal(self):
        entropy_results = [{"likely_packed": True}]
        result = compute_verdict(
            entropy_results=entropy_results,
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
        self.assertEqual(result["verdict"], "MEDIUM")
        self.assertEqual(result["score"], 3)

    def test_high_verdict_with_multiple_signals(self):
        entropy_results = [{"likely_packed": True}]
        rwx_flags = [{"name": ".packed", "reason": "W+X"}]
        name_flags = [{"name": "UPX1", "reason": "UPX"}]
        import_hits = [{"api": "IsDebuggerPresent"}] * 3
        result = compute_verdict(
            entropy_results=entropy_results,
            size_flags=[],
            name_flags=name_flags,
            count_flag=None,
            rwx_flags=rwx_flags,
            ep_flags=[],
            overlay_flag=None,
            import_hits=import_hits,
            iat_flags=[],
            string_hits=[],
            tls_flags=[],
            opcode_flags=[],
        )
        self.assertEqual(result["verdict"], "HIGH")
        self.assertGreaterEqual(result["score"], 7)

    def test_import_hits_are_capped_in_contribution(self):
        # 10 import hits should contribute the same score (3) as 3 hits.
        result_a = compute_verdict(
            entropy_results=[],
            size_flags=[],
            name_flags=[],
            count_flag=None,
            rwx_flags=[],
            ep_flags=[],
            overlay_flag=None,
            import_hits=[{"api": "x"}] * 3,
            iat_flags=[],
            string_hits=[],
            tls_flags=[],
            opcode_flags=[],
        )
        result_b = compute_verdict(
            entropy_results=[],
            size_flags=[],
            name_flags=[],
            count_flag=None,
            rwx_flags=[],
            ep_flags=[],
            overlay_flag=None,
            import_hits=[{"api": "x"}] * 10,
            iat_flags=[],
            string_hits=[],
            tls_flags=[],
            opcode_flags=[],
        )
        self.assertEqual(result_a["score"], result_b["score"])

    def test_syscall_flags_add_three_points(self):
        result = compute_verdict(
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
            syscall_flags=[{"reason": "Direct syscall stub"}],
        )
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["verdict"], "MEDIUM")
        self.assertTrue(any("Direct syscall" in r for r in result["reasons"]))

    def test_header_flags_add_points(self):
        result = compute_verdict(
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
            header_flags=[{"reason": "TimeDateStamp is 0"}],
        )
        self.assertEqual(result["score"], 1)
        self.assertEqual(result["verdict"], "LOW")


if __name__ == "__main__":
    unittest.main()
