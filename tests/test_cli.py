import os
import tempfile
import unittest
from types import SimpleNamespace

from auditor.report import CSV_FEATURE_COLUMNS, extract_feature_dict
from cli import audit_pe_file, audit_pe_worker, extract_pe_metadata, find_target_files


class TestCLI(unittest.TestCase):
    def test_extract_pe_metadata(self):
        mock_pe = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(Machine=0x8664),
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000, ImageBase=0x140000000),
            sections=[1, 2, 3, 4],
        )
        meta = extract_pe_metadata(mock_pe)
        self.assertEqual(meta["arch"], "x86_64 (64-bit)")
        self.assertEqual(meta["entry_point"], 0x1000)
        self.assertEqual(meta["image_base"], 0x140000000)
        self.assertEqual(meta["section_count"], 4)

    def test_find_target_files_single_file(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            tmp_name = f.name

        try:
            files = find_target_files(tmp_name)
            self.assertEqual(len(files), 1)
            self.assertEqual(os.path.abspath(files[0]), os.path.abspath(tmp_name))
        finally:
            os.remove(tmp_name)

    def test_find_target_files_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            f1 = os.path.join(tmp_dir, "sample1.exe")
            f2 = os.path.join(tmp_dir, "sample2.dll")
            f3 = os.path.join(tmp_dir, "readme.txt")

            for path in (f1, f2, f3):
                with open(path, "wb") as f:
                    f.write(b"test")

            files = find_target_files(tmp_dir, recursive=False)
            self.assertEqual(len(files), 2)
            self.assertTrue(any(f.endswith("sample1.exe") for f in files))
            self.assertTrue(any(f.endswith("sample2.dll") for f in files))

    def test_audit_pe_file_handles_invalid_file_gracefully(self):
        import contextlib
        import io

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"not a valid PE header")
            tmp_name = f.name

        try:
            with contextlib.redirect_stderr(io.StringIO()):
                res = audit_pe_file(tmp_name)
            self.assertIsNone(res)
        finally:
            os.remove(tmp_name)

    def test_extract_feature_dict_generates_all_columns(self):
        sample_report = {
            "file_path": "sample.exe",
            "metadata": {"arch": "x86_64", "section_count": 5},
            "sections": [
                {"name": ".text", "entropy": 6.2, "likely_packed": False},
                {"name": ".data", "entropy": 7.5, "likely_packed": True},
            ],
            "heuristics": {
                "rwx_sections": [{"name": ".data"}],
                "size_deltas": [],
                "packer_section_names": [],
                "overlay": {"size": 1024, "entropy": 7.8},
                "iat_density": [],
                "header_anomalies": [{"reason": "TimeDateStamp is 0"}],
            },
            "anti_analysis": {
                "imports": [{"api": "IsDebuggerPresent"}],
                "strings": [{"string": "ghidra"}],
                "tls_callbacks": [],
                "opcodes": [],
                "direct_syscalls": [{"reason": "Direct syscall"}],
            },
            "verdict": {"score": 8, "verdict": "HIGH"},
        }
        features = extract_feature_dict(sample_report)
        for col in CSV_FEATURE_COLUMNS:
            self.assertIn(col, features)

        self.assertEqual(features["high_entropy_sections"], 1)
        self.assertEqual(features["rwx_sections_count"], 1)
        self.assertEqual(features["direct_syscall_count"], 1)
        self.assertEqual(features["header_anomaly_count"], 1)
        self.assertEqual(features["risk_score"], 8)
        self.assertEqual(features["verdict"], "HIGH")

    def test_audit_pe_worker_handles_invalid_file(self):
        import contextlib
        import io

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"garbage content")
            tmp_name = f.name

        try:
            with contextlib.redirect_stderr(io.StringIO()):
                res = audit_pe_worker(tmp_name)
            self.assertIsNone(res)
        finally:
            os.remove(tmp_name)


if __name__ == "__main__":
    unittest.main()
