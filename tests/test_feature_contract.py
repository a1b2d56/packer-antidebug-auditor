"""Guards for the 17-feature ML contract shared by model.py, report.py and the trained model."""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from auditor.model import (
    FEATURE_NAMES,
    N_FEATURES,
    ModelFeatureMismatch,
    load_model,
    metadata_path,
    validate_model,
)
from auditor.report import CSV_FEATURE_COLUMNS, extract_feature_dict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "models", "packer_model.joblib")


class TestFeatureContract(unittest.TestCase):
    def test_feature_count_is_17(self):
        self.assertEqual(N_FEATURES, 17)
        self.assertEqual(len(set(FEATURE_NAMES)), 17)

    def test_csv_columns_match_feature_order(self):
        self.assertEqual(CSV_FEATURE_COLUMNS[0:2], ["file_path", "arch"])
        self.assertEqual(CSV_FEATURE_COLUMNS[-1], "verdict")
        self.assertEqual(CSV_FEATURE_COLUMNS[2:-1], FEATURE_NAMES)

    def test_extract_feature_dict_covers_every_feature(self):
        features = extract_feature_dict({})
        self.assertTrue(set(FEATURE_NAMES).issubset(features))
        self.assertEqual(list(features), CSV_FEATURE_COLUMNS)

    def test_validate_rejects_wrong_dimension(self):
        with self.assertRaises(ModelFeatureMismatch):
            validate_model(SimpleNamespace(n_features_in_=20))

    def test_validate_rejects_reordered_names(self):
        names = list(reversed(FEATURE_NAMES))
        with self.assertRaises(ModelFeatureMismatch):
            validate_model(SimpleNamespace(n_features_in_=17, feature_names_in_=names))

    def test_validate_accepts_matching_model(self):
        validate_model(SimpleNamespace(n_features_in_=17, feature_names_in_=list(FEATURE_NAMES)))

    def test_validate_checks_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_file = os.path.join(tmp, "m.joblib")
            with open(metadata_path(model_file), "w", encoding="utf-8") as fh:
                json.dump({"feature_names": FEATURE_NAMES[:-1]}, fh)
            with self.assertRaises(ModelFeatureMismatch):
                validate_model(SimpleNamespace(n_features_in_=17), model_file)

    @unittest.skipUnless(os.path.exists(MODEL_PATH), "trained model not present")
    def test_shipped_model_loads_and_matches(self):
        try:
            import sklearn  # noqa: F401
        except ImportError:
            self.skipTest("scikit-learn not installed")
        model = load_model(MODEL_PATH)
        self.assertEqual(model.n_features_in_, N_FEATURES)
        meta_file = metadata_path(MODEL_PATH)
        if os.path.exists(meta_file):
            with open(meta_file, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["feature_names"], FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
