import unittest
from types import SimpleNamespace

from auditor.model import FEATURE_NAMES, load_model, predict_sample, vectorize_features


class MockSklearnModel:
    def __init__(self, proba: float):
        self.proba = proba

    def predict_proba(self, X):
        return [[1.0 - self.proba, self.proba]]

    def predict(self, X):
        return [1 if self.proba >= 0.5 else 0]


class TestModel(unittest.TestCase):
    def test_vectorize_features_length_and_order(self):
        sample_dict = {
            "section_count": 5,
            "max_entropy": 7.4,
            "mean_entropy": 5.1,
            "high_entropy_sections": 2,
            "rwx_sections_count": 1,
            "risk_score": 8,
        }
        vec = vectorize_features(sample_dict)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertEqual(vec[0], 5.0)  # section_count
        self.assertEqual(vec[1], 7.4)  # max_entropy
        self.assertEqual(vec[-1], 8.0)  # risk_score

    def test_predict_sample_packed(self):
        mock_model = MockSklearnModel(proba=0.92)
        sample_dict = {"max_entropy": 7.9, "risk_score": 9}
        result = predict_sample(mock_model, sample_dict)

        self.assertEqual(result["label"], "PACKED")
        self.assertEqual(result["probability"], 0.92)
        self.assertGreaterEqual(result["confidence"], 0.8)

    def test_predict_sample_benign(self):
        mock_model = MockSklearnModel(proba=0.15)
        sample_dict = {"max_entropy": 5.2, "risk_score": 0}
        result = predict_sample(mock_model, sample_dict)

        self.assertEqual(result["label"], "BENIGN")
        self.assertEqual(result["probability"], 0.15)
        self.assertGreaterEqual(result["confidence"], 0.6)

    def test_load_model_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_model("nonexistent_path_to_model.joblib")


if __name__ == "__main__":
    unittest.main()
