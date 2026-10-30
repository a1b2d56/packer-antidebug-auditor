"""Machine learning model integration for static PE packer and evasion classification."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

FEATURE_NAMES = [
    "section_count",
    "max_entropy",
    "mean_entropy",
    "high_entropy_sections",
    "rwx_sections_count",
    "size_delta_flags_count",
    "packer_section_flags_count",
    "overlay_present",
    "overlay_entropy",
    "anti_debug_import_count",
    "sparse_iat_flag",
    "suspicious_strings_count",
    "tls_callbacks_present",
    "opcode_checks_count",
    "direct_syscall_count",
    "header_anomaly_count",
    "risk_score",
]


N_FEATURES = len(FEATURE_NAMES)


class ModelFeatureMismatch(ValueError):
    """Raised when a serialized model does not match the 17-feature FEATURE_NAMES contract."""


def metadata_path(model_path: str) -> str:
    """Return the sidecar metadata path for a model file (e.g. packer_model.meta.json)."""
    base, _ext = os.path.splitext(model_path)
    return base + ".meta.json"


def write_model_metadata(model_path: str, model: Any = None, extra: dict | None = None) -> str:
    """Write the feature-contract sidecar next to a serialized model and return its path."""
    try:
        import sklearn
        sklearn_version = sklearn.__version__
    except ImportError:  # pragma: no cover - sklearn is required to train
        sklearn_version = None

    meta = {
        "feature_names": list(FEATURE_NAMES),
        "n_features": N_FEATURES,
        "model_class": type(model).__name__ if model is not None else None,
        "sklearn_version": sklearn_version,
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **(extra or {}),
    }
    path = metadata_path(model_path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return path


def validate_model(model: Any, model_path: str | None = None) -> None:
    """Verify a loaded model agrees with FEATURE_NAMES in dimension, names and order."""
    n_in = getattr(model, "n_features_in_", None)
    if n_in is not None and int(n_in) != N_FEATURES:
        raise ModelFeatureMismatch(
            f"model expects {n_in} features but the auditor produces {N_FEATURES} ({model_path or 'model'})"
        )

    names_in = getattr(model, "feature_names_in_", None)
    if names_in is not None and list(names_in) != FEATURE_NAMES:
        raise ModelFeatureMismatch("model feature_names_in_ differ from auditor FEATURE_NAMES order")

    if model_path:
        meta_file = metadata_path(model_path)
        if os.path.exists(meta_file):
            with open(meta_file, encoding="utf-8") as fh:
                meta = json.load(fh)
            if meta.get("feature_names") != FEATURE_NAMES:
                raise ModelFeatureMismatch(f"feature names in {meta_file} differ from auditor FEATURE_NAMES")


def vectorize_features(features_dict: dict) -> list[float]:
    """Convert an extracted feature dictionary into a normalized numerical feature vector."""
    vec = []
    for name in FEATURE_NAMES:
        val = features_dict.get(name, 0.0)
        try:
            vec.append(float(val))
        except (ValueError, TypeError):
            vec.append(0.0)
    return vec


def load_model(model_path: str) -> Any:
    """Load a serialized scikit-learn model pipeline from disk via joblib."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    import joblib

    model = joblib.load(model_path)
    validate_model(model, model_path)
    return model


def predict_sample(model: Any, features_dict: dict) -> dict:
    """Run model inference on a single binary's extracted feature vector."""
    vec = vectorize_features(features_dict)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba([vec])[0]
        # Assuming class 1 is PACKED/SUSPICIOUS, class 0 is BENIGN
        if len(probs) > 1:
            packed_prob = float(probs[1])
        else:
            packed_prob = float(probs[0])
    else:
        pred = model.predict([vec])[0]
        packed_prob = 1.0 if pred == 1 else 0.0

    is_packed = packed_prob >= 0.5
    label = "PACKED" if is_packed else "BENIGN"
    confidence = round(abs(packed_prob - 0.5) * 2, 4)

    return {
        "probability": round(packed_prob, 4),
        "label": label,
        "confidence": confidence,
    }
