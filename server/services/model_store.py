"""Process-wide holder for the ML model, loaded once at server startup."""

import logging
from typing import Any, Optional

from auditor.model import load_model
from server.config import MODEL_PATH

logger = logging.getLogger(__name__)

_MODEL: Optional[Any] = None


def load_default_model() -> Optional[Any]:
    """Load (and feature-contract validate) the model at MODEL_PATH; None if unavailable."""
    global _MODEL
    try:
        _MODEL = load_model(str(MODEL_PATH))
        logger.info("ML model loaded from %s", MODEL_PATH)
    except Exception as exc:  # missing file, missing sklearn, or ModelFeatureMismatch
        logger.warning("ML model not loaded (%s): %s", MODEL_PATH, exc)
        _MODEL = None
    return _MODEL


def get_model() -> Optional[Any]:
    return _MODEL


def set_model(model: Optional[Any]) -> None:
    global _MODEL
    _MODEL = model
