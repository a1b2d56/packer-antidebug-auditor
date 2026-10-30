from __future__ import annotations

import logging
from pathlib import Path

from server.config import ROOT_DIR

try:
    import yara
except ImportError:  # yara-python is an optional dependency of the web extra
    yara = None

logger = logging.getLogger(__name__)

RULES_DIR = ROOT_DIR / "rules"
YARA_MATCH_TIMEOUT_S = 30

_GLOBAL_YARA_COMPILED = None
_COMPILE_ATTEMPTED = False


def load_yara_rules(force: bool = False):
    """Compile every rules/*.yar once; a failed compile is cached so it is not retried per scan."""
    global _GLOBAL_YARA_COMPILED, _COMPILE_ATTEMPTED
    if _COMPILE_ATTEMPTED and not force:
        return _GLOBAL_YARA_COMPILED
    _COMPILE_ATTEMPTED = True
    _GLOBAL_YARA_COMPILED = None

    if yara is None:
        logger.warning("yara-python is not installed; YARA scanning disabled")
        return None

    rule_files = {}
    if RULES_DIR.exists():
        for rule_file in sorted(RULES_DIR.glob("*.yar")):
            rule_files[rule_file.stem] = str(rule_file)

    if not rule_files:
        return None

    try:
        _GLOBAL_YARA_COMPILED = yara.compile(filepaths=rule_files)
    except yara.Error as e:
        logger.error("Error compiling YARA rules: %s", e)
    return _GLOBAL_YARA_COMPILED


def scan_file_with_yara(file_path: str | Path):
    rules = load_yara_rules()
    if not rules:
        return []

    try:
        matches = rules.match(str(file_path), timeout=YARA_MATCH_TIMEOUT_S)
    except yara.TimeoutError:
        logger.warning("YARA scan timed out after %ss for %s", YARA_MATCH_TIMEOUT_S, file_path)
        return []
    except yara.Error as e:
        logger.error("Error scanning with YARA: %s", e)
        return []

    return [
        {
            "rule": match.rule,
            "namespace": match.namespace,
            "description": match.meta.get("description", ""),
            "mitre_id": match.meta.get("mitre_att_ck"),
            "confidence": match.meta.get("confidence"),
            "tags": list(match.tags),
        }
        for match in matches
    ]
