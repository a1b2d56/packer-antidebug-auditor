"""Aggregates static signals into a weighted LOW / MEDIUM / HIGH verdict.

No single heuristic is treated as conclusive proof. The scoring model weighs
combinations of packer and anti-analysis indicators to minimize false positives
on benign software that utilizes single legitimate APIs or compiler artifacts.

Sensitivity profiles (aggressive / balanced / conservative) shift the verdict
thresholds and scale selected signal weights. The default "balanced" profile
reproduces the original scoring exactly.

Every verdict also carries a heuristic confidence and a score interval derived
from a deterministic leave-one-category-out sensitivity analysis: the score is
recomputed with each independent signal category removed. This measures how
much the verdict depends on any single piece of evidence. It is *not* a
statistically calibrated probability, which would require a labelled corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HIGH_THRESHOLD = 7
MEDIUM_THRESHOLD = 3


@dataclass(frozen=True)
class SensitivityProfile:
    """Verdict thresholds plus per-signal-category weight multipliers."""

    name: str
    high: int
    medium: int
    weight_scale: dict[str, float] = field(default_factory=dict)
    description: str = ""

    def scale(self, category: str) -> float:
        return self.weight_scale.get(category, 1.0)


# Signal categories that indicate deliberate evasion rather than build artifacts.
_EVASION_CATEGORIES = (
    "rwx_section", "anti_debug_import", "tls_callback", "opcode", "direct_syscall",
)
# Signal categories that frequently fire on benign installers / compilers.
_WEAK_CATEGORIES = ("section_count", "overlay_data", "suspicious_string")

PROFILES: dict[str, SensitivityProfile] = {
    "aggressive": SensitivityProfile(
        name="aggressive",
        high=5,
        medium=2,
        weight_scale={c: 1.25 for c in _EVASION_CATEGORIES},
        description="Threat hunting: lower thresholds, evasion signals weighted x1.25.",
    ),
    "balanced": SensitivityProfile(
        name="balanced",
        high=HIGH_THRESHOLD,
        medium=MEDIUM_THRESHOLD,
        description="Default triage profile (original weights and thresholds).",
    ),
    "conservative": SensitivityProfile(
        name="conservative",
        high=9,
        medium=4,
        weight_scale={c: 0.75 for c in _WEAK_CATEGORIES},
        description="Low false-positive mode: higher thresholds, weak signals weighted x0.75.",
    ),
}
DEFAULT_PROFILE = "balanced"

# Every signal key compute_verdict can emit (each has a MITRE ATT&CK mapping).
SIGNAL_KEYS = (
    "packed_entropy", "size_delta", "packer_section_name", "section_count", "rwx_section",
    "entry_point_anomaly", "overlay_data", "anti_debug_import", "sparse_iat",
    "suspicious_string", "tls_callback", "timing_opcode", "antidebug_opcode", "vm_opcode",
    "direct_syscall", "hells_gate_resolver", "halos_gate", "tartarus_gate",
    "freshycalls_sorted_ssn", "heavens_gate", "header_timestamp", "header_anomaly",
)

_OPCODE_KIND_KEYS = {
    "timing": ("timing_opcode", "timing"),
    "antidebug": ("antidebug_opcode", "anti-debug trap"),
    "vm": ("vm_opcode", "VM-detection"),
}


def get_profile(profile: str | SensitivityProfile) -> SensitivityProfile:
    """Resolve a profile name (case-insensitive) or pass through a profile object."""
    if isinstance(profile, SensitivityProfile):
        return profile
    try:
        return PROFILES[str(profile).lower()]
    except KeyError:
        raise ValueError(
            f"unknown sensitivity profile '{profile}' (choose from {', '.join(PROFILES)})"
        ) from None


def classify_score(score: float, profile: str | SensitivityProfile = DEFAULT_PROFILE) -> str:
    """Map a numeric score onto LOW / MEDIUM / HIGH for the given profile."""
    prof = get_profile(profile)
    if score >= prof.high:
        return "HIGH"
    if score >= prof.medium:
        return "MEDIUM"
    return "LOW"


def _as_number(value: float) -> int | float:
    """Keep integral scores as ints (balanced profile output stays byte-identical)."""
    return int(value) if float(value).is_integer() else round(value, 2)


def _header_signal_key(flag: dict) -> str:
    kind = flag.get("kind")
    if kind == "timestamp" or (kind is None and "TimeDateStamp" in flag.get("reason", "")):
        return "header_timestamp"
    return "header_anomaly"


def _confidence(score: float, verdict: str, loo_scores: list[float], prof: SensitivityProfile) -> float:
    """Blend verdict stability under leave-one-out with the margin to the nearest flip point."""
    if loo_scores:
        stability = sum(classify_score(s, prof) == verdict for s in loo_scores) / len(loo_scores)
    else:
        stability = 1.0

    if verdict == "LOW":
        margin = prof.medium - score
    elif verdict == "MEDIUM":
        margin = min(score - prof.medium + 1, prof.high - score)
    else:
        margin = score - prof.high + 1
    margin_term = max(0.0, min(1.0, margin / prof.medium))
    return round(0.5 * stability + 0.5 * margin_term, 3)


def compute_verdict(
    entropy_results: list[dict],
    size_flags: list[dict],
    name_flags: list[dict],
    count_flag: dict | None,
    rwx_flags: list[dict],
    ep_flags: list[dict],
    overlay_flag: dict | None,
    import_hits: list[dict],
    iat_flags: list[dict],
    string_hits: list[dict],
    tls_flags: list[dict],
    opcode_flags: list[dict],
    header_flags: list[dict] | None = None,
    syscall_flags: list[dict] | None = None,
    *,
    profile: str | SensitivityProfile = DEFAULT_PROFILE,
) -> dict:
    """Compute an aggregated risk score and categorical verdict from all audit checks."""
    prof = get_profile(profile)
    header_flags = header_flags or []
    syscall_flags = syscall_flags or []

    # Each entry: (category, raw points, [(reason, signal_key), ...])
    categories: list[tuple[str, int, list[tuple[str, str]]]] = []

    # Section Entropy
    packed_sections = [s for s in entropy_results if s.get("likely_packed")]
    if packed_sections:
        categories.append(("packed_entropy", 3, [
            (f"{len(packed_sections)} section(s) with entropy above threshold (> 7.0)", "packed_entropy"),
        ]))

    # Size Deltas (virtual vs raw)
    if size_flags:
        categories.append(("size_delta", 2, [
            (f"{len(size_flags)} section(s) with abnormal virtual/raw size delta", "size_delta"),
        ]))

    # Known Packer Section Names
    if name_flags:
        categories.append(("packer_section_name", 3, [
            (f"{len(name_flags)} section(s) matching known packer names", "packer_section_name"),
        ]))

    # Section Count
    if count_flag:
        categories.append(("section_count", 1, [(count_flag["reason"], "section_count")]))

    # W^X / Self-Modifying Sections
    if rwx_flags:
        categories.append(("rwx_section", 3, [
            (f"{len(rwx_flags)} section(s) with W+X characteristics (self-modifying code)", "rwx_section"),
        ]))

    # EntryPoint Placement
    if ep_flags:
        categories.append(("entry_point_anomaly", 2, [(f["reason"], "entry_point_anomaly") for f in ep_flags]))

    # Overlay Data
    if overlay_flag:
        if overlay_flag.get("likely_packed"):
            entry = ("overlay_data", 2, [(f"high-entropy overlay data detected ({overlay_flag['size']} bytes)", "overlay_data")])
        else:
            entry = ("overlay_data", 1, [(f"overlay data present ({overlay_flag['size']} bytes)", "overlay_data")])
        categories.append(entry)

    # Anti-Debug Imports
    if import_hits:
        pts = min(len(import_hits), 3)
        categories.append(("anti_debug_import", pts, [
            (f"{len(import_hits)} anti-debug API import(s) detected (+{pts} pts)", "anti_debug_import"),
        ]))

    # IAT Density & Dynamic Loader Stubs
    if iat_flags:
        categories.append(("sparse_iat", 2, [(f["reason"], "sparse_iat") for f in iat_flags]))

    # String Artifacts (VM, Sandbox, Debugger)
    if string_hits:
        pts = min(len(string_hits), 2)
        categories.append(("suspicious_string", pts, [
            (f"{len(string_hits)} suspicious tool/VM/debugger string(s) (+{pts} pts)", "suspicious_string"),
        ]))

    # TLS Callbacks
    if tls_flags:
        categories.append(("tls_callback", 2, [(f["reason"], "tls_callback") for f in tls_flags]))

    # Anti-Disassembly, Timing & VM-Detection Opcodes (one shared, capped contribution)
    if opcode_flags:
        pts = min(len(opcode_flags), 2)
        by_kind: dict[str, int] = {}
        for f in opcode_flags:
            kind = f.get("kind", "timing")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        entries = []
        for kind, (key, label) in _OPCODE_KIND_KEYS.items():
            if kind in by_kind:
                entries.append((f"{by_kind[kind]} {label} opcode(s) found", key))
        entries[0] = (f"{entries[0][0]} (+{pts} pts)", entries[0][1])
        categories.append(("opcode", pts, entries))

    # Direct Syscall / SSN Resolution / Heaven's Gate
    if syscall_flags:
        categories.append(("direct_syscall", 3, [
            (sf["reason"], sf.get("signal_key", "direct_syscall")) for sf in syscall_flags
        ]))

    # PE Header & Anti-Forensics Anomalies (timestomping, ASLR mismatch, obfuscated sections)
    if header_flags:
        pts = min(len(header_flags), 2)
        categories.append(("header_anomaly", pts, [(hf["reason"], _header_signal_key(hf)) for hf in header_flags]))

    contributions = [pts * prof.scale(cat) for cat, pts, _ in categories]
    total = sum(contributions)
    score = _as_number(total)
    verdict = classify_score(score, prof)

    reasons = [reason for _, _, entries in categories for reason, _ in entries]
    signal_keys = [key for _, _, entries in categories for _, key in entries]

    loo_scores = [_as_number(total - c) for c in contributions]
    score_interval = [min(loo_scores) if loo_scores else score, score]
    confidence = _confidence(score, verdict, loo_scores, prof)

    # Enrich with MITRE ATT&CK technique IDs
    from auditor.mitre_map import enrich_reasons
    mitre_techniques = enrich_reasons(reasons, signal_keys)

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "signal_keys": signal_keys,
        "mitre_techniques": mitre_techniques,
        "profile": prof.name,
        "thresholds": {"medium": prof.medium, "high": prof.high},
        "confidence": confidence,
        "score_interval": score_interval,
        "verdict_stable": all(classify_score(s, prof) == verdict for s in loo_scores),
    }
