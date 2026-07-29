"""Aggregates static signals into a weighted LOW / MEDIUM / HIGH verdict.

No single heuristic is treated as conclusive proof. The scoring model weighs
combinations of packer and anti-analysis indicators to minimize false positives
on benign software that utilizes single legitimate APIs or compiler artifacts.
"""

from __future__ import annotations

HIGH_THRESHOLD = 7
MEDIUM_THRESHOLD = 3


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
) -> dict:
    """Compute an aggregated risk score and categorical verdict from all audit checks."""
    score = 0
    reasons = []

    # Section Entropy
    packed_sections = [s for s in entropy_results if s.get("likely_packed")]
    if packed_sections:
        score += 3
        reasons.append(f"{len(packed_sections)} section(s) with entropy above threshold (> 7.0)")

    # Size Deltas (virtual vs raw)
    if size_flags:
        score += 2
        reasons.append(f"{len(size_flags)} section(s) with abnormal virtual/raw size delta")

    # Known Packer Section Names
    if name_flags:
        score += 3
        reasons.append(f"{len(name_flags)} section(s) matching known packer names")

    # Section Count
    if count_flag:
        score += 1
        reasons.append(count_flag["reason"])

    # W^X / Self-Modifying Sections
    if rwx_flags:
        score += 3
        reasons.append(f"{len(rwx_flags)} section(s) with W+X characteristics (self-modifying code)")

    # EntryPoint Placement
    if ep_flags:
        score += 2
        for ep_f in ep_flags:
            reasons.append(ep_f["reason"])

    # Overlay Data
    if overlay_flag:
        if overlay_flag.get("likely_packed"):
            score += 2
            reasons.append(f"high-entropy overlay data detected ({overlay_flag['size']} bytes)")
        else:
            score += 1
            reasons.append(f"overlay data present ({overlay_flag['size']} bytes)")

    # Anti-Debug Imports
    if import_hits:
        pts = min(len(import_hits), 3)
        score += pts
        reasons.append(f"{len(import_hits)} anti-debug API import(s) detected (+{pts} pts)")

    # IAT Density & Dynamic Loader Stubs
    if iat_flags:
        score += 2
        for f in iat_flags:
            reasons.append(f["reason"])

    # String Artifacts (VM, Sandbox, Debugger)
    if string_hits:
        pts = min(len(string_hits), 2)
        score += pts
        reasons.append(f"{len(string_hits)} suspicious tool/VM/debugger string(s) (+{pts} pts)")

    # TLS Callbacks
    if tls_flags:
        score += 2
        for tf in tls_flags:
            reasons.append(tf["reason"])

    # Anti-Disassembly Bytecodes
    if opcode_flags:
        pts = min(len(opcode_flags), 2)
        score += pts
        reasons.append(f"{len(opcode_flags)} anti-disassembly/timing opcode(s) found (+{pts} pts)")

    # Verdict Classification
    if score >= HIGH_THRESHOLD:
        verdict = "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
