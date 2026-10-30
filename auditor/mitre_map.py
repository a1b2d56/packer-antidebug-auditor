"""Maps packer-antidebug-auditor detection signals to MITRE ATT&CK technique IDs.

Purely a static lookup — no external API calls. Each signal key produced by
scoring.compute_verdict is mapped to a (technique_id, technique_name) pair
drawn from the MITRE ATT&CK Enterprise Matrix (v15+). Signals that evidence
more than one technique list the extras in SECONDARY_TECHNIQUES.
"""

from __future__ import annotations

TECHNIQUE_MAP: dict[str, tuple[str, str]] = {
    # Defense Evasion: packing & structural obfuscation
    "packed_entropy":      ("T1027.002", "Obfuscated Files: Software Packing"),
    "packer_section_name": ("T1027.002", "Obfuscated Files: Software Packing"),
    "size_delta":          ("T1027.002", "Obfuscated Files: Software Packing"),
    "sparse_iat":          ("T1027.002", "Obfuscated Files: Software Packing"),
    "section_count":       ("T1027.002", "Obfuscated Files: Software Packing"),
    "entry_point_anomaly": ("T1027.002", "Obfuscated Files: Software Packing"),
    "overlay_data":        ("T1027",     "Obfuscated Files or Information"),
    "rwx_section":         ("T1055.012", "Process Injection: Process Hollowing"),

    # Defense Evasion: header anti-forensics
    "header_timestamp":    ("T1070.006", "Indicator Removal: Timestomp"),
    "header_anomaly":      ("T1027",     "Obfuscated Files or Information"),

    # Anti-Analysis / Discovery
    "anti_debug_import":   ("T1622",     "Debugger Evasion"),
    "tls_callback":        ("T1622",     "Debugger Evasion"),
    "antidebug_opcode":    ("T1622",     "Debugger Evasion"),
    "timing_opcode":       ("T1497.003", "Virtualization/Sandbox Evasion: Time Based"),
    "vm_opcode":           ("T1497.001", "Virtualization/Sandbox Evasion: System Checks"),
    "suspicious_string":   ("T1518.001", "Software Discovery: Security Software"),

    # Execution: direct syscalls & SSN resolution (EDR hook evasion)
    "direct_syscall":         ("T1106", "Native API"),
    "hells_gate_resolver":    ("T1106", "Native API"),
    "halos_gate":             ("T1106", "Native API"),
    "tartarus_gate":          ("T1106", "Native API"),
    "freshycalls_sorted_ssn": ("T1106", "Native API"),
    "heavens_gate":           ("T1106", "Native API"),
}

# Additional techniques evidenced by a signal beyond its primary mapping.
SECONDARY_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    # Executing 64-bit code from a WoW64 process hides it from 32-bit analysis tooling.
    "heavens_gate": [("T1027", "Obfuscated Files or Information")],
}


def get_technique(signal_key: str) -> tuple[str, str] | None:
    """Return (technique_id, technique_name) for a signal key, or None."""
    return TECHNIQUE_MAP.get(signal_key)


def attack_url(technique_id: str) -> str:
    """Return the attack.mitre.org URL for a technique or sub-technique ID."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def enrich_reasons(reasons: list[str], signal_keys: list[str]) -> list[dict]:
    """Pair each reason string with its ATT&CK technique metadata.

    Returns a list of dicts, each with keys: reason, mitre_id, mitre_name,
    signal_key and secondary (a list of {mitre_id, mitre_name}).
    """
    enriched = []
    for reason, key in zip(reasons, signal_keys):
        technique = TECHNIQUE_MAP.get(key)
        enriched.append({
            "reason": reason,
            "mitre_id": technique[0] if technique else None,
            "mitre_name": technique[1] if technique else None,
            "signal_key": key,
            "secondary": [
                {"mitre_id": tid, "mitre_name": name}
                for tid, name in SECONDARY_TECHNIQUES.get(key, [])
            ],
        })
    return enriched
