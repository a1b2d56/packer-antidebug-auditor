"""Static heuristics for identifying packed PE files.

Covers section names, size divergences, W^X permissions, entry-point anomalies,
and overlay data without relying solely on entropy.
"""

from __future__ import annotations

from auditor.entropy import PACKED_ENTROPY_THRESHOLD, shannon_entropy

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Common section names and prefixes left behind by packers and protectors.
KNOWN_PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2",
    ".aspack", ".adata",
    "petite",
    "pec1", "pec2", ".pec",
    ".themida", ".taggant", "themida", ".wl",
    ".vmp0", ".vmp1", ".vmp2",
    ".mpress1", ".mpress2",
    ".nsp0", ".nsp1", ".nsp2",
    ".enigma1", ".enigma2",
    "fsg!", "mew", ".obsid",
    "pebundle", ".pack",
    ".cr0", ".cr1", ".confuser",
    ".armid", ".armad",
    "boxed", "bxapp",
    ".ndata",
    "molebox",
    ".spack", ".pecompact",
    "yoda",
}

KNOWN_PACKER_PREFIXES = (
    "upx", ".vmp", ".nsp", ".enigma", "pec", ".cr", ".mpress", ".aspack",
)

IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040


def size_delta_flags(sections: list[dict]) -> list[dict]:
    """Flag sections where virtual size sharply exceeds on-disk raw size.

    Excludes standard benign .bss sections with zero entropy to avoid false
    positives on uninitialized static data.
    """
    flagged = []
    for section in sections:
        raw = section["raw_size"]
        virtual = section["virtual_size"]
        name = section["name"].lower().strip()

        # Legitimate .bss has raw_size=0, but packers also use empty sections (like UPX0)
        # to hold unpacked payload. Flag if non-.bss, or if virtual size is abnormally large.
        if raw == 0 and virtual > 0:
            if name == ".bss":
                continue
            flagged.append({
                **section,
                "reason": "zero raw size with nonzero virtual size (unpacking allocation stub)",
            })
        elif raw > 0 and (virtual / raw) > 10:
            flagged.append({
                **section,
                "reason": f"virtual size is {virtual / raw:.1f}x raw size (unusual expansion ratio)",
            })
    return flagged


def section_name_flags(sections: list[dict]) -> list[dict]:
    """Flag section names matching known packer signatures or prefix families."""
    flagged = []
    for section in sections:
        clean_name = section["name"].lower().strip()
        matched = False
        if clean_name in KNOWN_PACKER_SECTION_NAMES:
            matched = True
        elif any(clean_name.startswith(pfx) for pfx in KNOWN_PACKER_PREFIXES if len(clean_name) > len(pfx)):
            matched = True

        if matched:
            flagged.append({
                **section,
                "reason": f"section name '{section['name']}' matches known packer signature",
            })
    return flagged


def pe_header_anomaly_flags(pe) -> list[dict]:
    """Flag PE header anti-forensics and compilation anomalies (timestomping, ASLR conflicts, obfuscated sections)."""
    flags = []

    # 1. Compilation TimeDateStamp Anomalies (Timestomping)
    file_header = getattr(pe, "FILE_HEADER", None)
    if file_header is not None:
        timestamp = getattr(file_header, "TimeDateStamp", None)
        if timestamp is not None:
            if timestamp == 0:
                flags.append({"kind": "timestamp", "reason": "TimeDateStamp is 0 (stripped or deliberately wiped compilation timestamp)"})
            elif 0 < timestamp < 946684800:  # Prior to 2000-01-01
                flags.append({"kind": "timestamp", "reason": f"TimeDateStamp is pre-2000 ({timestamp}) (possible timestomping)"})
            elif timestamp > 2082758400:  # Far in the future (beyond 2035)
                flags.append({"kind": "timestamp", "reason": f"TimeDateStamp is set far in future ({timestamp}) (timestomping indicator)"})

        # 2. Dynamic Base (ASLR) with Relocations Stripped Conflict
        opt_header = getattr(pe, "OPTIONAL_HEADER", None)
        if opt_header is not None:
            dll_chars = getattr(opt_header, "DllCharacteristics", 0)
            file_chars = getattr(file_header, "Characteristics", 0)
            has_dynamic_base = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            relocs_stripped = bool(file_chars & IMAGE_FILE_RELOCS_STRIPPED)
            if has_dynamic_base and relocs_stripped:
                flags.append({
                    "kind": "aslr_conflict",
                    "reason": "DYNAMIC_BASE (ASLR) enabled but RELOCS_STRIPPED flag is set (corrupted/custom loader state)"
                })

    # 3. Non-printable or obfuscated section names
    for section in getattr(pe, "sections", []):
        raw_name = getattr(section, "Name", b"")
        clean_raw = raw_name.rstrip(b"\x00")
        if clean_raw:
            # Check for non-printable characters outside standard ASCII range (0x20 - 0x7E)
            if any(b < 0x20 or b > 0x7E for b in clean_raw):
                flags.append({
                    "kind": "section_name",
                    "reason": f"non-printable/obfuscated bytes in section name ({repr(clean_raw)})"
                })
        else:
            flags.append({"kind": "section_name", "reason": "empty/blank section name detected"})

    return flags


def section_count_flag(pe) -> dict | None:
    """Flag abnormally low section counts.

    Standard compilers usually emit 4-6+ sections (.text, .rdata, .data, .pdata, .rsrc, .reloc).
    Many packers consolidate code and data into 1-3 sections.
    """
    count = len(pe.sections)
    if count <= 3:
        return {"reason": f"only {count} section(s) present (typical compiler output has 4+)"}
    return None


def rwx_section_flags(pe) -> list[dict]:
    """Flag sections that are simultaneously Writable and Executable (W^X violation).

    Self-modifying code and unpacker stubs require write access to decrypt or
    write executable code directly into the section before jumping to it.
    """
    flagged = []
    for section in pe.sections:
        characteristics = getattr(section, "Characteristics", 0)
        is_writable = bool(characteristics & IMAGE_SCN_MEM_WRITE)
        is_executable = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)

        if is_writable and is_executable:
            name = section.Name.rstrip(b"\x00").decode(errors="replace")
            flagged.append({
                "name": name,
                "reason": "section has both WRITE and EXECUTE characteristics (W^X violation / self-modifying code)",
            })
    return flagged


def entry_point_flags(pe) -> list[dict]:
    """Detect anomalies in AddressOfEntryPoint location.

    Packers often place the entry point in the last section (the unpacker stub)
    or in a writable section rather than the standard code section (.text).
    """
    flags = []
    if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint"):
        return flags

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep == 0 and not (pe.FILE_HEADER.Characteristics & 0x2000):  # 0x2000 is DLL
        flags.append({
            "reason": "AddressOfEntryPoint is 0 in a non-DLL PE",
        })
        return flags

    # Determine which section contains the entry point
    ep_section = None
    last_section = pe.sections[-1] if pe.sections else None

    for section in pe.sections:
        v_addr = section.VirtualAddress
        v_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if v_addr <= ep < (v_addr + v_size):
            ep_section = section
            break

    if ep_section is None:
        flags.append({
            "reason": f"EntryPoint RVA 0x{ep:X} points outside any mapped section",
        })
        return flags

    ep_name = ep_section.Name.rstrip(b"\x00").decode(errors="replace")
    characteristics = getattr(ep_section, "Characteristics", 0)

    # Check if entry point is in a writable section
    if characteristics & IMAGE_SCN_MEM_WRITE:
        flags.append({
            "reason": f"EntryPoint RVA 0x{ep:X} resides in writable section '{ep_name}'",
        })

    # Check if entry point is placed in the last section when there are >= 3 sections
    if len(pe.sections) >= 3 and ep_section == last_section:
        if ep_name.lower().strip() not in {".text", "code"}:
            flags.append({
                "reason": f"EntryPoint is located in the final section '{ep_name}' (common unpacker stub placement)",
            })

    return flags


def overlay_flags(pe) -> dict | None:
    """Check for appended overlay data after the last section and measure its entropy."""
    try:
        overlay_data = pe.get_overlay()
    except Exception:
        return None

    if not overlay_data or len(overlay_data) < 512:
        return None

    overlay_entropy = round(shannon_entropy(overlay_data), 3)
    is_suspicious = overlay_entropy > PACKED_ENTROPY_THRESHOLD

    return {
        "size": len(overlay_data),
        "entropy": overlay_entropy,
        "likely_packed": is_suspicious,
        "reason": (
            f"overlay data present ({len(overlay_data)} bytes, entropy {overlay_entropy}) "
            f"-- {'high entropy suggests embedded encrypted/compressed payload' if is_suspicious else 'appended data'}"
        ),
    }
