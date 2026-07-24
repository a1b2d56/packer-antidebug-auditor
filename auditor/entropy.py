"""Shannon entropy calculation for PE sections.

High entropy in a PE section is a well-known indicator of compressed or
encrypted content -- exactly what packers produce. Entropy is measured in
bits per byte, so it ranges from 0.0 (perfectly uniform, e.g. all zero
bytes) to 8.0 (perfectly random, indistinguishable from ciphertext or
compressed data).
"""

from __future__ import annotations

import math
from collections import Counter

PACKED_ENTROPY_THRESHOLD = 7.0


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of `data` in bits per byte."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def section_entropies(pe) -> list[dict]:
    """Compute entropy, size, and characteristic metadata for every section in a PE object."""
    results = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="replace")
        data = section.get_data()
        entropy = shannon_entropy(data)
        characteristics = getattr(section, "Characteristics", 0)
        results.append({
            "name": name,
            "entropy": round(entropy, 3),
            "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize,
            "characteristics": characteristics,
            "likely_packed": entropy > PACKED_ENTROPY_THRESHOLD,
        })
    return results
