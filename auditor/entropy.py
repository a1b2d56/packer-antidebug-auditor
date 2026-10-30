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

# Below this many bytes a section cannot reach high entropy in a statistically
# meaningful way (n bytes can hold at most log2(n) bits/byte of entropy), so
# small sections are reported but never classified as packed.
MIN_RELIABLE_ENTROPY_BYTES = 256


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of `data` in bits per byte."""
    if not data:
        return 0.0
    if isinstance(data, memoryview):
        data = data.tobytes()

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
        entropy = round(shannon_entropy(data), 3)
        reliable = len(data) >= MIN_RELIABLE_ENTROPY_BYTES
        characteristics = getattr(section, "Characteristics", 0)
        results.append({
            "name": name,
            "entropy": entropy,
            "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize,
            "characteristics": characteristics,
            # Compare the same rounded value that is reported so the flag never contradicts the number shown.
            "likely_packed": reliable and entropy > PACKED_ENTROPY_THRESHOLD,
            "entropy_reliable": reliable,
            "normalized_entropy": round(entropy / 8.0, 4),
        })
    return results
