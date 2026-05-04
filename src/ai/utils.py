"""
Shared utilities for AI modules.

Extracted from ueba.py and alert_triage.py to avoid duplication.
"""
import math
from typing import Dict, List


def shannon_entropy(values: List[str]) -> float:
    """
    Calculate Shannon entropy of a list of strings. Normalized 0-1.

    Higher entropy = more diverse = more suspicious for process names.
    Range: 0 (all same) to 1 (uniform distribution).
    """
    if not values:
        return 0.0

    freq: Dict[str, int] = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1

    total = len(values)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0
