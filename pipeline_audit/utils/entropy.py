from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string.

    An empty string has entropy 0.0. The threshold of 3.5 is the locked
    pipeline-audit default for distinguishing real secrets from short
    or low-variability values.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


__all__ = ["shannon_entropy"]