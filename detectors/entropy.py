"""Entropy detector — flag high-entropy strings that signatures miss.

Catches novel/unknown secret formats (random tokens, keys) by Shannon entropy.
Off by default in the engine because it is noisier than signatures; enable with
`--entropy`. Conservative defaults (length + mixed alphabet + threshold) keep
false positives down.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from core.models import Finding, Severity, fingerprint, redact
from detectors.base import BaseDetector

_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyDetector(BaseDetector):
    DETECTOR_ID = "entropy"

    def __init__(self, min_entropy: float = 4.0) -> None:
        self.min_entropy = min_entropy

    def detect(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in _TOKEN.finditer(content):
            tok = m.group(0)
            # require a mixed alphabet — pure words / hex-only runs are noisy
            if not (any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)):
                continue
            e = shannon_entropy(tok)
            if e < self.min_entropy:
                continue
            line, col = self.line_col(content, m.start())
            findings.append(
                Finding(
                    rule_id="high_entropy_string",
                    description=f"High-entropy string (H={e:.2f})",
                    severity=Severity.LOW,
                    path=path,
                    line=line,
                    column=col,
                    preview=redact(tok),
                    fingerprint=fingerprint("high_entropy_string", tok, path),
                    entropy=round(e, 3),
                )
            )
        return findings
