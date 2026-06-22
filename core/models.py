"""Data models for the secrets scanner.

A Finding is the core unit: one detected secret, with enough context to triage
(file, line, rule, severity) but with the secret value itself redacted so
reports and logs never leak the credential.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verification(str, Enum):
    UNVERIFIED = "unverified"   # not checked against a live service
    VALID = "valid"             # confirmed live (active credential)
    INVALID = "invalid"         # checked, not live
    SKIPPED = "skipped"         # no verifier for this rule


def redact(secret: str) -> str:
    """Mask a secret for safe display: keep a few edge chars, hide the middle."""
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}…{s[-2:]} ({len(s)} chars)"


def fingerprint(rule_id: str, secret: str, path: str = "") -> str:
    """Stable id for dedup + baseline suppression (no raw secret stored)."""
    h = hashlib.sha256(f"{rule_id}:{secret}:{path}".encode("utf-8")).hexdigest()
    return h[:16]


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: Severity
    path: str
    line: int
    column: int
    preview: str                          # redacted match — never the raw secret
    fingerprint: str
    source: str = "filesystem"            # filesystem | git-history
    entropy: float | None = None
    verification: Verification = Verification.UNVERIFIED
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    commits_scanned: int = 0          # populated by git-history scans

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def count(self) -> int:
        return len(self.findings)
