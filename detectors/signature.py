"""Signature detector — regex rule pack from rules/secret_patterns.yaml.

Each rule may declare a `capture` group index so the redacted preview and
fingerprint use the secret value, not the surrounding assignment syntax.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from core.models import Finding, Severity, fingerprint, redact
from detectors.base import BaseDetector

_DEFAULT_RULES = Path(__file__).resolve().parents[1] / "rules" / "secret_patterns.yaml"


class SignatureDetector(BaseDetector):
    DETECTOR_ID = "signature"

    def __init__(self, rules_path: str | Path = _DEFAULT_RULES) -> None:
        raw = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) or {}
        self._rules = []
        for r in raw.get("patterns", []):
            self._rules.append(
                {
                    "id": r["id"],
                    "description": r.get("description", r["id"]),
                    "regex": re.compile(r["regex"]),
                    "severity": Severity(r.get("severity", "medium")),
                    "capture": int(r.get("capture", 0)),
                }
            )

    def detect(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            for m in rule["regex"].finditer(content):
                grp = rule["capture"]
                secret = m.group(grp) if grp and m.groups() else m.group(0)
                start = m.start(grp) if grp and m.groups() else m.start(0)
                line, col = self.line_col(content, start)
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        description=rule["description"],
                        severity=rule["severity"],
                        path=path,
                        line=line,
                        column=col,
                        preview=redact(secret),
                        fingerprint=fingerprint(rule["id"], secret, path),
                    )
                )
        return findings
