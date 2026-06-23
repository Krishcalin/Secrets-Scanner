"""Signature detector — regex rule pack from rules/secret_patterns.yaml.

Each rule may declare:
  - `capture`     group index so the redacted preview and fingerprint use the
                  secret value, not the surrounding assignment syntax.
  - `min_entropy` minimum Shannon entropy of the captured value to emit — gates
                  noisy/generic patterns against low-entropy placeholders.
  - `verifier`    a hint stored in Finding.metadata for Phase 5 live checks.

An Allowlist filters documentation/placeholder values before a Finding is built.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from core.allowlist import Allowlist
from core.models import Finding, Severity, fingerprint, redact
from detectors.base import BaseDetector
from detectors.entropy import shannon_entropy

_DEFAULT_RULES = Path(__file__).resolve().parents[1] / "rules" / "secret_patterns.yaml"


class SignatureDetector(BaseDetector):
    DETECTOR_ID = "signature"

    def __init__(
        self,
        rules_path: str | Path = _DEFAULT_RULES,
        allowlist: Allowlist | None = None,
    ) -> None:
        raw = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) or {}
        self.allowlist = allowlist if allowlist is not None else Allowlist.from_rules(rules_path)
        self._rules = []
        for r in raw.get("patterns", []):
            self._rules.append(
                {
                    "id": r["id"],
                    "description": r.get("description", r["id"]),
                    "regex": re.compile(r["regex"]),
                    "severity": Severity(r.get("severity", "medium")),
                    "capture": int(r.get("capture", 0)),
                    "min_entropy": (
                        float(r["min_entropy"]) if r.get("min_entropy") is not None else None
                    ),
                    "verifier": r.get("verifier"),
                }
            )

    def rule_index(self) -> dict[str, dict]:
        """Map rule_id -> compiled rule. Used by live verification to recover the
        raw secret from a finding's line (the regex + capture group)."""
        return {r["id"]: r for r in self._rules}

    def detect(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            for m in rule["regex"].finditer(content):
                grp = rule["capture"]
                has_grp = bool(grp) and bool(m.groups())
                secret = m.group(grp) if has_grp else m.group(0)
                start = m.start(grp) if has_grp else m.start(0)

                if self.allowlist.allows(secret, path):
                    continue

                entropy: float | None = None
                if rule["min_entropy"] is not None:
                    entropy = shannon_entropy(secret)
                    if entropy < rule["min_entropy"]:
                        continue

                line, col = self.line_col(content, start)
                metadata = {"verifier": rule["verifier"]} if rule["verifier"] else {}
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
                        entropy=round(entropy, 3) if entropy is not None else None,
                        metadata=metadata,
                    )
                )
        return findings
