"""Allowlist — suppress obvious placeholder/example/test secrets.

Documentation samples (AWS's `AKIAIOSFODNN7EXAMPLE`), template tokens
(`<your-api-key>`, `${SECRET}`, `{{ token }}`), and fixture values are not real
leaks. The allowlist filters them out *before* a Finding is emitted, keeping
signal high. Rules live in the `allowlist:` section of the rule pack YAML, so
users can tune them without code changes.

Two axes:
  - value_patterns: regex matched against the *secret value* (case-insensitive).
  - path_patterns:  regex matched against the file *path* (empty by default —
                    suppressing whole paths risks hiding real secrets in tests).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_DEFAULT_RULES = Path(__file__).resolve().parents[1] / "rules" / "secret_patterns.yaml"


class Allowlist:
    def __init__(
        self,
        value_patterns: list[str] | None = None,
        path_patterns: list[str] | None = None,
    ) -> None:
        self._value = [re.compile(p, re.IGNORECASE) for p in (value_patterns or [])]
        self._path = [re.compile(p, re.IGNORECASE) for p in (path_patterns or [])]

    @classmethod
    def from_rules(cls, rules_path: str | Path = _DEFAULT_RULES) -> "Allowlist":
        raw = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) or {}
        section = raw.get("allowlist", {}) or {}
        return cls(section.get("value_patterns", []), section.get("path_patterns", []))

    @classmethod
    def default(cls) -> "Allowlist":
        return cls.from_rules()

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls()

    def allows_value(self, secret: str) -> bool:
        return any(p.search(secret) for p in self._value)

    def allows_path(self, path: str) -> bool:
        return any(p.search(path) for p in self._path)

    def allows(self, secret: str, path: str = "") -> bool:
        return self.allows_value(secret) or (bool(path) and self.allows_path(path))
