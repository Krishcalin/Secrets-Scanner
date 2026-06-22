"""Baseline suppression — accept known/triaged findings so re-scans stay quiet.

A baseline is a JSON file of finding fingerprints to suppress. Generate one
after triaging a repo's existing findings; future scans then surface only *new*
secrets. Fingerprints are stable across line moves (they hash rule + secret +
path), not the raw secret value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.models import Finding


@dataclass
class Baseline:
    fingerprints: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        return cls(set(data.get("fingerprints", [])))

    def suppresses(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints

    @staticmethod
    def write(path: str | Path, findings: list[Finding]) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "fingerprints": sorted({f.fingerprint for f in findings}),
            "count": len({f.fingerprint for f in findings}),
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out
