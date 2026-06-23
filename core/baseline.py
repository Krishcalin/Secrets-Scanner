"""Baseline suppression — accept known/triaged findings so re-scans stay quiet.

A baseline is a JSON file of finding fingerprints to suppress. Generate one after
triaging a repo's existing findings; future scans then surface only *new* secrets.
Fingerprints are stable across line moves (they hash rule + secret + path), not the
raw secret value.

The file also stores a human-readable `entries` map (fingerprint → rule/path/reason)
purely for auditability — suppression itself only ever consults the fingerprint set.
`write(..., update=True)` merges into an existing baseline so triage is incremental:
scan, fix the real leaks, then fold the rest into the baseline as accepted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.models import Finding


@dataclass
class Baseline:
    fingerprints: set[str] = field(default_factory=set)
    entries: dict[str, dict] = field(default_factory=dict)   # fingerprint -> {rule_id, path, reason?}

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        entries = data.get("entries", {}) or {}
        fps = set(data.get("fingerprints", [])) or set(entries)
        return cls(fps, entries)

    def suppresses(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints

    @staticmethod
    def write(
        path: str | Path,
        findings: list[Finding],
        *,
        update: bool = False,
        reason: str | None = None,
    ) -> Path:
        out = Path(path)
        base = Baseline.load(out) if update and out.exists() else Baseline()
        entries = dict(base.entries)
        for f in findings:
            entry = {"rule_id": f.rule_id, "path": f.path}
            if reason:
                entry["reason"] = reason
            entries.setdefault(f.fingerprint, entry)
        fps = sorted(set(base.fingerprints) | set(entries))
        payload = {
            "fingerprints": fps,
            "count": len(fps),
            "entries": {fp: entries[fp] for fp in fps if fp in entries},
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out
