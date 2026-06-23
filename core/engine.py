"""Scan engine — walk a tree, run detectors, dedup, apply the baseline.

Phase 1 scans the filesystem. Git-history scanning (Phase 3) reuses the same
detectors against blob content.
"""

from __future__ import annotations

from pathlib import Path

from core.baseline import Baseline
from core.gitignore import filter_ignored
from core.logger import get_logger
from core.models import ScanResult
from core.pragma import line_allowlisted
from core.walker import walk_files
from detectors.base import BaseDetector

log = get_logger("engine")


class SecretScanner:
    def __init__(
        self,
        detectors: list[BaseDetector],
        baseline: Baseline | None = None,
        skip_gitignored: bool = False,
    ) -> None:
        self.detectors = detectors
        self.baseline = baseline
        self.skip_gitignored = skip_gitignored

    def scan(self, root: str | Path) -> ScanResult:
        result = ScanResult(root=str(root))
        seen: set[str] = set()
        paths = list(walk_files(root))
        if self.skip_gitignored:
            paths = filter_ignored(root, paths)
        for path in paths:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                log.warning("read_failed", path=str(path), error=str(exc))
                result.files_skipped += 1
                continue
            result.files_scanned += 1
            rel = str(path)
            lines = content.split("\n")
            for det in self.detectors:
                try:
                    for finding in det.detect(rel, content):
                        idx = finding.line - 1
                        if 0 <= idx < len(lines) and line_allowlisted(lines[idx]):
                            continue
                        if finding.fingerprint in seen:
                            continue
                        if self.baseline and self.baseline.suppresses(finding):
                            continue
                        seen.add(finding.fingerprint)
                        result.findings.append(finding)
                except Exception as exc:  # a broken detector must not abort the scan
                    log.error("detector_failed", detector=det.DETECTOR_ID,
                              path=rel, error=str(exc))
        return result


def default_detectors(entropy: bool = False, allowlist: bool = True) -> list[BaseDetector]:
    """Built-in detector set. Entropy is opt-in (noisier than signatures).

    The allowlist (documentation/placeholder suppression) is on by default; pass
    ``allowlist=False`` to report even obvious sample values.
    """
    from core.allowlist import Allowlist
    from detectors.entropy import EntropyDetector
    from detectors.signature import SignatureDetector

    al = Allowlist.default() if allowlist else Allowlist.empty()
    detectors: list[BaseDetector] = [SignatureDetector(allowlist=al)]
    if entropy:
        detectors.append(EntropyDetector(allowlist=al))
    return detectors
