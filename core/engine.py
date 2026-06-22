"""Scan engine — walk a tree, run detectors, dedup, apply the baseline.

Phase 1 scans the filesystem. Git-history scanning (Phase 3) reuses the same
detectors against blob content.
"""

from __future__ import annotations

from pathlib import Path

from core.baseline import Baseline
from core.logger import get_logger
from core.models import Finding, ScanResult
from core.walker import walk_files
from detectors.base import BaseDetector

log = get_logger("engine")


class SecretScanner:
    def __init__(
        self,
        detectors: list[BaseDetector],
        baseline: Baseline | None = None,
    ) -> None:
        self.detectors = detectors
        self.baseline = baseline

    def scan(self, root: str | Path) -> ScanResult:
        result = ScanResult(root=str(root))
        seen: set[str] = set()
        for path in walk_files(root):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                log.warning("read_failed", path=str(path), error=str(exc))
                result.files_skipped += 1
                continue
            result.files_scanned += 1
            rel = str(path)
            for det in self.detectors:
                try:
                    for finding in det.detect(rel, content):
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


def default_detectors(entropy: bool = False) -> list[BaseDetector]:
    """Built-in detector set. Entropy is opt-in (noisier than signatures)."""
    from detectors.entropy import EntropyDetector
    from detectors.signature import SignatureDetector

    detectors: list[BaseDetector] = [SignatureDetector()]
    if entropy:
        detectors.append(EntropyDetector())
    return detectors
