"""BaseDetector — the contract every secret detector implements.

A detector scans one file's full text and returns Findings. Working on full
content (not line-by-line) lets multi-line secrets — e.g. PEM private keys — be
matched, with the line number derived from the match offset.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Finding


class BaseDetector(ABC):
    DETECTOR_ID: str = "base"

    @abstractmethod
    def detect(self, path: str, content: str) -> list[Finding]:
        """Return zero or more Findings for this file's content."""
        raise NotImplementedError

    @staticmethod
    def line_col(content: str, offset: int) -> tuple[int, int]:
        """1-based (line, column) for a match offset within content."""
        line = content.count("\n", 0, offset) + 1
        last_nl = content.rfind("\n", 0, offset)
        col = offset - last_nl
        return line, col
