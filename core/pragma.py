"""Inline allowlist pragmas — let developers suppress a known-safe match in place.

A finding is dropped when its source line carries an inline marker, e.g.:

    test_key = "AKIA................"   # pragma: allowlist secret
    fake = "sk_live_0000000000000000"  # gitleaks:allow

This is the per-line escape hatch that complements the global rule-pack allowlist
and the baseline file: use it for an intentional fixture the scanner can't tell
from a real leak. Comment style is irrelevant — the marker is matched anywhere on
the line.
"""

from __future__ import annotations

import re

_INLINE = re.compile(r"pragma:\s*allowlist[ _-]secret|gitleaks:allow", re.IGNORECASE)


def line_allowlisted(text: str) -> bool:
    """True if a source line carries an inline allowlist pragma."""
    return bool(_INLINE.search(text))
