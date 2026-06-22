"""Filesystem walker — yield scannable text files under a root.

Skips noise directories, oversized files, and binaries so scanning stays fast
and false-positive-free. Honors an extra ignore list from config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

# directories never worth scanning for source secrets
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv", "env",
    "dist", "build", ".eggs", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "vendor", "target", ".terraform",
}
# extensions that are almost always binary / not source
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo",
}

_MAX_BYTES = 5 * 1024 * 1024  # skip files larger than 5 MB


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def walk_files(
    root: str | Path,
    extra_skip_dirs: set[str] | None = None,
    max_bytes: int = _MAX_BYTES,
) -> Iterator[Path]:
    skip_dirs = _SKIP_DIRS | (extra_skip_dirs or set())
    root = Path(root)
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in _SKIP_EXT:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        if _looks_binary(path):
            continue
        yield path
