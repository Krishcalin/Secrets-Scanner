"""`.gitignore`-aware filtering — delegate to git so semantics are exactly right.

Re-implementing gitignore matching (negation, anchoring, `**`, directory rules)
is a well-known footgun. Since the scanner already shells out to git for history
scanning, we let `git check-ignore` decide: it applies the repo's full exclude
stack (`.gitignore`, `.git/info/exclude`, global core.excludesFile). This only
applies inside a git work tree; elsewhere it is a no-op.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from core.git_history import is_git_repo
from core.logger import get_logger

log = get_logger("gitignore")


def filter_ignored(root: str | Path, paths: list[Path]) -> list[Path]:
    """Return ``paths`` with git-ignored entries removed.

    No-op (returns the list unchanged) when ``root`` is not a git work tree or
    git is unavailable. Uses one batched ``git check-ignore`` call.
    """
    if not paths or not is_git_repo(root):
        return paths
    root_path = Path(root)
    rels: list[str] = []
    rel_to_path: dict[str, Path] = {}
    for p in paths:
        try:
            rel = str(p.relative_to(root_path))
        except ValueError:
            rel = str(p)
        rels.append(rel)
        rel_to_path[rel] = p

    try:
        proc = subprocess.run(
            ["git", "-C", str(root_path), "check-ignore", "-z", "--stdin"],
            input="\0".join(rels),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError as exc:
        log.warning("check_ignore_failed", error=str(exc))
        return paths
    # rc 0 = some ignored, 1 = none ignored, other = error
    if proc.returncode not in (0, 1):
        log.warning("check_ignore_error", code=proc.returncode,
                    stderr=(proc.stderr or "").strip()[:200])
        return paths

    ignored = {r for r in proc.stdout.split("\0") if r}
    if not ignored:
        return paths
    return [rel_to_path[r] for r in rels if r not in ignored]
