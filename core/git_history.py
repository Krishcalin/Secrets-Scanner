"""Git-history scanning — find secrets that were committed, even if later removed.

Deleting a secret from the working tree does **not** remove it from git history;
anyone with the repo can recover it. This scanner walks every commit on every ref
and runs the same detectors against the *added* lines of each commit's diff, so a
credential is caught at the commit that introduced it — regardless of whether a
later commit deleted it.

Findings get ``source="git-history"`` and commit/author metadata so a responder
knows where the leak entered and whose key to rotate.

Implementation: a single ``git log --all -p`` stream is parsed (one subprocess,
not one per commit). Per (commit, file) the added lines are reconstructed into a
text blob — preserving real new-file line numbers via a line map — so multi-line
secrets (PEM keys) still match and locations stay accurate.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from core.baseline import Baseline
from core.logger import get_logger
from core.models import Finding, ScanResult
from detectors.base import BaseDetector

log = get_logger("git-history")

# Sentinel emitted by --format before each commit's patch. 0x1f is the ASCII unit
# separator — it never appears in a unified-diff line prefix, so it cannot collide
# with file content.
_US = "\x1f"
_COMMIT_MARK = "__SECRETS_SCANNER_COMMIT__"
_FORMAT = _COMMIT_MARK + _US + "%H" + _US + "%an" + _US + "%ae" + _US + "%aI" + _US + "%s"

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_MAX_BLOB = 1 * 1024 * 1024  # cap reconstructed added-content per (commit, file)


def is_git_repo(path: str | Path) -> bool:
    try:
        out = _run_git(["rev-parse", "--is-inside-work-tree"], path)
    except (OSError, subprocess.SubprocessError):
        return False
    return out is not None and out.strip() == "true"


def _run_git(args: list[str], cwd: str | Path) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        log.warning("git_failed", args=args, code=proc.returncode,
                    stderr=(proc.stderr or "").strip()[:200])
        return None
    return proc.stdout


class _CommitBlock:
    """Accumulates per-file added lines for one commit while parsing the diff."""

    __slots__ = ("hash", "author", "email", "date", "summary", "files")

    def __init__(self, hash_: str, author: str, email: str, date: str, summary: str) -> None:
        self.hash = hash_
        self.author = author
        self.email = email
        self.date = date
        self.summary = summary
        # path -> list[(new_line_number, text)]
        self.files: dict[str, list[tuple[int, str]]] = {}


class GitHistoryScanner:
    def __init__(
        self,
        detectors: list[BaseDetector],
        baseline: Baseline | None = None,
        max_commits: int | None = None,
    ) -> None:
        self.detectors = detectors
        self.baseline = baseline
        self.max_commits = max_commits

    def scan(self, repo: str | Path) -> ScanResult:
        result = ScanResult(root=str(repo))
        if not is_git_repo(repo):
            log.warning("not_a_git_repo", path=str(repo))
            return result

        args = ["log", "--all", "--no-merges", "--reverse", "--no-color",
                "-p", "--unified=0", f"--format={_FORMAT}"]
        if self.max_commits:
            args.insert(1, f"--max-count={self.max_commits}")
        out = _run_git(args, repo)
        if not out:
            return result

        seen: set[str] = set()
        for block in self._iter_commits(out):
            result.commits_scanned += 1
            for path, added in block.files.items():
                for finding in self._scan_added(path, added):
                    if finding.fingerprint in seen:
                        continue
                    if self.baseline and self.baseline.suppresses(finding):
                        continue
                    seen.add(finding.fingerprint)
                    self._attribute(finding, block)
                    result.findings.append(finding)
        return result

    # ── diff parsing ─────────────────────────────────────────────────────
    @staticmethod
    def _iter_commits(log_output: str):
        block: _CommitBlock | None = None
        path: str | None = None
        new_lineno = 0
        for line in log_output.split("\n"):
            if line.startswith(_COMMIT_MARK + _US):
                if block is not None:
                    yield block
                parts = line.split(_US)
                # parts[0] is the sentinel; pad defensively
                parts += [""] * (6 - len(parts))
                block = _CommitBlock(parts[1], parts[2], parts[3], parts[4], parts[5])
                path = None
                continue
            if block is None:
                continue
            if line.startswith("+++ "):
                target = line[4:].strip()
                path = None if target == "/dev/null" else target[2:] if target[:2] in ("b/", "a/") else target
                continue
            if line.startswith("--- ") or line.startswith("diff ") or line.startswith("index "):
                continue
            m = _HUNK.match(line)
            if m:
                new_lineno = int(m.group(1))
                continue
            if path is None:
                continue
            if line.startswith("+"):
                block.files.setdefault(path, []).append((new_lineno, line[1:]))
                new_lineno += 1
            # '-' lines and metadata don't advance the new-file counter
        if block is not None:
            yield block

    # ── detection on reconstructed added content ─────────────────────────
    def _scan_added(self, path: str, added: list[tuple[int, str]]) -> list[Finding]:
        if not added:
            return []
        texts = [t for _, t in added]
        line_map = [ln for ln, _ in added]      # content line i (0-based) -> real new line
        content = "\n".join(texts)
        if len(content) > _MAX_BLOB:
            content = content[:_MAX_BLOB]
        findings: list[Finding] = []
        for det in self.detectors:
            try:
                for f in det.detect(path, content):
                    idx = f.line - 1
                    if 0 <= idx < len(line_map):
                        f.line = line_map[idx]
                    findings.append(f)
            except Exception as exc:  # a broken detector must not abort the scan
                log.error("detector_failed", detector=det.DETECTOR_ID, path=path, error=str(exc))
        return findings

    @staticmethod
    def _attribute(finding: Finding, block: _CommitBlock) -> None:
        finding.source = "git-history"
        finding.metadata = {
            **finding.metadata,
            "commit": block.hash,
            "commit_short": block.hash[:8],
            "author": block.author,
            "email": block.email,
            "date": block.date,
            "summary": block.summary,
        }
