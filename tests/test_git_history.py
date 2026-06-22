"""Phase 3 tests — git-history scanning."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from core.engine import default_detectors
from core.git_history import GitHistoryScanner, is_git_repo

FAKE_AWS_KEY = "AKIAZ7XQ4WL9PRT2KD8N"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=Tester", "-c", "user.email=tester@example.com",
         "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, text=True,
    )


def _init_repo(path):
    _git(path, "init", "-q")


def _commit(repo, filename, content, message):
    (repo / filename).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


# ── basics ────────────────────────────────────────────────────────────────
def test_not_a_repo_returns_empty(tmp_path):
    assert not is_git_repo(tmp_path)
    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    assert result.count == 0 and result.commits_scanned == 0


def test_history_finds_committed_secret(tmp_path):
    _init_repo(tmp_path)
    _commit(tmp_path, "config.py", f'AWS_KEY = "{FAKE_AWS_KEY}"\n', "add config")

    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    assert result.commits_scanned == 1
    aws = [f for f in result.findings if f.rule_id == "aws_access_key_id"]
    assert aws, "AWS key not found in history"
    f = aws[0]
    assert f.source == "git-history"
    assert f.metadata["author"] == "Tester"
    assert f.metadata["commit_short"] and len(f.metadata["commit"]) == 40


# ── the headline feature: secret removed from the tree is still in history ──
def test_history_finds_leaked_then_removed_secret(tmp_path):
    _init_repo(tmp_path)
    _commit(tmp_path, "config.py", f'KEY = "{FAKE_AWS_KEY}"\n', "leak secret")
    _commit(tmp_path, "config.py", "KEY = read_env()\n", "remove secret")

    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    assert result.commits_scanned == 2
    aws = [f for f in result.findings if f.rule_id == "aws_access_key_id"]
    assert aws, "removed-but-historical secret not detected"
    # attributed to the commit that introduced it ("leak secret")
    assert aws[0].metadata["summary"] == "leak secret"


def test_history_reports_accurate_new_file_line(tmp_path):
    _init_repo(tmp_path)
    body = f'first = 1\nsecond = 2\nKEY = "{FAKE_AWS_KEY}"\nlast = 3\n'
    _commit(tmp_path, "app.py", body, "add app")

    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    f = next(x for x in result.findings if x.rule_id == "aws_access_key_id")
    assert f.line == 3  # secret is on the 3rd line of the file


def test_history_dedups_secret_present_across_commits(tmp_path):
    _init_repo(tmp_path)
    _commit(tmp_path, "a.py", f'K = "{FAKE_AWS_KEY}"\n', "c1")
    _commit(tmp_path, "b.py", "x = 1\n", "c2")  # secret still in a.py, unchanged
    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    # a.py's secret was added once (c1); c2 doesn't re-add it → exactly one finding
    aws = [f for f in result.findings if f.rule_id == "aws_access_key_id"]
    assert len(aws) == 1


def test_history_allowlist_suppresses_example_key(tmp_path):
    _init_repo(tmp_path)
    _commit(tmp_path, "doc.md", "Example: AKIAIOSFODNN7EXAMPLE\n", "docs")
    result = GitHistoryScanner(default_detectors()).scan(tmp_path)
    assert not any(f.rule_id == "aws_access_key_id" for f in result.findings)


def test_history_max_commits_limit(tmp_path):
    _init_repo(tmp_path)
    _commit(tmp_path, "a.py", "x = 1\n", "c1")
    _commit(tmp_path, "b.py", "y = 2\n", "c2")
    _commit(tmp_path, "c.py", "z = 3\n", "c3")
    result = GitHistoryScanner(default_detectors(), max_commits=2).scan(tmp_path)
    assert result.commits_scanned == 2
