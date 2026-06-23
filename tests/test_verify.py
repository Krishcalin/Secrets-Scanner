"""Phase 5 tests — live verification (no real network; HTTP is injected)."""

from __future__ import annotations

from core.engine import SecretScanner, default_detectors
from core.models import Finding, Severity, Verification, fingerprint
from core.verify import (
    GitHubVerifier,
    StripeVerifier,
    VerificationRunner,
    collect_verifiable,
    default_verifiers,
)

GH_TOKEN = "ghp_" + "A" * 36


def _finding(verifier: str, secret: str = "x", path: str = "a.py") -> Finding:
    return Finding("github_pat", "GitHub PAT", Severity.CRITICAL, path, 1, 1,
                   "ghp_…", fingerprint("github_pat", secret, path),
                   metadata={"verifier": verifier})


# ── verifier request specs ────────────────────────────────────────────────
def test_github_request_uses_bearer_and_user_agent():
    url, headers, method, body = GitHubVerifier().request(GH_TOKEN)
    assert url == "https://api.github.com/user" and method == "GET" and body is None
    assert headers["Authorization"] == f"Bearer {GH_TOKEN}"
    assert headers["User-Agent"]  # GitHub requires a UA


def test_stripe_uses_basic_auth():
    _, headers, _, _ = StripeVerifier().request("sk_live_abc")
    assert headers["Authorization"].startswith("Basic ")


def test_interpret_status_mapping():
    v = GitHubVerifier()
    assert v.interpret(200) == Verification.VALID
    assert v.interpret(204) == Verification.VALID
    assert v.interpret(401) == Verification.INVALID
    assert v.interpret(403) == Verification.INVALID
    assert v.interpret(500) == Verification.UNVERIFIED
    assert v.interpret(429) == Verification.UNVERIFIED


# ── runner behavior (fake http) ───────────────────────────────────────────
def _runner(status_or_exc, calls=None, sleeps=None):
    def http(url, headers, method, body, timeout):
        if calls is not None:
            calls.append(url)
        if isinstance(status_or_exc, Exception):
            raise status_or_exc
        return status_or_exc
    return VerificationRunner(default_verifiers(), rate_limit=0.5,
                              http=http, sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


def test_runner_marks_valid():
    f = _finding("github_user")
    _runner(200).verify([(f, GH_TOKEN)])
    assert f.verification == Verification.VALID


def test_runner_marks_invalid():
    f = _finding("github_user")
    _runner(401).verify([(f, GH_TOKEN)])
    assert f.verification == Verification.INVALID


def test_runner_network_error_is_unverified_not_invalid():
    f = _finding("github_user")
    _runner(OSError("boom")).verify([(f, GH_TOKEN)])
    assert f.verification == Verification.UNVERIFIED


def test_runner_dedups_identical_secret():
    f1 = _finding("github_user", GH_TOKEN, "a.py")
    f2 = _finding("github_user", GH_TOKEN, "b.py")
    calls: list[str] = []
    _runner(200, calls=calls).verify([(f1, GH_TOKEN), (f2, GH_TOKEN)])
    assert len(calls) == 1  # same secret checked once
    assert f1.verification == f2.verification == Verification.VALID


def test_runner_rate_limits_between_distinct_calls():
    f1 = _finding("github_user", "tokA", "a.py")
    f2 = _finding("github_user", "tokB", "b.py")
    sleeps: list[float] = []
    _runner(200, sleeps=sleeps).verify([(f1, "tokA"), (f2, "tokB")])
    assert sleeps == [0.5]  # one pause between the two distinct calls


def test_runner_unregistered_verifier_is_skipped():
    f = _finding("nonexistent")
    _runner(200).verify([(f, "x")])
    assert f.verification == Verification.SKIPPED


# ── recovering raw secrets from the working tree ──────────────────────────
def test_collect_verifiable_recovers_secret_and_skips_others(tmp_path):
    (tmp_path / "app.py").write_text(f'gh = "{GH_TOKEN}"\n', encoding="utf-8")
    (tmp_path / "aws.py").write_text('k = "AKIAZ7XQ4WL9PRT2KD8N"\n', encoding="utf-8")
    result = SecretScanner(default_detectors()).scan(tmp_path)

    items = collect_verifiable(result.findings, set(default_verifiers()))
    # the GitHub token is verifiable; its raw value is recovered exactly
    assert any(secret == GH_TOKEN for _, secret in items)
    # the AWS key (no registered verifier) is marked SKIPPED, not queued
    aws = next(f for f in result.findings if f.rule_id == "aws_access_key_id")
    assert aws.verification == Verification.SKIPPED
    assert all(f.rule_id != "aws_access_key_id" for f, _ in items)
