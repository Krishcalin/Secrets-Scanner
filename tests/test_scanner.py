"""Phase 1 tests — detectors, engine, baseline, redaction."""

from __future__ import annotations

from core.baseline import Baseline
from core.engine import SecretScanner, default_detectors
from core.models import Severity, fingerprint, redact
from detectors.entropy import EntropyDetector, shannon_entropy
from detectors.signature import SignatureDetector


# ── models ──────────────────────────────────────────────────────────────
def test_redact_hides_secret_body():
    out = redact("AKIAIOSFODNN7EXAMPLE")
    assert "IOSFODNN" not in out and out.startswith("AKIA")


def test_fingerprint_is_stable_and_line_independent():
    assert fingerprint("r", "s", "f") == fingerprint("r", "s", "f")
    assert fingerprint("r", "s", "f") != fingerprint("r", "other", "f")


# ── signature detector ──────────────────────────────────────────────────
def test_signature_detects_aws_key():
    det = SignatureDetector()
    findings = det.detect("config.py", "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    ids = {f.rule_id for f in findings}
    assert "aws_access_key_id" in ids
    f = next(f for f in findings if f.rule_id == "aws_access_key_id")
    assert f.severity == Severity.CRITICAL and f.line == 1


def test_signature_captures_assignment_value():
    det = SignatureDetector()
    content = 'password = "hunter2hunter2hunter2"\n'
    f = det.detect("a.py", content)
    assert any(x.rule_id == "generic_api_key_assignment" for x in f)
    # preview is redacted — raw secret never appears
    assert all("hunter2hunter2hunter2" not in x.preview for x in f)


def test_signature_detects_private_key_block():
    det = SignatureDetector()
    f = det.detect("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
    assert any(x.rule_id == "private_key_block" for x in f)


def test_signature_clean_file_is_empty():
    det = SignatureDetector()
    assert det.detect("ok.py", "def add(a, b):\n    return a + b\n") == []


# ── entropy detector ────────────────────────────────────────────────────
def test_entropy_function():
    assert shannon_entropy("aaaa") < 1.0
    assert shannon_entropy("aB3$xZ9qLm2Kp7Wv") > 3.0


def test_entropy_flags_random_token():
    det = EntropyDetector(min_entropy=4.0)
    token = "Zk9Q2xL7mP4rT1vY8wB3nC6dF0aH5jK"  # mixed, high entropy
    f = det.detect("a.py", f'token = "{token}"\n')
    assert any(x.rule_id == "high_entropy_string" for x in f)


# ── engine + baseline ───────────────────────────────────────────────────
def test_engine_scans_tmp_tree(tmp_path):
    (tmp_path / "app.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "img.png").write_bytes(b"\x89PNG\x00\x00binary")
    result = SecretScanner(default_detectors()).scan(tmp_path)
    assert result.count >= 1
    assert any(f.rule_id == "aws_access_key_id" for f in result.findings)
    assert result.files_scanned >= 2  # png skipped by walker


def test_baseline_suppresses_known(tmp_path):
    (tmp_path / "app.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")
    first = SecretScanner(default_detectors()).scan(tmp_path)
    bl_path = tmp_path / "baseline.json"
    Baseline.write(bl_path, first.findings)

    second = SecretScanner(default_detectors(), baseline=Baseline.load(bl_path)).scan(tmp_path)
    assert second.count == 0  # all prior findings suppressed
