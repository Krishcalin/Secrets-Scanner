"""Phase 1 tests — detectors, engine, baseline, redaction."""

from __future__ import annotations

from core.allowlist import Allowlist
from core.baseline import Baseline
from core.engine import SecretScanner, default_detectors
from core.models import Finding, Severity, fingerprint, redact
from core.pragma import line_allowlisted
from detectors.entropy import EntropyDetector, shannon_entropy
from detectors.signature import SignatureDetector

# Fake-but-well-formed AWS key (not AWS's "...EXAMPLE" doc sample, which the
# allowlist intentionally suppresses).
FAKE_AWS_KEY = "AKIAZ7XQ4WL9PRT2KD8N"


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
    findings = det.detect("config.py", f"AWS_KEY = '{FAKE_AWS_KEY}'\n")
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
    (tmp_path / "app.py").write_text(f"KEY='{FAKE_AWS_KEY}'", encoding="utf-8")
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "img.png").write_bytes(b"\x89PNG\x00\x00binary")
    result = SecretScanner(default_detectors()).scan(tmp_path)
    assert result.count >= 1
    assert any(f.rule_id == "aws_access_key_id" for f in result.findings)
    assert result.files_scanned >= 2  # png skipped by walker


def test_baseline_suppresses_known(tmp_path):
    (tmp_path / "app.py").write_text(f"KEY='{FAKE_AWS_KEY}'", encoding="utf-8")
    first = SecretScanner(default_detectors()).scan(tmp_path)
    bl_path = tmp_path / "baseline.json"
    Baseline.write(bl_path, first.findings)

    second = SecretScanner(default_detectors(), baseline=Baseline.load(bl_path)).scan(tmp_path)
    assert second.count == 0  # all prior findings suppressed


# ── Phase 2: detector breadth ────────────────────────────────────────────
def test_new_provider_patterns_detected():
    det = SignatureDetector()
    samples = {
        "github_oauth_token": "gho_" + "a" * 36,
        "gitlab_pat": "glpat-" + "A1b2C3d4E5f6G7h8I9j0",
        "anthropic_api_key": "sk-ant-api03-" + "Zk9Q2xL7mP4rT1vY8wB3" * 4 + "abcd",
        "sendgrid_api_key": "SG." + "a" * 22 + "." + "b" * 43,
        "npm_token": "npm_" + "Z" * 36,
        "digitalocean_pat": "dop_v1_" + "a" * 64,
    }
    for rule_id, blob in samples.items():
        ids = {f.rule_id for f in det.detect("c.py", f"x = '{blob}'\n")}
        assert rule_id in ids, f"{rule_id} not detected"


def test_openai_key_carries_verifier_metadata():
    det = SignatureDetector()
    blob = "sk-proj-" + "Zk9Q2xL7mP4rT1vY8wB3nC6dF0aH5jK"
    f = next(x for x in det.detect("c.py", f"k='{blob}'") if x.rule_id == "openai_api_key")
    assert f.metadata.get("verifier") == "openai"
    assert f.entropy is not None  # min_entropy rule records the measured entropy


def test_allowlist_suppresses_aws_example_key():
    det = SignatureDetector()  # allowlist on by default
    assert det.detect("c.py", "KEY='AKIAIOSFODNN7EXAMPLE'\n") == []


def test_allowlist_suppresses_template_placeholders():
    det = SignatureDetector()
    content = 'api_key = "<your-api-key-here>"\npassword = "${DB_PASSWORD}"\n'
    assert det.detect("c.py", content) == []


def test_no_allowlist_reports_example_key():
    det = SignatureDetector(allowlist=Allowlist.empty())
    ids = {f.rule_id for f in det.detect("c.py", "KEY='AKIAIOSFODNN7EXAMPLE'\n")}
    assert "aws_access_key_id" in ids


def test_min_entropy_gate_drops_low_entropy_generic():
    det = SignatureDetector()
    # repeated low-entropy value below the generic rule's min_entropy (2.5)
    findings = det.detect("c.py", 'token = "aaaaaaaaaaaaaaaa"\n')
    assert not any(f.rule_id == "generic_api_key_assignment" for f in findings)


def test_allowlist_default_loads_value_patterns():
    al = Allowlist.default()
    assert al.allows_value("AKIAIOSFODNN7EXAMPLE")
    assert al.allows_value("changeme")
    assert not al.allows_value("Zk9Q2xL7mP4rT1vY8wB3nC6dF0aH5jK")


# ── Phase 4: triage & suppression ────────────────────────────────────────
def test_line_allowlisted_recognizes_pragmas():
    assert line_allowlisted('k = "x"  # pragma: allowlist secret')
    assert line_allowlisted("token = y  // gitleaks:allow")
    assert not line_allowlisted('k = "x"  # ordinary comment')


def test_inline_pragma_suppresses_only_marked_line(tmp_path):
    (tmp_path / "a.py").write_text(
        f'k = "{FAKE_AWS_KEY}"  # pragma: allowlist secret\n', encoding="utf-8")
    (tmp_path / "b.py").write_text(f'k = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    result = SecretScanner(default_detectors()).scan(tmp_path)
    aws = [f for f in result.findings if f.rule_id == "aws_access_key_id"]
    assert len(aws) == 1 and aws[0].path.endswith("b.py")


def _fp_finding(rule_id, secret, path):
    return Finding(rule_id, "d", Severity.HIGH, path, 1, 1, "p",
                   fingerprint(rule_id, secret, path))


def test_baseline_update_merges_findings(tmp_path):
    f1 = _fp_finding("r1", "s1", "a.py")
    f2 = _fp_finding("r2", "s2", "b.py")
    bp = tmp_path / "bl.json"
    Baseline.write(bp, [f1])
    Baseline.write(bp, [f2], update=True)        # merge, don't overwrite
    bl = Baseline.load(bp)
    assert bl.suppresses(f1) and bl.suppresses(f2)


def test_baseline_overwrite_drops_old(tmp_path):
    f1 = _fp_finding("r1", "s1", "a.py")
    f2 = _fp_finding("r2", "s2", "b.py")
    bp = tmp_path / "bl.json"
    Baseline.write(bp, [f1])
    Baseline.write(bp, [f2])                      # no update → replaces
    bl = Baseline.load(bp)
    assert not bl.suppresses(f1) and bl.suppresses(f2)


def test_baseline_stores_entry_metadata(tmp_path):
    f1 = _fp_finding("aws_access_key_id", "s1", "a.py")
    bp = tmp_path / "bl.json"
    Baseline.write(bp, [f1], reason="known test fixture")
    entry = Baseline.load(bp).entries[f1.fingerprint]
    assert entry["rule_id"] == "aws_access_key_id" and entry["reason"] == "known test fixture"
