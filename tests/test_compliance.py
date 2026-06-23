"""Phase 6 tests — compliance mapping."""

from __future__ import annotations

from core.compliance import controls_for, summarize
from core.models import Finding, ScanResult, Severity, fingerprint


def _f(rule_id: str, path: str = "a.py") -> Finding:
    return Finding(rule_id, "d", Severity.HIGH, path, 1, 1, "x…",
                   fingerprint(rule_id, rule_id + path, path))


def _ids(controls):
    return {cid for cid, _ in controls}


def test_plain_secret_maps_to_cwe_798():
    c = controls_for("aws_access_key_id")
    assert _ids(c["CWE"]) == {"CWE-798"}
    assert _ids(c["OWASP_2021"]) == {"A07:2021"}
    assert "PCI DSS 8.6.2" in _ids(c["PCI_DSS_4"])
    assert "IA-5" in _ids(c["NIST_800_53"])


def test_private_key_maps_to_crypto_controls():
    c = controls_for("private_key_block")
    assert _ids(c["CWE"]) == {"CWE-321"}
    assert _ids(c["OWASP_2021"]) == {"A02:2021"}
    assert "SC-12" in _ids(c["NIST_800_53"])


def test_jwt_maps_to_protected_credentials():
    assert _ids(controls_for("jwt")["CWE"]) == {"CWE-522"}


def test_summarize_counts_controls_across_findings():
    result = ScanResult(root="r", findings=[
        _f("aws_access_key_id"), _f("github_pat", "b.py"), _f("private_key_block", "c.py"),
    ])
    summary = summarize(result)
    cwe = summary["frameworks"]["CWE"]
    assert cwe["CWE-798"]["count"] == 2   # aws + github
    assert cwe["CWE-321"]["count"] == 1   # private key
    assert summary["findings_mapped"] == 3
    assert summary["controls_implicated"] > 0
