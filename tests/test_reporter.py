"""Phase 6 tests — JSON/CSV/HTML reporting."""

from __future__ import annotations

import json

import pytest

from core.models import Finding, ScanResult, Severity, Verification, fingerprint
from core.reporter import result_to_dict, to_csv, to_html, write_report


def _f(rule_id="aws_access_key_id", sev=Severity.CRITICAL, path="a.py",
       verification=Verification.UNVERIFIED) -> Finding:
    return Finding(rule_id, "desc", sev, path, 1, 1, "AKIA…XX (20 chars)",
                   fingerprint(rule_id, rule_id + path, path), verification=verification)


def _result(findings=None):
    return ScanResult(root="repo", findings=findings if findings is not None else [_f()],
                      files_scanned=3)


def test_result_to_dict_includes_compliance_and_findings():
    d = result_to_dict(_result([_f(), _f("github_pat", path="b.py")]))
    assert d["scope"] == "filesystem" and d["count"] == 2
    assert d["compliance"]["frameworks"]["CWE"]["CWE-798"]["count"] == 2
    assert len(d["findings"]) == 2 and "generated_at" in d


def test_csv_has_header_and_rows_without_raw_secret():
    csv_text = to_csv(_result())
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("severity,rule_id,path,line")
    assert "aws_access_key_id" in lines[1]


def test_html_is_escaped_and_contains_summary():
    result = _result([_f(path="<script>evil</script>.py")])
    html_text = to_html(result)
    assert "Secrets Scan Report" in html_text
    assert "CWE-798" in html_text                  # compliance section rendered
    assert "&lt;script&gt;" in html_text           # path is escaped
    assert "<script>evil" not in html_text         # ...and not injected raw


def test_html_shows_status_column_when_verified():
    result = _result([_f(verification=Verification.VALID)])
    assert "Status" in to_html(result)


def test_write_report_dispatches_by_extension(tmp_path):
    result = _result()
    for ext in ("json", "csv", "html"):
        out = write_report(result, tmp_path / f"r.{ext}")
        assert out.exists() and out.read_text(encoding="utf-8")
    # JSON file is valid JSON
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["count"] == 1


def test_write_report_rejects_unknown_extension(tmp_path):
    with pytest.raises(ValueError):
        write_report(_result(), tmp_path / "r.txt")
