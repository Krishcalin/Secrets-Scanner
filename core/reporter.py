"""Report generation — JSON, CSV, and a self-contained HTML report.

The HTML is built inline (no Jinja2 dependency) as a single dark-themed file with
an executive summary, a compliance roll-up, and the findings table. Every value is
HTML-escaped; redacted previews are used throughout — raw secrets never appear.

`result_to_dict()` is the canonical machine-readable payload shared by the CLI's
JSON console output and the JSON report file, so the two never drift.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from core.compliance import summarize
from core.models import ScanResult, Severity, Verification

_SEV_COLOR = {
    "critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
    "low": "#0dcaf0", "info": "#6c757d",
}
_VERIFY_COLOR = {
    "valid": "#dc3545", "invalid": "#6c757d",
    "unverified": "#ffc107", "skipped": "#495057",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _finding_dict(f) -> dict:
    return {
        "rule_id": f.rule_id, "severity": f.severity.value, "path": f.path,
        "line": f.line, "preview": f.preview, "fingerprint": f.fingerprint,
        "description": f.description, "entropy": f.entropy, "source": f.source,
        "verifier": f.metadata.get("verifier"), "verification": f.verification.value,
        "commit": f.metadata.get("commit_short"), "author": f.metadata.get("author"),
        "date": f.metadata.get("date"),
    }


def _by_verification(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.verification.value] = counts.get(f.verification.value, 0) + 1
    return counts


def result_to_dict(result: ScanResult, scope: str = "filesystem") -> dict:
    """Canonical machine-readable payload for a scan result."""
    return {
        "scope": scope,
        "generated_at": _now_iso(),
        "root": result.root,
        "files_scanned": result.files_scanned,
        "commits_scanned": result.commits_scanned,
        "count": result.count,
        "by_severity": result.by_severity(),
        "by_verification": _by_verification(result),
        "compliance": summarize(result),
        "findings": [_finding_dict(f) for f in result.findings],
    }


def to_json(result: ScanResult, scope: str = "filesystem") -> str:
    return json.dumps(result_to_dict(result, scope), indent=2)


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["severity", "rule_id", "path", "line", "source",
                     "verification", "verifier", "fingerprint", "description"])
    for f in result.findings:
        writer.writerow([
            f.severity.value, f.rule_id, f.path, f.line, f.source,
            f.verification.value, f.metadata.get("verifier", ""),
            f.fingerprint, f.description,
        ])
    return buf.getvalue()


# ── HTML ──────────────────────────────────────────────────────────────────
_SEV_ORDER = {s.value: i for i, s in enumerate(Severity)}


def _badge(text: str, color: str) -> str:
    return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:10px;font-size:12px;font-weight:600">{html.escape(text)}</span>')


def _summary_cards(result: ScanResult) -> str:
    sev = result.by_severity()
    cards = [f'<div class="card"><div class="num">{result.count}</div><div>findings</div></div>']
    for s in reversed(list(Severity)):
        n = sev.get(s.value, 0)
        if n:
            cards.append(f'<div class="card"><div class="num" style="color:{_SEV_COLOR[s.value]}">'
                         f'{n}</div><div>{s.value}</div></div>')
    return '<div class="cards">' + "".join(cards) + "</div>"


def _compliance_section(result: ScanResult) -> str:
    summary = summarize(result)
    titles = {"CWE": "CWE", "OWASP_2021": "OWASP Top 10 (2021)",
              "PCI_DSS_4": "PCI DSS v4.0", "NIST_800_53": "NIST 800-53"}
    rows = []
    for fw, controls in summary["frameworks"].items():
        if not controls:
            continue
        items = ", ".join(f"{html.escape(cid)} ({c['count']})"
                          for cid, c in sorted(controls.items()))
        rows.append(f"<tr><td><b>{titles.get(fw, fw)}</b></td><td>{items}</td></tr>")
    if not rows:
        return ""
    return ('<h2>Compliance</h2><table class="compliance"><tr>'
            '<th>Framework</th><th>Controls implicated</th></tr>'
            + "".join(rows) + "</table>")


def _findings_table(result: ScanResult, show_verification: bool) -> str:
    if not result.findings:
        return '<p class="ok">No secrets found.</p>'
    head = "<th>Severity</th><th>Rule</th><th>Location</th>"
    if show_verification:
        head += "<th>Status</th>"
    head += "<th>Preview</th>"
    rows = []
    for f in sorted(result.findings, key=lambda x: -_SEV_ORDER[x.severity.value]):
        loc = html.escape(f"{f.path}:{f.line}")
        if f.metadata.get("commit_short"):
            loc += f'<br><span class="dim">@ {html.escape(f.metadata["commit_short"])}'
            if f.metadata.get("author"):
                loc += " " + html.escape(f.metadata["author"])
            loc += "</span>"
        cells = [
            f"<td>{_badge(f.severity.value, _SEV_COLOR[f.severity.value])}</td>",
            f"<td><code>{html.escape(f.rule_id)}</code></td>",
            f"<td>{loc}</td>",
        ]
        if show_verification:
            v = f.verification.value
            cells.append(f"<td>{_badge(v, _VERIFY_COLOR.get(v, '#495057'))}</td>")
        cells.append(f'<td><code>{html.escape(f.preview)}</code></td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table class='findings'><tr>{head}</tr>" + "".join(rows) + "</table>"


def to_html(result: ScanResult, scope: str = "filesystem") -> str:
    show_verification = any(f.verification is not Verification.UNVERIFIED for f in result.findings)
    scanned = (f"{result.commits_scanned} commits" if scope == "git-history"
               else f"{result.files_scanned} files")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secrets Scan Report</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;
       color:#c9d1d9;margin:0;padding:32px;line-height:1.5}}
  h1{{margin:0 0 4px}} h2{{margin-top:32px;border-bottom:1px solid #30363d;padding-bottom:6px}}
  .meta{{color:#8b949e;font-size:14px;margin-bottom:24px}}
  .cards{{display:flex;gap:16px;flex-wrap:wrap}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 24px;text-align:center;min-width:90px}}
  .num{{font-size:32px;font-weight:700}}
  table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
  th{{color:#8b949e;font-weight:600}}
  code{{background:#161b22;padding:1px 5px;border-radius:4px;color:#c9d1d9}}
  .dim{{color:#8b949e;font-size:12px}} .ok{{color:#3fb950;font-size:18px}}
</style></head><body>
<h1>Secrets Scan Report</h1>
<div class="meta">scope: <b>{html.escape(scope)}</b> &middot; root: <code>{html.escape(result.root)}</code>
 &middot; scanned {scanned} &middot; generated {_now_iso()}</div>
{_summary_cards(result)}
{_compliance_section(result)}
<h2>Findings</h2>
{_findings_table(result, show_verification)}
</body></html>"""


def write_report(result: ScanResult, path: str | Path, scope: str = "filesystem") -> Path:
    """Write a report; format inferred from the file extension (.json/.csv/.html)."""
    out = Path(path)
    ext = out.suffix.lower()
    if ext == ".json":
        text = to_json(result, scope)
    elif ext == ".csv":
        text = to_csv(result)
    elif ext in (".html", ".htm"):
        text = to_html(result, scope)
    else:
        raise ValueError(f"unsupported report extension: {ext!r} (use .json, .csv, or .html)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out
