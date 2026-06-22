# Secrets Scanner

> Detect hardcoded credentials and secrets across source, config, and (soon) git
> history — with redacted reporting, allowlist tuning, baseline suppression, and a
> CI fail-gate.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-17%20passing-brightgreen.svg)](tests/)

Secrets Scanner is the **defensive mirror** of the offensive
**T1552.001 "Credentials in Files"** module in the KIZEN red-team portfolio: that
tool finds the gaps, this one closes them — sharing the same pattern intelligence
in the opposite direction. It maps to the AccuKnox **SECURING SECRETS** capability.

**Status:** Phases 1–2 complete (filesystem scanning + detector breadth) ·
**Python** 3.10+ · **License** MIT

---

## Why another secrets scanner?

- **Secrets never leak out of the scanner.** Findings carry a *redacted* preview
  (`AKIA…8N (20 chars)`) and a stable fingerprint — the raw value is never written
  to a finding, log, baseline, or report.
- **Low noise by default.** A built-in allowlist drops documentation samples and
  template placeholders; generic rules are entropy-gated; the walker skips
  binaries and vendored trees.
- **Rules are data, not code.** Every detection lives in
  [`rules/secret_patterns.yaml`](rules/secret_patterns.yaml) — add or tune patterns
  without touching Python.
- **CI-first.** A single `--fail-on` flag turns the scanner into a build gate.

---

## Features

### Detection (28 signature rules)

| Category | Providers / formats |
|----------|---------------------|
| **Cloud** | AWS access key ID + secret access key, Azure storage account key, GCP API key / service-account JSON / OAuth client secret |
| **VCS / CI** | GitHub PAT (classic + fine-grained) & OAuth/app/refresh tokens, GitLab PAT |
| **AI / LLM** | OpenAI API key, Anthropic API key |
| **SaaS** | Stripe, Slack token + webhook, SendGrid, Twilio, Mailgun, Telegram bot, Shopify, DigitalOcean |
| **Registries** | npm token, PyPI upload token |
| **Generic** | PEM private-key blocks, JWTs, DB connection URIs with inline creds, generic `api_key = "…"` assignments |

- **Per-rule entropy gating** — noisy/generic rules only fire above a configurable
  Shannon-entropy floor, cutting false positives on values like `password123`.
- **Entropy detector** *(opt-in, `--entropy`)* — flags high-entropy strings that no
  signature matches, catching unknown/novel key formats.
- **Verifier hints** — rules carry a `verifier` tag (`aws_sts`, `github_user`,
  `openai`, …) for the planned Phase 5 live-verification, surfaced in JSON output.

### Noise control

- **Allowlist** *(on by default)* — suppresses documentation samples
  (`AKIAIOSFODNN7EXAMPLE`), template placeholders (`<your-api-key>`, `${SECRET}`,
  `{{ token }}`), and obvious fixtures. Tune in the `allowlist:` section of the rule
  pack; disable entirely with `--no-allowlist`.
- **Baseline suppression** — snapshot today's findings, then surface only *new*
  secrets on future scans. Fingerprints are stable across line moves.
- **Fast walker** — skips binaries (null-byte sniff + extension list), files > 5 MB,
  and noise dirs (`.git`, `node_modules`, `venv`, `dist`, `vendor`, `.terraform`, …).

### Output & integration

- **Table** (rich) for humans, **JSON** for tooling/SIEM.
- **CI gate** — `--fail-on <severity>` exits non-zero when any finding is at or
  above the threshold.

---

## Install

```bash
git clone https://github.com/Krishcalin/Secrets-Scanner.git
cd Secrets-Scanner
pip install -r requirements.txt        # or:  pip install -e ".[test]"
```

Installing with `pip install -e .` also exposes a `secrets-scan` console script
(equivalent to `python main.py`).

---

## Usage

```bash
# Scan a directory (or a single file)
python main.py scan --path .

# Include the entropy detector (catches unknown formats; noisier)
python main.py scan --path . --entropy

# Report even documentation/placeholder sample values
python main.py scan --path . --no-allowlist

# JSON output (for tooling / SIEM ingestion)
python main.py scan --path . --format json

# CI gate — exit 1 on any HIGH-or-above finding
python main.py scan --path . --fail-on high

# Create a baseline of existing findings, then scan suppressing them
python main.py baseline --path . -o .secrets-baseline.json
python main.py scan --path . --baseline .secrets-baseline.json
```

### `scan` options

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | `.` | File or directory to scan |
| `--entropy` | off | Also run the entropy detector |
| `--no-allowlist` | off | Report documentation/placeholder values too |
| `--baseline <file>` | — | Baseline JSON of fingerprints to suppress |
| `--format table\|json` | `table` | Output format |
| `--fail-on <severity>` | — | Exit 1 if any finding is at/above this severity |
| `--log-level` | `WARNING` | Set on the top-level `cli` group |

### Example JSON finding

```json
{
  "rule_id": "aws_access_key_id",
  "severity": "critical",
  "path": "config/prod.py",
  "line": 12,
  "preview": "AKIA…8N (20 chars)",
  "fingerprint": "9f2c1a7b6e4d0c83",
  "description": "AWS Access Key ID",
  "entropy": null,
  "verifier": "aws_sts"
}
```

---

## How it works

```
walk_files(root)  →  detectors  →  dedup (fingerprint)  →  baseline filter  →  ScanResult
   skip binary/        signature                                                  table / json
   noise/oversized     + entropy (opt-in)                                         + fail-on gate
```

1. **Walk** the tree, skipping binaries, oversized files, and noise directories.
2. **Run detectors** over each file's full text (full content, not line-by-line —
   so multi-line PEM keys match; the line/column is derived from the match offset).
3. Each detector applies the **allowlist** and any **entropy gate** before emitting
   a `Finding` with a redacted preview + fingerprint.
4. **Dedup** by fingerprint, then drop anything in the **baseline**.
5. Render **table/JSON**, and optionally enforce the **`--fail-on` gate**.

---

## Adding & tuning rules

Append to [`rules/secret_patterns.yaml`](rules/secret_patterns.yaml) — no code change:

```yaml
patterns:
  - id: my_internal_token
    description: Internal service token
    regex: "INT-[0-9A-F]{32}"
    severity: critical          # info | low | medium | high | critical
    # capture: 1                # optional: group index of the secret value
    # min_entropy: 3.5          # optional: skip matches below this Shannon entropy
    # verifier: my_api          # optional: Phase 5 live-verification hint
```

The `allowlist:` section of the same file controls suppression:

```yaml
allowlist:
  value_patterns:               # regex matched against the secret value (case-insensitive)
    - "example"
    - "<[^>]+>"                 # <your-api-key>
  path_patterns: []             # opt-in; matched against the file path
```

---

## Project layout

```
secrets-scanner/
├── main.py                     # Click CLI: scan, baseline
├── core/
│   ├── models.py               # Severity, Verification, Finding, ScanResult, redact(), fingerprint()
│   ├── walker.py               # walk_files() — skip binaries/noise/oversized
│   ├── engine.py               # SecretScanner + default_detectors()
│   ├── baseline.py             # Baseline load/write/suppress (fingerprint set)
│   ├── allowlist.py            # Allowlist — placeholder/example/template suppression
│   └── logger.py               # structlog setup (never logs raw secrets)
├── detectors/
│   ├── base.py                 # BaseDetector ABC (detect / line_col)
│   ├── signature.py            # YAML rule-pack regex detector
│   └── entropy.py              # Shannon-entropy detector (opt-in)
├── rules/secret_patterns.yaml  # 28 signature rules + allowlist
└── tests/test_scanner.py       # 17 pytest tests
```

See [CLAUDE.md](CLAUDE.md) for architecture detail and the full phase roadmap.

---

## Roadmap

| Phase | Scope | Status |
|------:|-------|--------|
| 1 | Filesystem scanning foundation | ✅ Complete |
| 2 | Detector breadth (28 rules, entropy gating, verifier hints, allowlist) | ✅ Complete |
| 3 | Git-history scanning (leaked-then-removed secrets) | Planned |
| 4 | Triage & suppression (`.gitignore`-aware, inline `# pragma: allowlist secret`) | Planned |
| 5 | Safe live verification (AWS STS, GitHub `/user`, … — rate-limited, read-only) | Planned |
| 6 | HTML/JSON/CSV reports, pre-commit hook, CI gate, CWE-798/OWASP/PCI-DSS mapping | Planned |

---

## Testing

```bash
pytest                # 17 tests
pytest --cov=core --cov=detectors
```

---

## Safety & responsible use

This tool is **read-only**: it detects secrets, it never exfiltrates or transmits
them. Run it only against code you are authorized to scan. When it finds a live
credential, **rotate it** — removing the line from the latest commit does not
revoke a key that already leaked into git history.

## License

MIT — see [LICENSE](LICENSE).
