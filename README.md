# Secrets Scanner

> Detect hardcoded credentials and secrets across source, config, and git
> history — with redacted reporting, allowlist tuning, baseline suppression,
> opt-in live verification, and a CI fail-gate.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-41%20passing-brightgreen.svg)](tests/)

Secrets Scanner is the **defensive mirror** of the offensive
**T1552.001 "Credentials in Files"** module in the KIZEN red-team portfolio: that
tool finds the gaps, this one closes them — sharing the same pattern intelligence
in the opposite direction. It maps to the AccuKnox **SECURING SECRETS** capability.

**Status:** Phases 1–5 complete (filesystem + git-history scanning, triage, live verification) ·
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
  `openai`, …) that drive live verification, surfaced in JSON output.

### Live verification *(opt-in)*

- **`verify` command** — after scanning, makes a single **read-only** request per
  unique secret to its own provider and reports whether the credential is actually
  **live**: `VALID` (rotate now!), `INVALID`, `UNVERIFIED` (couldn't tell), or
  `SKIPPED` (no verifier for that type).
- **Providers:** GitHub, GitLab, OpenAI, Anthropic, Stripe, SendGrid.
- **Safe by construction:** opt-in command requiring confirmation; read-only
  endpoints only; a secret is sent only to its own provider; redirects are never
  followed (no header leakage); per-call timeout + rate limiting; network errors
  fail safe to `UNVERIFIED` (never a false `INVALID`); raw secrets are recovered
  into memory only for the call and **never logged or stored**.
- **`--fail-on-valid`** turns "a live credential is in the code" into a build break.

### Git-history scanning

- **`history` command** — walks **every commit on every ref** and scans each
  commit's *added* lines, so a secret is caught at the commit that introduced it
  **even if a later commit deleted it** (the value still lives in history and is
  recoverable). Findings carry `source="git-history"` plus the commit hash,
  author, email, date, and message — so you know where the leak entered and whose
  key to rotate.
- Accurate new-file line numbers and multi-line secret support; reuses the same
  signature/entropy detectors, allowlist, and baseline as filesystem scans.
- `--max-commits N` caps the walk for large repos.

### Noise control

- **Allowlist** *(on by default)* — suppresses documentation samples
  (`AKIAIOSFODNN7EXAMPLE`), template placeholders (`<your-api-key>`, `${SECRET}`,
  `{{ token }}`), and obvious fixtures. Tune in the `allowlist:` section of the rule
  pack; disable entirely with `--no-allowlist`.
- **Baseline suppression** — snapshot today's findings, then surface only *new*
  secrets on future scans. Fingerprints are stable across line moves. `baseline
  --update` merges into an existing baseline so triage is **incremental**: scan,
  fix the real leaks, fold the rest in as accepted (with an optional `--reason`).
- **Inline pragmas** — drop a single known-safe match in place with a
  `# pragma: allowlist secret` (or `gitleaks:allow`) comment on the line.
- **`.gitignore`-aware** — `--gitignore` skips git-ignored files using git's own
  `check-ignore` engine (correct semantics, no extra dependency).
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

# Skip git-ignored files (build artifacts, local .env, …)
python main.py scan --path . --gitignore

# Create a baseline of existing findings, then scan suppressing them
python main.py baseline --path . -o .secrets-baseline.json
python main.py scan --path . --baseline .secrets-baseline.json

# Incrementally accept remaining findings into the baseline after triage
python main.py baseline --path . -o .secrets-baseline.json --update --reason "triaged 2026-06"

# Scan the full git history (catches leaked-then-removed secrets)
python main.py history --path .
python main.py history --path . --max-commits 500 --format json
python main.py history --path . --fail-on high       # CI gate on history too

# Verify whether detected credentials are actually LIVE (read-only, opt-in)
python main.py verify --path .                       # prompts before any request
python main.py verify --path . --yes --fail-on-valid # CI: break the build on a live key
```

### `scan` options

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | `.` | File or directory to scan |
| `--entropy` | off | Also run the entropy detector |
| `--no-allowlist` | off | Report documentation/placeholder values too |
| `--gitignore` | off | Skip git-ignored files (inside a git work tree) |
| `--baseline <file>` | — | Baseline JSON of fingerprints to suppress |
| `--format table\|json` | `table` | Output format |
| `--fail-on <severity>` | — | Exit 1 if any finding is at/above this severity |
| `--log-level` | `WARNING` | Set on the top-level `cli` group |

`history` takes the same options plus `--max-commits N` (limit the walk to the
most recent N commits). Its table adds a **Commit** column; its JSON adds
`source`, `commit`, `author`, and `date` per finding.

`verify` takes the scan options plus `--rate-limit <s>` (pause between calls,
default 1.0), `--timeout <s>` (per-call, default 8.0), `-y/--yes` (skip the
confirmation prompt — required for non-interactive/CI use), and `--fail-on-valid`
(exit 1 if any credential is confirmed live). Its table adds a **Status** column;
every command's JSON now includes a `verification` field per finding.

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
  "verifier": "aws_sts",
  "verification": "skipped"
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

The `history` command swaps step 1 for a `git log --all -p` walk: it reconstructs
the *added* lines of each commit (per file, with a line map for accurate line
numbers), runs the same detectors, and attributes each finding to the introducing
commit — so deleted-but-historical secrets still surface.

---

## Suppressing false positives

Three layers, from broadest to most surgical:

| Mechanism | Scope | When to use |
|-----------|-------|-------------|
| **Allowlist** (`allowlist:` in the rule pack) | every scan, by value/path regex | doc samples & template placeholders that recur everywhere |
| **Baseline** (`--baseline` + `baseline --update`) | a known set of fingerprints | accept a repo's existing findings, then alert only on *new* ones |
| **Inline pragma** | one line | a single intentional fixture the scanner can't distinguish from a real leak |

```python
test_key = "AKIA...................."   # pragma: allowlist secret
demo     = "sk_live_000000000000000000"  # gitleaks:allow
```

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
├── main.py                     # Click CLI: scan, history, verify, baseline
├── core/
│   ├── models.py               # Severity, Verification, Finding, ScanResult, redact(), fingerprint()
│   ├── walker.py               # walk_files() — skip binaries/noise/oversized
│   ├── engine.py               # SecretScanner + default_detectors()
│   ├── git_history.py          # GitHistoryScanner — scan commit diffs (added lines)
│   ├── verify.py               # live verification — Verifier/Runner, raw-secret recovery
│   ├── baseline.py             # Baseline load/write/suppress + incremental --update
│   ├── allowlist.py            # Allowlist — placeholder/example/template suppression
│   ├── pragma.py               # inline `# pragma: allowlist secret` suppression
│   ├── gitignore.py            # .gitignore-aware filtering (git check-ignore)
│   └── logger.py               # structlog setup (never logs raw secrets)
├── detectors/
│   ├── base.py                 # BaseDetector ABC (detect / line_col)
│   ├── signature.py            # YAML rule-pack regex detector
│   └── entropy.py              # Shannon-entropy detector (opt-in)
├── rules/secret_patterns.yaml  # 28 signature rules + allowlist
└── tests/                      # 41 pytest tests (scanner, git_history, verify)
```

See [CLAUDE.md](CLAUDE.md) for architecture detail and the full phase roadmap.

---

## Roadmap

| Phase | Scope | Status |
|------:|-------|--------|
| 1 | Filesystem scanning foundation | ✅ Complete |
| 2 | Detector breadth (28 rules, entropy gating, verifier hints, allowlist) | ✅ Complete |
| 3 | Git-history scanning (leaked-then-removed secrets) | ✅ Complete |
| 4 | Triage & suppression (`.gitignore`-aware, inline pragmas, baseline merge) | ✅ Complete |
| 5 | Safe live verification (GitHub, GitLab, OpenAI, Anthropic, Stripe, SendGrid — rate-limited, read-only) | ✅ Complete |
| 6 | HTML/JSON/CSV reports, pre-commit hook, CI gate, CWE-798/OWASP/PCI-DSS mapping | Planned |

---

## Testing

```bash
pytest                # 41 tests
pytest --cov=core --cov=detectors
```

The git-history tests spin up throwaway repos and are skipped automatically if
`git` is not on `PATH`. The verification tests inject a fake HTTP layer and make
**no real network calls**.

---

## Safety & responsible use

Detection is **read-only** and never transmits secrets. The only feature that
makes outbound network calls is `verify`, and it is deliberately constrained: it
is opt-in (a separate command requiring confirmation), contacts only each secret's
own provider over read-only endpoints, never follows redirects, rate-limits and
times out every call, and never logs or stores the raw value. Run the tool only
against code you are authorized to scan. When it finds a live credential,
**rotate it** — removing the line from the latest commit does not revoke a key
that already leaked into git history.

## License

MIT — see [LICENSE](LICENSE).
