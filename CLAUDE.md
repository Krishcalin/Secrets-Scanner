# CLAUDE.md — Secrets Scanner

## Project Overview

A scanner that detects hardcoded credentials and secrets across source, config,
and (later) git history, with redacted reporting, baseline suppression, safe
live-verification, and CI/SIEM integration. Defensive mirror of the offensive
**T1552.001 "Credentials in Files"** module in the KIZEN Windows-Red-Teaming
tool — shared pattern intelligence, opposite direction.

Maps to AccuKnox **SECURING SECRETS**.

**Python**: 3.10+ · **License**: MIT · **Status**: Phases 1-2 complete (17 tests)

---

## Architecture

```
secrets-scanner/
├── main.py                    # Click CLI: scan, baseline
├── core/
│   ├── models.py              # Severity, Verification, Finding, ScanResult,
│   │                          #   redact(), fingerprint()
│   ├── walker.py              # walk_files() — skip binaries/noise/oversized
│   ├── engine.py              # SecretScanner + default_detectors()
│   ├── baseline.py            # Baseline load/write/suppress (fingerprint set)
│   ├── allowlist.py           # Allowlist — placeholder/example/template suppression
│   └── logger.py              # structlog setup (never logs raw secrets)
├── detectors/
│   ├── base.py                # BaseDetector ABC (detect / line_col)
│   ├── signature.py           # YAML rule-pack regex detector
│   └── entropy.py             # Shannon-entropy detector (opt-in)
├── rules/secret_patterns.yaml # signature rule pack (id/desc/regex/severity/capture)
├── config/                    # settings (later phases)
└── tests/test_scanner.py
```

### Core contracts

- **`BaseDetector`** — `detect(path, content) -> list[Finding]`; works on full
  file content so multi-line secrets (PEM keys) match. Helper `line_col()` maps a
  match offset to 1-based line/column.
- **`Finding`** — `rule_id, description, severity, path, line, column, preview
  (redacted), fingerprint, source, entropy, verification`.
- **`fingerprint(rule_id, secret, path)`** — stable hash (no raw secret stored);
  used for dedup and baseline suppression, independent of line moves.
- **`SecretScanner.scan(root)`** — walk → run detectors → dedup by fingerprint →
  apply baseline → `ScanResult`.

### Design principles

1. **Secrets never leak** — store redacted previews + fingerprints, never the
   raw value, in findings, logs, baselines, or reports.
2. **YAML-driven rules** — detections are data; add patterns without code changes.
3. **Low-noise by default** — entropy detector is opt-in; walker skips binaries.
4. **Safe by default** — detection is read-only; live verification (Phase 5) is
   opt-in and rate-limited, never exfiltrates.
5. **CI-first** — `--fail-on` gate and (Phase 6) pre-commit hook.

---

## Development Phases

### Phase 1 — Foundation (COMPLETE)
- [x] Models (`Finding`/`ScanResult`), `redact()`, `fingerprint()`
- [x] Filesystem walker (binary/size/noise-dir skipping)
- [x] `BaseDetector` ABC + signature detector (YAML rule pack) + entropy detector
- [x] Scan engine (dedup + baseline suppression)
- [x] Baseline load/write/suppress
- [x] CLI: `scan` (table/json, `--fail-on` gate), `baseline`
- [x] 10 pytest tests

### Phase 2 — Detector breadth (COMPLETE)
- [x] Expanded `secret_patterns.yaml` to 27 rules — added OpenAI, Anthropic,
      Azure storage key, GCP SA JSON + OAuth client secret, Twilio, SendGrid,
      Mailgun, Telegram, Shopify, DigitalOcean, npm, PyPI, GitLab PAT,
      GitHub OAuth/app/refresh tokens
- [x] Per-rule `min_entropy` gating + `verifier` hint metadata (→ Finding.metadata)
- [x] `core/allowlist.py` — value/path allowlist (example/placeholder/template
      suppression), on by default; `scan --no-allowlist` to disable
- [x] Allowlist wired into both signature + entropy detectors and `default_detectors`
- [x] 7 new pytest tests (17 total)

### Phase 3 — Git-history scanning
- [ ] Scan full commit history (`git log -p` / blob walk) for leaked-then-removed
      secrets; `source="git-history"` with commit + author metadata

### Phase 4 — Triage & suppression
- [ ] `.gitignore`-aware walking; inline `# pragma: allowlist secret`
- [ ] Baseline tuning + false-positive feedback loop

### Phase 5 — Live verification (opt-in, safe)
- [ ] `verify` command: confirm whether a detected credential is live
      (AWS STS GetCallerIdentity, GitHub /user, etc.) — rate-limited, never
      mutates, never exfiltrates; sets `Verification.VALID/INVALID`

### Phase 6 — Reporting, hooks & GRC
- [ ] HTML/JSON/CSV reports (reuse Guardrail reporter pattern)
- [ ] Pre-commit hook + GitHub Actions CI gate
- [ ] Compliance mapping (CWE-798 Hardcoded Credentials, OWASP, PCI-DSS 8.2)

---

## Coding Conventions

- Python 3.10+ (`X | Y` unions), type hints on public functions
- `structlog` only — never bare `print()` in library code (CLI uses `rich`)
- All rules via YAML — no hardcoded patterns in detector code
- Tests mirror source layout under `tests/`
- **Never log, store, or print a raw secret** — always `redact()` first
