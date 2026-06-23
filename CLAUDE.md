# CLAUDE.md — Secrets Scanner

## Project Overview

A scanner that detects hardcoded credentials and secrets across source, config,
and (later) git history, with redacted reporting, baseline suppression, safe
live-verification, and CI/SIEM integration. Defensive mirror of the offensive
**T1552.001 "Credentials in Files"** module in the KIZEN Windows-Red-Teaming
tool — shared pattern intelligence, opposite direction.

Maps to AccuKnox **SECURING SECRETS**.

**Repository**: https://github.com/Krishcalin/Secrets-Scanner
**Python**: 3.10+ · **License**: MIT · **Status**: Phases 1-4 complete (28 rules, 31 tests)

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
│   ├── git_history.py         # GitHistoryScanner — scan commit diffs (added lines)
│   ├── baseline.py            # Baseline load/write/suppress + incremental --update
│   ├── allowlist.py           # Allowlist — placeholder/example/template suppression
│   ├── pragma.py              # inline `# pragma: allowlist secret` line suppression
│   ├── gitignore.py           # .gitignore-aware filtering (delegates to git check-ignore)
│   └── logger.py              # structlog setup (never logs raw secrets)
├── detectors/
│   ├── base.py                # BaseDetector ABC (detect / line_col)
│   ├── signature.py           # YAML rule-pack regex detector
│   └── entropy.py             # Shannon-entropy detector (opt-in)
├── rules/secret_patterns.yaml # 28 signature rules + allowlist section
├── config/                    # settings (later phases)
├── tests/test_scanner.py      # filesystem/detector/baseline tests (17)
└── tests/test_git_history.py  # git-history tests (7)
```

### Core contracts

- **`BaseDetector`** — `detect(path, content) -> list[Finding]`; works on full
  file content so multi-line secrets (PEM keys) match. Helper `line_col()` maps a
  match offset to 1-based line/column.
- **`SignatureDetector(rules_path, allowlist)`** — compiles the YAML rule pack;
  per match, applies the allowlist, then the rule's `min_entropy` gate, then emits
  a `Finding` (with `verifier` in `metadata` when set).
- **`EntropyDetector(min_entropy=4.0, allowlist)`** — opt-in; flags high-entropy,
  mixed-alphabet tokens that signatures miss.
- **`Allowlist(value_patterns, path_patterns)`** — `allows(secret, path)` suppresses
  documentation samples / template placeholders. `Allowlist.default()` loads from
  the rule pack's `allowlist:` section; `Allowlist.empty()` disables it.
- **`Finding`** — `rule_id, description, severity, path, line, column, preview
  (redacted), fingerprint, source, entropy, verification, metadata`.
- **`fingerprint(rule_id, secret, path)`** — stable hash (no raw secret stored);
  used for dedup and baseline suppression, independent of line moves.
- **`SecretScanner.scan(root)`** — walk → (optional `skip_gitignored` filter) →
  run detectors → drop inline-pragma'd lines → dedup by fingerprint → apply
  baseline → `ScanResult`. `default_detectors(entropy=, allowlist=)` builds the set.
- **`line_allowlisted(text)`** (`core/pragma.py`) — true when a source line carries
  `# pragma: allowlist secret` (or `gitleaks:allow`); applied in both scanners.
- **`filter_ignored(root, paths)`** (`core/gitignore.py`) — drops git-ignored paths
  via one batched `git check-ignore`; no-op outside a git work tree.
- **`Baseline`** — `suppresses()` consults a fingerprint set; `write(..., update=,
  reason=)` merges into an existing baseline and records `entries` (fp → rule/path/
  reason) for auditability.
- **`GitHistoryScanner.scan(repo)`** — parses one `git log --all -p --unified=0`
  stream; per (commit, file) reconstructs the *added* lines into a blob (keeping a
  line map for accurate new-file line numbers), runs the same detectors, dedups by
  fingerprint (oldest commit wins via `--reverse`), and stamps each Finding with
  `source="git-history"` + commit/author metadata. Catches leaked-then-removed
  secrets. `max_commits` caps the walk.

### Rule schema (`rules/secret_patterns.yaml`)

```yaml
patterns:
  - id: openai_api_key          # unique id (also feeds the fingerprint)
    description: OpenAI API key  # human-readable label
    regex: "sk-(?!ant-)..."     # Python regex against full file content
    severity: critical          # info | low | medium | high | critical
    capture: 1                  # optional: group index of the secret value (0 = whole match)
    min_entropy: 3.5            # optional: skip matches below this Shannon entropy
    verifier: openai            # optional: Phase 5 live-verification hint → Finding.metadata
allowlist:
  value_patterns: ["example", "<[^>]+>", ...]   # regex vs. secret value (case-insensitive)
  path_patterns: []                              # regex vs. file path (opt-in)
```

### CLI reference

- `scan --path --entropy --no-allowlist --gitignore --baseline <f> --format table|json --fail-on <sev>`
- `history --path --entropy --no-allowlist --baseline <f> --max-commits <n> --format --fail-on`
  — scan git commit history (incl. leaked-then-removed secrets)
- `baseline --path --entropy --gitignore [-u/--update] [--reason <r>] -o <out>`
  — snapshot/merge fingerprints to suppress later
- top-level `--log-level` on the `cli` group (default `WARNING`)

### Design principles

1. **Secrets never leak** — store redacted previews + fingerprints, never the
   raw value, in findings, logs, baselines, or reports.
2. **YAML-driven rules** — detections are data; add patterns without code changes.
3. **Low-noise by default** — allowlist on by default, generic rules entropy-gated,
   entropy detector opt-in, walker skips binaries/oversized/noise dirs.
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
- [x] Expanded `secret_patterns.yaml` to 28 rules — added OpenAI, Anthropic,
      Azure storage key, GCP SA JSON + OAuth client secret, Twilio, SendGrid,
      Mailgun, Telegram, Shopify, DigitalOcean, npm, PyPI, GitLab PAT,
      GitHub OAuth/app/refresh tokens
- [x] Per-rule `min_entropy` gating + `verifier` hint metadata (→ Finding.metadata)
- [x] `core/allowlist.py` — value/path allowlist (example/placeholder/template
      suppression), on by default; `scan --no-allowlist` to disable
- [x] Allowlist wired into both signature + entropy detectors and `default_detectors`
- [x] 7 new pytest tests (17 total)

### Phase 3 — Git-history scanning (COMPLETE)
- [x] `core/git_history.py` — `GitHistoryScanner` parses a single
      `git log --all --no-merges --reverse -p --unified=0` stream
- [x] Detects secrets in each commit's *added* lines → catches leaked-then-removed
      credentials the working tree no longer contains
- [x] Accurate new-file line numbers (per-file line map), multi-line secrets supported
- [x] `source="git-history"` + commit/author/email/date/summary in `Finding.metadata`
- [x] Reuses signature + entropy detectors, allowlist, baseline; dedup oldest-wins
- [x] CLI `history` command (`--max-commits`, table adds Commit column, JSON adds
      source/commit/author/date); shared `_emit()` render+gate with `scan`
- [x] `ScanResult.commits_scanned`; 7 new pytest tests (24 total)

### Phase 4 — Triage & suppression (COMPLETE)
- [x] `.gitignore`-aware walking — `core/gitignore.py` `filter_ignored()` delegates
      to `git check-ignore` (correct semantics, no new dep); `scan/baseline --gitignore`
- [x] Inline `# pragma: allowlist secret` (+ `gitleaks:allow`) — `core/pragma.py`,
      applied in both filesystem and git-history scans
- [x] Baseline feedback loop — `write(update=, reason=)` merges into an existing
      baseline; stores `entries` (fp → rule/path/reason); CLI `baseline -u/--update --reason`
- [x] `ScanResult` line-level pragma drop happens before dedup/baseline
- [x] 7 new pytest tests (31 total)

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
