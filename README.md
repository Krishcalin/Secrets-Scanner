# Secrets Scanner

Detect hardcoded credentials and secrets across source, config, and git history —
with safe live-verification, baseline suppression, and CI/SIEM integration.

The defensive mirror of the offensive **T1552.001 "Credentials in Files"**
red-team module in the KIZEN portfolio: that tool finds the gaps, this one closes
them, sharing the same pattern intelligence. Maps to the AccuKnox
**SECURING SECRETS** capability.

**Status:** Phases 1-2 complete (filesystem scanning + detector breadth) · **Python** 3.10+ · **License** MIT

---

## Features

- **Signature detection** — 27-rule YAML pack (`rules/secret_patterns.yaml`): AWS,
  Azure, GCP (API key / service-account / OAuth), GitHub (PAT / fine-grained /
  OAuth) + GitLab, OpenAI & Anthropic, Stripe, Slack, SendGrid, Twilio, Mailgun,
  Telegram, Shopify, DigitalOcean, npm, PyPI, JWTs, PEM private keys, DB URIs.
- **Allowlist** *(on by default)* — suppresses documentation samples
  (`AKIAIOSFODNN7EXAMPLE`), template placeholders (`<your-api-key>`, `${SECRET}`),
  and obvious fixtures. Disable with `--no-allowlist`.
- **Per-rule entropy gating** — generic/noisy rules only fire above a configurable
  Shannon-entropy floor, cutting false positives.
- **Verifier hints** — rules carry a `verifier` tag (e.g. `aws_sts`, `github_user`)
  for Phase 5 live verification; surfaced in JSON output.
- **Entropy detection** *(opt-in)* — flags high-entropy strings signatures miss.
- **Secrets never leak** — findings store a redacted preview (`AKIA…LE (20 chars)`)
  and a fingerprint, never the raw value.
- **Baseline suppression** — accept triaged findings so re-scans surface only new ones.
- **CI gate** — `--fail-on <severity>` exits non-zero for pipeline enforcement.
- **Fast, low-noise walker** — skips binaries, oversized files, and noise dirs.

## Install

```bash
git clone https://github.com/Krishcalin/Secrets-Scanner.git
cd Secrets-Scanner
pip install -r requirements.txt        # or:  pip install -e ".[test]"
```

## Usage

```bash
# Scan a directory (or file)
python main.py scan --path .

# Include the entropy detector (catches unknown formats; noisier)
python main.py scan --path . --entropy

# Report even documentation/placeholder sample values
python main.py scan --path . --no-allowlist

# JSON output (for tooling/SIEM)
python main.py scan --path . --format json

# CI gate — fail the build on any HIGH+ finding
python main.py scan --path . --fail-on high

# Create a baseline of existing findings, then scan suppressing them
python main.py baseline --path . -o .secrets-baseline.json
python main.py scan --path . --baseline .secrets-baseline.json
```

## Adding rules

Append to `rules/secret_patterns.yaml` — no code change:

```yaml
patterns:
  - id: my_internal_token
    description: Internal service token
    regex: "INT-[0-9A-F]{32}"
    severity: critical
    # capture: 1        # optional: group index of the secret value
    # min_entropy: 3.5  # optional: skip matches below this Shannon entropy
    # verifier: my_api  # optional: Phase 5 live-verification hint
```

The `allowlist:` section of the same file holds `value_patterns` / `path_patterns`
that suppress placeholders and documentation samples.

See `CLAUDE.md` for architecture and the phase roadmap (git-history scanning,
live verification, HTML reports + pre-commit/CI).

## Test

```bash
pytest
```

## License

MIT
