# Secrets Scanner

Detect hardcoded credentials and secrets across source, config, and git history —
with safe live-verification, baseline suppression, and CI/SIEM integration.

The defensive mirror of the offensive **T1552.001 "Credentials in Files"**
red-team module in the KIZEN portfolio: that tool finds the gaps, this one closes
them, sharing the same pattern intelligence. Maps to the AccuKnox
**SECURING SECRETS** capability.

**Status:** Phase 1 complete (filesystem scanning) · **Python** 3.10+ · **License** MIT

---

## Features (Phase 1)

- **Signature detection** — YAML rule pack (`rules/secret_patterns.yaml`) for AWS,
  GCP, GitHub, Slack, Stripe, JWTs, PEM private keys, DB URIs, generic assignments.
- **Entropy detection** *(opt-in)* — flags high-entropy strings signatures miss.
- **Secrets never leak** — findings store a redacted preview (`AKIA…LE (20 chars)`)
  and a fingerprint, never the raw value.
- **Baseline suppression** — accept triaged findings so re-scans surface only new ones.
- **CI gate** — `--fail-on <severity>` exits non-zero for pipeline enforcement.
- **Fast, low-noise walker** — skips binaries, oversized files, and noise dirs.

## Install

```bash
git clone https://github.com/<owner>/Secrets-Scanner.git
cd Secrets-Scanner
pip install -r requirements.txt        # or:  pip install -e ".[test]"
```

## Usage

```bash
# Scan a directory (or file)
python main.py scan --path .

# Include the entropy detector (catches unknown formats; noisier)
python main.py scan --path . --entropy

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
    # capture: 1   # optional: group index of the secret value
```

See `CLAUDE.md` for architecture and the phase roadmap (git-history scanning,
live verification, HTML reports + pre-commit/CI).

## Test

```bash
pytest
```

## License

MIT
