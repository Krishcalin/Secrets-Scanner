"""Live verification — is a detected credential actually *active*?

A detected secret may be a long-dead test key or a live production credential.
Verification answers that by making a single **read-only** request to the secret's
own provider (e.g. GitHub `GET /user`) and reading the HTTP status:

    2xx        -> VALID      (the credential is live — rotate it now)
    401 / 403  -> INVALID    (provider rejected it; not live)
    anything else / network error -> UNVERIFIED  (couldn't determine — fail safe)

Safety contract:
  - **Opt-in.** Only the `verify` CLI command (with confirmation) runs this.
  - **Read-only.** Every verifier hits a GET/identity endpoint; nothing is mutated.
  - **Provider-scoped.** A secret is only ever sent to its own provider.
  - **No redirects.** A redirect is never followed, so the Authorization header
    can't leak to another host.
  - **No exfiltration / no logging of secrets.** The raw value lives only in memory
    for the duration of the call; findings keep just the redacted preview.
  - **Rate-limited + timed out.** A pause between calls and a hard per-call timeout.

Recovering the raw secret: findings never store it, so `collect_verifiable()`
re-reads each finding's file, re-matches the rule's regex on the recorded line, and
confirms it found the exact value by recomputing the fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path

from core.allowlist import Allowlist
from core.logger import get_logger
from core.models import Finding, Verification, fingerprint
from detectors.signature import SignatureDetector

log = get_logger("verify")

# (url, headers, method, body)
Request = tuple[str, dict[str, str], str, bytes | None]


# ── HTTP (no-redirect, status only — never returns a body) ────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - never follow
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_status(url: str, headers: dict[str, str], method: str,
                body: bytes | None, timeout: float) -> int:
    """Return the HTTP status code for a request. Raises on network failure."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


# ── Verifiers — one per provider, request spec + status interpretation ─────
class Verifier(ABC):
    id: str = "base"

    @abstractmethod
    def request(self, secret: str) -> Request:
        """Build the read-only request that checks this secret."""

    def interpret(self, status: int) -> Verification:
        if 200 <= status < 300:
            return Verification.VALID
        if status in (401, 403):
            return Verification.INVALID
        return Verification.UNVERIFIED


class _Bearer(Verifier):
    """GET <url> with `Authorization: Bearer <secret>` and optional extra headers."""
    url = ""
    extra: dict[str, str] = {}

    def request(self, secret: str) -> Request:
        headers = {"Authorization": f"Bearer {secret}", "User-Agent": "secrets-scanner",
                   **self.extra}
        return self.url, headers, "GET", None


class GitHubVerifier(_Bearer):
    id = "github_user"
    url = "https://api.github.com/user"
    extra = {"Accept": "application/vnd.github+json"}


class OpenAIVerifier(_Bearer):
    id = "openai"
    url = "https://api.openai.com/v1/models"


class SendGridVerifier(_Bearer):
    id = "sendgrid"
    url = "https://api.sendgrid.com/v3/scopes"


class GitLabVerifier(Verifier):
    id = "gitlab"

    def request(self, secret: str) -> Request:
        return "https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": secret}, "GET", None


class AnthropicVerifier(Verifier):
    id = "anthropic"

    def request(self, secret: str) -> Request:
        headers = {"x-api-key": secret, "anthropic-version": "2023-06-01"}
        return "https://api.anthropic.com/v1/models", headers, "GET", None


class StripeVerifier(Verifier):
    id = "stripe"

    def request(self, secret: str) -> Request:
        token = base64.b64encode(f"{secret}:".encode()).decode()
        return "https://api.stripe.com/v1/account", {"Authorization": f"Basic {token}"}, "GET", None


def default_verifiers() -> dict[str, Verifier]:
    """Registered verifiers keyed by the rule pack's `verifier` hint.

    Providers whose 'invalid' response is still HTTP 200 (e.g. Slack auth.test)
    are intentionally omitted — status alone can't classify them safely.
    """
    vs = [GitHubVerifier(), GitLabVerifier(), OpenAIVerifier(), AnthropicVerifier(),
          StripeVerifier(), SendGridVerifier()]
    return {v.id: v for v in vs}


# ── Recover raw secrets for findings that have a registered verifier ───────
def collect_verifiable(
    findings: list[Finding],
    registered: set[str],
) -> list[tuple[Finding, str]]:
    """Return (finding, raw_secret) pairs to verify; mark the rest SKIPPED.

    Findings whose rule has no registered verifier — or whose raw value can't be
    recovered from the working tree — are set to ``Verification.SKIPPED``.
    """
    idx = SignatureDetector(allowlist=Allowlist.empty()).rule_index()
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        vid = f.metadata.get("verifier")
        if vid in registered and f.source == "filesystem":
            by_path[f.path].append(f)
        else:
            f.verification = Verification.SKIPPED

    items: list[tuple[Finding, str]] = []
    for path, group in by_path.items():
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").split("\n")
        except OSError:
            for f in group:
                f.verification = Verification.SKIPPED
            continue
        for f in group:
            rule = idx.get(f.rule_id)
            line = lines[f.line - 1] if 0 <= f.line - 1 < len(lines) else ""
            secret = _recover(rule, f.path, line, f) if rule else None
            if secret is None:
                f.verification = Verification.SKIPPED
            else:
                items.append((f, secret))
    return items


def _recover(rule: dict, path: str, line_text: str, finding: Finding) -> str | None:
    for m in rule["regex"].finditer(line_text):
        grp = rule["capture"]
        has = bool(grp) and bool(m.groups())
        secret = m.group(grp) if has else m.group(0)
        if fingerprint(finding.rule_id, secret, path) == finding.fingerprint:
            return secret
    return None


# ── Runner — performs the network policy (timeout, rate-limit, dedup) ──────
class VerificationRunner:
    def __init__(
        self,
        verifiers: dict[str, Verifier],
        *,
        timeout: float = 8.0,
        rate_limit: float = 1.0,
        http=http_status,
        sleep=time.sleep,
    ) -> None:
        self.verifiers = verifiers
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._http = http
        self._sleep = sleep

    def verify(self, items: list[tuple[Finding, str]]) -> None:
        """Set ``finding.verification`` for each (finding, secret). Identical
        secrets are checked once (cached); a pause separates distinct calls."""
        cache: dict[str, Verification] = {}
        made_call = False
        for finding, secret in items:
            verifier = self.verifiers.get(finding.metadata.get("verifier", ""))
            if verifier is None:
                finding.verification = Verification.SKIPPED
                continue
            key = hashlib.sha256(secret.encode()).hexdigest()
            if key in cache:
                finding.verification = cache[key]
                continue
            if made_call and self.rate_limit:
                self._sleep(self.rate_limit)
            made_call = True
            url, headers, method, body = verifier.request(secret)
            try:
                status = self._http(url, headers, method, body, self.timeout)
                result = verifier.interpret(status)
            except Exception as exc:  # network/transient — fail safe, don't claim INVALID
                log.warning("verify_call_failed", verifier=verifier.id, error=str(exc))
                result = Verification.UNVERIFIED
            cache[key] = result
            finding.verification = result
