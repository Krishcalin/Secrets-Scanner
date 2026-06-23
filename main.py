"""Secrets Scanner — CLI entry point.

Commands:
  scan      Scan a filesystem path for hardcoded secrets (table/json; CI gate).
  history   Scan git commit history for secrets (incl. leaked-then-removed).
  baseline  Write a baseline of current findings to suppress on future scans.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from core.baseline import Baseline
from core.engine import SecretScanner, default_detectors
from core.git_history import GitHistoryScanner
from core.logger import configure_logging
from core.models import ScanResult, Severity, Verification

console = Console()
_SEV_ORDER = {s: i for i, s in enumerate(Severity)}
_VERIFY_STYLE = {
    Verification.VALID: "[bold red]VALID[/]",
    Verification.INVALID: "[dim]invalid[/]",
    Verification.UNVERIFIED: "[yellow]unverified[/]",
    Verification.SKIPPED: "[dim]skipped[/]",
}


@click.group()
@click.option("--log-level", default="WARNING")
def cli(log_level: str) -> None:
    """Detect hardcoded credentials and secrets."""
    configure_logging(log_level)


def _detectors(entropy: bool, allowlist: bool):
    return default_detectors(entropy=entropy, allowlist=allowlist)


def _emit(result: ScanResult, fmt: str, fail_on: str | None, *,
          history: bool = False, verify: bool = False) -> None:
    """Render a ScanResult (table/json) and enforce the --fail-on gate."""
    if fmt == "json":
        console.print_json(data={
            "root": result.root,
            "scope": "git-history" if history else "filesystem",
            "files_scanned": result.files_scanned,
            "commits_scanned": result.commits_scanned,
            "count": result.count,
            "by_severity": result.by_severity(),
            "findings": [{
                "rule_id": f.rule_id, "severity": f.severity.value, "path": f.path,
                "line": f.line, "preview": f.preview, "fingerprint": f.fingerprint,
                "description": f.description, "entropy": f.entropy, "source": f.source,
                "verifier": f.metadata.get("verifier"),
                "verification": f.verification.value,
                "commit": f.metadata.get("commit_short"),
                "author": f.metadata.get("author"),
                "date": f.metadata.get("date"),
            } for f in result.findings],
        })
    else:
        if result.findings:
            cols = ["Severity", "Rule", "Location", "Preview"]
            if history:
                cols.insert(3, "Commit")
            if verify:
                cols.insert(3, "Status")
            table = Table(*cols, title=f"Secrets — {result.count} finding(s)")
            for f in sorted(result.findings, key=lambda x: -_SEV_ORDER[x.severity]):
                row = [f.severity.value, f.rule_id, f"{f.path}:{f.line}", f.preview]
                if history:
                    commit = f.metadata.get("commit_short", "?")
                    author = f.metadata.get("author", "")
                    row.insert(3, f"{commit} {author}".strip())
                if verify:
                    row.insert(3, _VERIFY_STYLE.get(f.verification, f.verification.value))
                table.add_row(*row)
            console.print(table)
        else:
            console.print("[green]No secrets found.[/]")
        if history:
            console.print(f"[dim]scanned {result.commits_scanned} commits[/]")
        else:
            console.print(f"[dim]scanned {result.files_scanned} files · "
                          f"{result.files_skipped} skipped[/]")

    if fail_on:
        threshold = _SEV_ORDER[Severity(fail_on)]
        if any(_SEV_ORDER[f.severity] >= threshold for f in result.findings):
            console.print(f"[red]Gate failed:[/] finding(s) at/above {fail_on}.")
            raise SystemExit(1)


@cli.command("scan")
@click.option("--path", default=".", help="File or directory to scan.")
@click.option("--entropy", is_flag=True, default=False, help="Also run the entropy detector.")
@click.option("--no-allowlist", is_flag=True, default=False,
              help="Report even documentation/placeholder sample values.")
@click.option("--gitignore", is_flag=True, default=False,
              help="Skip git-ignored files (only inside a git work tree).")
@click.option("--baseline", "baseline_path", default=None, help="Baseline JSON to suppress.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Exit 1 if any finding is at/above this severity (CI gate).")
def scan(path: str, entropy: bool, no_allowlist: bool, gitignore: bool,
         baseline_path: str | None, fmt: str, fail_on: str | None) -> None:
    """Scan PATH for hardcoded secrets."""
    baseline = Baseline.load(baseline_path) if baseline_path else None
    scanner = SecretScanner(_detectors(entropy, not no_allowlist), baseline=baseline,
                            skip_gitignored=gitignore)
    _emit(scanner.scan(path), fmt, fail_on, history=False)


@cli.command("history")
@click.option("--path", default=".", help="Git repository to scan.")
@click.option("--entropy", is_flag=True, default=False, help="Also run the entropy detector.")
@click.option("--no-allowlist", is_flag=True, default=False,
              help="Report even documentation/placeholder sample values.")
@click.option("--baseline", "baseline_path", default=None, help="Baseline JSON to suppress.")
@click.option("--max-commits", type=int, default=None,
              help="Limit to the most recent N commits (omit to scan all history).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Exit 1 if any finding is at/above this severity (CI gate).")
def history(path: str, entropy: bool, no_allowlist: bool, baseline_path: str | None,
            max_commits: int | None, fmt: str, fail_on: str | None) -> None:
    """Scan the git history of PATH for secrets (including leaked-then-removed)."""
    baseline = Baseline.load(baseline_path) if baseline_path else None
    scanner = GitHistoryScanner(_detectors(entropy, not no_allowlist),
                                baseline=baseline, max_commits=max_commits)
    _emit(scanner.scan(path), fmt, fail_on, history=True)


@cli.command("verify")
@click.option("--path", default=".", help="File or directory to scan, then verify.")
@click.option("--entropy", is_flag=True, default=False)
@click.option("--no-allowlist", is_flag=True, default=False)
@click.option("--gitignore", is_flag=True, default=False, help="Skip git-ignored files.")
@click.option("--baseline", "baseline_path", default=None, help="Baseline JSON to suppress.")
@click.option("--rate-limit", type=float, default=1.0,
              help="Seconds to pause between provider calls (default 1.0).")
@click.option("--timeout", type=float, default=8.0, help="Per-call timeout seconds.")
@click.option("-y", "--yes", is_flag=True, default=False,
              help="Skip the confirmation prompt (required for non-interactive use).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on-valid", is_flag=True, default=False,
              help="Exit 1 if any credential is confirmed live (CI gate).")
def verify(path: str, entropy: bool, no_allowlist: bool, gitignore: bool,
           baseline_path: str | None, rate_limit: float, timeout: float, yes: bool,
           fmt: str, fail_on_valid: bool) -> None:
    """Scan PATH, then check whether detected credentials are actually LIVE.

    Makes a single read-only request per unique secret to its own provider
    (GitHub, GitLab, OpenAI, Anthropic, Stripe, SendGrid). Read-only, rate-limited,
    no redirects followed, secrets never logged. Opt-in: requires confirmation.
    """
    from core.verify import VerificationRunner, collect_verifiable, default_verifiers

    baseline = Baseline.load(baseline_path) if baseline_path else None
    scanner = SecretScanner(_detectors(entropy, not no_allowlist), baseline=baseline,
                            skip_gitignored=gitignore)
    result = scanner.scan(path)

    verifiers = default_verifiers()
    items = collect_verifiable(result.findings, set(verifiers))
    if not items:
        console.print("[dim]No verifiable credentials found "
                      "(no live-checkable provider keys detected).[/]")
        _emit(result, fmt, None, verify=True)
        return

    if not yes:
        msg = (f"About to make up to {len(items)} read-only request(s) to credential "
               f"providers to check if detected secrets are live. Proceed?")
        if not sys.stdin.isatty():
            console.print("[yellow]Refusing outbound calls without --yes "
                          "(non-interactive session).[/]")
            raise SystemExit(2)
        if not click.confirm(msg, default=False):
            console.print("[dim]Aborted; no requests made.[/]")
            raise SystemExit(1)

    runner = VerificationRunner(verifiers, timeout=timeout, rate_limit=rate_limit)
    runner.verify(items)

    _emit(result, fmt, None, verify=True)
    live = sum(1 for f in result.findings if f.verification == Verification.VALID)
    if live:
        console.print(f"[bold red]{live} credential(s) confirmed LIVE — rotate immediately.[/]")
    if fail_on_valid and live:
        raise SystemExit(1)


@cli.command("baseline")
@click.option("--path", default=".", help="File or directory to scan.")
@click.option("--entropy", is_flag=True, default=False)
@click.option("--gitignore", is_flag=True, default=False, help="Skip git-ignored files.")
@click.option("-u", "--update", is_flag=True, default=False,
              help="Merge into the existing baseline instead of overwriting.")
@click.option("--reason", default=None, help="Note stored with newly accepted findings.")
@click.option("-o", "--output", default=".secrets-baseline.json", help="Baseline output path.")
def baseline(path: str, entropy: bool, gitignore: bool, update: bool,
             reason: str | None, output: str) -> None:
    """Write (or update) a baseline of current findings to suppress on future scans."""
    result = SecretScanner(default_detectors(entropy=entropy),
                           skip_gitignored=gitignore).scan(path)
    out = Baseline.write(output, result.findings, update=update, reason=reason)
    total = len(Baseline.load(out).fingerprints)
    verb = "updated" if update else "written"
    console.print(f"[green]Baseline {verb}:[/] {out} "
                  f"({len({f.fingerprint for f in result.findings})} from this scan · "
                  f"{total} total)")


if __name__ == "__main__":
    cli()
