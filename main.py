"""Secrets Scanner — CLI entry point.

Commands:
  scan      Scan a filesystem path for hardcoded secrets (table/json; CI gate).
  history   Scan git commit history for secrets (incl. leaked-then-removed).
  baseline  Write a baseline of current findings to suppress on future scans.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from core.baseline import Baseline
from core.engine import SecretScanner, default_detectors
from core.git_history import GitHistoryScanner
from core.logger import configure_logging
from core.models import ScanResult, Severity

console = Console()
_SEV_ORDER = {s: i for i, s in enumerate(Severity)}


@click.group()
@click.option("--log-level", default="WARNING")
def cli(log_level: str) -> None:
    """Detect hardcoded credentials and secrets."""
    configure_logging(log_level)


def _detectors(entropy: bool, allowlist: bool):
    return default_detectors(entropy=entropy, allowlist=allowlist)


def _emit(result: ScanResult, fmt: str, fail_on: str | None, *, history: bool) -> None:
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
            table = Table(*cols, title=f"Secrets — {result.count} finding(s)")
            for f in sorted(result.findings, key=lambda x: -_SEV_ORDER[x.severity]):
                row = [f.severity.value, f.rule_id, f"{f.path}:{f.line}", f.preview]
                if history:
                    commit = f.metadata.get("commit_short", "?")
                    author = f.metadata.get("author", "")
                    row.insert(3, f"{commit} {author}".strip())
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
@click.option("--baseline", "baseline_path", default=None, help="Baseline JSON to suppress.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Exit 1 if any finding is at/above this severity (CI gate).")
def scan(path: str, entropy: bool, no_allowlist: bool, baseline_path: str | None, fmt: str,
         fail_on: str | None) -> None:
    """Scan PATH for hardcoded secrets."""
    baseline = Baseline.load(baseline_path) if baseline_path else None
    scanner = SecretScanner(_detectors(entropy, not no_allowlist), baseline=baseline)
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


@cli.command("baseline")
@click.option("--path", default=".", help="File or directory to scan.")
@click.option("--entropy", is_flag=True, default=False)
@click.option("-o", "--output", default=".secrets-baseline.json", help="Baseline output path.")
def baseline(path: str, entropy: bool, output: str) -> None:
    """Write a baseline of current findings (suppress them on future scans)."""
    result = SecretScanner(default_detectors(entropy=entropy)).scan(path)
    out = Baseline.write(output, result.findings)
    console.print(f"[green]Baseline written:[/] {out} "
                  f"({len({f.fingerprint for f in result.findings})} fingerprints)")


if __name__ == "__main__":
    cli()
