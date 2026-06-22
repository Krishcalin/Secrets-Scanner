"""Secrets Scanner — CLI entry point.

Commands:
  scan      Scan a path for hardcoded secrets (table/json; CI fail-on gate).
  baseline  Write a baseline of current findings to suppress on future scans.
"""

from __future__ import annotations

import json as _json

import click
from rich.console import Console
from rich.table import Table

from core.baseline import Baseline
from core.engine import SecretScanner, default_detectors
from core.logger import configure_logging
from core.models import Severity

console = Console()
_SEV_ORDER = {s: i for i, s in enumerate(Severity)}


@click.group()
@click.option("--log-level", default="WARNING")
def cli(log_level: str) -> None:
    """Detect hardcoded credentials and secrets."""
    configure_logging(log_level)


def _scanner(entropy: bool, baseline_path: str | None) -> SecretScanner:
    baseline = Baseline.load(baseline_path) if baseline_path else None
    return SecretScanner(default_detectors(entropy=entropy), baseline=baseline)


@cli.command("scan")
@click.option("--path", default=".", help="File or directory to scan.")
@click.option("--entropy", is_flag=True, default=False, help="Also run the entropy detector.")
@click.option("--baseline", "baseline_path", default=None, help="Baseline JSON to suppress.")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Exit 1 if any finding is at/above this severity (CI gate).")
def scan(path: str, entropy: bool, baseline_path: str | None, fmt: str,
         fail_on: str | None) -> None:
    """Scan PATH for hardcoded secrets."""
    result = _scanner(entropy, baseline_path).scan(path)

    if fmt == "json":
        console.print_json(data={
            "root": result.root,
            "files_scanned": result.files_scanned,
            "count": result.count,
            "by_severity": result.by_severity(),
            "findings": [{
                "rule_id": f.rule_id, "severity": f.severity.value, "path": f.path,
                "line": f.line, "preview": f.preview, "fingerprint": f.fingerprint,
                "description": f.description,
            } for f in result.findings],
        })
    else:
        if result.findings:
            table = Table("Severity", "Rule", "Location", "Preview",
                          title=f"Secrets — {result.count} finding(s)")
            for f in sorted(result.findings, key=lambda x: -_SEV_ORDER[x.severity]):
                table.add_row(f.severity.value, f.rule_id,
                              f"{f.path}:{f.line}", f.preview)
            console.print(table)
        else:
            console.print("[green]No secrets found.[/]")
        console.print(f"[dim]scanned {result.files_scanned} files · "
                      f"{result.files_skipped} skipped[/]")

    if fail_on:
        threshold = _SEV_ORDER[Severity(fail_on)]
        if any(_SEV_ORDER[f.severity] >= threshold for f in result.findings):
            console.print(f"[red]Gate failed:[/] finding(s) at/above {fail_on}.")
            raise SystemExit(1)


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
