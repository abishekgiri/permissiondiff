"""Human presentation and canonical JSON persistence for findings."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from permissiondiff.config import FailOnConfig
from permissiondiff.models import ChangeType, Finding, FindingKind, JsonObject, Severity

REPORT_SCHEMA_VERSION = 1


def assign_finding_ids(findings: list[Finding] | tuple[Finding, ...]) -> list[Finding]:
    """Assign stable sequential IDs after deterministic semantic sorting."""
    ordered = sorted(findings, key=lambda finding: finding.semantic_key)
    return [finding.with_id(f"PD-{index:04d}") for index, finding in enumerate(ordered, 1)]


def persist_findings(
    findings: list[Finding],
    *,
    failures_dir: Path,
    report_path: Path,
    cases_evaluated: int,
) -> None:
    """Write canonical report JSON and one exact reproduction per finding."""
    failures_dir.mkdir(parents=True, exist_ok=True)
    for stale in failures_dir.glob("PD-*.json"):
        stale.unlink()
    for finding in findings:
        destination = failures_dir / f"{finding.finding_id}.json"
        _write_json(destination, finding.to_dict())
    report: JsonObject = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "cases_evaluated": cases_evaluated,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    _write_json(report_path, report)


def render_terminal(
    findings: list[Finding],
    *,
    cases_evaluated: int,
    failures_dir: Path,
    console: Console | None = None,
) -> None:
    """Render concise actionable findings without affecting semantics."""
    output = console or Console()
    output.print(f"[bold]PermissionDiff[/bold] evaluated {cases_evaluated:,} exact cases")
    if not findings:
        output.print("[green]PASS[/green] No authorization changes or invariant violations found.")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Result")
    table.add_column("Minimal reproduction")
    for finding in findings:
        case = finding.case
        path = failures_dir / f"{finding.finding_id}.json"
        summary = (
            f"{case.subject.role or case.subject.id}({case.subject.tenant or '-'}) "
            f"→ {case.action.name} → {case.resource.type}({case.resource.tenant or '-'})"
        )
        decisions = ""
        if finding.baseline and finding.candidate:
            decisions = f" [{finding.baseline.value} → {finding.candidate.value}]"
        elif finding.candidate:
            decisions = f" [actual: {finding.candidate.value}]"
        equivalent = (
            f" ({finding.equivalent_cases} equivalent cases)"
            if finding.equivalent_cases > 1
            else ""
        )
        table.add_row(
            finding.finding_id,
            _severity_label(finding.severity),
            f"{finding.message}\n{summary}{decisions}{equivalent}",
            str(path),
        )
    output.print(table)


def result_exit_code(findings: list[Finding], fail_on: FailOnConfig) -> int:
    """Apply the documented CI exit-code contract."""
    if any(finding.kind is FindingKind.EVALUATION_ERROR for finding in findings):
        return 3
    for finding in findings:
        if finding.kind is FindingKind.INVARIANT_VIOLATION and fail_on.invariant_violation:
            return 1
        if finding.change is ChangeType.NEWLY_ALLOWED and fail_on.newly_allowed:
            return 1
        if finding.change is ChangeType.NEWLY_DENIED and fail_on.newly_denied:
            return 1
    return 0


def explain_finding(path: Path) -> str:
    """Return a persisted reproduction as readable canonical JSON."""
    return json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2, sort_keys=True)


def _write_json(path: Path, payload: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _severity_label(severity: Severity) -> str:
    colors = {
        Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
        Severity.WARNING: "[yellow]WARNING[/yellow]",
        Severity.ERROR: "[bold magenta]ERROR[/bold magenta]",
    }
    return colors[severity]
