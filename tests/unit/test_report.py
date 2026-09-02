"""Finding persistence, stable IDs, and exit-code tests."""

import json
from pathlib import Path

from permissiondiff.config import FailOnConfig
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    ChangeType,
    Context,
    Decision,
    Finding,
    FindingKind,
    Resource,
    Severity,
    Subject,
)
from permissiondiff.report import assign_finding_ids, persist_findings, result_exit_code


def finding(change: ChangeType = ChangeType.NEWLY_ALLOWED) -> Finding:
    """Create a changed-decision finding."""
    case = AuthorizationCase(
        Subject("alice", "acme", "support"),
        Action("read"),
        Resource("one", "invoice", "globex", "bob"),
        Context(),
    )
    return Finding(
        kind=FindingKind.CHANGE,
        severity=Severity.CRITICAL,
        case=case,
        message="changed",
        baseline=Decision.DENY,
        candidate=Decision.ALLOW,
        change=change,
    )


def test_finding_ids_and_reproduction_are_stable(tmp_path: Path) -> None:
    findings = assign_finding_ids([finding()])
    failures = tmp_path / "failures"
    report = tmp_path / "report.json"
    persist_findings(findings, failures_dir=failures, report_path=report, cases_evaluated=1)
    reproduction = json.loads((failures / "PD-0001.json").read_text())
    assert reproduction["case_fingerprint"] == findings[0].case.fingerprint
    assert AuthorizationCase.from_dict(reproduction["case"]) == findings[0].case
    assert json.loads(report.read_text())["finding_count"] == 1


def test_exit_code_contract() -> None:
    assert result_exit_code([], FailOnConfig()) == 0
    assert result_exit_code([finding()], FailOnConfig()) == 1
    assert result_exit_code([finding(ChangeType.NEWLY_DENIED)], FailOnConfig()) == 0
    error = Finding(
        kind=FindingKind.EVALUATION_ERROR,
        severity=Severity.ERROR,
        case=finding().case,
        message="failed",
        error="boom",
    )
    assert result_exit_code([error], FailOnConfig()) == 3
