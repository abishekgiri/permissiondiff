"""Pure comparison, invariant evaluation, and finding minimization logic."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace

from permissiondiff.invariants import Invariant
from permissiondiff.models import (
    AuthorizationCase,
    CaseEvaluation,
    ChangeType,
    ComparisonResult,
    Decision,
    Finding,
    FindingKind,
    Severity,
)


def classify_change(baseline: Decision, candidate: Decision) -> ChangeType:
    """Classify one exhaustive pair of authorization decisions."""
    mapping = {
        (Decision.DENY, Decision.DENY): ChangeType.UNCHANGED_DENIED,
        (Decision.ALLOW, Decision.ALLOW): ChangeType.UNCHANGED_ALLOWED,
        (Decision.DENY, Decision.ALLOW): ChangeType.NEWLY_ALLOWED,
        (Decision.ALLOW, Decision.DENY): ChangeType.NEWLY_DENIED,
    }
    return mapping[(baseline, candidate)]


def compare_decisions(
    case: AuthorizationCase,
    baseline: Decision,
    candidate: Decision,
) -> ComparisonResult:
    """Compare two decisions for one exact authorization case."""
    return ComparisonResult(
        case=case,
        baseline=baseline,
        candidate=candidate,
        change=classify_change(baseline, candidate),
    )


def invariant_findings(
    evaluations: Iterable[CaseEvaluation],
    invariants: Iterable[Invariant],
) -> list[Finding]:
    """Evaluate invariants and return minimized, deduplicated violations."""
    findings: list[Finding] = []
    invariant_list = list(invariants)
    for evaluation in evaluations:
        if evaluation.decision is None:
            findings.append(
                Finding(
                    kind=FindingKind.EVALUATION_ERROR,
                    severity=Severity.ERROR,
                    case=evaluation.case,
                    message="Authorizer evaluation failed",
                    error=evaluation.error,
                )
            )
            continue
        for invariant in invariant_list:
            result = invariant.evaluate(evaluation.case, evaluation.decision)
            if not result.passed:
                findings.append(
                    Finding(
                        kind=FindingKind.INVARIANT_VIOLATION,
                        severity=Severity.CRITICAL,
                        case=evaluation.case,
                        message=result.message,
                        candidate=evaluation.decision,
                        invariant=result.name,
                    )
                )
    return minimize_findings(findings)


def comparison_findings(comparisons: Iterable[ComparisonResult]) -> list[Finding]:
    """Convert changed decisions into minimized security findings."""
    findings: list[Finding] = []
    for comparison in comparisons:
        if comparison.change is ChangeType.NEWLY_ALLOWED:
            findings.append(
                Finding(
                    kind=FindingKind.CHANGE,
                    severity=Severity.CRITICAL,
                    case=comparison.case,
                    message="Authorization path is newly allowed",
                    baseline=comparison.baseline,
                    candidate=comparison.candidate,
                    change=comparison.change,
                )
            )
        elif comparison.change is ChangeType.NEWLY_DENIED:
            findings.append(
                Finding(
                    kind=FindingKind.CHANGE,
                    severity=Severity.WARNING,
                    case=comparison.case,
                    message="Authorization path is newly denied",
                    baseline=comparison.baseline,
                    candidate=comparison.candidate,
                    change=comparison.change,
                )
            )
    return minimize_findings(findings)


def minimize_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate equivalent failures and retain the smallest reproduction."""
    groups: dict[tuple[object, ...], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding_equivalence_key(finding), []).append(finding)

    minimized: list[Finding] = []
    for equivalents in groups.values():
        smallest = min(equivalents, key=finding_case_complexity)
        minimized.append(replace(smallest, equivalent_cases=len(equivalents)))
    return sorted(minimized, key=lambda finding: finding.semantic_key)


def finding_equivalence_key(finding: Finding) -> tuple[object, ...]:
    """Group failures with the same security meaning before shrinking."""
    case = finding.case
    tenant_relation = (
        "unknown"
        if case.subject.tenant is None or case.resource.tenant is None
        else "same"
        if case.subject.tenant == case.resource.tenant
        else "different"
    )
    return (
        finding.kind,
        finding.change,
        finding.invariant,
        finding.error,
        case.action.name,
        case.subject.role,
        case.resource.type,
        tenant_relation,
    )


def finding_case_complexity(finding: Finding) -> tuple[int, str]:
    """Order reproductions by compact canonical case representation."""
    serialized = json.dumps(finding.case.to_dict(), sort_keys=True, separators=(",", ":"))
    return (len(serialized), serialized)
