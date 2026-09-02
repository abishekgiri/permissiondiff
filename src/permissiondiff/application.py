"""Application orchestration composed from generation, evaluation, and pure logic."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from permissiondiff.config import PermissionDiffConfig
from permissiondiff.engine import (
    compare_decisions,
    comparison_findings,
    invariant_findings,
)
from permissiondiff.evaluator import evaluate_cases
from permissiondiff.generator import generate_cases, shrink_findings
from permissiondiff.invariants import build_invariants
from permissiondiff.models import AuthorizationCase, CaseEvaluation, ComparisonResult, Finding
from permissiondiff.snapshot import Snapshot, load_snapshot, snapshot_from_evaluations


@dataclass(frozen=True, slots=True)
class RunResult:
    """Semantic output shared by human and machine report renderers."""

    cases_evaluated: int
    findings: tuple[Finding, ...]


def run_test(
    config: PermissionDiffConfig,
    *,
    workdir: Path,
    seed: int,
    max_examples: int | None = None,
) -> RunResult:
    """Generate cases, evaluate the authorizer, and check all invariants."""
    cases = generate_cases(config, seed=seed, max_examples=max_examples)
    evaluations = _evaluate(config, cases, workdir)
    invariants = build_invariants(config.invariants, workdir=workdir)
    findings = shrink_findings(
        invariant_findings(evaluations, invariants, minimize=False),
        seed=seed,
    )
    return RunResult(len(cases), tuple(findings))


def create_snapshot(
    config: PermissionDiffConfig,
    *,
    workdir: Path,
    seed: int,
    max_examples: int | None = None,
) -> Snapshot:
    """Generate and evaluate the exact baseline case corpus."""
    cases = generate_cases(config, seed=seed, max_examples=max_examples)
    evaluations = _evaluate(config, cases, workdir)
    return snapshot_from_evaluations(evaluations, seed=seed)


def run_diff(
    config: PermissionDiffConfig,
    *,
    workdir: Path,
    baseline_path: Path,
) -> RunResult:
    """Replay every exact baseline case against the candidate authorizer."""
    snapshot = load_snapshot(baseline_path)
    cases = [snapshot_case.case for snapshot_case in snapshot.cases]
    evaluations = _evaluate(config, cases, workdir)
    comparisons: list[ComparisonResult] = []
    for snapshot_case, evaluation in zip(snapshot.cases, evaluations, strict=True):
        if evaluation.decision is not None:
            comparisons.append(
                compare_decisions(
                    snapshot_case.case,
                    snapshot_case.baseline_decision,
                    evaluation.decision,
                )
            )
    invariants = build_invariants(config.invariants, workdir=workdir)
    findings = shrink_findings(
        [
            *comparison_findings(comparisons, minimize=False),
            *invariant_findings(evaluations, invariants, minimize=False),
        ],
        seed=snapshot.seed,
    )
    return RunResult(len(cases), tuple(findings))


def _evaluate(
    config: PermissionDiffConfig,
    cases: Sequence[AuthorizationCase],
    workdir: Path,
) -> list[CaseEvaluation]:
    return evaluate_cases(
        list(cases),
        config.authorizer,
        workdir=workdir,
        timeout_seconds=config.execution.timeout_seconds,
    )
