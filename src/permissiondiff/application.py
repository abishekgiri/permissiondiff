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
from permissiondiff.generator import generate_cases
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
    findings = invariant_findings(evaluations, invariants)
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
    """Replay every exact baseline case (from a snapshot file) against the candidate."""
    return _diff_against_snapshot(config, workdir=workdir, snapshot=load_snapshot(baseline_path))


def run_git_diff(
    config: PermissionDiffConfig,
    *,
    workdir: Path,
    ref: str,
    seed: int,
    max_examples: int | None = None,
) -> RunResult:
    """Diff the candidate against the baseline authorizer as it existed at a git ref.

    The ref is checked out into a temporary detached worktree; the candidate config's domain
    generates the corpus, which is evaluated against the baseline authorizer code there. The
    candidate then replays that exact corpus in the working tree.
    """
    from permissiondiff.gitref import baseline_worktree, repo_root

    relative = workdir.resolve().relative_to(repo_root(workdir))
    with baseline_worktree(workdir, ref) as tree:
        baseline = create_snapshot(
            config, workdir=tree / relative, seed=seed, max_examples=max_examples
        )
    return _diff_against_snapshot(config, workdir=workdir, snapshot=baseline)


def _diff_against_snapshot(
    config: PermissionDiffConfig,
    *,
    workdir: Path,
    snapshot: Snapshot,
) -> RunResult:
    """Replay every exact baseline case against the candidate authorizer."""
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
    # Comparison and invariant findings never share an equivalence key (their
    # FindingKind differs), so minimizing each group independently is equivalent
    # to minimizing the combined list, and it preserves equivalent-case counts.
    findings = [
        *comparison_findings(comparisons),
        *invariant_findings(evaluations, invariants),
    ]
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
        mode=config.execution.worker,
    )
