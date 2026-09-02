"""Parent-side orchestration for subprocess authorizer evaluation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from permissiondiff.models import AuthorizationCase, CaseEvaluation, Decision


def evaluate_case(
    case: AuthorizationCase,
    authorizer_spec: str,
    *,
    workdir: Path,
    timeout_seconds: float,
) -> CaseEvaluation:
    """Evaluate a case in a fresh worker process with a hard timeout."""
    command = [sys.executable, "-m", "permissiondiff.worker", authorizer_spec]
    payload = json.dumps(case.to_dict(), sort_keys=True, separators=(",", ":"))
    environment = os.environ.copy()
    package_root = str(Path(__file__).resolve().parents[1])
    inherited_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        [package_root, inherited_path] if inherited_path else [package_root]
    )
    try:
        completed = subprocess.run(
            command,
            input=payload,
            text=True,
            capture_output=True,
            cwd=workdir,
            env=environment,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CaseEvaluation(
            case=case,
            error=f"authorizer timed out after {timeout_seconds:g} seconds",
        )
    except OSError as exc:
        return CaseEvaluation(case=case, error=f"could not start authorizer worker: {exc}")

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no worker output"
        return CaseEvaluation(
            case=case,
            error=f"authorizer worker exited with code {completed.returncode}: {detail}",
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return CaseEvaluation(case=case, error="authorizer worker returned invalid JSON")
    if not isinstance(result, dict):
        return CaseEvaluation(case=case, error="authorizer worker returned a non-object result")
    if isinstance(result.get("error"), str):
        return CaseEvaluation(case=case, error=result["error"])
    try:
        decision = Decision(result["decision"])
    except (KeyError, TypeError, ValueError):
        return CaseEvaluation(case=case, error="authorizer worker returned an invalid decision")
    return CaseEvaluation(case=case, decision=decision)


def evaluate_cases(
    cases: list[AuthorizationCase] | tuple[AuthorizationCase, ...],
    authorizer_spec: str,
    *,
    workdir: Path,
    timeout_seconds: float,
) -> list[CaseEvaluation]:
    """Evaluate cases independently so a crash cannot corrupt parent state."""
    return [
        evaluate_case(
            case,
            authorizer_spec,
            workdir=workdir,
            timeout_seconds=timeout_seconds,
        )
        for case in cases
    ]
