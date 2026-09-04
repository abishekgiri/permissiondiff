"""Subprocess authorizer fault-isolation tests."""

import subprocess
from pathlib import Path

import pytest

from permissiondiff.evaluator import evaluate_case
from permissiondiff.models import Action, AuthorizationCase, Context, Decision, Resource, Subject
from tests.conftest import write_authorizer

CASE = AuthorizationCase(
    Subject("alice", "acme", "support"),
    Action("read_invoice"),
    Resource("inv", "invoice", "acme", "alice"),
    Context(),
)

HEADER = """from permissiondiff import Decision\n"""


def test_valid_authorizer_runs_out_of_process(tmp_path: Path) -> None:
    spec = write_authorizer(
        tmp_path,
        HEADER
        + "\ndef authorize(subject, action, resource, context):\n"
        + "    return Decision.ALLOW\n",
    )
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=1)
    assert result.decision is Decision.ALLOW
    assert result.error is None


def test_authorizer_crash_is_explicit_error(tmp_path: Path) -> None:
    spec = write_authorizer(
        tmp_path,
        "def authorize(subject, action, resource, context):\n    raise RuntimeError('boom')\n",
    )
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=1)
    assert result.decision is None
    assert "RuntimeError: boom" in (result.error or "")


def test_authorizer_timeout_is_explicit_error(tmp_path: Path) -> None:
    spec = write_authorizer(
        tmp_path,
        "import time\ndef authorize(subject, action, resource, context):\n    time.sleep(5)\n",
    )
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=0.05)
    assert result.decision is None
    assert "timed out" in (result.error or "")


def test_invalid_authorizer_return_is_explicit_error(tmp_path: Path) -> None:
    spec = write_authorizer(
        tmp_path,
        "def authorize(subject, action, resource, context):\n    return 'ALLOW'\n",
    )
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=1)
    assert result.decision is None
    assert "invalid value" in (result.error or "")


def test_worker_hard_exit_is_explicit_error(tmp_path: Path) -> None:
    """A worker that exits nonzero without a result is reported, never fail-open."""
    spec = write_authorizer(
        tmp_path,
        "import os\ndef authorize(subject, action, resource, context):\n    os._exit(7)\n",
    )
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=1)
    assert result.decision is None
    assert "exited with code 7" in (result.error or "")


def _patch_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_worker_start_failure_is_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_oserror(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("no interpreter")

    monkeypatch.setattr(subprocess, "run", raise_oserror)
    result = evaluate_case(CASE, "auth:authorize", workdir=Path("."), timeout_seconds=1)
    assert result.decision is None
    assert "could not start authorizer worker" in (result.error or "")


def test_worker_nonzero_exit_detail_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, returncode=1, stderr="explosion")
    result = evaluate_case(CASE, "auth:authorize", workdir=Path("."), timeout_seconds=1)
    assert result.decision is None
    assert "exited with code 1: explosion" in (result.error or "")


def test_worker_invalid_json_is_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, stdout="not json")
    result = evaluate_case(CASE, "auth:authorize", workdir=Path("."), timeout_seconds=1)
    assert result.decision is None
    assert "invalid JSON" in (result.error or "")


def test_worker_non_object_result_is_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, stdout="5")
    result = evaluate_case(CASE, "auth:authorize", workdir=Path("."), timeout_seconds=1)
    assert result.decision is None
    assert "non-object result" in (result.error or "")


def test_worker_invalid_decision_is_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, stdout='{"decision": "MAYBE"}')
    result = evaluate_case(CASE, "auth:authorize", workdir=Path("."), timeout_seconds=1)
    assert result.decision is None
    assert "invalid decision" in (result.error or "")
