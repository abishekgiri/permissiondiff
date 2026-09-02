"""Subprocess authorizer fault-isolation tests."""

from pathlib import Path

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
