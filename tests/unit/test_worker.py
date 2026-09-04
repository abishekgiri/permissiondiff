"""Direct tests for the fault-isolated evaluation worker."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from permissiondiff.evaluator import evaluate_case
from permissiondiff.models import Action, AuthorizationCase, Context, Decision, Resource, Subject
from permissiondiff.worker import evaluate_payload
from tests.conftest import write_authorizer

CASE = AuthorizationCase(
    Subject("alice", "acme", "support"),
    Action("read_invoice"),
    Resource("inv", "invoice", "acme", "alice"),
    Context(),
)
PAYLOAD = CASE.to_dict()

NOISY_AUTHORIZER = (
    "import os\n"
    "from permissiondiff import Decision\n"
    "print('import-time noise on stdout')\n"
    "def authorize(subject, action, resource, context):\n"
    "    print('runtime noise on stdout')\n"
    "    os.write(1, b'raw fd-1 write\\n')\n"
    "    return Decision.ALLOW\n"
)


def _run_worker(
    args: list[str], stdin: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Invoke the worker module exactly as the evaluator does."""
    return subprocess.run(
        [sys.executable, "-m", "permissiondiff.worker", *args],
        input=stdin,
        text=True,
        capture_output=True,
        cwd=cwd,
        check=False,
    )


# --- regression: a correct authorizer that writes to stdout must still evaluate ---


def test_stdout_writing_authorizer_is_still_evaluated(tmp_path: Path) -> None:
    """Import-time, runtime, and raw fd-1 writes must not corrupt the result."""
    spec = write_authorizer(tmp_path, NOISY_AUTHORIZER)
    result = evaluate_case(CASE, spec, workdir=tmp_path, timeout_seconds=5)
    assert result.error is None
    assert result.decision is Decision.ALLOW


# --- direct evaluate_payload unit tests ---


def test_evaluate_payload_returns_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "auth_ok.py").write_text(
        "from permissiondiff import Decision\n"
        "def authorize(s, a, r, c):\n    return Decision.DENY\n",
        encoding="utf-8",
    )
    assert evaluate_payload("auth_ok:authorize", PAYLOAD) == {"decision": "DENY"}


def test_evaluate_payload_non_decision_return_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "auth_bad.py").write_text(
        "def authorize(s, a, r, c):\n    return 'ALLOW'\n", encoding="utf-8"
    )
    result = evaluate_payload("auth_bad:authorize", PAYLOAD)
    assert "invalid value" in result["error"]


def test_evaluate_payload_crash_is_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "auth_boom.py").write_text(
        "def authorize(s, a, r, c):\n    raise RuntimeError('boom')\n", encoding="utf-8"
    )
    result = evaluate_payload("auth_boom:authorize", PAYLOAD)
    assert "RuntimeError: boom" in result["error"]


def test_evaluate_payload_bad_spec_is_error() -> None:
    result = evaluate_payload("permissiondiff_missing_module:authorize", PAYLOAD)
    assert "could not import" in result["error"]


# --- direct main() tests via subprocess (argv, stdin, and fd-level containment) ---


def test_main_rejects_missing_authorizer_spec() -> None:
    proc = _run_worker([], "")
    assert proc.returncode == 2
    assert json.loads(proc.stdout) == {"error": "worker requires one authorizer spec"}


def test_main_rejects_non_object_payload() -> None:
    proc = _run_worker(["auth:authorize"], "[]")
    assert proc.returncode == 0
    assert "worker input must be an object" in json.loads(proc.stdout)["error"]


def test_main_emits_only_json_and_diverts_user_output(tmp_path: Path) -> None:
    write_authorizer(tmp_path, NOISY_AUTHORIZER)
    proc = _run_worker(["auth:authorize"], json.dumps(PAYLOAD), cwd=tmp_path)
    assert proc.returncode == 0
    # stdout must parse as exactly one JSON object -- no user noise mixed in.
    assert json.loads(proc.stdout) == {"decision": "ALLOW"}
    # the user's stdout writes are contained on stderr instead.
    assert "runtime noise on stdout" in proc.stderr
    assert "raw fd-1 write" in proc.stderr
