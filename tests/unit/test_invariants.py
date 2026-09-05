"""Tests for all built-in invariants and the custom API."""

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from permissiondiff.errors import InvariantEvaluationError
from permissiondiff.invariants import (
    CustomInvariant,
    OwnershipInvariant,
    RoleBoundaryInvariant,
    TenantIsolationInvariant,
    build_invariants,
)
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    Context,
    Decision,
    InvariantResult,
    Resource,
    Subject,
)


def make_case(
    *, tenant: str = "globex", action: str = "read", owner: str = "bob"
) -> AuthorizationCase:
    """Build a concise authorization case for invariant tests."""
    return AuthorizationCase(
        Subject("alice", "acme", "support"),
        Action(action),
        Resource("one", "invoice", tenant, owner),
        Context(),
    )


def test_tenant_isolation_catches_cross_tenant_allow() -> None:
    result = TenantIsolationInvariant().evaluate(make_case(), Decision.ALLOW)
    assert not result.passed


def test_role_boundary_catches_non_admin() -> None:
    invariant = RoleBoundaryInvariant(frozenset({"delete"}), frozenset({"admin"}))
    assert not invariant.evaluate(make_case(action="delete"), Decision.ALLOW).passed
    assert invariant.evaluate(make_case(action="read"), Decision.ALLOW).passed


def test_ownership_catches_non_owner() -> None:
    invariant = OwnershipInvariant(frozenset({"read"}))
    assert not invariant.evaluate(make_case(owner="bob"), Decision.ALLOW).passed
    assert invariant.evaluate(make_case(owner="alice"), Decision.ALLOW).passed


def test_custom_invariant_loads_from_config_directory(tmp_path: Path) -> None:
    (tmp_path / "custom_rules.py").write_text(
        "def deny_all(case, decision):\n    return decision.value == 'DENY'\n",
        encoding="utf-8",
    )
    invariants = build_invariants(
        [{"custom": {"name": "deny_all", "callable": "custom_rules:deny_all"}}],
        workdir=tmp_path,
    )
    assert not invariants[0].evaluate(make_case(), Decision.ALLOW).passed


def test_custom_invariant_accepts_bool_and_invariant_result() -> None:
    passed = CustomInvariant("ok_bool", lambda case, decision: True)
    assert passed.evaluate(make_case(), Decision.ALLOW).passed
    detailed = CustomInvariant(
        "ok_result",
        lambda case, decision: InvariantResult("ok_result", passed=False, message="nope"),
    )
    result = detailed.evaluate(make_case(), Decision.ALLOW)
    assert not result.passed and result.message == "nope"


def _raiser(exc: BaseException) -> Callable[[AuthorizationCase, Decision], bool]:
    def _invariant(case: AuthorizationCase, decision: Decision) -> bool:
        raise exc

    return _invariant


@pytest.mark.parametrize(
    "exc",
    [SystemExit(0), SystemExit(1), KeyboardInterrupt(), RuntimeError("boom")],
)
def test_custom_invariant_termination_becomes_explicit_error(exc: BaseException) -> None:
    """A custom invariant that terminates the process must never fake success."""
    invariant = CustomInvariant("terminator", _raiser(exc))
    with pytest.raises(InvariantEvaluationError):
        invariant.evaluate(make_case(), Decision.ALLOW)


def test_custom_invariant_invalid_return_is_explicit_error() -> None:
    # Deliberately violate the return contract to exercise the runtime guard.
    bad = cast(
        "Callable[[AuthorizationCase, Decision], bool | InvariantResult]",
        lambda case, decision: "ALLOW",
    )
    invariant = CustomInvariant("bad_return", bad)
    with pytest.raises(InvariantEvaluationError, match="expected bool or InvariantResult"):
        invariant.evaluate(make_case(), Decision.ALLOW)


def test_custom_invariant_import_time_exit_is_explicit_error(tmp_path: Path) -> None:
    (tmp_path / "exiting_rules.py").write_text(
        "import sys\nsys.exit(0)\ndef rule(case, decision):\n    return True\n",
        encoding="utf-8",
    )
    with pytest.raises(InvariantEvaluationError):
        build_invariants(
            [{"custom": {"name": "rule", "callable": "exiting_rules:rule"}}],
            workdir=tmp_path,
        )
