"""Tests for all built-in invariants and the custom API."""

from pathlib import Path

from permissiondiff.invariants import (
    OwnershipInvariant,
    RoleBoundaryInvariant,
    TenantIsolationInvariant,
    build_invariants,
)
from permissiondiff.models import Action, AuthorizationCase, Context, Decision, Resource, Subject


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
