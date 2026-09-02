"""Deterministic built-in and custom authorization invariants."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from permissiondiff.errors import InvariantDefinitionError
from permissiondiff.loader import load_callable
from permissiondiff.models import AuthorizationCase, Decision, InvariantResult


class Invariant(Protocol):
    """Interface shared by every deterministic invariant."""

    @property
    def name(self) -> str: ...

    def evaluate(self, case: AuthorizationCase, decision: Decision) -> InvariantResult: ...


@dataclass(frozen=True, slots=True)
class TenantIsolationInvariant:
    """Require cross-tenant authorization cases to be denied."""

    name: str = "tenant_isolation"

    def evaluate(self, case: AuthorizationCase, decision: Decision) -> InvariantResult:
        """Check tenant isolation when both tenants are known and differ."""
        applies = (
            case.subject.tenant is not None
            and case.resource.tenant is not None
            and case.subject.tenant != case.resource.tenant
        )
        passed = not applies or decision is Decision.DENY
        return InvariantResult(
            name=self.name,
            passed=passed,
            message=(
                "Cross-tenant access must be denied" if not passed else "Tenant isolation holds"
            ),
        )


@dataclass(frozen=True, slots=True)
class RoleBoundaryInvariant:
    """Restrict selected actions to an explicit set of roles."""

    actions: frozenset[str]
    allowed_roles: frozenset[str]
    name: str = "role_boundary"

    def evaluate(self, case: AuthorizationCase, decision: Decision) -> InvariantResult:
        """Require denial when a selected action is attempted by another role."""
        applies = case.action.name in self.actions and case.subject.role not in self.allowed_roles
        passed = not applies or decision is Decision.DENY
        return InvariantResult(
            name=self.name,
            passed=passed,
            message=(
                f"Role {case.subject.role!r} must not perform {case.action.name!r}"
                if not passed
                else "Role boundary holds"
            ),
        )


@dataclass(frozen=True, slots=True)
class OwnershipInvariant:
    """Require non-owners to be denied for selected actions."""

    actions: frozenset[str]
    name: str = "ownership"

    def evaluate(self, case: AuthorizationCase, decision: Decision) -> InvariantResult:
        """Check ownership only when the resource declares an owner."""
        applies = (
            case.action.name in self.actions
            and case.resource.owner_id is not None
            and case.subject.id != case.resource.owner_id
        )
        passed = not applies or decision is Decision.DENY
        return InvariantResult(
            name=self.name,
            passed=passed,
            message=(
                "Non-owner access must be denied" if not passed else "Ownership boundary holds"
            ),
        )


@dataclass(frozen=True, slots=True)
class CustomInvariant:
    """Adapter for a user-defined deterministic invariant callable."""

    name: str
    function: Callable[[AuthorizationCase, Decision], bool | InvariantResult]

    def evaluate(self, case: AuthorizationCase, decision: Decision) -> InvariantResult:
        """Validate and normalize the custom invariant result."""
        try:
            result = self.function(case, decision)
        except Exception as exc:
            raise InvariantDefinitionError(
                f"custom invariant {self.name!r} crashed: {exc}"
            ) from exc
        if isinstance(result, InvariantResult):
            return result
        if isinstance(result, bool):
            return InvariantResult(
                name=self.name,
                passed=result,
                message=(
                    f"Custom invariant {self.name!r} failed"
                    if not result
                    else f"Custom invariant {self.name!r} holds"
                ),
            )
        raise InvariantDefinitionError(
            f"custom invariant {self.name!r} returned {type(result).__name__}, expected bool"
        )


def build_invariants(declarations: list[str | dict[str, Any]], *, workdir: Path) -> list[Invariant]:
    """Turn validated config declarations into core invariant objects."""
    invariants: list[Invariant] = []
    for declaration in declarations:
        if isinstance(declaration, str):
            if declaration != "tenant_isolation":
                raise InvariantDefinitionError(f"unknown invariant {declaration!r}")
            invariants.append(TenantIsolationInvariant())
            continue
        if len(declaration) != 1:
            raise InvariantDefinitionError("invariant mappings must contain exactly one key")
        name, raw_options = next(iter(declaration.items()))
        options = _options(raw_options, name)
        if name == "tenant_isolation":
            invariants.append(TenantIsolationInvariant())
        elif name == "role_boundary":
            actions = _actions(options, name)
            roles = options.get("allowed_roles")
            if (
                not isinstance(roles, list)
                or not roles
                or not all(isinstance(role, str) for role in roles)
            ):
                raise InvariantDefinitionError("role_boundary.allowed_roles must be a string list")
            invariants.append(RoleBoundaryInvariant(actions, frozenset(roles)))
        elif name == "ownership":
            invariants.append(OwnershipInvariant(_actions(options, name)))
        elif name == "custom":
            spec = options.get("callable")
            custom_name = options.get("name", spec)
            if not isinstance(spec, str) or not isinstance(custom_name, str):
                raise InvariantDefinitionError(
                    "custom invariant requires callable and optional name"
                )
            invariants.append(CustomInvariant(custom_name, _load_from_workdir(spec, workdir)))
        else:
            raise InvariantDefinitionError(f"unknown invariant {name!r}")
    return invariants


def _actions(options: dict[str, Any], name: str) -> frozenset[str]:
    raw = options.get("actions", options.get("action"))
    if isinstance(raw, str):
        return frozenset({raw})
    if isinstance(raw, list) and raw and all(isinstance(action, str) for action in raw):
        return frozenset(raw)
    raise InvariantDefinitionError(f"{name}.actions must be a string or non-empty string list")


def _options(value: object, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InvariantDefinitionError(f"{name} options must be a mapping")
    return value


def _load_from_workdir(spec: str, workdir: Path) -> Callable[..., Any]:
    path = str(workdir.resolve())
    added = path not in sys.path
    if added:
        sys.path.insert(0, path)
    try:
        return load_callable(spec)
    finally:
        if added:
            sys.path.remove(path)
