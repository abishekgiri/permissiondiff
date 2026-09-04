"""Typed domain vocabulary for authorization evaluation and reporting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

JsonObject = dict[str, Any]


class Decision(StrEnum):
    """The only two valid authorization verdicts."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class ChangeType(StrEnum):
    """Classification of one baseline/candidate decision pair."""

    UNCHANGED_DENIED = "unchanged_denied"
    UNCHANGED_ALLOWED = "unchanged_allowed"
    NEWLY_ALLOWED = "newly_allowed"
    NEWLY_DENIED = "newly_denied"


class FindingKind(StrEnum):
    """Kinds of actionable results PermissionDiff persists."""

    CHANGE = "change"
    INVARIANT_VIOLATION = "invariant_violation"
    EVALUATION_ERROR = "evaluation_error"


class Severity(StrEnum):
    """Human-facing finding severity."""

    CRITICAL = "critical"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Subject:
    """A principal whose authority is being tested."""

    id: str
    tenant: str | None = None
    role: str | None = None
    attributes: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        """Return a JSON-compatible representation."""
        return {
            "id": self.id,
            "tenant": self.tenant,
            "role": self.role,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: JsonObject) -> Subject:
        """Build a subject from serialized data."""
        return cls(
            id=str(data["id"]),
            tenant=_optional_string(data.get("tenant")),
            role=_optional_string(data.get("role")),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True, slots=True)
class Resource:
    """An application object an action may target."""

    id: str
    type: str
    tenant: str | None = None
    owner_id: str | None = None
    attributes: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        """Return a JSON-compatible representation."""
        return {
            "id": self.id,
            "type": self.type,
            "tenant": self.tenant,
            "owner_id": self.owner_id,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: JsonObject) -> Resource:
        """Build a resource from serialized data."""
        return cls(
            id=str(data["id"]),
            type=str(data["type"]),
            tenant=_optional_string(data.get("tenant")),
            owner_id=_optional_string(data.get("owner_id")),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True, slots=True)
class Action:
    """A named operation a subject may attempt."""

    name: str

    def __str__(self) -> str:
        """Return the action name for concise authorizer code."""
        return self.name


@dataclass(frozen=True, slots=True)
class Context:
    """Additional deterministic inputs to an authorization decision."""

    amount: int | float | None = None
    attributes: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        """Return a JSON-compatible representation."""
        return {"amount": self.amount, "attributes": self.attributes}

    @classmethod
    def from_dict(cls, data: JsonObject) -> Context:
        """Build context from serialized data."""
        amount = data.get("amount")
        if amount is not None and not isinstance(amount, int | float):
            raise ValueError("context.amount must be numeric or null")
        return cls(amount=amount, attributes=dict(data.get("attributes", {})))


@dataclass(frozen=True, slots=True)
class AuthorizationCase:
    """One complete, replayable authorization input."""

    subject: Subject
    action: Action
    resource: Resource
    context: Context = field(default_factory=Context)

    def to_dict(self) -> JsonObject:
        """Return canonical semantic case data."""
        return {
            "subject": self.subject.to_dict(),
            "action": self.action.name,
            "resource": self.resource.to_dict(),
            "context": self.context.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: JsonObject) -> AuthorizationCase:
        """Recreate an authorization case from serialized data."""
        return cls(
            subject=Subject.from_dict(_object(data["subject"])),
            action=Action(str(data["action"])),
            resource=Resource.from_dict(_object(data["resource"])),
            context=Context.from_dict(_object(data.get("context", {}))),
        )

    @property
    def fingerprint(self) -> str:
        """Return a stable digest containing only semantic case fields."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


class AuthorizationFunction(Protocol):
    """Interface implemented by user authorization functions."""

    def __call__(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context,
    ) -> Decision: ...


@dataclass(frozen=True, slots=True)
class CaseEvaluation:
    """A decision or explicit evaluation error for one case."""

    case: AuthorizationCase
    decision: Decision | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        """Require exactly one of decision and error."""
        if (self.decision is None) == (self.error is None):
            raise ValueError("evaluation must contain exactly one of decision or error")


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    """One baseline/candidate comparison over the same exact case."""

    case: AuthorizationCase
    baseline: Decision
    candidate: Decision
    change: ChangeType


@dataclass(frozen=True, slots=True)
class InvariantResult:
    """Result of evaluating a deterministic invariant."""

    name: str
    passed: bool
    message: str


@dataclass(frozen=True, slots=True)
class Finding:
    """A stable, replayable issue found by evaluation or comparison."""

    kind: FindingKind
    severity: Severity
    case: AuthorizationCase
    message: str
    finding_id: str = ""
    baseline: Decision | None = None
    candidate: Decision | None = None
    change: ChangeType | None = None
    invariant: str | None = None
    error: str | None = None
    equivalent_cases: int = 1

    @property
    def semantic_key(self) -> str:
        """Return stable finding identity independent of display ID."""
        payload = {
            "kind": self.kind.value,
            "case_fingerprint": self.case.fingerprint,
            "baseline": self.baseline.value if self.baseline is not None else None,
            "candidate": self.candidate.value if self.candidate is not None else None,
            "change": self.change.value if self.change is not None else None,
            "invariant": self.invariant,
            "error": self.error,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def with_id(self, finding_id: str) -> Finding:
        """Return this immutable finding with its stable display ID."""
        return replace(self, finding_id=finding_id)

    def to_dict(self) -> JsonObject:
        """Return a machine-readable finding and reproduction."""
        return {
            "schema_version": 1,
            "finding_id": self.finding_id,
            "kind": self.kind.value,
            "severity": self.severity.value,
            "message": self.message,
            "invariant": self.invariant,
            "change": self.change.value if self.change is not None else None,
            "baseline": self.baseline.value if self.baseline is not None else None,
            "candidate": self.candidate.value if self.candidate is not None else None,
            "error": self.error,
            "equivalent_cases": self.equivalent_cases,
            "case_fingerprint": self.case.fingerprint,
            "case": self.case.to_dict(),
        }


def _object(value: object) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else str(value)
