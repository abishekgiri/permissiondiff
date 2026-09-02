"""YAML configuration models and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from permissiondiff.errors import ConfigurationError
from permissiondiff.models import Resource, Subject


class SubjectConfig(BaseModel):
    """A meaningful subject declared by the application."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    tenant: str | None = None
    role: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    def to_domain(self) -> Subject:
        """Convert boundary validation data into the core model."""
        return Subject(
            id=self.id,
            tenant=self.tenant,
            role=self.role,
            attributes=self.attributes,
        )


class ResourceConfig(BaseModel):
    """A meaningful resource declared by the application."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    tenant: str | None = None
    owner_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    def to_domain(self) -> Resource:
        """Convert boundary validation data into the core model."""
        return Resource(
            id=self.id,
            type=self.type,
            tenant=self.tenant,
            owner_id=self.owner_id,
            attributes=self.attributes,
        )


class AmountDomain(BaseModel):
    """Numeric context range plus security-relevant boundary values."""

    model_config = ConfigDict(extra="forbid")

    min: int = 0
    max: int = 1000
    boundaries: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_range(self) -> AmountDomain:
        """Reject inverted amount ranges."""
        if self.max < self.min:
            raise ValueError("amounts.max must be greater than or equal to amounts.min")
        return self

    def interesting_values(self) -> tuple[int, ...]:
        """Return sorted, unique values that emphasize range edges."""
        candidates = {
            self.min,
            self.max,
            self.min + 1 if self.min < self.max else self.min,
            self.max - 1 if self.min < self.max else self.max,
            *self.boundaries,
        }
        return tuple(sorted(candidates))


class ContextDomains(BaseModel):
    """Explicit context dimensions available to case generation."""

    model_config = ConfigDict(extra="forbid")

    amounts: AmountDomain | None = None


class GenerationConfig(BaseModel):
    """Bounds for deterministic, lazy case-corpus generation."""

    model_config = ConfigDict(extra="forbid")

    max_examples: int = Field(default=64, ge=1, le=10_000)


class ExecutionConfig(BaseModel):
    """Fault-isolation settings for the authorizer worker."""

    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float = Field(default=2.0, gt=0, le=300)


class FailOnConfig(BaseModel):
    """Controls which semantic results fail CI."""

    model_config = ConfigDict(extra="forbid")

    invariant_violation: bool = True
    newly_allowed: bool = True
    newly_denied: bool = False


class PermissionDiffConfig(BaseModel):
    """Validated user-facing PermissionDiff configuration."""

    model_config = ConfigDict(extra="forbid")

    authorizer: str = Field(min_length=3)
    subjects: list[SubjectConfig] = Field(min_length=1)
    resources: list[ResourceConfig] = Field(min_length=1)
    actions: list[str] = Field(min_length=1)
    contexts: ContextDomains = Field(default_factory=ContextDomains)
    invariants: list[str | dict[str, Any]] = Field(default_factory=list)
    fail_on: FailOnConfig = Field(default_factory=FailOnConfig)
    generation: GenerationConfig = Field(default_factory=GenerationConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    @model_validator(mode="after")
    def validate_domain_identity(self) -> PermissionDiffConfig:
        """Require unique named entities and actions for stable fingerprints."""
        _ensure_unique([subject.id for subject in self.subjects], "subject ids")
        _ensure_unique([resource.id for resource in self.resources], "resource ids")
        _ensure_unique(self.actions, "actions")
        if any(not action.strip() for action in self.actions):
            raise ValueError("actions must not be blank")
        return self


def load_config(path: Path) -> PermissionDiffConfig:
    """Load and validate a PermissionDiff YAML file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file not found: {path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"could not read configuration {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("configuration root must be a YAML mapping")
    try:
        return PermissionDiffConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc


def _ensure_unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
