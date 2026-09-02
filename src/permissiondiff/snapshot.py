"""Versioned, canonical snapshots containing exact cases and decisions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from permissiondiff import __version__
from permissiondiff.errors import EvaluationError, SnapshotVersionError
from permissiondiff.models import AuthorizationCase, CaseEvaluation, Decision, JsonObject

SNAPSHOT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class SnapshotCase:
    """An exact baseline input and its decision."""

    case: AuthorizationCase
    baseline_decision: Decision

    def to_dict(self) -> JsonObject:
        """Serialize the exact case, decision, and stable fingerprint."""
        return {
            "fingerprint": self.case.fingerprint,
            "case": self.case.to_dict(),
            "baseline_decision": self.baseline_decision.value,
        }

    @classmethod
    def from_dict(cls, raw: JsonObject) -> SnapshotCase:
        """Load and integrity-check one stored baseline case."""
        try:
            case = AuthorizationCase.from_dict(_object(raw["case"]))
            decision = Decision(raw["baseline_decision"])
            fingerprint = str(raw["fingerprint"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SnapshotVersionError(f"invalid snapshot case: {exc}") from exc
        if fingerprint != case.fingerprint:
            raise SnapshotVersionError("snapshot case fingerprint does not match case content")
        return cls(case=case, baseline_decision=decision)


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A complete, versioned baseline corpus."""

    seed: int
    cases: tuple[SnapshotCase, ...]
    permissiondiff_version: str = __version__
    schema_version: int = SNAPSHOT_SCHEMA_VERSION

    def to_dict(self) -> JsonObject:
        """Return canonical snapshot data with stable case ordering."""
        return {
            "schema_version": self.schema_version,
            "permissiondiff_version": self.permissiondiff_version,
            "seed": self.seed,
            "cases": [case.to_dict() for case in sorted(self.cases, key=_fingerprint)],
        }

    @classmethod
    def from_dict(cls, raw: JsonObject) -> Snapshot:
        """Load a supported snapshot without reinterpreting its schema."""
        schema_version = raw.get("schema_version")
        if schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise SnapshotVersionError(
                f"unsupported snapshot schema {schema_version!r}; "
                f"expected {SNAPSHOT_SCHEMA_VERSION}"
            )
        raw_cases = raw.get("cases")
        if not isinstance(raw_cases, list):
            raise SnapshotVersionError("snapshot cases must be a list")
        try:
            return cls(
                schema_version=SNAPSHOT_SCHEMA_VERSION,
                permissiondiff_version=str(raw["permissiondiff_version"]),
                seed=int(raw["seed"]),
                cases=tuple(SnapshotCase.from_dict(_object(case)) for case in raw_cases),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SnapshotVersionError(f"invalid snapshot: {exc}") from exc


def snapshot_from_evaluations(evaluations: list[CaseEvaluation], *, seed: int) -> Snapshot:
    """Create a baseline only when every exact case has a decision."""
    failures = [evaluation for evaluation in evaluations if evaluation.error is not None]
    if failures:
        raise EvaluationError(
            f"cannot create snapshot: {len(failures)} case(s) failed evaluation; "
            f"first error: {failures[0].error}"
        )
    return Snapshot(
        seed=seed,
        cases=tuple(
            SnapshotCase(evaluation.case, _decision(evaluation)) for evaluation in evaluations
        ),
    )


def write_snapshot(snapshot: Snapshot, path: Path) -> None:
    """Write canonical, diff-friendly JSON with no volatile fields."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_snapshot(path: Path) -> Snapshot:
    """Read a versioned snapshot and validate its exact-case fingerprints."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotVersionError(f"snapshot not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotVersionError(f"could not read snapshot {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SnapshotVersionError("snapshot root must be an object")
    return Snapshot.from_dict(raw)


def _decision(evaluation: CaseEvaluation) -> Decision:
    if evaluation.decision is None:
        raise EvaluationError(evaluation.error or "missing decision")
    return evaluation.decision


def _fingerprint(snapshot_case: SnapshotCase) -> str:
    return snapshot_case.case.fingerprint


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotVersionError("expected a JSON object")
    return value
