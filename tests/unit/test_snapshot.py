"""Snapshot schema, canonicalization, and replay integrity tests."""

import json
from pathlib import Path

import pytest

from permissiondiff.errors import SnapshotVersionError
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    CaseEvaluation,
    Context,
    Decision,
    Resource,
    Subject,
)
from permissiondiff.snapshot import (
    Snapshot,
    load_snapshot,
    snapshot_from_evaluations,
    write_snapshot,
)


def case(identifier: str = "one") -> AuthorizationCase:
    """Create an exact case for snapshot tests."""
    return AuthorizationCase(
        Subject("alice", "acme", "support"),
        Action("read"),
        Resource(identifier, "invoice", "acme", "alice"),
        Context(500),
    )


@pytest.mark.parametrize("decision", list(Decision))
def test_snapshot_round_trip_preserves_semantic_decision(
    tmp_path: Path, decision: Decision
) -> None:
    original = snapshot_from_evaluations([CaseEvaluation(case(), decision=decision)], seed=42)
    path = tmp_path / "snapshot.json"
    write_snapshot(original, path)
    assert load_snapshot(path) == original


def test_snapshot_output_is_canonical(tmp_path: Path) -> None:
    snapshot = snapshot_from_evaluations(
        [
            CaseEvaluation(case("z"), decision=Decision.DENY),
            CaseEvaluation(case("a"), decision=Decision.ALLOW),
        ],
        seed=7,
    )
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_snapshot(snapshot, first)
    write_snapshot(Snapshot.from_dict(snapshot.to_dict()), second)
    assert first.read_bytes() == second.read_bytes()


def test_incompatible_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "old.json"
    path.write_text('{"schema_version": 999, "cases": []}', encoding="utf-8")
    with pytest.raises(SnapshotVersionError, match="unsupported"):
        load_snapshot(path)


def test_tampered_case_fingerprint_is_rejected(tmp_path: Path) -> None:
    snapshot = snapshot_from_evaluations(
        [CaseEvaluation(case(), decision=Decision.DENY)], seed=1
    ).to_dict()
    snapshot["cases"][0]["fingerprint"] = "tampered"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SnapshotVersionError, match="fingerprint"):
        load_snapshot(path)
