"""Tests for stable typed domain serialization."""

from permissiondiff.models import Action, AuthorizationCase, Context, Resource, Subject


def test_case_round_trip_and_fingerprint_are_stable() -> None:
    case = AuthorizationCase(
        subject=Subject("alice", "acme", "support", {"team": "one"}),
        action=Action("read_invoice"),
        resource=Resource("inv-1", "invoice", "globex", "bob"),
        context=Context(500, {"approved": True}),
    )

    restored = AuthorizationCase.from_dict(case.to_dict())

    assert restored == case
    assert restored.fingerprint == case.fingerprint
    assert len(case.fingerprint) == 64


def test_context_rejects_non_numeric_amount() -> None:
    try:
        Context.from_dict({"amount": "five"})
    except ValueError as exc:
        assert "numeric" in str(exc)
    else:
        raise AssertionError("invalid amount was accepted")
