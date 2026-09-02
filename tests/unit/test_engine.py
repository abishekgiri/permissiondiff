"""Unit and property tests for exhaustive comparison logic."""

from hypothesis import given
from hypothesis import strategies as st

from permissiondiff.engine import classify_change, compare_decisions
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    ChangeType,
    Context,
    Decision,
    Resource,
    Subject,
)

CASE = AuthorizationCase(
    Subject("alice", "acme", "support"),
    Action("read"),
    Resource("one", "invoice", "acme", "alice"),
    Context(),
)


def test_classification_truth_table() -> None:
    assert classify_change(Decision.DENY, Decision.DENY) is ChangeType.UNCHANGED_DENIED
    assert classify_change(Decision.ALLOW, Decision.ALLOW) is ChangeType.UNCHANGED_ALLOWED
    assert classify_change(Decision.DENY, Decision.ALLOW) is ChangeType.NEWLY_ALLOWED
    assert classify_change(Decision.ALLOW, Decision.DENY) is ChangeType.NEWLY_DENIED


@given(st.sampled_from(list(Decision)))
def test_compare_identical_decisions_never_reports_change(decision: Decision) -> None:
    result = compare_decisions(CASE, decision, decision)
    assert result.change in {ChangeType.UNCHANGED_ALLOWED, ChangeType.UNCHANGED_DENIED}


@given(st.sampled_from(list(Decision)), st.sampled_from(list(Decision)))
def test_classification_is_exhaustive(baseline: Decision, candidate: Decision) -> None:
    assert isinstance(classify_change(baseline, candidate), ChangeType)
