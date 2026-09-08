"""Unit and property tests for exhaustive comparison logic."""

from hypothesis import given
from hypothesis import strategies as st

from permissiondiff.engine import (
    classify_change,
    compare_decisions,
    delegation_findings,
    mine_grants,
    minimize_findings,
)
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    CaseEvaluation,
    ChangeType,
    Context,
    Decision,
    Finding,
    FindingKind,
    Resource,
    Severity,
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


def test_minimize_findings_selects_smallest_and_counts_equivalents() -> None:
    findings = [
        Finding(
            kind=FindingKind.INVARIANT_VIOLATION,
            severity=Severity.CRITICAL,
            case=AuthorizationCase(
                Subject("alice", "acme", "support"),
                Action("read"),
                Resource("invoice", "invoice", "globex", "bob"),
                Context(amount),
            ),
            message="cross tenant",
            invariant="tenant_isolation",
        )
        for amount in (1000, 0, 500)
    ]

    minimized = minimize_findings(findings)

    assert len(minimized) == 1
    assert minimized[0].case.context.amount == 0
    assert minimized[0].equivalent_cases == 3


# --- least-privilege mining ---


def _eval(role: str, tenant: str, owner: str, decision: Decision) -> CaseEvaluation:
    return CaseEvaluation(
        AuthorizationCase(
            Subject("alice", "acme", role),
            Action("read_invoice"),
            Resource("inv", "invoice", tenant, owner),
            Context(),
        ),
        decision=decision,
    )


def test_mine_grants_reports_only_allows_and_flags_broad() -> None:
    evaluations = [
        _eval("support", "acme", "alice", Decision.ALLOW),  # scoped (same tenant, owner)
        _eval("support", "acme", "alice", Decision.ALLOW),  # duplicate -> count 2
        _eval("support", "globex", "bob", Decision.ALLOW),  # broad (cross-tenant, non-owner)
        _eval("support", "acme", "bob", Decision.DENY),  # ignored (DENY)
    ]
    grants = mine_grants(evaluations)
    assert len(grants) == 2
    scoped = next(g for g in grants if not g.broad)
    broad = next(g for g in grants if g.broad)
    assert scoped.tenant_relation == "same" and scoped.ownership == "owner" and scoped.count == 2
    assert broad.tenant_relation == "different" and broad.ownership == "non_owner"


def test_mine_grants_ignores_errors_and_is_deterministic() -> None:
    from permissiondiff.models import AuthorizationCase as _AC

    err = CaseEvaluation(
        _AC(Subject("x", "acme", "support"), Action("read_invoice"), Resource("i", "invoice")),
        error="boom",
    )
    allow = _eval("support", "acme", "alice", Decision.ALLOW)
    assert mine_grants([err]) == []
    assert [g.key for g in mine_grants([allow, err])] == [g.key for g in mine_grants([err, allow])]


# --- delegation (least-privilege intersection) ---


def _deleg_eval(subject: Subject, decision: Decision) -> CaseEvaluation:
    return CaseEvaluation(
        AuthorizationCase(
            subject,
            Action("refund"),
            Resource("inv", "invoice", "acme", "alice"),
            Context(),
        ),
        decision=decision,
    )


def test_delegation_flags_agent_exceeding_delegator() -> None:
    admin = Subject("admin", "acme", "admin")
    agent = Subject("agent", "acme", "agent", delegated_by=("admin",))
    findings = delegation_findings(
        [
            _deleg_eval(agent, Decision.ALLOW),  # delegated principal allowed
            _deleg_eval(admin, Decision.DENY),  # delegator denied on the identical case
        ]
    )
    assert len(findings) == 1
    assert findings[0].invariant == "delegation"
    assert "escalation" in findings[0].message


def test_delegation_allows_agent_within_delegator_authority() -> None:
    admin = Subject("admin", "acme", "admin")
    agent = Subject("agent", "acme", "agent", delegated_by=("admin",))
    findings = delegation_findings(
        [
            _deleg_eval(agent, Decision.ALLOW),
            _deleg_eval(admin, Decision.ALLOW),  # delegator also allowed -> no escalation
        ]
    )
    assert findings == []
