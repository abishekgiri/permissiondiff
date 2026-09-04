"""Property-oriented tests for declared-domain generation."""

from permissiondiff.config import PermissionDiffConfig
from permissiondiff.generator import generate_cases


def config() -> PermissionDiffConfig:
    """Return a small domain with meaningful relationship edges."""
    return PermissionDiffConfig.model_validate(
        {
            "authorizer": "auth:authorize",
            "subjects": [
                {"id": "alice", "tenant": "acme", "role": "support"},
                {"id": "bob", "tenant": "globex", "role": "support"},
            ],
            "resources": [
                {"id": "a", "type": "invoice", "tenant": "acme", "owner_id": "alice"},
                {"id": "b", "type": "invoice", "tenant": "globex", "owner_id": "bob"},
            ],
            "actions": ["read", "refund"],
            "contexts": {"amounts": {"min": 0, "max": 1000, "boundaries": [499, 500, 501]}},
            "generation": {"max_examples": 24},
        }
    )


def test_same_seed_and_environment_produces_same_corpus() -> None:
    first = generate_cases(config(), seed=101)
    second = generate_cases(config(), seed=101)
    assert [case.fingerprint for case in first] == [case.fingerprint for case in second]


def test_generation_uses_only_declared_entities_and_is_bounded() -> None:
    cases = generate_cases(config(), seed=42, max_examples=18)
    assert len(cases) <= 18
    assert {case.subject.id for case in cases} <= {"alice", "bob"}
    assert {case.resource.id for case in cases} <= {"a", "b"}
    assert {case.action.name for case in cases} <= {"read", "refund"}
    assert any(case.subject.tenant != case.resource.tenant for case in cases)


def test_declared_numeric_boundaries_are_explored() -> None:
    amounts = {case.context.amount for case in generate_cases(config(), seed=42)}
    assert {0, 499, 500, 501, 999, 1000} & amounts
