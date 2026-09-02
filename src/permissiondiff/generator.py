"""Bounded authorization-case generation over explicit application domains."""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable
from dataclasses import replace

from hypothesis import HealthCheck, Phase, find, given, settings
from hypothesis import seed as hypothesis_seed
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from permissiondiff.config import PermissionDiffConfig
from permissiondiff.engine import finding_case_complexity, finding_equivalence_key
from permissiondiff.models import Action, AuthorizationCase, Context, Finding, Resource, Subject


def case_strategy(config: PermissionDiffConfig) -> SearchStrategy[AuthorizationCase]:
    """Build a Hypothesis strategy that combines only declared domain entities."""
    subjects = [subject.to_domain() for subject in config.subjects]
    resources = [resource.to_domain() for resource in config.resources]
    actions = [Action(name) for name in config.actions]
    amount_strategy: SearchStrategy[int | None]
    if config.contexts.amounts is None:
        amount_strategy = st.none()
    else:
        amount_domain = config.contexts.amounts
        boundary_values = amount_domain.interesting_values()
        amount_strategy = st.one_of(
            st.sampled_from(boundary_values),
            st.integers(min_value=amount_domain.min, max_value=amount_domain.max),
        )
    return st.builds(
        AuthorizationCase,
        subject=st.sampled_from(subjects),
        action=st.sampled_from(actions),
        resource=st.sampled_from(resources),
        context=st.builds(Context, amount=amount_strategy),
    )


def generate_cases(
    config: PermissionDiffConfig,
    *,
    seed: int,
    max_examples: int | None = None,
) -> list[AuthorizationCase]:
    """Generate a stable, bounded corpus with relationship and numeric boundaries."""
    limit = max_examples or config.generation.max_examples
    if limit < 1:
        raise ValueError("max_examples must be positive")

    cases_by_fingerprint: dict[str, AuthorizationCase] = {}
    coverage_budget = max(1, limit // 2)
    for case in _coverage_cases(config):
        cases_by_fingerprint.setdefault(case.fingerprint, case)
        if len(cases_by_fingerprint) >= coverage_budget:
            break

    remaining = limit - len(cases_by_fingerprint)
    if remaining:
        strategy = case_strategy(config)

        @hypothesis_seed(seed)
        @settings(
            max_examples=max(remaining * 3, remaining),
            database=None,
            deadline=None,
            phases=(Phase.generate,),
            suppress_health_check=(HealthCheck.filter_too_much,),
        )
        @given(strategy)
        def collect(case: AuthorizationCase) -> None:
            if len(cases_by_fingerprint) < limit:
                cases_by_fingerprint.setdefault(case.fingerprint, case)

        collect()

    return sorted(cases_by_fingerprint.values(), key=lambda case: case.fingerprint)[:limit]


def shrink_findings(findings: Iterable[Finding], *, seed: int) -> list[Finding]:
    """Use Hypothesis shrinking to select one minimal exact-corpus reproduction."""
    groups: dict[tuple[object, ...], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding_equivalence_key(finding), []).append(finding)

    minimized: list[Finding] = []
    for index, equivalents in enumerate(groups.values()):
        ordered = sorted(equivalents, key=finding_case_complexity)
        smallest = find(
            st.sampled_from(ordered),
            equivalents.__contains__,
            settings=settings(
                max_examples=max(10, len(ordered) * 2),
                database=None,
                deadline=None,
                phases=(Phase.generate, Phase.shrink),
            ),
            random=random.Random(seed + index),
        )
        minimized.append(replace(smallest, equivalent_cases=len(equivalents)))
    return sorted(minimized, key=lambda finding: finding.semantic_key)


def _coverage_cases(config: PermissionDiffConfig) -> Iterable[AuthorizationCase]:
    """Yield a lazy spine covering same/cross-tenant and owner relationships."""
    subjects = [subject.to_domain() for subject in config.subjects]
    resources = [resource.to_domain() for resource in config.resources]
    amounts: tuple[int | None, ...]
    if config.contexts.amounts is None:
        amounts = (None,)
    else:
        amounts = config.contexts.amounts.interesting_values()

    index = 0
    for action_name in config.actions:
        for subject in subjects:
            for resource in _relationship_resources(subject, resources):
                amount = amounts[index % len(amounts)]
                index += 1
                yield AuthorizationCase(
                    subject=subject,
                    action=Action(action_name),
                    resource=resource,
                    context=Context(amount=amount),
                )


def _relationship_resources(subject: Subject, resources: list[Resource]) -> list[Resource]:
    selected: list[Resource] = []
    predicates: tuple[Callable[[Resource], bool], ...] = (
        lambda resource: resource.owner_id == subject.id,
        lambda resource: resource.tenant == subject.tenant,
        lambda resource: (
            subject.tenant is not None
            and resource.tenant is not None
            and resource.tenant != subject.tenant
        ),
    )
    for predicate in predicates:
        match = next((resource for resource in resources if predicate(resource)), None)
        if match is not None and match not in selected:
            selected.append(match)
    if not selected:
        selected.append(resources[0])
    return selected
