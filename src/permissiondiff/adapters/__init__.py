"""User-side toolkit for building a PermissionDiff authorizer from an external policy system.

Adapters live **outside** the core engine (the core never imports this package). An adapter turns
an external authorization decision -- a boolean check from a policy-engine SDK (OpenFGA, SpiceDB,
Cedar, Auth0 FGA, ...) or a JSON response from an HTTP policy endpoint (OPA, ...) -- into the
``authorize(subject, action, resource, context) -> Decision`` callable that PermissionDiff
evaluates.

Adapters make **read-only decision calls only**. As with any authorizer, point them at a
non-production / test policy instance -- never at production data or anything with side effects.

Most SDK-based engines reduce to a boolean check, so :func:`from_boolean` is usually all you need;
:func:`from_decision` covers engines that already return an allow/deny verdict object. See
``examples/adapters/`` for concrete per-engine wrappers.
"""

from __future__ import annotations

from collections.abc import Callable

from permissiondiff.adapters.http import http_authorizer
from permissiondiff.models import (
    Action,
    AuthorizationFunction,
    Context,
    Decision,
    Resource,
    Subject,
)

BooleanCheck = Callable[[Subject, Action, Resource, Context], bool]

__all__ = ["BooleanCheck", "from_boolean", "from_decision", "http_authorizer"]


def from_boolean(check: BooleanCheck) -> AuthorizationFunction:
    """Wrap a boolean allow/deny check (the shape of most SDK calls) as an authorizer."""

    def _authorize(
        subject: Subject, action: Action, resource: Resource, context: Context
    ) -> Decision:
        return Decision.ALLOW if check(subject, action, resource, context) else Decision.DENY

    return _authorize


def from_decision(
    check: Callable[[Subject, Action, Resource, Context], bool | Decision],
) -> AuthorizationFunction:
    """Wrap a check that returns a bool or an actual ``Decision``.

    Anything that is not a ``Decision`` or a ``bool`` raises ``TypeError`` so a misconfigured
    adapter surfaces as an explicit evaluation error rather than a silent wrong verdict.
    """

    def _authorize(
        subject: Subject, action: Action, resource: Resource, context: Context
    ) -> Decision:
        result = check(subject, action, resource, context)
        if isinstance(result, Decision):
            return result
        if isinstance(result, bool):
            return Decision.ALLOW if result else Decision.DENY
        raise TypeError(
            f"adapter check returned {type(result).__name__}, expected bool or Decision"
        )

    return _authorize
