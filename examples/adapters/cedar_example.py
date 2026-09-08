"""Cedar / AWS Verified Permissions adapter example.

Cedar returns an explicit decision, so this uses ``from_decision``. Provide an ``is_authorized``
callable from your Cedar binding (or an AWS Verified Permissions client wrapper) that returns
whether the request is permitted. The mapping below builds Cedar-style principal/action/resource
identifiers from the case.

Real validation requires your Cedar policy set and entities.
"""

from __future__ import annotations

from typing import Any

from permissiondiff.adapters import from_decision
from permissiondiff.models import Action, Context, Resource, Subject


def build_authorizer(is_authorized: Any) -> Any:
    """Return an authorizer backed by a Cedar ``is_authorized(principal, action, resource)`` call.

    ``is_authorized`` should return True/False (or a Decision). Anything else raises, surfacing as
    an explicit evaluation error rather than a silent wrong verdict.
    """

    def _decide(subject: Subject, action: Action, resource: Resource, context: Context) -> bool:
        return bool(
            is_authorized(
                principal=f'User::"{subject.id}"',
                action=f'Action::"{action.name}"',
                resource=f'{resource.type.capitalize()}::"{resource.id}"',
                context=context.attributes,
            )
        )

    return from_decision(_decide)
