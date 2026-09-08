"""SpiceDB / Authzed adapter example.

Maps a case to a SpiceDB permission check: subject -> permission (action) -> resource. Supply a
configured Authzed client; the SDK import is lazy. The exact request objects depend on your
``authzed`` client version -- adapt the body to your client while keeping the boolean result.

Real validation requires a running SpiceDB with your schema and relationships.
"""

from __future__ import annotations

from typing import Any

from permissiondiff.adapters import from_boolean
from permissiondiff.models import Action, Context, Resource, Subject

_PERMISSIONSHIP_HAS_PERMISSION = "PERMISSIONSHIP_HAS_PERMISSION"


def build_authorizer(client: Any) -> Any:
    """Return an authorizer backed by a SpiceDB CheckPermission call."""

    def _check(subject: Subject, action: Action, resource: Resource, context: Context) -> bool:
        response = client.CheckPermission(
            {
                "resource": {"object_type": resource.type, "object_id": resource.id},
                "permission": action.name,
                "subject": {"object": {"object_type": "user", "object_id": subject.id}},
            }
        )
        return getattr(response, "permissionship", None) == _PERMISSIONSHIP_HAS_PERMISSION

    return from_boolean(_check)
