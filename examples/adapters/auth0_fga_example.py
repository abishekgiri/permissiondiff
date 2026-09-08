"""Auth0 FGA adapter example.

Auth0 FGA shares OpenFGA's relationship-check model, so the mapping is identical: wrap the FGA
client's check() as a boolean. Supply a configured client; the SDK import is lazy.

Real validation requires a running Auth0 FGA store with your model.
"""

from __future__ import annotations

from typing import Any

from permissiondiff.adapters import from_boolean
from permissiondiff.models import Action, Context, Resource, Subject


def build_authorizer(client: Any, *, store_id: str) -> Any:
    """Return an authorizer backed by an Auth0 FGA client's check() call."""

    def _check(subject: Subject, action: Action, resource: Resource, context: Context) -> bool:
        response = client.check(
            store_id=store_id,
            body={
                "tuple_key": {
                    "user": f"user:{subject.id}",
                    "relation": action.name,
                    "object": f"{resource.type}:{resource.id}",
                }
            },
        )
        return bool(getattr(response, "allowed", False))

    return from_boolean(_check)
