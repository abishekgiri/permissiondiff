"""OpenFGA adapter example.

Maps a case to an OpenFGA relationship check: ``user`` = subject, ``relation`` = action,
``object`` = ``<type>:<id>``. Install the vendor SDK (``openfga-sdk``) and supply a configured
client; the import is lazy so PermissionDiff does not depend on it.

Real validation requires a running OpenFGA store with your authorization model.
"""

from __future__ import annotations

from typing import Any

from permissiondiff.adapters import from_boolean
from permissiondiff.models import Action, Context, Resource, Subject


def build_authorizer(client: Any, *, store_id: str) -> Any:
    """Return an authorizer backed by an OpenFGA client's check() call."""

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
