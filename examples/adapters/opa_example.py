"""Open Policy Agent adapter example.

Maps each case to OPA's Data API input document and reads a boolean ``result`` back. Set the
endpoint to your OPA server's decision path, e.g.
``http://localhost:8181/v1/data/permissiondiff/allow``.

This module is a runnable pattern; the test suite exercises the same wiring against a local server.
"""

from __future__ import annotations

import os
from typing import Any

from permissiondiff.adapters import http_authorizer
from permissiondiff.models import Action, Context, Resource, Subject

OPA_ENDPOINT = os.environ.get("OPA_ENDPOINT", "http://localhost:8181/v1/data/permissiondiff/allow")


def _build_request(
    subject: Subject, action: Action, resource: Resource, context: Context
) -> dict[str, Any]:
    return {
        "input": {
            "subject": subject.to_dict(),
            "action": action.name,
            "resource": resource.to_dict(),
            "context": context.to_dict(),
        }
    }


def _parse_allowed(payload: Any) -> bool:
    # OPA returns {"result": <policy output>}; treat a truthy boolean result as ALLOW.
    return bool(isinstance(payload, dict) and payload.get("result") is True)


authorize = http_authorizer(
    OPA_ENDPOINT, build_request=_build_request, parse_allowed=_parse_allowed
)
