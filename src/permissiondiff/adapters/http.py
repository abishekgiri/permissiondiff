"""Generic HTTP-JSON policy adapter (e.g. Open Policy Agent's data API), standard library only.

This is user-side glue that the core engine never imports. It POSTs a JSON request built from the
case to a policy endpoint and turns the JSON response into a ``Decision``. Point it at a
non-production policy server; it performs a read-only decision query.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any

from permissiondiff.models import (
    Action,
    AuthorizationFunction,
    Context,
    Decision,
    Resource,
    Subject,
)

RequestBuilder = Callable[[Subject, Action, Resource, Context], dict[str, Any]]
AllowedParser = Callable[[Any], bool]


def http_authorizer(
    endpoint: str,
    *,
    build_request: RequestBuilder,
    parse_allowed: AllowedParser,
    timeout: float = 5.0,
) -> AuthorizationFunction:
    """Build an authorizer that queries an HTTP-JSON policy endpoint.

    ``build_request`` maps a case to the JSON body to POST; ``parse_allowed`` maps the decoded
    JSON response to a boolean allow/deny. Network or parse failures propagate, so PermissionDiff
    records them as explicit evaluation errors rather than guessing a verdict.
    """

    def _authorize(
        subject: Subject, action: Action, resource: Resource, context: Context
    ) -> Decision:
        body = json.dumps(build_request(subject, action, resource, context)).encode("utf-8")
        # The endpoint is operator-supplied configuration, not attacker-controlled case data.
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return Decision.ALLOW if parse_allowed(payload) else Decision.DENY

    return _authorize
