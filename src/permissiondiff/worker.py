"""One-case subprocess worker for fault-isolated authorizer evaluation."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from permissiondiff.loader import load_callable
from permissiondiff.models import AuthorizationCase, Decision


def evaluate_payload(authorizer_spec: str, payload: dict[str, Any]) -> dict[str, str]:
    """Evaluate one serialized case and return a serialized result."""
    try:
        authorizer = load_callable(authorizer_spec)
        case = AuthorizationCase.from_dict(payload)
        result = authorizer(case.subject, case.action, case.resource, case.context)
        if not isinstance(result, Decision):
            return {
                "error": (
                    "authorizer returned an invalid value; expected "
                    f"Decision.ALLOW or Decision.DENY, got {result!r}"
                )
            }
        return {"decision": result.value}
    except BaseException as exc:  # worker must report SystemExit and user exceptions
        return {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    """Read one case from stdin and write exactly one JSON result to stdout.

    The authorizer and its import may write to file descriptor 1 -- through
    ``print``, C extensions, or shelled-out subprocesses. Any such output would
    corrupt the JSON result channel the parent parses. To contain it, fd 1 is
    duplicated aside and then redirected onto stderr for the whole evaluation;
    the result is written to the saved original stdout afterwards.
    """
    if len(sys.argv) != 2:
        print(json.dumps({"error": "worker requires one authorizer spec"}))
        return 2

    saved_stdout_fd = os.dup(1)
    try:
        os.dup2(2, 1)  # redirect fd 1 onto stderr so user output cannot leak here
        try:
            payload = json.loads(sys.stdin.read())
            if not isinstance(payload, dict):
                raise ValueError("worker input must be an object")
            result = evaluate_payload(sys.argv[1], payload)
        except BaseException as exc:
            result = {"error": f"worker input error: {type(exc).__name__}: {exc}"}
        sys.stdout.flush()  # flush any buffered user output onto the redirected fd
    finally:
        os.dup2(saved_stdout_fd, 1)  # restore the real stdout
        os.close(saved_stdout_fd)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
