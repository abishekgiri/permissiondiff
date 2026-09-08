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


def _write_result(protocol_fd: int, result: dict[str, str]) -> None:
    """Write exactly one canonical JSON result line to the private protocol channel."""
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    os.write(protocol_fd, payload.encode("utf-8"))


def _result_for_line(authorizer_spec: str, line: str) -> dict[str, str]:
    """Parse one request line and evaluate it, never raising."""
    try:
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("worker input must be an object")
        return evaluate_payload(authorizer_spec, payload)
    except BaseException as exc:
        return {"error": f"worker input error: {type(exc).__name__}: {exc}"}


def main() -> int:
    """Serve authorization decisions over a line-delimited (NDJSON) request/response protocol.

    The authorizer is imported once, then each newline-terminated JSON case read from stdin
    produces exactly one JSON result line, until stdin closes. A single case followed by EOF is
    the degenerate one-shot form, so the process-per-case caller works unchanged.

    Results travel on a *private* channel: fd 1 is duplicated to a fresh descriptor before any
    user code runs, and fd 1 itself is then pointed at stderr for the **entire** remaining
    process lifetime and never restored. Everything the authorizer or its module writes to fd 1
    -- ``print``, raw ``os.write(1, ...)``, C extensions, import-time output, and
    ``atexit``/interpreter-shutdown output -- therefore lands on stderr and can never corrupt
    the protocol. (Uses ``os.dup``/``os.dup2``; portable to POSIX and Windows.)
    """
    if len(sys.argv) != 2:
        # No user code has run yet; fd 1 is still the real stdout.
        os.write(1, (json.dumps({"error": "worker requires one authorizer spec"}) + "\n").encode())
        return 2

    authorizer_spec = sys.argv[1]
    protocol_fd = os.dup(1)  # private copy of the original stdout for results only
    os.dup2(2, 1)  # fd 1 -> stderr for the rest of the process; never restored
    try:
        while True:
            line = sys.stdin.readline()
            if line == "":  # EOF: the parent closed the request stream
                break
            if line.strip() == "":  # ignore blank keep-alive lines
                continue
            _write_result(protocol_fd, _result_for_line(authorizer_spec, line))
    finally:
        os.close(protocol_fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
