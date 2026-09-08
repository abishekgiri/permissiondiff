"""Tests for the policy-engine adapter toolkit and example adapters."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from permissiondiff.adapters import from_boolean, from_decision, http_authorizer
from permissiondiff.models import (
    Action,
    AuthorizationCase,
    AuthorizationFunction,
    Context,
    Decision,
    Resource,
    Subject,
)

CASE = AuthorizationCase(
    Subject("alice", "acme", "support"),
    Action("read_invoice"),
    Resource("inv", "invoice", "acme", "alice"),
    Context(),
)


def _call(authorizer: AuthorizationFunction) -> Decision:
    return authorizer(CASE.subject, CASE.action, CASE.resource, CASE.context)


def test_from_boolean_maps_true_and_false() -> None:
    assert _call(from_boolean(lambda s, a, r, c: True)) is Decision.ALLOW
    assert _call(from_boolean(lambda s, a, r, c: False)) is Decision.DENY


def test_from_decision_accepts_bool_and_decision() -> None:
    assert _call(from_decision(lambda s, a, r, c: True)) is Decision.ALLOW
    assert _call(from_decision(lambda s, a, r, c: Decision.DENY)) is Decision.DENY


def test_from_decision_rejects_other_types() -> None:
    with pytest.raises(TypeError, match="expected bool or Decision"):
        _call(from_decision(lambda s, a, r, c: "ALLOW"))  # type: ignore[arg-type,return-value]


@pytest.fixture
def allow_server(request: pytest.FixtureRequest) -> Iterator[str]:
    """A tiny HTTP policy server that returns {"result": <allowed>} based on a flag."""
    allowed: bool = request.param

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"result": allowed}).encode("utf-8"))

        def log_message(self, *args: object) -> None:  # silence test output
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = str(server.server_address[0])
        port = int(server.server_address[1])
        yield f"http://{host}:{port}/v1/data/permissiondiff/allow"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize("allow_server", [True], indirect=True)
def test_http_authorizer_allow(allow_server: str) -> None:
    authorizer = http_authorizer(
        allow_server,
        build_request=lambda s, a, r, c: {"input": {"action": a.name}},
        parse_allowed=lambda payload: payload.get("result") is True,
    )
    assert _call(authorizer) is Decision.ALLOW


@pytest.mark.parametrize("allow_server", [False], indirect=True)
def test_http_authorizer_deny(allow_server: str) -> None:
    authorizer = http_authorizer(
        allow_server,
        build_request=lambda s, a, r, c: {"input": {"action": a.name}},
        parse_allowed=lambda payload: payload.get("result") is True,
    )
    assert _call(authorizer) is Decision.DENY


@pytest.mark.parametrize("allow_server", [True], indirect=True)
def test_opa_example_end_to_end(allow_server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPA_ENDPOINT", allow_server)
    import importlib

    from examples.adapters import opa_example

    importlib.reload(opa_example)  # rebuild `authorize` against the patched endpoint
    assert _call(opa_example.authorize) is Decision.ALLOW


class _FakeCheck:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed


def test_openfga_example_maps_check(monkeypatch: pytest.MonkeyPatch) -> None:
    from examples.adapters import openfga_example

    class _Client:
        def check(self, *, store_id: str, body: dict[str, Any]) -> _FakeCheck:
            assert body["tuple_key"]["user"] == "user:alice"
            assert body["tuple_key"]["relation"] == "read_invoice"
            return _FakeCheck(True)

    authorizer = openfga_example.build_authorizer(_Client(), store_id="s1")
    assert _call(authorizer) is Decision.ALLOW


def test_cedar_example_maps_decision() -> None:
    from examples.adapters import cedar_example

    def _is_authorized(**kwargs: Any) -> bool:
        assert kwargs["principal"] == 'User::"alice"'
        return False

    authorizer = cedar_example.build_authorizer(_is_authorized)
    assert _call(authorizer) is Decision.DENY


def test_spicedb_example_maps_permissionship() -> None:
    from examples.adapters import spicedb_example

    class _Resp:
        permissionship = "PERMISSIONSHIP_HAS_PERMISSION"

    class _Client:
        def CheckPermission(self, body: dict[str, Any]) -> _Resp:
            assert body["permission"] == "read_invoice"
            return _Resp()

    authorizer = spicedb_example.build_authorizer(_Client())
    assert _call(authorizer) is Decision.ALLOW
