"""Shared test helpers for temporary authorizers and configuration."""

from __future__ import annotations

from pathlib import Path

import yaml


def write_authorizer(directory: Path, body: str, module: str = "auth") -> str:
    """Write an importable temporary authorizer module and return its spec."""
    (directory / f"{module}.py").write_text(body, encoding="utf-8")
    return f"{module}:authorize"


def write_config(
    directory: Path,
    authorizer: str,
    *,
    invariants: list[object] | None = None,
    timeout: float = 1.0,
) -> Path:
    """Write a small explicit-domain config for integration tests."""
    payload = {
        "authorizer": authorizer,
        "subjects": [
            {"id": "alice", "tenant": "acme", "role": "support"},
            {"id": "bob", "tenant": "globex", "role": "support"},
        ],
        "resources": [
            {
                "id": "invoice-acme",
                "type": "invoice",
                "tenant": "acme",
                "owner_id": "alice",
            },
            {
                "id": "invoice-globex",
                "type": "invoice",
                "tenant": "globex",
                "owner_id": "bob",
            },
        ],
        "actions": ["read_invoice"],
        "contexts": {"amounts": {"min": 0, "max": 1000, "boundaries": [499, 500, 501]}},
        "invariants": invariants if invariants is not None else ["tenant_isolation"],
        "generation": {"max_examples": 8},
        "execution": {"timeout_seconds": timeout},
    }
    path = directory / "permissiondiff.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path
