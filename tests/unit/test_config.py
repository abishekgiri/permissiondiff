"""Configuration validation tests."""

from pathlib import Path

import pytest

from permissiondiff.config import PermissionDiffConfig, load_config
from permissiondiff.errors import ConfigurationError


def test_explicit_domain_config_validates() -> None:
    config = PermissionDiffConfig.model_validate(
        {
            "authorizer": "auth:authorize",
            "subjects": [{"id": "alice", "tenant": "acme", "role": "support"}],
            "resources": [{"id": "one", "type": "invoice", "tenant": "acme"}],
            "actions": ["read"],
        }
    )
    assert config.subjects[0].to_domain().id == "alice"
    assert config.generation.max_examples == 64


@pytest.mark.parametrize(
    "content",
    [
        "not-a-mapping",
        "authorizer: auth:authorize\nsubjects: []\nresources: []\nactions: []\n",
        (
            "authorizer: auth:authorize\n"
            "subjects: [{id: alice}, {id: alice}]\n"
            "resources: [{id: one, type: x}]\nactions: [read]\n"
        ),
    ],
)
def test_malformed_config_fails_clearly(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)
