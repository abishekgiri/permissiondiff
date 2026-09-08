"""Tests for git worktree orchestration used by ``diff --git-ref``."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from permissiondiff.errors import ConfigurationError
from permissiondiff.gitref import baseline_worktree, repo_root


def _init_repo(path: Path) -> None:
    for args in (
        ["init"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, text=True)
    (path / "seed.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True, text=True
    )


def test_repo_root_rejects_non_repository(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not inside a git repository"):
        repo_root(tmp_path)


def test_baseline_worktree_rejects_unknown_ref(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    with (
        pytest.raises(ConfigurationError, match="git ref not found"),
        baseline_worktree(tmp_path, "does-not-exist"),
    ):
        pass


def test_baseline_worktree_checks_out_and_cleans_up(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    with baseline_worktree(tmp_path, "HEAD") as tree:
        assert (tree / "seed.txt").read_text(encoding="utf-8") == "x"
        created = tree
    assert not created.exists()  # removed on exit
