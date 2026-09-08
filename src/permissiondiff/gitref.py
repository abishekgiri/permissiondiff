"""Git worktree orchestration for baseline-vs-candidate diffing against a git ref.

This is an I/O boundary module (it shells out to ``git``); the core engine never imports it.
It lets ``diff --git-ref REF`` evaluate the baseline authorizer *as it existed at REF* by checking
that ref out into a temporary, detached worktree, without disturbing the working tree.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from permissiondiff.errors import ConfigurationError


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _require_git() -> None:
    if shutil.which("git") is None:
        raise ConfigurationError("git is not installed; --git-ref requires git on PATH")


def repo_root(start: Path) -> Path:
    """Return the top level of the git repository containing ``start``."""
    _require_git()
    result = _git("rev-parse", "--show-toplevel", cwd=start)
    if result.returncode != 0:
        raise ConfigurationError(f"{start} is not inside a git repository")
    return Path(result.stdout.strip())


def _resolve_ref(root: Path, ref: str) -> str:
    result = _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", cwd=root)
    if result.returncode != 0 or not result.stdout.strip():
        raise ConfigurationError(f"git ref not found: {ref!r}")
    return result.stdout.strip()


@contextmanager
def baseline_worktree(start: Path, ref: str) -> Iterator[Path]:
    """Yield a temporary detached worktree checked out at ``ref``.

    The worktree is always removed afterwards, even on error. ``start`` is any path inside the
    repository (typically the config directory); the yielded path is the worktree root.
    """
    root = repo_root(start)
    commit = _resolve_ref(root, ref)
    tmp = Path(tempfile.mkdtemp(prefix="permissiondiff-worktree-"))
    added = _git("worktree", "add", "--detach", "--force", str(tmp), commit, cwd=root)
    if added.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        detail = added.stderr.strip() or added.stdout.strip() or "unknown error"
        raise ConfigurationError(f"could not create git worktree for {ref!r}: {detail}")
    try:
        yield tmp
    finally:
        _git("worktree", "remove", "--force", str(tmp), cwd=root)
        shutil.rmtree(tmp, ignore_errors=True)
