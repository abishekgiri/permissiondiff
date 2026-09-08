"""Parent-side orchestration for subprocess authorizer evaluation.

Two execution models share one worker program (``permissiondiff.worker``), which serves a
line-delimited (NDJSON) request/response protocol:

* ``process_per_case`` -- a fresh interpreter per case (maximum isolation).
* ``persistent`` -- one long-lived worker that imports the authorizer once and streams cases,
  re-spawned on any crash or timeout so a single bad case cannot corrupt later cases.

Both never fail open: a timeout, crash, invalid protocol response, or worker-reported error
becomes an explicit :class:`CaseEvaluation` error, never a guessed decision.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from permissiondiff.models import AuthorizationCase, CaseEvaluation, Decision

WorkerMode = Literal["persistent", "process_per_case"]


def _worker_command(authorizer_spec: str) -> list[str]:
    return [sys.executable, "-m", "permissiondiff.worker", authorizer_spec]


def _worker_env() -> dict[str, str]:
    environment = os.environ.copy()
    package_root = str(Path(__file__).resolve().parents[1])
    inherited_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        [package_root, inherited_path] if inherited_path else [package_root]
    )
    return environment


def _encode(case: AuthorizationCase) -> str:
    return json.dumps(case.to_dict(), sort_keys=True, separators=(",", ":"))


def _decode(case: AuthorizationCase, raw: str) -> CaseEvaluation:
    """Turn one worker response line into a CaseEvaluation, never failing open."""
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return CaseEvaluation(case=case, error="authorizer worker returned invalid JSON")
    if not isinstance(result, dict):
        return CaseEvaluation(case=case, error="authorizer worker returned a non-object result")
    if isinstance(result.get("error"), str):
        return CaseEvaluation(case=case, error=result["error"])
    try:
        decision = Decision(result["decision"])
    except (KeyError, TypeError, ValueError):
        return CaseEvaluation(case=case, error="authorizer worker returned an invalid decision")
    return CaseEvaluation(case=case, decision=decision)


def evaluate_case(
    case: AuthorizationCase,
    authorizer_spec: str,
    *,
    workdir: Path,
    timeout_seconds: float,
) -> CaseEvaluation:
    """Evaluate a case in a fresh worker process with a hard timeout."""
    try:
        completed = subprocess.run(
            _worker_command(authorizer_spec),
            input=_encode(case),
            text=True,
            capture_output=True,
            cwd=workdir,
            env=_worker_env(),
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CaseEvaluation(
            case=case,
            error=f"authorizer timed out after {timeout_seconds:g} seconds",
        )
    except OSError as exc:
        return CaseEvaluation(case=case, error=f"could not start authorizer worker: {exc}")

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no worker output"
        return CaseEvaluation(
            case=case,
            error=f"authorizer worker exited with code {completed.returncode}: {detail}",
        )
    return _decode(case, completed.stdout)


class _PersistentWorker:
    """A long-lived worker that evaluates cases one at a time and re-spawns on failure."""

    def __init__(self, authorizer_spec: str, *, workdir: Path) -> None:
        self._spec = authorizer_spec
        self._workdir = workdir
        self._env = _worker_env()
        self._proc: subprocess.Popen[str] | None = None
        self._stderr_tail: deque[str] = deque(maxlen=50)
        self._stderr_thread: threading.Thread | None = None

    def _spawn(self) -> None:
        self._stderr_tail = deque(maxlen=50)
        self._proc = subprocess.Popen(
            _worker_command(self._spec),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self._workdir,
            env=self._env,
            bufsize=1,  # line-buffered
        )
        stderr = self._proc.stderr
        if stderr is not None:
            thread = threading.Thread(target=self._drain_stderr, args=(stderr,), daemon=True)
            thread.start()
            self._stderr_thread = thread

    def _drain_stderr(self, stream: object) -> None:
        # Continuously drain stderr so a noisy authorizer cannot deadlock on a full pipe.
        try:
            for line in stream:  # type: ignore[attr-defined]
                self._stderr_tail.append(line)
        except (ValueError, OSError):
            pass

    def _detail(self) -> str:
        return "".join(self._stderr_tail).strip() or "no worker output"

    def _kill(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def evaluate(self, case: AuthorizationCase, timeout_seconds: float) -> CaseEvaluation:
        if self._proc is None or self._proc.poll() is not None:
            try:
                self._spawn()
            except OSError as exc:
                return CaseEvaluation(case=case, error=f"could not start authorizer worker: {exc}")

        proc = self._proc
        assert proc is not None and proc.stdin is not None and proc.stdout is not None

        try:
            proc.stdin.write(_encode(case) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            detail = self._detail()
            self._kill()
            return CaseEvaluation(case=case, error=f"authorizer worker exited: {detail}")

        line, timed_out = self._read_line(proc.stdout, timeout_seconds)
        if timed_out:
            self._kill()  # next case gets a fresh worker
            return CaseEvaluation(
                case=case, error=f"authorizer timed out after {timeout_seconds:g} seconds"
            )
        if line == "":  # worker died mid-case
            detail = self._detail()
            self._kill()
            return CaseEvaluation(case=case, error=f"authorizer worker exited: {detail}")
        return _decode(case, line)

    @staticmethod
    def _read_line(stream: object, timeout_seconds: float) -> tuple[str, bool]:
        holder: list[str] = []

        def _reader() -> None:
            try:
                holder.append(stream.readline())  # type: ignore[attr-defined]
            except (ValueError, OSError):
                holder.append("")

        thread = threading.Thread(target=_reader, daemon=True)
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive():
            return "", True
        return (holder[0] if holder else ""), False

    def close(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()  # EOF -> worker loop exits
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self._kill()
        finally:
            self._proc = None


def evaluate_cases(
    cases: Sequence[AuthorizationCase],
    authorizer_spec: str,
    *,
    workdir: Path,
    timeout_seconds: float,
    mode: WorkerMode = "persistent",
) -> list[CaseEvaluation]:
    """Evaluate cases so a crash or timeout in one cannot corrupt the parent or later cases."""
    if mode == "process_per_case":
        return [
            evaluate_case(case, authorizer_spec, workdir=workdir, timeout_seconds=timeout_seconds)
            for case in cases
        ]
    worker = _PersistentWorker(authorizer_spec, workdir=workdir)
    try:
        return [worker.evaluate(case, timeout_seconds) for case in cases]
    finally:
        worker.close()
