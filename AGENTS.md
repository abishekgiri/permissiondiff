# PermissionDiff agent map

PermissionDiff owns deterministic authorization diffs: generate meaningful cases, evaluate explicit `ALLOW`/`DENY` decisions, enforce invariants, snapshot exact cases, and replay those cases against candidates.

Non-negotiable: never use AI for verdicts; never fail open; keep core logic pure and independent of CLI/presentation; run user authorizers in the worker subprocess with explicit timeout/error results; version serialized formats; keep findings reproducible and minimal; do not build roadmap features.

Required verification:

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest
uv run pytest --cov=permissiondiff --cov-report=term-missing
uv build
uv run permissiondiff --help
uv run python -m permissiondiff --help
```
