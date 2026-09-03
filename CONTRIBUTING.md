# Contributing to PermissionDiff

Thank you for helping make authorization changes easier to review.

## Development setup

PermissionDiff requires Python 3.12 or newer and
[uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/abishekgiri/permissiondiff.git
cd permissiondiff
uv sync --all-groups
```

Before opening a pull request, run the same checks used by CI:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=permissiondiff --cov-report=term-missing
uv build
```

Keep changes focused, add tests for changed behavior, and update public documentation when an
interface changes. Commit generated lockfile changes when dependencies change.

## Architecture and security expectations

- Keep authorization verdicts deterministic and independent of LLM output.
- Keep the CLI as a thin orchestration layer; put reusable behavior in the existing application,
  engine, evaluator, generator, invariant, snapshot, and report modules.
- Treat crashes, timeouts, malformed decisions, and invalid inputs as explicit errors. Never
  introduce fail-open behavior.
- Remember that the evaluator subprocess provides fault isolation, not a hostile-code security
  boundary. Tests and examples must not access production systems, credentials, or side effects.
- Add unit or integration regression coverage for every behavior change, especially changes to
  case generation, invariant evaluation, snapshot compatibility, and exit codes.

## Pull requests and issues

Open an issue before starting a large change so scope and design can be discussed. Pull requests
should explain the user-visible effect, verification performed, and any compatibility concerns.
All contributions must be compatible with the Apache-2.0 license.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
