# PermissionDiff

> **Prove your code didn't just hand the wrong person the keys.**

[![CI](https://github.com/abishekgiri/permissiondiff/actions/workflows/ci.yml/badge.svg)](https://github.com/abishekgiri/permissiondiff/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/permissiondiff)](https://pypi.org/project/permissiondiff/)
![Python](https://img.shields.io/badge/python-3.12%E2%80%933.14-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
[![Ruff](https://img.shields.io/badge/lint-ruff-000000)](https://github.com/astral-sh/ruff)
![Typed](https://img.shields.io/badge/typed-mypy%20strict-blue)

**PermissionDiff is a CI-native tool that shows exactly how a code change alters effective authorization.** It answers: “Did this pull request accidentally give a user, tenant, role, or service access it did not have before?”

PermissionDiff generates meaningful authorization cases from subjects, resources, actions, and context values you declare. It checks explicit invariants and records baseline cases so a candidate authorizer evaluates the **same exact corpus**. Security verdicts are deterministic Python decisions—never LLM judgments.

```text
CRITICAL — Cross-tenant access must be denied
support(acme) → read_invoice → invoice(globex)
actual: ALLOW
repro: .permissiondiff/failures/PD-0001.json
```

PermissionDiff is at **v0/alpha** maturity. The core workflow is tested and usable, but public
interfaces may evolve before 1.0. It supports Python 3.12, 3.13, and 3.14 and is licensed under
[Apache-2.0](https://github.com/abishekgiri/permissiondiff/blob/main/LICENSE).

## Install

Add the [published package](https://pypi.org/project/permissiondiff/) to an existing uv project:

```bash
uv add permissiondiff
uv run permissiondiff --help
```

For a standalone CLI, install it with uv:

```bash
uv tool install permissiondiff
```

Or install it in an active virtual environment with pip:

```bash
python -m pip install permissiondiff
```

## Five-minute quickstart

After standalone CLI installation (or use `uv run permissiondiff` inside a uv project):

```bash
permissiondiff init demo
cd demo
permissiondiff test
```

`init` creates a runnable config and a deliberately vulnerable authorizer. The test reports a minimized cross-tenant reproduction under `.permissiondiff/failures/` and exits `1` because the tenant-isolation invariant fails.

## Authorizer interface

Point PermissionDiff at one ordinary decision function:

```python
from permissiondiff import Action, Context, Decision, Resource, Subject


def authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: Context,
) -> Decision:
    if subject.tenant != resource.tenant:
        return Decision.DENY
    if action.name == "read_invoice" and subject.role in {"support", "admin"}:
        return Decision.ALLOW
    return Decision.DENY
```

The result must be exactly `Decision.ALLOW` or `Decision.DENY`. Crashes, hangs, and invalid return values are explicit evaluation errors and exit `3`; PermissionDiff never fails open.

## Configuration

The YAML describes real entities rather than asking a fuzzer to invent arbitrary application objects:

```yaml
authorizer: auth:authorize

subjects:
  - {id: alice, tenant: acme, role: support}
  - {id: bob, tenant: globex, role: support}

resources:
  - {id: invoice-acme, type: invoice, tenant: acme, owner_id: alice}
  - {id: invoice-globex, type: invoice, tenant: globex, owner_id: bob}

actions: [read_invoice, refund]
contexts:
  amounts: {min: 0, max: 1000, boundaries: [499, 500, 501]}

invariants:
  - tenant_isolation
  - role_boundary: {action: refund, allowed_roles: [admin]}
  - ownership: {actions: [read_invoice]}

fail_on:
  invariant_violation: true
  newly_allowed: true
  newly_denied: false

generation: {max_examples: 64}
execution: {timeout_seconds: 2}
```

Hypothesis combines declared entities and explores numeric boundaries. With the same PermissionDiff and Python versions, configuration, seed, exact corpus, and deterministic authorizer, findings are semantically reproducible. Canonical JSON, stable case fingerprints, stable finding ordering, and fixed IDs make review practical. A nondeterministic authorizer remains nondeterministic; PermissionDiff does not conceal that.

## Test and invariant workflow

```bash
uv run permissiondiff test --config permissiondiff.yaml --seed 42
uv run permissiondiff explain PD-0001
```

Built-in invariants cover tenant isolation, action-specific role boundaries, and ownership. A custom deterministic invariant can be declared as:

```yaml
invariants:
  - custom: {name: refund_limit, callable: invariants:refund_limit}
```

The callable receives `(AuthorizationCase, Decision)` and returns `bool` or `InvariantResult`.

## Baseline and diff workflow

Create a baseline on trusted code:

```bash
uv run permissiondiff snapshot --config permissiondiff.yaml \
  --output .permissiondiff/main.json --seed 42
```

The snapshot stores every exact input case, its baseline decision, a stable fingerprint, the corpus seed, and schema/package versions. On candidate code, replay it:

```bash
uv run permissiondiff diff --config permissiondiff.yaml \
  --baseline .permissiondiff/main.json
```

Classification is exhaustive:

| Baseline | Candidate | Result |
|---|---|---|
| DENY | DENY | `unchanged_denied` |
| ALLOW | ALLOW | `unchanged_allowed` |
| DENY | ALLOW | `newly_allowed` |
| ALLOW | DENY | `newly_denied` |

A newly allowed path is security-sensitive, not automatically a vulnerability. `fail_on` decides what blocks CI. Invariants can still catch a vulnerability already present in the baseline.

The complete machine report is `.permissiondiff/report.json` by default.

## CI

```yaml
name: permissiondiff
on: [pull_request]
jobs:
  authorization:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uv sync --all-groups
      - run: uv run permissiondiff diff --baseline .permissiondiff/main.json
```

Exit codes are stable: `0` pass, `1` configured policy/invariant failure, `2` configuration or snapshot error, `3` evaluation/runtime error.

The repository's thin composite action invokes the same CLI without duplicating its logic:

```yaml
- uses: abishekgiri/permissiondiff@v0
  with:
    config: permissiondiff.yaml
    baseline: .permissiondiff/main.json
```

Check out the calling repository before this step and make sure the baseline is present in CI.
Use `@v0.1.0` to pin this release; `@v0` follows compatible v0 releases. The
[published-consumer smoke test](https://github.com/abishekgiri/permissiondiff/blob/main/.github/workflows/published-smoke.yml)
exercises the PyPI package and the remote action in a fresh workspace without a source checkout.

## Security and limitations

**Only point PermissionDiff at decision logic with no live side effects. Never use an authorizer that issues refunds, deletes data, sends messages, or contacts production.**

Authorizers run in a timeout-controlled subprocess to isolate crashes and hangs from the main CLI. **This subprocess is not a security sandbox.** Imported Python code has the operating-system permissions of the user running PermissionDiff and may be malicious. Use trusted code and isolated CI environments.

Snapshots and reproductions may contain sensitive identifiers. Treat them accordingly. v0 supports local Python authorizers and explicit domains; it does not include Git worktree orchestration, remote policy engines, live agent/tool interception, a dashboard, or least-privilege mining.

Report vulnerabilities privately as described in the
[security policy](https://github.com/abishekgiri/permissiondiff/security/policy). For bugs and
feature requests, use [GitHub Issues](https://github.com/abishekgiri/permissiondiff/issues).

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest
uv run pytest --cov=permissiondiff --cov-report=term-missing
uv build
```

The roadmap is deliberately short: prove authorization diffs are useful, then consider policy-engine adapters, Git-aware orchestration, agent principals/delegation, safe shadow interception, and least-privilege reduction with proof.

See the [contribution guide](https://github.com/abishekgiri/permissiondiff/blob/main/CONTRIBUTING.md)
for the contribution workflow and the
[changelog](https://github.com/abishekgiri/permissiondiff/blob/main/CHANGELOG.md) for release
history.
