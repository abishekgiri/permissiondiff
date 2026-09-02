# PermissionDiff

**PermissionDiff is a CI-native tool that shows exactly how a code change alters effective authorization.** It answers: “Did this pull request accidentally give a user, tenant, role, or service access it did not have before?”

PermissionDiff generates meaningful authorization cases from subjects, resources, actions, and context values you declare. It checks explicit invariants and records baseline cases so a candidate authorizer evaluates the **same exact corpus**. Security verdicts are deterministic Python decisions—never LLM judgments.

## Five-minute quickstart

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-groups
uv run permissiondiff init demo
cd demo
uv run permissiondiff test
```

`init` creates a runnable config and a deliberately vulnerable authorizer. The test reports a minimized cross-tenant reproduction under `.permissiondiff/failures/` and exits `1` because the tenant-isolation invariant fails.

Install into another uv project with:

```bash
uv add permissiondiff
```

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

Example failure:

```text
CRITICAL — Cross-tenant access must be denied
support(acme) → read_invoice → invoice(globex)
actual: ALLOW
repro: .permissiondiff/failures/PD-0001.json
```

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

Once published, the repository's thin composite action can invoke the same CLI without duplicating its logic:

```yaml
- uses: permissiondiff/permissiondiff@v0
  with:
    config: permissiondiff.yaml
    baseline: .permissiondiff/main.json
```

## Security and limitations

**Only point PermissionDiff at decision logic with no live side effects. Never use an authorizer that issues refunds, deletes data, sends messages, or contacts production.**

Authorizers run in a timeout-controlled subprocess to isolate crashes and hangs from the main CLI. **This subprocess is not a security sandbox.** Imported Python code has the operating-system permissions of the user running PermissionDiff and may be malicious. Use trusted code and isolated CI environments.

Snapshots and reproductions may contain sensitive identifiers. Treat them accordingly. v0 supports local Python authorizers and explicit domains; it does not include Git worktree orchestration, remote policy engines, live agent/tool interception, a dashboard, or least-privilege mining.

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
