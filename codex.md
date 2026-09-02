# CLAUDE.md — PermissionDiff

Read this fully before writing code. It explains **what** we're building, **why**, **how the code is organized**, and **the rules that must never be broken**. It's written to be understood by a newer developer and by AI assistants alike — the Glossary at the end defines every term.

---

## 1. What PermissionDiff is

**PermissionDiff is a CI-native authorization regression testing tool.** In one sentence, it answers the question a developer should ask about every pull request but almost never can:

> **"Did this change accidentally give any user, tenant, role, or (later) agent access they didn't have before?"**

**The pitch:** *"Prove your code didn't just hand the wrong person the keys."*

### The problem
Apps make authorization decisions constantly — *can this user refund this order? read this invoice? delete this account?* Teams test the happy path ("can Alice refund Alice's own customer? ✅") but almost nobody systematically tests the **thousands of wrong-user / wrong-tenant / wrong-role / over-limit variations.** Those untested paths are where real breaches come from (Customer A reaching Customer B's data). A one-line code change can silently open one of them, and no existing test catches it.

### The core insight (internalize this — it's the whole product)
We don't ask the developer to hand-write the correct answer for thousands of authorization combinations. That's the hard, boring part nobody does. Instead we use **two deterministic pillars**:

1. **Differential testing (the primary mode).** Generate a large state space of authorization cases, evaluate each one against the **baseline** (e.g. `main`) *and* the **candidate** (e.g. the PR), and report what **changed**:
   - `DENY → ALLOW` = **newly allowed** (security-sensitive — surface it loudly)
   - `ALLOW → DENY` = **newly denied** (usually a bug of the safe kind, still worth showing)
   - unchanged = ignore
   The current trusted branch *is* the specification. No giant expected-results file required.

2. **Invariants (the safety net).** Differential testing alone can't catch a vulnerability that *already exists* on `main` (it didn't "change"). So we also let the developer declare explicit properties that must hold no matter what — e.g. *"different tenant → always DENY."* Any case that violates one is a finding, baseline or not.

Together these answer both "what did this PR change?" and "does the system violate a security rule right now?"

### The one property that defines us
> **A security verdict is always deterministic.** Given the same PermissionDiff and Python versions, configuration, seed, exact case corpus, and deterministic authorizer, PermissionDiff produces semantically identical findings. Canonical serialized output is stable where practical; PermissionDiff does not hide nondeterminism in user code.

AI may *later* suggest test scenarios, explain a failure in English, or propose invariants — but **AI must never decide whether access is allowed or denied.** That decision comes only from the developer's authorization function, deterministic comparison, and deterministic invariants. This is what makes us trustworthy in CI and what separates us from flaky "AI security scanners."

### What v0 is (and is NOT)
- **v0 IS:** a differential + invariant tester for a **pluggable Python authorization function** the developer provides. No live agents, no network, no side effects.
- **v0 is NOT:** live AI-agent runtime interception, MCP inspection, tool execution, LLM verdicts, a dashboard, or a policy-engine replacement. Those are the roadmap (§10). Building them now is the main way this project fails.

### Own one primitive, not a platform
Model to imitate: Semgrep (static patterns), Playwright (browser tests), Snyk (dependency security). **PermissionDiff = authorization diffs.** If a request smells like agent observability, IAM, a policy editor, or a security dashboard — stop and ask whether it belongs here. Narrowness is the moat.

---

## 2. Tech stack

- **Language:** Python **3.12+**.
- **Env / packaging:** [uv](https://docs.astral.sh/uv/) for everything — env, deps, lockfile, running commands, building. Do **not** use Poetry/Pipenv/Conda or ad-hoc `pip install` in normal dev.
- **CLI:** [Typer](https://typer.tiangolo.com/).
- **Property-based generation (the fuzzer):** [Hypothesis](https://hypothesis.readthedocs.io/) — for state generation, boundary values, and shrinking failures to minimal counterexamples.
- **Config:** `dataclasses` for internal domain models; **Pydantic v2** only at the config/serialization boundary where runtime validation actually helps; `PyYAML` for the optional `permissiondiff.yaml`. Don't make every object a Pydantic model.
- **Terminal output:** [Rich](https://rich.readthedocs.io/) for tables/color — **the core engine must never import Rich.**
- **Testing:** `pytest` + Hypothesis + `pytest-cov`.
- **Lint + format:** [Ruff](https://docs.astral.sh/ruff/) (both).
- **Types:** `mypy`, strict on the core engine.

**Dependency rule:** the core (`models`, `generator`, `engine`, `invariants`) has **no network, no I/O, no side effects** — it only computes. Never add an LLM SDK to the core package.

---

## 3. Folder structure

Standard **src layout**, kept deliberately flat for v0 — do not add sub-package hierarchies until a second concrete use case demands them.

```
permissiondiff/
├── CLAUDE.md                 # this file
├── README.md                 # user-facing intro + quickstart
├── pyproject.toml
├── uv.lock
├── .python-version
├── .gitignore
├── .github/workflows/ci.yml  # tests + ruff + mypy + build
├── src/
│   └── permissiondiff/
│       ├── __init__.py       # version string + public exports (Decision, etc.)
│       ├── __main__.py       # enables `python -m permissiondiff`
│       ├── cli.py            # Typer app: init, test, snapshot, diff, explain
│       ├── models.py         # Subject, Action, Resource, Context, AuthorizationCase, Decision, ChangeType, Finding — dataclasses/enums, NO logic
│       ├── config.py         # load + validate permissiondiff.yaml
│       ├── loader.py         # import the developer's authorizer callable ("module:func")
│       ├── worker.py         # isolated subprocess entry point for one authorizer decision
│       ├── evaluator.py      # parent-side timeout/crash/invalid-result handling
│       ├── generator.py      # Hypothesis strategies over explicit entities + boundary cases
│       ├── engine.py         # evaluate cases; compare baseline vs candidate; classify changes — PURE
│       ├── invariants.py     # tenant_isolation, role_boundary, ownership + custom-invariant API
│       ├── snapshot.py       # exact cases + decisions in deterministic, versioned JSON
│       ├── application.py    # orchestration composed from separate core operations
│       └── report.py         # Rich terminal output + JSON counterexamples + exit codes
├── examples/
│   ├── basic_rbac/           # auth.py + permissiondiff.yaml + README
│   └── multi_tenant/         # auth.py with a DELIBERATE cross-tenant bug (the demo + regression guard)
└── tests/
    ├── unit/                 # test_engine, test_classify, test_invariants, test_snapshot, test_config
    ├── property/             # test_generation, test_shrinking (meta-properties)
    └── integration/          # test_basic_rbac, test_multi_tenant
```

**Module responsibilities (one concern each — don't let logic leak across them):**
- `models.py` — the vocabulary. An `AuthorizationCase` = `(subject, action, resource, context)`. A `Decision` is the enum `ALLOW` / `DENY`. Plain data, no logic.
- `engine.py` — the brain. Evaluate a case, compare baseline vs candidate, classify into `ChangeType`. **Pure functions**, no clocks/globals/randomness (pass `now`/`seed` in explicitly).
- `generator.py` — the fuzzer. Produces the flood of cases and shrinks failures. Deterministic given `--seed`.
- `invariants.py` — the deterministic security rules. Each invariant takes a case+decision and returns pass/fail.
- `loader.py` / `worker.py` / `evaluator.py` — import and execute `authorize` in a timeout-controlled subprocess. This is fault isolation, not a hostile-code sandbox; caveats are in §7.
- `snapshot.py` — record exact baseline input cases and decisions to versioned JSON. Candidate diffing replays those exact cases rather than generating a second corpus.
- `report.py` — rank findings, print them, write minimal reproductions, set the exit code. The only module that prints.
- `cli.py` — thin wiring only.

---

## 4. The authorization interface (how a developer plugs in)

The v0 integration point is a single Python function the developer writes:

```python
from permissiondiff import Decision


def authorize(subject, action, resource, context) -> Decision: ...
```

Or, typed as a protocol the engine depends on (never on a specific auth product):

```python
class AuthorizationFunction(Protocol):
    def __call__(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context,
    ) -> Decision: ...
```

The function returns exactly `Decision.ALLOW` or `Decision.DENY`. **If it crashes or can't decide, that is an explicit `EvaluationError` — never silently treated as allow or deny (see §7, "never fail open").** Adapters (OpenFGA/Cedar/OPA, later) translate other systems into this one interface.

---

## 5. The config (`permissiondiff.yaml`)

Small on purpose — a user should never learn a new policy language to use this. It declares where the authorizer lives, what state space to generate, which invariants to enforce, and what should fail CI:

```yaml
authorizer: examples.multi_tenant.auth:authorize   # "module:function" we import and call

subjects:                      # meaningful application entities
  - {id: alice, tenant: acme, role: support}
  - {id: bob, tenant: globex, role: support}
  - {id: root, tenant: system, role: admin}

resources:
  - {id: invoice-acme, type: invoice, tenant: acme, owner_id: alice}
  - {id: invoice-globex, type: invoice, tenant: globex, owner_id: bob}

actions: [read_invoice, refund, delete_account]
contexts:
  amounts: {min: 0, max: 1000, boundaries: [499, 500, 501]}

invariants:
  - tenant_isolation                       # different tenant → must DENY
  - role_boundary: { action: delete_account, allowed_roles: [admin] }
  - ownership:     { actions: [read_invoice] }   # non-owner → must DENY

fail_on:                       # what makes `permissiondiff` exit non-zero in CI
  invariant_violation: true
  newly_allowed: true          # a newly-ALLOWED path is security-sensitive
  newly_denied: false          # newly-DENIED is usually safe; don't fail CI on it
```

`newly_allowed` is **not automatically a vulnerability** — but it's security-sensitive and must be visible. The developer decides via `fail_on` what blocks a merge.

---

## 6. Key commands

```bash
# setup (one time)
uv sync --all-groups

# scaffold a config + example authorizer in the current dir
uv run permissiondiff init

# run generation + invariants against the current authorizer
uv run permissiondiff test

# record a baseline (run this on main)
uv run permissiondiff snapshot --output .permissiondiff/main.json

# compare the current code (candidate) against that baseline
uv run permissiondiff diff --baseline .permissiondiff/main.json

# show the full minimal reproduction for one finding
uv run permissiondiff explain PD-0001

# deterministic run for CI
uv run permissiondiff test --seed 42

# dev loop
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
uv build
```

**Exit codes (contract — CI depends on it; keep stable once published):**
`0` = pass · `1` = policy/invariant failure (a `fail_on` condition hit) · `2` = configuration error · `3` = evaluation/runtime error. Document any change here.

---

## 7. Non-negotiable rules

**Determinism and reproducibility.** The pass/fail logic is deterministic. AI/randomness may only *generate scenarios*, never decide a verdict. Given the same PermissionDiff and Python versions, configuration, seed, exact corpus, and deterministic authorizer, findings are semantically identical. Semantic fingerprints contain no timestamps or random values, JSON is canonical where practical, and user-authorizer nondeterminism remains visible.

**Never fail open.** If PermissionDiff cannot evaluate a case, it reports an explicit `EvaluationError` — it never guesses ALLOW or DENY. For a security tool, a loud "I don't know" beats a confident wrong answer.

**No real side effects in v0.** The developer's `authorize()` must be a *decision* function. PermissionDiff must never issue refunds, delete accounts, send email, hit production, or invoke agent tools. The README warns users in bold: point it at authorization logic, **not** code with live effects, and never at production data. The timeout-controlled subprocess isolates faults, crashes, and hangs from the parent. **It is not a security sandbox** and does not make malicious Python safe.

**Minimal, minimized counterexamples.** Never dump hundreds of equivalent failures. Shrink each failure to the smallest reproduction and show *one* clear case. Counterexample quality is a core product feature. Good output looks like:
```
CRITICAL — cross-tenant invoice read introduced
  support(acme) → read_invoice → invoice(globex)
  baseline (main): DENY
  candidate (PR):  ALLOW
  (18 equivalent cases reduced to this one)
  repro: .permissiondiff/failures/PD-0001.json
```
Bad output: `Failed 827 cases.`

**Deterministic delegation model (when agents arrive, roadmap).** A delegated principal may never obtain more authority than the delegating principal (least-privilege intersection). Keep this rule explicit and in one place. Not a v0 concern.

**Versioned serialized formats.** Snapshots and JSON reports carry a `schema_version`. Never silently reinterpret an old snapshot under new semantics. Snapshots may contain sensitive identifiers — say so, and keep reports to the minimum needed to reproduce a failure.

---

## 8. Coding conventions

- **Type hints everywhere** in core/public APIs; `mypy src` passes clean.
- **Small, pure functions**, especially in `engine.py` and `invariants.py` — no globals, clocks, or randomness; pass `now`/`seed` explicitly.
- **Enums for decisions** (`Decision.ALLOW`), **dataclasses for domain models**, **Protocols for adapters**, **`pathlib.Path`** for paths, **explicit exceptions** (`ConfigurationError`, `AdapterError`, `EvaluationError`, `SnapshotVersionError`).
- **Dependency direction:** `cli → engine → core`; adapters plug in behind the interface. Core imports none of Typer, Rich, Git, cloud SDKs, or policy engines.
- **Names say intent:** `evaluate_case`, `compare_decisions`, `classify_change`, `is_newly_allowed` — not `res`, `tmp`, `d`. Prefer `authorization` over `authz` in public APIs; `authz` is fine in internal names/comments.
- **Docstrings** on every public function: one line on *what*, plus *why* for anything non-obvious.
- **Don't abstract early.** No framework hierarchies before a second concrete adapter/use case exists.

---

## 9. Testing conventions

This is a security tool; its own tests must be unusually strong.
- **Unit:** classification, invariant evaluation, snapshot round-trips, config parsing, exit codes.
- **Property (Hypothesis) meta-properties:** e.g. `compare(x, x)` never yields newly-allowed/denied; classification is exhaustive; `snapshot(load(snapshot(x)))` preserves decisions; a saved counterexample replays to the same verdict.
- **Integration — build these early:** (1) safe RBAC change, (2) accidental cross-tenant access, (3) accidental admin expansion, (4) expected newly-denied, (5) baseline already violates an invariant, (6) authorizer crashes → `EvaluationError`, (7) malformed config.
- **The known-vulnerable fixture is sacred.** `examples/multi_tenant/` ships a deliberate cross-tenant refund/read bug that `permissiondiff` **must** catch. It's both the 10-second demo and a regression guard — if we ever stop catching it, tests fail.
- Every security-impacting bug fixed gets a regression test.

---

## 10. Roadmap (context — do NOT build in v0)

Evolve only after developers actually use v0. Do not skip ahead to runtime interception.
1. **Policy-engine adapters** — OpenFGA / Cedar / OPA / Auth0 FGA behind the same interface.
2. **Git-aware diffing** — `permissiondiff diff --git-ref main` (worktree orchestration). Start with two snapshot files instead.
3. **Agent principals + delegation graphs** — agents are just another principal with delegation metadata; add mutation dimensions (swap agent identity, delegation depth/expiry, tool sequence) and the "no more authority than the delegator" invariant.
4. **Tool-call shadow interception** — safely test *running* agents in dry-run ("this call *would have* written X"). The hard, valuable core — needs v0 proven first.
5. **Least-privilege mining + proof** — observe legitimate runs, propose a smaller permission set, then *re-run the real workflows under the reduced policy to prove they still pass.* The primitive is **reduction + proof**, not "these look unused."

---

## 11. Definition of done for v0

A developer can: `uv add permissiondiff` → `permissiondiff init` (gets config + sample authorizer) → `permissiondiff test` sees generated-case counts, catches the sample cross-tenant escalation as a CRITICAL with a minimized repro and a non-zero exit → wire in their *own* `authorize()` and get real findings → `snapshot` on main, `diff` the PR → run it non-interactively in CI. When that works cleanly, **stop adding features and show it to backend/security engineers.** Technical completion ≠ product validation — the signals that matter are real installs, repeat use, CI adoption, and teams willing to pay.

---

## 12. Glossary (for newer developers)

- **Authorization (authz):** deciding whether an *already-identified* actor may do a specific thing. (Different from **authentication** = proving who you are.)
- **RBAC / ABAC:** access decided by **R**ole (e.g. `admin`) or by **A**ttributes (tenant, amount, ownership).
- **Tenant / tenant isolation:** one customer in a multi-customer system; isolation means customer A can never touch customer B's data. Breaking it is the nightmare scenario.
- **Horizontal privilege escalation:** acting as a *different peer* (Alice reaching Bob's data). **Vertical:** gaining a *higher* role's powers (support → admin).
- **Confused deputy:** tricking a trusted component into misusing *its* authority for you (common once agents delegate).
- **Property-based testing:** instead of hand-writing examples, you state a property that must always hold and let a tool (Hypothesis) generate many inputs trying to break it. Our property: *actual authority never exceeds intended/baseline authority.*
- **Shrinking:** when a fuzzer finds a failure, it automatically reduces it to the smallest input that still fails — that's your minimal counterexample.
- **Baseline vs candidate:** baseline = the trusted version (usually `main`); candidate = the version under test (usually the PR). We diff their authorization behavior.
- **Invariant:** a security rule that must hold regardless of baseline (e.g. "different tenant → DENY"). Catches bugs already present on `main`.
- **Snapshot:** a deterministic, versioned record of exact baseline input cases and decisions. A candidate authorizer replays those same cases; it does not generate a different corpus for comparison.

---

### For AI assistants working in this repo
Understand the product before coding: PermissionDiff exposes **changes in effective authorization** and **invariant violations** — it is not a generic test framework. Preserve determinism (never put an LLM in the verdict path). Don't widen scope casually (agent observability, IAM, policy admin, MCP scanning → ask first). Respect layer boundaries (no Rich/Typer/Git imports in the core). Every behavior change ships with tests. If an adapter can't decide, return an explicit error — never fabricate allow/deny. Version any serialized schema you change. Update this file if you change a command, exit code, or the config schema.
