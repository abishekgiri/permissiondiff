# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Persistent worker execution (default): the authorizer is imported once in a long-lived worker
  and cases stream over a line-delimited protocol, roughly an order of magnitude faster on large
  corpora. Each crash or timeout kills and re-spawns the worker so one bad case cannot corrupt
  later cases, and output stays byte-identical for deterministic authorizers. Set
  `execution.worker: process_per_case` to restore a fresh interpreter per case.

## [0.1.1] - 2026-09-04

### Fixed

- A custom invariant that terminated the process (for example `SystemExit(0)`) could exit
  PermissionDiff with a success code, reporting an incomplete evaluation as a pass. Custom
  invariant termination, crashes, and invalid return values are now explicit evaluation errors
  (exit 3) and never fail open.
- The subprocess worker kept authorizer output off the result channel only until interpreter
  shutdown, so `atexit`/shutdown writes to stdout could corrupt the JSON result and turn a valid
  decision into an error. The worker now writes results on a private descriptor and redirects
  stdout to stderr for the entire process lifetime.

### Hardened

- Restored dependency-review as a blocking pull-request gate now that the repository dependency
  graph is active.
- Added security-critical regression tests for custom-invariant termination/return handling and
  for late-lifetime worker stdout.

### Internal

- No product features were added; this is a correctness and hardening patch.

## [0.1.0] - 2026-09-03

### Added

- Deterministic generation of authorization cases from declared subjects, resources, actions,
  and bounded context values.
- Built-in tenant-isolation, role-boundary, and ownership invariants, plus custom invariant
  callables.
- Snapshot and exact-corpus diff workflows with stable fingerprints and exhaustive decision
  classifications.
- Minimized failure reproductions, human-readable terminal findings, and JSON reports.
- Timeout-controlled subprocess evaluation with explicit configuration, snapshot, policy, and
  runtime exit codes.
- A thin composite GitHub Action for replaying committed baselines in pull requests.

### Known limitations

- Python authorizers run as trusted local code; the evaluator is not a security sandbox.
- v0 supports local Python authorizers only. Remote policy engines, Git worktree orchestration,
  dashboards, and live agent or tool interception are not included.
- Reproducibility requires deterministic authorizer code and matching package, Python,
  configuration, seed, and corpus inputs.

[Unreleased]: https://github.com/abishekgiri/permissiondiff/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/abishekgiri/permissiondiff/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/abishekgiri/permissiondiff/releases/tag/v0.1.0
