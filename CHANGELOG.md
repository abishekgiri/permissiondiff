# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/abishekgiri/permissiondiff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/abishekgiri/permissiondiff/releases/tag/v0.1.0
