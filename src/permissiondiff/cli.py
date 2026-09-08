"""Thin Typer command layer for PermissionDiff workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from permissiondiff import __version__
from permissiondiff.application import create_snapshot, run_diff, run_git_diff, run_test
from permissiondiff.config import PermissionDiffConfig, load_config
from permissiondiff.errors import ConfigurationError, PermissionDiffError
from permissiondiff.models import Finding
from permissiondiff.report import (
    assign_finding_ids,
    explain_finding,
    persist_findings,
    render_terminal,
    result_exit_code,
)
from permissiondiff.snapshot import write_snapshot

app = typer.Typer(
    help="Deterministic differential authorization regression testing.",
    no_args_is_help=True,
)
console = Console()

CONFIG_OPTION = Annotated[
    Path,
    typer.Option("--config", "-c", help="PermissionDiff YAML configuration."),
]
SEED_OPTION = Annotated[int, typer.Option("--seed", help="Case-corpus seed.")]
DEBUG_OPTION = Annotated[bool, typer.Option("--debug", help="Show unexpected tracebacks.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"permissiondiff {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """Expose global CLI options."""


@app.command()
def init(
    directory: Annotated[Path, typer.Argument(help="Directory to initialize.")] = Path("."),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite generated sample files."),
    ] = False,
) -> None:
    """Create a runnable sample config and deliberately vulnerable authorizer."""
    config_path = directory / "permissiondiff.yaml"
    authorizer_path = directory / "permissiondiff_authorizer.py"
    existing = [path for path in (config_path, authorizer_path) if path.exists()]
    if existing and not force:
        console.print(f"[red]Configuration error:[/red] {existing[0]} already exists")
        raise typer.Exit(2)
    directory.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_INIT_CONFIG, encoding="utf-8")
    authorizer_path.write_text(_INIT_AUTHORIZER, encoding="utf-8")
    console.print(f"Created {config_path} and {authorizer_path}")
    console.print("Run [bold]permissiondiff test[/bold] to find the sample cross-tenant bug.")


@app.command("test")
def test_command(
    config: CONFIG_OPTION = Path("permissiondiff.yaml"),
    seed: SEED_OPTION = 42,
    max_examples: Annotated[
        int | None, typer.Option("--max-examples", min=1, help="Override corpus size.")
    ] = None,
    json_output: Annotated[
        Path, typer.Option("--json-output", help="Machine-readable report path.")
    ] = Path(".permissiondiff/report.json"),
    failures_dir: Annotated[
        Path, typer.Option("--failures-dir", help="Minimal reproduction directory.")
    ] = Path(".permissiondiff/failures"),
    debug: DEBUG_OPTION = False,
) -> None:
    """Generate cases and enforce configured invariants."""
    try:
        loaded = load_config(config)
        result = run_test(
            loaded,
            workdir=config.resolve().parent,
            seed=seed,
            max_examples=max_examples,
        )
        _finish_run(loaded, result.cases_evaluated, result.findings, failures_dir, json_output)
    except typer.Exit:
        raise
    except PermissionDiffError as exc:
        _fail(exc, debug)
    except Exception as exc:
        _unexpected(exc, debug)


@app.command()
def snapshot(
    output: Annotated[Path, typer.Option("--output", "-o", help="Baseline JSON path.")],
    config: CONFIG_OPTION = Path("permissiondiff.yaml"),
    seed: SEED_OPTION = 42,
    max_examples: Annotated[
        int | None, typer.Option("--max-examples", min=1, help="Override corpus size.")
    ] = None,
    debug: DEBUG_OPTION = False,
) -> None:
    """Record exact generated cases and baseline decisions."""
    try:
        loaded = load_config(config)
        baseline = create_snapshot(
            loaded,
            workdir=config.resolve().parent,
            seed=seed,
            max_examples=max_examples,
        )
        write_snapshot(baseline, output)
        console.print(f"Wrote {len(baseline.cases):,} exact baseline cases to {output}")
    except typer.Exit:
        raise
    except PermissionDiffError as exc:
        _fail(exc, debug)
    except Exception as exc:
        _unexpected(exc, debug)


@app.command()
def diff(
    baseline: Annotated[
        Path | None, typer.Option("--baseline", help="Baseline snapshot path.")
    ] = None,
    git_ref: Annotated[
        str | None,
        typer.Option("--git-ref", help="Baseline git ref to evaluate in a temporary worktree."),
    ] = None,
    config: CONFIG_OPTION = Path("permissiondiff.yaml"),
    seed: SEED_OPTION = 42,
    max_examples: Annotated[
        int | None, typer.Option("--max-examples", min=1, help="Override corpus size (--git-ref).")
    ] = None,
    json_output: Annotated[
        Path, typer.Option("--json-output", help="Machine-readable report path.")
    ] = Path(".permissiondiff/report.json"),
    failures_dir: Annotated[
        Path, typer.Option("--failures-dir", help="Minimal reproduction directory.")
    ] = Path(".permissiondiff/failures"),
    debug: DEBUG_OPTION = False,
) -> None:
    """Replay the exact baseline corpus against the candidate authorizer.

    Provide exactly one baseline source: --baseline (a snapshot file) or --git-ref (a git ref
    whose authorizer is evaluated in a temporary worktree).
    """
    try:
        if (baseline is None) == (git_ref is None):
            raise ConfigurationError("provide exactly one of --baseline or --git-ref")
        loaded = load_config(config)
        workdir = config.resolve().parent
        if git_ref is not None:
            result = run_git_diff(
                loaded, workdir=workdir, ref=git_ref, seed=seed, max_examples=max_examples
            )
        else:
            assert baseline is not None
            result = run_diff(loaded, workdir=workdir, baseline_path=baseline)
        _finish_run(loaded, result.cases_evaluated, result.findings, failures_dir, json_output)
    except typer.Exit:
        raise
    except PermissionDiffError as exc:
        _fail(exc, debug)
    except Exception as exc:
        _unexpected(exc, debug)


@app.command()
def explain(
    finding_id: Annotated[str, typer.Argument(help="Stable finding ID, e.g. PD-0001")],
    failures_dir: Annotated[
        Path, typer.Option("--failures-dir", help="Minimal reproduction directory.")
    ] = Path(".permissiondiff/failures"),
) -> None:
    """Print a persisted minimal reproduction."""
    path = failures_dir / f"{finding_id}.json"
    try:
        console.print_json(explain_finding(path))
    except (OSError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] could not read {path}: {exc}")
        raise typer.Exit(2) from exc


def _finish_run(
    config: PermissionDiffConfig,
    cases_evaluated: int,
    raw_findings: tuple[Finding, ...],
    failures_dir: Path,
    report_path: Path,
) -> None:
    findings = assign_finding_ids(raw_findings)
    persist_findings(
        findings,
        failures_dir=failures_dir,
        report_path=report_path,
        cases_evaluated=cases_evaluated,
    )
    render_terminal(findings, cases_evaluated=cases_evaluated, failures_dir=failures_dir)
    raise typer.Exit(result_exit_code(findings, config.fail_on))


def _fail(error: PermissionDiffError, debug: bool) -> None:
    if debug:
        raise error
    name = type(error).__name__
    configuration_errors = {
        "ConfigurationError",
        "InvariantDefinitionError",
        "SnapshotVersionError",
    }
    exit_code = 2 if name in configuration_errors else 3
    console.print(f"[red]{name}:[/red] {error}")
    raise typer.Exit(exit_code) from error


def _unexpected(error: Exception, debug: bool) -> None:
    if debug:
        raise error
    console.print(f"[red]Runtime error:[/red] {type(error).__name__}: {error}")
    raise typer.Exit(3) from error


_INIT_CONFIG = """authorizer: permissiondiff_authorizer:authorize

subjects:
  - {id: alice, tenant: acme, role: support}
  - {id: bob, tenant: globex, role: support}
  - {id: root, tenant: system, role: admin}

resources:
  - {id: invoice-acme, type: invoice, tenant: acme, owner_id: alice}
  - {id: invoice-globex, type: invoice, tenant: globex, owner_id: bob}

actions: [read_invoice, delete_account]

contexts:
  amounts: {min: 0, max: 1000, boundaries: [499, 500, 501]}

invariants:
  - tenant_isolation
  - role_boundary: {action: delete_account, allowed_roles: [admin]}

fail_on:
  invariant_violation: true
  newly_allowed: true
  newly_denied: false

generation: {max_examples: 32}
execution: {timeout_seconds: 2}
"""

_INIT_AUTHORIZER = '''"""Deliberately vulnerable sample authorizer generated by PermissionDiff."""

from permissiondiff import Action, Context, Decision, Resource, Subject


def authorize(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: Context,
) -> Decision:
    """Return a decision; this sample intentionally forgets tenant isolation."""
    if subject.role == "admin":
        return Decision.ALLOW
    if subject.role == "support" and action.name == "read_invoice":
        return Decision.ALLOW  # BUG: resource.tenant is never checked
    return Decision.DENY
'''
