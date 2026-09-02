"""End-to-end CLI workflows and documented exit-code integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from permissiondiff.cli import app
from tests.conftest import write_authorizer, write_config

RUNNER = CliRunner()
ROOT = Path(__file__).parents[2]

SAFE_AUTHORIZER = """from permissiondiff import Decision
def authorize(subject, action, resource, context):
    if subject.tenant != resource.tenant:
        return Decision.DENY
    return Decision.ALLOW if action.name == 'read_invoice' else Decision.DENY
"""

VULNERABLE_AUTHORIZER = """from permissiondiff import Decision
def authorize(subject, action, resource, context):
    return Decision.ALLOW if action.name == 'read_invoice' else Decision.DENY
"""


def report_options(tmp_path: Path) -> list[str]:
    """Keep integration artifacts isolated from the repository."""
    return [
        "--json-output",
        str(tmp_path / "report.json"),
        "--failures-dir",
        str(tmp_path / "failures"),
    ]


def test_safe_rbac_example_passes(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        app,
        [
            "test",
            "--config",
            str(ROOT / "examples/basic_rbac/permissiondiff.yaml"),
            "--max-examples",
            "8",
            *report_options(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output


def test_deliberate_cross_tenant_example_is_caught(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        app,
        [
            "test",
            "--config",
            str(ROOT / "examples/multi_tenant/permissiondiff.yaml"),
            "--max-examples",
            "8",
            *report_options(tmp_path),
        ],
    )
    assert result.exit_code == 1, result.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert any(
        item["message"] == "Cross-tenant access must be denied" for item in report["findings"]
    )
    assert (tmp_path / "failures/PD-0001.json").exists()


def test_init_creates_runnable_vulnerable_sample(tmp_path: Path) -> None:
    initialized = RUNNER.invoke(app, ["init", str(tmp_path)])
    assert initialized.exit_code == 0, initialized.output
    tested = RUNNER.invoke(
        app,
        [
            "test",
            "--config",
            str(tmp_path / "permissiondiff.yaml"),
            "--max-examples",
            "8",
            *report_options(tmp_path),
        ],
    )
    assert tested.exit_code == 1, tested.output
    assert "tenant" in tested.output.lower()


def test_exact_baseline_cases_are_replayed_and_new_allow_is_found(tmp_path: Path) -> None:
    baseline_spec = write_authorizer(tmp_path, SAFE_AUTHORIZER, "baseline_auth")
    baseline_config = write_config(tmp_path, baseline_spec)
    baseline_path = tmp_path / "baseline.json"
    snapshot_result = RUNNER.invoke(
        app,
        [
            "snapshot",
            "--config",
            str(baseline_config),
            "--output",
            str(baseline_path),
            "--max-examples",
            "8",
            "--seed",
            "91",
        ],
    )
    assert snapshot_result.exit_code == 0, snapshot_result.output
    snapshot = json.loads(baseline_path.read_text())

    candidate_spec = write_authorizer(tmp_path, VULNERABLE_AUTHORIZER, "candidate_auth")
    candidate_config = write_config(tmp_path, candidate_spec)
    diff_result = RUNNER.invoke(
        app,
        [
            "diff",
            "--config",
            str(candidate_config),
            "--baseline",
            str(baseline_path),
            *report_options(tmp_path),
        ],
    )
    report = json.loads((tmp_path / "report.json").read_text())
    assert diff_result.exit_code == 1, diff_result.output
    assert report["cases_evaluated"] == len(snapshot["cases"])
    assert any(item["change"] == "newly_allowed" for item in report["findings"])
    assert all("case" in item and "case_fingerprint" in item for item in report["findings"])


def test_admin_expansion_is_newly_allowed(tmp_path: Path) -> None:
    baseline_spec = write_authorizer(
        tmp_path,
        "from permissiondiff import Decision\ndef authorize(s,a,r,c): return Decision.DENY\n",
        "admin_baseline",
    )
    config_path = write_config(tmp_path, baseline_spec, invariants=[])
    payload = yaml.safe_load(config_path.read_text())
    payload["actions"] = ["delete_account"]
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    snapshot_path = tmp_path / "admin.json"
    assert (
        RUNNER.invoke(
            app,
            [
                "snapshot",
                "-c",
                str(config_path),
                "-o",
                str(snapshot_path),
                "--max-examples",
                "4",
            ],
        ).exit_code
        == 0
    )

    candidate_spec = write_authorizer(
        tmp_path,
        (
            "from permissiondiff import Decision\n"
            "def authorize(s,a,r,c):\n"
            "    return Decision.ALLOW if s.role == 'support' else Decision.DENY\n"
        ),
        "admin_candidate",
    )
    payload["authorizer"] = candidate_spec
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    result = RUNNER.invoke(
        app,
        [
            "diff",
            "-c",
            str(config_path),
            "--baseline",
            str(snapshot_path),
            *report_options(tmp_path),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "newly allowed" in result.output.lower()


def test_newly_denied_is_visible_but_does_not_fail_by_default(tmp_path: Path) -> None:
    allow_spec = write_authorizer(tmp_path, VULNERABLE_AUTHORIZER, "allow_auth")
    config_path = write_config(tmp_path, allow_spec, invariants=[])
    snapshot_path = tmp_path / "allow.json"
    assert (
        RUNNER.invoke(
            app,
            ["snapshot", "-c", str(config_path), "-o", str(snapshot_path), "--max-examples", "4"],
        ).exit_code
        == 0
    )

    deny_spec = write_authorizer(
        tmp_path,
        "from permissiondiff import Decision\ndef authorize(s,a,r,c): return Decision.DENY\n",
        "deny_auth",
    )
    payload = yaml.safe_load(config_path.read_text())
    payload["authorizer"] = deny_spec
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    result = RUNNER.invoke(
        app,
        [
            "diff",
            "-c",
            str(config_path),
            "--baseline",
            str(snapshot_path),
            *report_options(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert any(item["change"] == "newly_denied" for item in report["findings"])


def test_crash_timeout_and_invalid_return_exit_three(tmp_path: Path) -> None:
    authorizers = {
        "crash": "def authorize(s,a,r,c): raise RuntimeError('boom')\n",
        "timeout": "import time\ndef authorize(s,a,r,c): time.sleep(5)\n",
        "invalid": "def authorize(s,a,r,c): return 'ALLOW'\n",
    }
    for name, source in authorizers.items():
        spec = write_authorizer(tmp_path, source, f"{name}_auth")
        config_path = write_config(
            tmp_path,
            spec,
            invariants=[],
            timeout=0.05 if name == "timeout" else 1,
        )
        result = RUNNER.invoke(
            app,
            [
                "test",
                "-c",
                str(config_path),
                "--max-examples",
                "1",
                *report_options(tmp_path),
            ],
        )
        assert result.exit_code == 3, f"{name}: {result.output}"


def test_malformed_config_and_incompatible_snapshot_exit_two(tmp_path: Path) -> None:
    malformed = tmp_path / "bad.yaml"
    malformed.write_text("authorizer: nope\n", encoding="utf-8")
    malformed_result = RUNNER.invoke(app, ["test", "-c", str(malformed)])
    assert malformed_result.exit_code == 2

    spec = write_authorizer(tmp_path, SAFE_AUTHORIZER)
    config_path = write_config(tmp_path, spec)
    snapshot = tmp_path / "old.json"
    snapshot.write_text('{"schema_version": 999, "cases": []}', encoding="utf-8")
    old_result = RUNNER.invoke(
        app,
        ["diff", "-c", str(config_path), "--baseline", str(snapshot)],
    )
    assert old_result.exit_code == 2
