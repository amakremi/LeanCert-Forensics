from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import leancert.cli as cli
import leancert.report as report_module
from leancert.datasets import register_local_artifact
from leancert.metrics import compute_metrics
from leancert.plots import generate_figures
from leancert.report import process_directory, process_trace_file, write_experiment_results
from leancert.schema import ForensicTrace
from leancert.trace_builder import baseline_trace
from leancert.utils import sha256_file, write_json
from leancert.validator import validate_trace


MISSING_LEAN = {
    "lean_available": False, "lean_path": None, "lean_version": None,
    "lake_available": False, "lake_path": None, "lake_version": None,
    "lean_check_mode": "not run", "path_entry_hints": ["hint"],
}


def test_check_lean_does_not_crash_when_missing(monkeypatch, capsys):
    monkeypatch.setattr(cli, "detect_lean", lambda: MISSING_LEAN)
    assert cli.main(["check-lean"]) == 0
    assert "Lean available: false" in capsys.readouterr().out


def test_install_lean_windows_is_safe_off_windows(monkeypatch, capsys):
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    assert cli.main(["install-lean-windows"]) == 0
    assert "only supported on Windows" in capsys.readouterr().out


def test_require_lean_stops_when_unavailable(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "detect_lean", lambda: MISSING_LEAN)
    assert cli.main(["run-experiment", str(tmp_path), "--require-lean"]) == 2
    assert "required but unavailable" in capsys.readouterr().out


def test_local_registration_hashes_and_updates_manifest(tmp_path):
    artifact = tmp_path / "nist sample.raw"
    artifact.write_bytes(b"registered public bytes")
    manifest = tmp_path / "manifest.json"
    record = register_local_artifact(
        source_name="NIST CFReDS", artifact_name="Small image",
        kind="disk_image", path=artifact, manifest_path=manifest,
    )
    assert record["sha256"] == sha256_file(artifact)
    assert record["download_status"] == "local_registered"
    assert json.loads(manifest.read_text(encoding="utf-8"))[0]["size_bytes"] == artifact.stat().st_size


def test_trace_builder_varies_event_count_by_kind(public_artifact):
    digest = sha256_file(public_artifact)
    counts = set()
    for kind in ("report", "memory_dump", "network_capture", "disk_image"):
        data = baseline_trace({
            "source_name": "Corpus", "artifact_name": kind, "artifact_kind": kind,
            "source_url": "https://example.invalid", "local_path": str(public_artifact),
            "sha256": digest, "size_bytes": public_artifact.stat().st_size,
            "retrieved_at_utc": "2025-01-01T00:00:00Z",
        })
        assert validate_trace(ForensicTrace.model_validate(data)).overall_status == "PASSED"
        counts.add(len(data["events"]))
    assert counts == {4, 5, 6, 8}


def test_trace_size_plot_warns_for_identical_counts(tmp_path):
    rows = [{
        "trace_id": "T", "predicted_status": "PASSED", "event_count": 4,
        "failure_count": 0, "validation_time_ms": 1.0, "lean_check_time_ms": None,
    }]
    summary = {"TP": 0, "TN": 1, "FP": 0, "FN": 0}
    failures = [{"requirement": "IdentityCompleteness", "failure_count": 0, "failure_rate": 0.0}]
    warnings = generate_figures(rows, summary, failures, failures, failures, tmp_path)
    assert "trace_size_vs_validation_time" in warnings
    assert (tmp_path / "direct_vs_cascading_failures.png").is_file()


def test_report_traceability_direct_failure(valid_data):
    valid_data["report_claims"][0]["supporting_evidence_ids"] = ["MISSING"]
    result = validate_trace(ForensicTrace.model_validate(valid_data))
    report = next(item for item in result.requirement_results if item.requirement == "ReportTraceability")
    assert report.failure_type == "direct"
    assert report.failures[0]["is_cascading"] is False


def test_report_traceability_cascading_failure(valid_data):
    valid_data["events"][1]["prev_hash"] = "broken"
    result = validate_trace(ForensicTrace.model_validate(valid_data))
    report = next(item for item in result.requirement_results if item.requirement == "ReportTraceability")
    assert report.failure_type == "cascading"
    assert report.failures[0]["is_cascading"] is True
    assert "HashContinuity" in report.failures[0]["upstream_failed_requirements"]


def test_direct_and_cascading_outputs_and_mocked_lean_manifest(
    monkeypatch, tmp_path, valid_data
):
    valid_path = tmp_path / "valid.json"
    invalid_path = tmp_path / "invalid.json"
    write_json(valid_path, valid_data)
    invalid = copy.deepcopy(valid_data)
    invalid["trace_id"] += "-BAD"
    invalid["expected_label"] = "invalid"
    invalid["events"][1]["prev_hash"] = "broken"
    write_json(invalid_path, invalid)
    records = [
        process_trace_file(valid_path, run_lean=False),
        process_trace_file(invalid_path, run_lean=False),
    ]
    for record in records:
        record["row"]["lean_check_status"] = "PASSED"
        record["row"]["lean_check_time_ms"] = 2.5
        record["report"]["lean_check_status"] = "PASSED"
        record["report"]["lean_check_time_ms"] = 2.5
    mocked = {
        "lean_available": True, "lean_path": "lean", "lean_version": "Lean 4.x",
        "lake_available": True, "lake_path": "lake", "lake_version": "Lake x",
        "lean_check_mode": "lean file", "path_entry_hints": [],
    }
    monkeypatch.setattr(report_module, "detect_lean", lambda: mocked)
    results = tmp_path / "results"
    write_experiment_results(
        records, trace_dir=tmp_path, repeat=1, repeat_lean=1,
        results_dir=results,
    )
    assert (results / "per_requirement_failures_direct.csv").is_file()
    assert (results / "per_requirement_failures_cascading.csv").is_file()
    manifest = json.loads((results / "experiment_manifest.json").read_text(encoding="utf-8"))
    assert manifest["lean_available"] is True
    assert manifest["lake_version"] == "Lake x"
    assert manifest["lean_proof_checking_completed"] is True
    summary = json.loads((results / "evaluation_summary.json").read_text(encoding="utf-8"))
    assert summary["lean_checked_traces"] == 2
    assert summary["lean_passed_artifacts"] == 2
    assert summary["lean_failed_artifacts"] == 0


def test_metrics_are_computed_from_rows():
    row = {
        "is_expected_valid": False, "is_predicted_valid": True,
        "validation_time_ms": 7.0, "lean_check_time_ms": None,
        "dataset_source": "S", "artifact_name": "A", "artifact_sha256": "h",
    }
    metrics = compute_metrics([row])
    assert metrics["FN"] == 1
    assert metrics["accuracy"] == 0.0


def test_process_directory_does_not_omit_malformed_trace(tmp_path):
    valid = tmp_path / "valid.json"
    malformed = tmp_path / "malformed.json"
    # Minimal parseable object is still a schema failure and must be included.
    valid.write_text('{"expected_label":"invalid"}', encoding="utf-8")
    malformed.write_text("{", encoding="utf-8")
    records = process_directory(tmp_path, run_lean=False, reports_dir=tmp_path / "reports")
    assert len(records) == 2
