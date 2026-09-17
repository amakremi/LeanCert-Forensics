from __future__ import annotations

import inspect
from pathlib import Path

import matplotlib

from leancert.cli import main
from leancert.plots import generate_figures
from leancert.report import process_trace_file
from leancert.utils import write_json


def test_malformed_json_is_reported_as_schema_failure(tmp_path):
    path = tmp_path / "malformed.json"
    path.write_text('{"expected_label":"invalid",', encoding="utf-8")
    record = process_trace_file(path, run_lean=False)
    assert record["row"]["predicted_status"] == "FAILED"
    assert record["row"]["failed_requirements"] == "SchemaValidation"
    assert "parse_error" in record["report"]


def test_internal_path_code_uses_pathlib():
    import leancert.datasets as datasets
    import leancert.report as report
    source = inspect.getsource(datasets) + inspect.getsource(report)
    assert "os.path" not in source
    assert "Path(" in source


def test_json_reports_are_utf8(tmp_path):
    path = tmp_path / "résultat.json"
    write_json(path, {"message": "دليل رقمي"})
    assert "دليل رقمي" in path.read_text(encoding="utf-8")


def test_matplotlib_uses_agg_and_generates_figures(tmp_path):
    rows = [{
        "trace_id": "T", "predicted_status": "PASSED", "event_count": 1,
        "failure_count": 0, "validation_time_ms": 1.0, "lean_check_time_ms": None,
    }]
    summary = {"TP": 0, "TN": 1, "FP": 0, "FN": 0}
    failures = [{"requirement": "IdentityCompleteness", "failure_count": 0, "failure_rate": 0.0}]
    generate_figures(rows, summary, failures, failures, failures, tmp_path)
    assert "agg" in matplotlib.get_backend().lower()
    assert (tmp_path / "confusion_matrix.png").is_file()


def test_cli_accepts_directory_without_trailing_slash(tmp_path):
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    assert main(["run-experiment", str(trace_dir), "--repeat", "1"]) == 0
