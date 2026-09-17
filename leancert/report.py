from __future__ import annotations

import csv
import json
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .artifact_native import artifact_native_metrics, evaluate_artifact_native
from .datasets import usable_manifest_records
from .lean_generator import check_lean_file, detect_lean, generate_lean
from .metrics import (
    classified_failure_entry_counts, compute_metrics, percentile, requirement_failures,
)
from .plots import generate_figures
from .schema import ForensicTrace, RequirementResult, ValidationResult, ValidationTrace
from .utils import PROJECT_ROOT, read_json, relative_to_project, safe_filename, utc_now, write_json
from .validator import REQUIREMENTS, validate_trace

RESULT_REQUIREMENTS = [*REQUIREMENTS, "SchemaValidation"]
PER_TRACE_COLUMNS = [
    "trace_id", "dataset_source", "artifact_name", "expected_label", "predicted_status",
    "correct", "failed_requirements", "direct_failure_count", "cascading_failure_count",
    "event_count", "validation_time_us", "lean_status", "lean_check_time_ms",
    "lean_cold_time_ms", "lean_obligation_count", "lean_file_compiled",
    "trace_validity_theorem_emitted", "trace_validity_theorem_checked",
    "passed_obligation_count", "failed_obligation_count", "documented_failed_obligations",
    "certificate_kind", "invalid_trace_theorem_emitted", "invalid_trace_theorem_checked",
    "direct_negative_theorem_count", "cascading_negative_theorem_count",
    "negative_theorem_requirements",
]


def _schema_failure(path: Path, raw: Any, error: str) -> tuple[ValidationResult, dict]:
    data = raw if isinstance(raw, dict) else {}
    trace_id = str(data.get("trace_id") or f"MALFORMED-{path.stem}")
    case_id = str(data.get("case_id") or "UNKNOWN")
    origin = data.get("dataset_origin") if isinstance(data.get("dataset_origin"), dict) else {}
    result = ValidationResult(
        case_id=case_id, trace_id=trace_id, overall_status="FAILED",
        passed_requirements=[], failed_requirements=["SchemaValidation"],
        requirement_results=[RequirementResult(
            requirement="SchemaValidation", passed=False,
            failures=[{"reason": error}],
        )],
        warnings=[], failure_count=1, dataset_origin=origin,
    )
    return result, data


def process_trace_file(
    path: Path,
    *,
    repeat: int = 1,
    repeat_lean: int = 1,
    strict_artifacts: bool = False,
    run_lean: bool = True,
    expected_label_override: str | None = None,
) -> dict:
    raw: Any = {}
    trace: ValidationTrace | None = None
    parse_error = ""
    try:
        raw = read_json(path)
        trace = (
            ForensicTrace.model_validate(raw)
            if isinstance(raw, dict) and "expected_label" in raw
            else ValidationTrace.model_validate(raw)
        )
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, ValidationError) as exc:
        parse_error = str(exc)

    times_ns: list[int] = []
    if trace is None:
        result, raw_data = _schema_failure(path, raw, parse_error)
        times_ns = [0]
    else:
        raw_data = raw
        for _ in range(10 if repeat > 1 else 0):
            validate_trace(trace, strict_artifacts=strict_artifacts)
        for _ in range(max(1, repeat)):
            started = time.perf_counter_ns()
            result = validate_trace(trace, strict_artifacts=strict_artifacts)
            times_ns.append(time.perf_counter_ns() - started)
        primary, library = generate_lean(trace, result)
        if run_lean:
            lean_result = check_lean_file(library, repeat_lean)
            for key, value in lean_result.items():
                setattr(result, key, value)
            result.lean_file_compiled = result.lean_check_status == "PASSED"
            result.trace_validity_theorem_checked = (
                result.trace_validity_theorem_emitted and result.lean_file_compiled
            )
            result.invalid_trace_theorem_checked = (
                result.invalid_trace_theorem_emitted and result.lean_file_compiled
            )

    origin = raw_data.get("dataset_origin", {}) if isinstance(raw_data, dict) else {}
    expected_label = (
        expected_label_override
        if expected_label_override is not None
        else raw_data.get("expected_label", "invalid") if isinstance(raw_data, dict) else "invalid"
    )
    if expected_label not in {"valid", "invalid"}:
        expected_label = "invalid"
    predicted_valid = result.overall_status == "PASSED"
    expected_valid = expected_label == "valid"
    row = {
        "trace_id": result.trace_id,
        "case_id": result.case_id,
        "file_path": relative_to_project(path),
        "dataset_source": origin.get("source_name", ""),
        "artifact_name": origin.get("artifact_name", ""),
        "artifact_sha256": origin.get("sha256", ""),
        "artifact_size_bytes": origin.get("size_bytes", 0),
        "expected_label": expected_label,
        "predicted_status": result.overall_status,
        "is_expected_valid": expected_valid,
        "is_predicted_valid": predicted_valid,
        "correct": expected_valid == predicted_valid,
        "failure_count": result.failure_count,
        "failed_requirements": ";".join(result.failed_requirements),
        "failed_requirements_list": list(result.failed_requirements),
        "evidence_count": len(raw_data.get("evidence", [])) if isinstance(raw_data, dict) else 0,
        "actor_count": len(raw_data.get("actors", [])) if isinstance(raw_data, dict) else 0,
        "event_count": len(raw_data.get("events", [])) if isinstance(raw_data, dict) else 0,
        "claim_count": len(raw_data.get("report_claims", [])) if isinstance(raw_data, dict) else 0,
        "validation_time_us": (sum(times_ns) / len(times_ns)) / 1000,
        "validation_time_samples_us": [elapsed / 1000 for elapsed in times_ns],
        "lean_artifact": result.lean_artifact or "",
        "lean_check_status": result.lean_check_status,
        "lean_status": result.lean_check_status,
        "lean_check_time_ms": result.lean_check_time_ms,
        "lean_cold_time_ms": result.lean_cold_time_ms,
        "lean_warm_times_ms": list(result.lean_warm_times_ms),
        "lean_obligation_count": result.lean_obligation_count,
        "lean_file_compiled": result.lean_file_compiled,
        "trace_validity_theorem_emitted": result.trace_validity_theorem_emitted,
        "trace_validity_theorem_checked": result.trace_validity_theorem_checked,
        "passed_obligation_count": result.passed_obligation_count,
        "failed_obligation_count": result.failed_obligation_count,
        "documented_failed_obligations": ";".join(result.documented_failed_obligations),
        "certificate_kind": result.certificate_kind or "",
        "invalid_trace_theorem_emitted": result.invalid_trace_theorem_emitted,
        "invalid_trace_theorem_checked": result.invalid_trace_theorem_checked,
        "direct_negative_theorem_count": result.direct_negative_theorem_count,
        "cascading_negative_theorem_count": result.cascading_negative_theorem_count,
        "negative_theorem_requirements": ";".join(result.negative_theorem_requirements),
    }
    report = result.model_dump()
    report["file_path"] = relative_to_project(path)
    report["validation_time_us"] = row["validation_time_us"]
    if parse_error:
        report["parse_error"] = parse_error
    row["direct_failure_count"] = sum(
        not failure.get("is_cascading", False)
        for requirement in report["requirement_results"]
        for failure in requirement.get("failures", [])
    )
    row["cascading_failure_count"] = sum(
        failure.get("is_cascading", False)
        for requirement in report["requirement_results"]
        for failure in requirement.get("failures", [])
    )
    return {"row": row, "report": report, "raw": raw_data}


def process_directory(
    trace_dir: Path,
    *,
    repeat: int = 1,
    repeat_lean: int = 1,
    strict_artifacts: bool = False,
    run_lean: bool = True,
    reports_dir: Path = PROJECT_ROOT / "reports",
    label_mapping: dict[str, dict[str, Any]] | None = None,
) -> list[dict]:
    files = sorted(path for path in trace_dir.rglob("*.json") if path.is_file())
    reports_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for path in files:
        raw_id = ""
        if label_mapping is not None:
            try:
                raw_id = str(read_json(path).get("trace_id", ""))
            except (OSError, json.JSONDecodeError, AttributeError):
                raw_id = ""
        expected_override = (
            label_mapping.get(raw_id, {}).get("expected_label")
            if label_mapping is not None else None
        )
        record = process_trace_file(
            path, repeat=repeat, repeat_lean=repeat_lean,
            strict_artifacts=strict_artifacts, run_lean=run_lean,
            expected_label_override=expected_override,
        )
        report_name = safe_filename(f"{record['row']['trace_id']}_report.json")
        write_json(reports_dir / report_name, record["report"])
        records.append(record)
    if trace_dir.resolve() == (PROJECT_ROOT / "traces").resolve():
        active_primary = {
            (PROJECT_ROOT / record["row"]["lean_artifact"]).resolve()
            for record in records if record["row"]["lean_artifact"]
        }
        active_names = {path.name for path in active_primary}
        for directory in (
            PROJECT_ROOT / "generated" / "lean",
            PROJECT_ROOT / "lean" / "LeanCert" / "Generated",
        ):
            if directory.is_dir():
                for stale in directory.glob("*.lean"):
                    if stale.name not in active_names:
                        stale.unlink()
        active_reports = {
            safe_filename(f"{record['row']['trace_id']}_report.json")
            for record in records
        }
        for stale in reports_dir.glob("*_report.json"):
            if stale.name not in active_reports:
                stale.unlink()
    return records


def process_scalability_directory(
    trace_dir: Path,
    *,
    repeat: int = 30,
    repeat_lean: int = 3,
    lean_traces_per_size: int = 5,
    strict_artifacts: bool = True,
) -> list[dict]:
    """Time every diverse trace in Python and a fixed subset in Lean."""
    records: list[dict] = []
    files_by_size: dict[int, list[Path]] = {}
    for path in trace_dir.rglob("*.json"):
        if path.is_file():
            raw = read_json(path)
            files_by_size.setdefault(len(raw.get("events", [])), []).append(path)
    for event_count in sorted(files_by_size):
        for index, path in enumerate(sorted(files_by_size[event_count])):
            records.append(process_trace_file(
                path, repeat=repeat, repeat_lean=repeat_lean,
                strict_artifacts=strict_artifacts,
                run_lean=index < lean_traces_per_size,
            ))
    return records


def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _md(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_md(value) for value in row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def _git_commit() -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    result = subprocess.run(
        [git, "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
        capture_output=True, text=True, shell=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _lean_version() -> str | None:
    lean = shutil.which("lean")
    if not lean:
        return None
    result = subprocess.run([lean, "--version"], capture_output=True, text=True, shell=False)
    return result.stdout.strip() if result.returncode == 0 else None


def write_experiment_results(
    records: list[dict],
    *,
    trace_dir: Path,
    repeat: int,
    repeat_lean: int,
    strict_artifacts: bool = False,
    trace_generation_variants: str = "standard",
    paper_figures_only: bool = False,
    results_dir: Path = PROJECT_ROOT / "results",
    scalability_records: list[dict] | None = None,
) -> dict:
    results_dir.mkdir(parents=True, exist_ok=True)
    rows = [record["row"] for record in records]
    summary = compute_metrics(rows)
    failures = requirement_failures(records, RESULT_REQUIREMENTS)
    direct_failures = requirement_failures(records, RESULT_REQUIREMENTS, "direct")
    cascading_failures = requirement_failures(records, RESULT_REQUIREMENTS, "cascading")
    direct_count, cascading_count = classified_failure_entry_counts(records)
    summary["direct_failure_count"] = direct_count
    summary["cascading_failure_count"] = cascading_count
    summary["per_requirement_direct_failure_count"] = {
        item["requirement"]: item["failure_count"] for item in direct_failures
    }
    summary["per_requirement_cascading_failure_count"] = {
        item["requirement"]: item["failure_count"] for item in cascading_failures
    }
    csv_rows = [{key: row.get(key) for key in PER_TRACE_COLUMNS} for row in rows]
    _write_csv(results_dir / "per_trace_results.csv", csv_rows, PER_TRACE_COLUMNS)
    _write_csv(
        results_dir / "per_requirement_failures.csv", failures,
        ["requirement", "failure_count", "affected_traces", "failure_rate"],
    )
    _write_csv(
        results_dir / "per_requirement_failures_direct.csv", direct_failures,
        ["requirement", "failure_count", "affected_traces", "failure_rate"],
    )
    _write_csv(
        results_dir / "per_requirement_failures_cascading.csv", cascading_failures,
        ["requirement", "failure_count", "affected_traces", "failure_rate"],
    )
    confusion = [
        {"actual": "invalid", "predicted": "invalid", "count": summary["TP"]},
        {"actual": "invalid", "predicted": "valid", "count": summary["FN"]},
        {"actual": "valid", "predicted": "invalid", "count": summary["FP"]},
        {"actual": "valid", "predicted": "valid", "count": summary["TN"]},
    ]
    _write_csv(results_dir / "confusion_matrix.csv", confusion, ["actual", "predicted", "count"])

    dataset_manifest = PROJECT_ROOT / "datasets" / "manifests" / "download_manifest.json"
    manifest = read_json(dataset_manifest) if dataset_manifest.is_file() else []
    used_manifest = usable_manifest_records(manifest)
    artifact_rows = evaluate_artifact_native(used_manifest)
    native_columns = [
        "source_name", "dataset_family", "artifact_name", "artifact_kind", "local_path",
        "artifact_exists", "artifact_readable", "artifact_hash_match", "artifact_size_match",
        "artifact_provenance_complete", "artifact_signature_consistent", "overall_pass",
        "computed_sha256", "actual_size_bytes",
    ]
    _write_csv(results_dir / "artifact_native_results.csv", artifact_rows, native_columns)
    summary.update(artifact_native_metrics(artifact_rows))

    scalability_source_records = scalability_records if scalability_records is not None else records
    scalability_rows = [record["row"] for record in scalability_source_records if (
        "traces/scalability/" in str(record["row"].get("file_path", "")).replace("\\", "/").casefold()
    )]
    summary["scalability_trace_count"] = len(scalability_rows)
    summary["distinct_event_counts"] = sorted({int(row["event_count"]) for row in scalability_rows})
    scalability_results = []
    raw_python: list[dict] = []
    raw_lean: list[dict] = []
    for event_count in sorted({int(row["event_count"]) for row in scalability_rows}):
        group = [row for row in scalability_rows if int(row["event_count"]) == event_count]
        for row in group:
            for sample_index, sample in enumerate(row["validation_time_samples_us"], 1):
                raw_python.append({
                    "trace_id": row["trace_id"], "event_count": event_count,
                    "measured_repeat": sample_index, "validation_time_us": float(sample),
                    "warmup_runs_excluded": 10,
                })
            for sample_index, sample in enumerate(row.get("lean_warm_times_ms", []), 1):
                raw_lean.append({
                    "trace_id": row["trace_id"], "event_count": event_count,
                    "timing_kind": "warm", "measured_repeat": sample_index,
                    "lean_time_ms": float(sample),
                })
            if row.get("lean_cold_time_ms") not in (None, ""):
                raw_lean.append({
                    "trace_id": row["trace_id"], "event_count": event_count,
                    "timing_kind": "cold", "measured_repeat": 1,
                    "lean_time_ms": float(row["lean_cold_time_ms"]),
                })
        python_samples = [
            float(sample) for row in group for sample in row["validation_time_samples_us"]
        ]
        lean_times = [
            float(sample) for row in group for sample in row.get("lean_warm_times_ms", [])
        ]
        cold_times = [
            float(row["lean_cold_time_ms"]) for row in group
            if row.get("lean_cold_time_ms") not in (None, "")
        ]
        scalability_results.append({
            "event_count": event_count,
            "trace_count": len(group),
            "python_sample_count": len(python_samples),
            "mean_python_time_us": statistics.fmean(python_samples),
            "median_python_time_us": statistics.median(python_samples),
            "std_python_time_us": statistics.stdev(python_samples) if len(python_samples) > 1 else 0.0,
            "q1_python_time_us": percentile(python_samples, 0.25),
            "q3_python_time_us": percentile(python_samples, 0.75),
            "iqr_python_time_us": percentile(python_samples, 0.75) - percentile(python_samples, 0.25),
            "p95_python_time_us": percentile(python_samples, 0.95),
            "lean_trace_count": sum(bool(row.get("lean_warm_times_ms")) for row in group),
            "lean_sample_count": len(lean_times),
            "median_lean_time_ms": statistics.median(lean_times) if lean_times else None,
            "q1_lean_time_ms": percentile(lean_times, 0.25) if lean_times else None,
            "q3_lean_time_ms": percentile(lean_times, 0.75) if lean_times else None,
            "iqr_lean_time_ms": (
                percentile(lean_times, 0.75) - percentile(lean_times, 0.25)
                if lean_times else None
            ),
            "median_cold_lean_time_ms": statistics.median(cold_times) if cold_times else None,
        })
    _write_csv(
        results_dir / "scalability_raw_python.csv", raw_python,
        ["trace_id", "event_count", "measured_repeat", "validation_time_us", "warmup_runs_excluded"],
    )
    _write_csv(
        results_dir / "scalability_summary_python.csv", scalability_results,
        ["event_count", "trace_count", "python_sample_count", "mean_python_time_us",
         "median_python_time_us", "std_python_time_us", "q1_python_time_us",
         "q3_python_time_us", "iqr_python_time_us", "p95_python_time_us"],
    )
    _write_csv(
        results_dir / "scalability_raw_lean.csv", raw_lean,
        ["trace_id", "event_count", "timing_kind", "measured_repeat", "lean_time_ms"],
    )
    _write_csv(
        results_dir / "scalability_summary_lean.csv", scalability_results,
        ["event_count", "lean_trace_count", "lean_sample_count", "median_lean_time_ms",
         "q1_lean_time_ms", "q3_lean_time_ms", "iqr_lean_time_ms",
         "median_cold_lean_time_ms"],
    )

    sources = sorted({row["dataset_source"] for row in rows if row["dataset_source"]})
    lean_status = detect_lean()
    lean_checked = summary["lean_checked_traces"]
    lean_passed = summary["lean_passed_artifacts"]
    lean_failed = summary["lean_failed_artifacts"]
    generated_count = sum(bool(row["lean_artifact"]) for row in rows)
    lean_not_run_reason = ""
    if not lean_status["lean_available"]:
        lean_not_run_reason = "Lean 4 executable was not found in PATH."
    elif lean_checked == 0:
        lean_not_run_reason = "No generated Lean artifacts were proof-checked."
    summary.update({
        "lean_available": lean_status["lean_available"],
        "lake_available": lean_status["lake_available"],
        "lean_check_mode": lean_status["lean_check_mode"],
        "strict_artifacts": strict_artifacts,
    })
    write_json(results_dir / "evaluation_summary.json", summary)
    _write_csv(results_dir / "evaluation_summary.csv", [summary], list(summary))
    plot_warnings = generate_figures(
        [*rows, *scalability_rows], summary, direct_failures, cascading_failures,
        artifact_rows, scalability_rows,
        results_dir / "figures",
    )
    write_json(results_dir / "plot_warnings.json", plot_warnings)
    reason_path = results_dir / "lean_not_run_reason.txt"
    if lean_not_run_reason:
        reason_path.write_text(lean_not_run_reason + "\n", encoding="utf-8")
    else:
        reason_path.unlink(missing_ok=True)
    requested_toolchain = (
        (PROJECT_ROOT / "lean" / "lean-toolchain").read_text(encoding="utf-8").strip()
    )
    requested_version = requested_toolchain.rsplit(":", 1)[-1].removeprefix("v")
    active_lean_version = lean_status["lean_version"] or ""
    active_lake_version = lean_status["lake_version"] or ""
    def result_json(name: str, default: Any) -> Any:
        path = results_dir / name
        return read_json(path) if path.is_file() else default

    processing_path = PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    processing = read_json(processing_path) if processing_path.is_file() else []
    inspection_summary = result_json("image_inspection_summary.json", {})
    reference_summary = result_json("reference_checksum_summary.json", {})
    formalization_summary = result_json("formalization_coverage_summary.json", {})
    external_summary = result_json("external_case_summary.json", {
        "natural_external_case_count": 0,
        "natural_external_evaluation_status": "NOT_AVAILABLE",
    })
    lock_path = PROJECT_ROOT / "benchmark" / "manifests" / "benchmark_lock.json"
    benchmark_lock = read_json(lock_path) if lock_path.is_file() else {}
    experiment_manifest = {
        "prototype": "LeanCert-Forensics",
        "run_timestamp_utc": utc_now(),
        "python_version": sys.version,
        "platform": f"{platform.system()} {platform.release()}".strip(),
        "requested_lean_toolchain": requested_toolchain,
        "active_lean_version": active_lean_version,
        "active_lake_version": active_lake_version,
        "toolchain_match": bool(active_lean_version and requested_version in active_lean_version),
        "lean_available": lean_status["lean_available"],
        "lake_available": lean_status["lake_available"],
        "lean_version": active_lean_version,
        "lake_version": active_lake_version,
        "lean_check_mode": lean_status["lean_check_mode"],
        "trace_directory": relative_to_project(trace_dir),
        "benchmark_lock_sha256": benchmark_lock.get("benchmark_sha256", ""),
        "benchmark_blinded": "holdout_blinded" in relative_to_project(trace_dir),
        "development_mutation_count": benchmark_lock.get("development_mutation_count", 0),
        "holdout_mutation_count": benchmark_lock.get("holdout_mutation_count", 0),
        "natural_external_case_count": external_summary.get("natural_external_case_count", 0),
        "natural_external_evaluation_status": external_summary.get(
            "natural_external_evaluation_status", "NOT_AVAILABLE"
        ),
        "compressed_cfreds_artifacts": len(processing),
        "decompressed_cfreds_images": sum(
            row.get("decompression_status") == "PASSED" for row in processing
        ),
        "successfully_inspected_images": inspection_summary.get("successfully_inspected_images", 0),
        "external_reference_available_count": reference_summary.get(
            "external_reference_available_count", 0
        ),
        "external_reference_verified_count": reference_summary.get(
            "external_reference_verified_count", 0
        ),
        "external_reference_unavailable_count": reference_summary.get(
            "external_reference_unavailable_count", 0
        ),
        "catalogue_relative_formalization_rate": formalization_summary.get(
            "catalogue_relative_formalization_rate", 0.0
        ),
        "scalability_event_counts": summary["distinct_event_counts"],
        "scalability_traces_per_size": (
            min(
                (sum(int(row["event_count"]) == size for row in scalability_rows)
                 for size in summary["distinct_event_counts"]),
                default=0,
            )
        ),
        "python_timing_repeats": repeat,
        "lean_timing_repeats": repeat_lean,
        "public_sources_used": sources,
        "public_artifacts_used": summary["public_artifacts_used"],
        "nist_cfreds_artifacts_used": summary["nist_cfreds_artifacts_used"],
        "total_traces": summary["total_traces"],
        "valid_traces": summary["valid_traces"],
        "invalid_traces": summary["invalid_traces"],
        "scalability_trace_count": summary["scalability_trace_count"],
        "distinct_event_counts": summary["distinct_event_counts"],
        "python_repeat_count": repeat,
        "lean_checked_traces": lean_checked,
        "lean_passed_artifacts": lean_passed,
        "lean_failed_artifacts": lean_failed,
        "lean_proof_checking_completed": generated_count > 0 and lean_checked == generated_count,
        "strict_artifacts": strict_artifacts,
        "artifact_native_evaluation_completed": len(artifact_rows) == len(used_manifest),
        "controlled_process_evaluation_completed": len(rows) > 0,
        "residual_limitations": [
            "Controlled process violations are injected rather than naturally occurring.",
            "No independently labeled natural chain-of-custody failure corpus was available.",
            "Publisher checksum authenticity remains unverified where official references are unavailable.",
            "Catalogue-relative coverage does not establish domain-complete forensic formalization.",
            "Implementation-level differential checking shares the declared conceptual requirements.",
        ],
        "trace_generation_variants": trace_generation_variants,
        "paper_figures_only": paper_figures_only,
        "plot_warnings": plot_warnings,
        "git_commit": _git_commit(),
    }
    write_json(results_dir / "experiment_manifest.json", experiment_manifest)
    write_json(results_dir / "dataset_manifest_used.json", used_manifest)
    _write_tables(
        records, summary, artifact_rows, scalability_results, used_manifest,
        results_dir / "paper_tables",
    )
    return summary


def _write_tables(
    records: list[dict],
    summary: dict,
    artifact_rows: list[dict],
    scalability_results: list[dict],
    used_manifest: list[dict],
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    primary_names = {
        "table_dataset_sources.md", "table_artifact_integrity.md",
        "table_holdout_metrics.md", "table_metamorphic_differential_results.md",
        "table_formalization_coverage.md", "table_lean_semantics.md",
        "table_scalability.md", "table_external_case_status.md",
        "table_residual_limitations.md",
    }
    supplemental_names = {
        "table_image_inspection.md", "table_reference_checksum_verification.md",
        "table_unformalized_scope.md",
    }
    for stale in output_dir.glob("*.md"):
        if stale.name not in primary_names | supplemental_names:
            stale.unlink()

    dataset_rows = [[
        item.get("source_name", ""), item.get("dataset_family", ""),
        item.get("artifact_name", ""), item.get("artifact_kind", ""),
        item.get("size_bytes", 0), item.get("sha256", ""),
        item.get("download_status", ""),
    ] for item in used_manifest]
    (output_dir / "table_dataset_sources.md").write_text(
        _table(
            ["Source", "Dataset family", "Artifact", "Type", "Distribution bytes",
             "Local SHA-256", "Status"],
            dataset_rows,
        ),
        encoding="utf-8",
    )

    processing_path = PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    processing = read_json(processing_path) if processing_path.is_file() else []
    inspection_path = PROJECT_ROOT / "results" / "image_inspection_summary.json"
    inspection = read_json(inspection_path) if inspection_path.is_file() else {}
    references_path = PROJECT_ROOT / "results" / "reference_checksum_summary.json"
    references = read_json(references_path) if references_path.is_file() else {}
    cfreds = [row for row in artifact_rows if row.get("source_name") == "NIST CFReDS"]
    local_manifest_rate = (
        sum(row["artifact_hash_match"] and row["artifact_size_match"] for row in cfreds) / len(cfreds)
        if cfreds else 0.0
    )
    integrity_rows = [
        ["Local existence/readability", sum(row["artifact_exists"] and row["artifact_readable"] for row in cfreds), len(cfreds)],
        ["Local manifest consistency", sum(row["artifact_hash_match"] and row["artifact_size_match"] for row in cfreds), len(cfreds)],
        ["Decompression success", sum(row.get("decompression_status") == "PASSED" for row in processing), len(processing)],
        ["Semantic inspection passed", inspection.get("successfully_inspected_images", 0), inspection.get("image_count", 0)],
        ["Official checksum available", references.get("external_reference_available_count", 0), references.get("artifact_count", 0)],
        ["Official checksum verified", references.get("external_reference_verified_count", 0), references.get("external_reference_available_count", 0)],
    ]
    (output_dir / "table_artifact_integrity.md").write_text(
        _table(["Integrity dimension", "Count", "Denominator"], integrity_rows)
        + "\nLocal manifest consistency is distinct from official publisher-reference verification. "
        "Unavailable official checksums are not passes.\n",
        encoding="utf-8",
    )

    metric_keys = [
        ("Holdout traces", "total_traces"), ("Valid holdout traces", "valid_traces"),
        ("Invalid holdout traces", "invalid_traces"), ("TP", "TP"), ("TN", "TN"),
        ("FP", "FP"), ("FN", "FN"), ("Accuracy", "accuracy"),
        ("Precision", "precision"), ("Recall", "recall"), ("Specificity", "specificity"),
        ("F1", "f1"), ("False acceptance rate", "false_acceptance_rate"),
        ("False rejection rate", "false_rejection_rate"),
    ]
    (output_dir / "table_holdout_metrics.md").write_text(
        _table(["Locked blinded holdout metric", "Value"], [
            [label, summary.get(key)] for label, key in metric_keys
        ])
        + "\nThe locked holdout benchmark reduces implementation coupling but does not make "
        "controlled perturbations equivalent to naturally occurring failures.\n",
        encoding="utf-8",
    )

    metamorphic_path = PROJECT_ROOT / "results" / "metamorphic_summary.json"
    metamorphic = read_json(metamorphic_path) if metamorphic_path.is_file() else {}
    differential_path = PROJECT_ROOT / "results" / "differential_validation.csv"
    differential_rows = []
    if differential_path.is_file():
        with differential_path.open(encoding="utf-8", newline="") as stream:
            differential_rows = list(csv.DictReader(stream))
    agreements = sum(str(row.get("agreement", "")).casefold() == "true" for row in differential_rows)
    (output_dir / "table_metamorphic_differential_results.md").write_text(
        _table(["Measure", "Value"], [
            ["Metamorphic tests", metamorphic.get("metamorphic_test_count", 0)],
            ["Metamorphic tests passed", metamorphic.get("metamorphic_tests_passed", 0)],
            ["Metamorphic tests failed", metamorphic.get("metamorphic_tests_failed", 0)],
            ["Production/reference comparisons", len(differential_rows)],
            ["Production/reference agreements", agreements],
            ["Production/reference disagreements", len(differential_rows) - agreements],
        ])
        + "\nThe reference validator provides implementation-level differential checking for "
        "a subset; it is not fully independent of the declared conceptual model.\n",
        encoding="utf-8",
    )

    lean_rows = [
        ["Lean files compiled", sum(row.get("lean_file_compiled", False) for row in (record["row"] for record in records))],
        ["Lean compilation failures", sum(row.get("lean_check_status") == "FAILED" for row in (record["row"] for record in records))],
        ["Valid traces with checked ValidTrace theorem", sum(
            row.get("is_expected_valid") and row.get("trace_validity_theorem_checked")
            for row in (record["row"] for record in records)
        )],
        ["Invalid traces with no ValidTrace theorem emitted", sum(
            not row.get("is_expected_valid") and not row.get("trace_validity_theorem_emitted")
            for row in (record["row"] for record in records)
        )],
        ["Mean warm Lean time ms", summary.get("mean_lean_check_time_ms")],
        ["Median warm Lean time ms", summary.get("median_lean_check_time_ms")],
    ]
    cold_times = [
        float(record["row"]["lean_cold_time_ms"]) for record in records
        if record["row"].get("lean_cold_time_ms") not in (None, "")
    ]
    lean_rows.append(["Median cold startup time ms", statistics.median(cold_times) if cold_times else None])
    (output_dir / "table_lean_semantics.md").write_text(
        _table(["Lean semantic measure", "Value"], lean_rows)
        + "\nSuccessful Lean checking establishes acceptance of emitted propositions by the "
        "tested Lean kernel; invalid traces do not receive a ValidTrace theorem.\n",
        encoding="utf-8",
    )

    (output_dir / "table_scalability.md").write_text(
        _table(
            ["Events", "Python traces", "Python median us", "Python IQR us", "Python P95 us",
             "Lean traces", "Lean warm median ms", "Lean IQR ms", "Lean cold median ms"],
            [[
                row["event_count"], row["trace_count"], row["median_python_time_us"],
                row["iqr_python_time_us"], row["p95_python_time_us"],
                row["lean_trace_count"], row["median_lean_time_ms"],
                row["iqr_lean_time_ms"], row["median_cold_lean_time_ms"],
            ] for row in scalability_results],
        )
        + "\nTimes are descriptive measurements; no asymptotic complexity claim is inferred "
        "from visual appearance.\n",
        encoding="utf-8",
    )

    external_path = PROJECT_ROOT / "results" / "external_case_summary.json"
    external = read_json(external_path) if external_path.is_file() else {
        "natural_external_case_count": 0,
        "natural_external_evaluation_status": "NOT_AVAILABLE",
        "residual_limitation": "No independently labeled natural chain-of-custody failure corpus was available.",
    }
    (output_dir / "table_external_case_status.md").write_text(
        _table(["Measure", "Value"], [
            ["Independently labeled case count", external.get("natural_external_case_count", 0)],
            ["Evaluation status", external.get("natural_external_evaluation_status", "NOT_AVAILABLE")],
            ["Residual limitation", external.get("residual_limitation", "")],
        ]),
        encoding="utf-8",
    )
    limitations = [
        ["Fixed", "One-trace-per-size scalability design", "15 structurally distinct traces at each declared size."],
        ["Fixed", "Decompressed-image hashes absent", "Compressed and decompressed hashes are recorded separately."],
        ["Fixed", "Lean compilation conflated with trace validity", "ValidTrace theorem metadata is recorded independently."],
        ["Fixed", "Formalization coverage unmeasured", "Catalogue-relative audit is generated."],
        ["Fixed", "No locked/blinded holdout", "Frozen mutation digests and label-free validation payloads are used."],
        ["Mitigated", "Validator/benchmark conceptual coupling", "Physical/code separation, blinding, and differential checks reduce coupling."],
        ["Mitigated", "Reliance on controlled violations", "Held-out mutation families are used, but they remain controlled."],
        ["Mitigated", "External artifact authenticity", "Official references are verified only where available."],
        ["Mitigated", "Formalization completeness", "Declared catalogue coverage is measured with known exclusions."],
        ["Unresolved", "Natural custody-failure corpus", "No independently labeled natural chain-of-custody failure corpus was available."],
    ]
    (output_dir / "table_residual_limitations.md").write_text(
        _table(["Classification", "Limitation", "Scientific status"], limitations),
        encoding="utf-8",
    )
    return

    # Legacy table code retained below for source compatibility; the publication package
    # returns after producing the required tables above.
    table_names = {
        "table_dataset_sources.md",
        "table_metrics.md",
        "table_artifact_native_validation.md",
        "table_lean_checking.md",
        "table_scalability.md",
    }
    for stale in output_dir.glob("*.md"):
        if stale.name not in table_names:
            stale.unlink()

    dataset_rows = [[
        item.get("source_name", ""),
        item.get("dataset_family", ""),
        item.get("artifact_name", ""),
        item.get("artifact_kind", ""),
        item.get("size_bytes", 0),
        item.get("sha256", ""),
        item.get("download_status", ""),
    ] for item in used_manifest]
    (output_dir / "table_dataset_sources.md").write_text(
        _table(
            ["Source", "Dataset Family", "Artifact", "Artifact Type", "Size",
             "SHA-256", "Registration Status"],
            dataset_rows,
        ),
        encoding="utf-8",
    )

    metric_keys = [
        ("TP", "TP"), ("TN", "TN"), ("FP", "FP"), ("FN", "FN"),
        ("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"),
        ("Specificity", "specificity"), ("F1", "f1"),
        ("False Acceptance Rate", "false_acceptance_rate"),
        ("False Rejection Rate", "false_rejection_rate"),
    ]
    metric_content = _table(
        ["Metric", "Value"],
        [[label, summary[key]] for label, key in metric_keys],
    )
    metric_content += (
        "\nPerfect classification on this controlled benchmark demonstrates enforcement of "
        "the modeled requirements over the evaluated traces. It does not imply universal "
        "forensic correctness or legal admissibility.\n"
    )
    (output_dir / "table_metrics.md").write_text(metric_content, encoding="utf-8")

    native_content = _table(
        ["Artifact", "Exists", "Readable", "Hash Match", "Size Match",
         "Provenance Complete", "Signature Consistent"],
        [[
            row["artifact_name"], row["artifact_exists"], row["artifact_readable"],
            row["artifact_hash_match"], row["artifact_size_match"],
            row["artifact_provenance_complete"], row["artifact_signature_consistent"],
        ] for row in artifact_rows],
    )
    native_content += (
        "\nArtifact-native checks establish local availability, readability, cryptographic "
        "binding, size consistency, provenance completeness, and distribution-signature "
        "consistency for the registered bytes.\n"
    )
    (output_dir / "table_artifact_native_validation.md").write_text(
        native_content, encoding="utf-8"
    )

    grouped = {
        "Controlled benchmark": [
            record["row"] for record in records
            if "traces/scalability/" not in record["row"]["file_path"].replace("\\", "/").casefold()
        ],
        "Scalability traces": [
            record["row"] for record in records
            if "traces/scalability/" in record["row"]["file_path"].replace("\\", "/").casefold()
        ],
    }
    lean_rows = []
    for name, group in grouped.items():
        checked = [row for row in group if row["lean_check_status"] != "NOT_RUN"]
        times = [
            float(row["lean_check_time_ms"]) for row in checked
            if row.get("lean_check_time_ms") not in (None, "")
        ]
        lean_rows.append([
            name,
            len(checked),
            sum(row["lean_check_status"] == "PASSED" for row in checked),
            sum(row["lean_check_status"] == "FAILED" for row in checked),
            statistics.fmean(times) if times else None,
            statistics.median(times) if times else None,
        ])
    lean_content = _table(
        ["Trace Group", "Checked", "Passed", "Failed", "Mean Time ms", "Median Time ms"],
        lean_rows,
    )
    lean_content += (
        "\nLean proof checking establishes that generated formal artifacts and emitted proof "
        "obligations are accepted by the tested Lean kernel. It does not establish factual "
        "truth of external evidence or correctness of external forensic tools.\n"
    )
    (output_dir / "table_lean_checking.md").write_text(lean_content, encoding="utf-8")

    (output_dir / "table_scalability.md").write_text(
        _table(
            ["Event Count", "Trace Count", "Median Python Time us",
             "P95 Python Time us", "Median Lean Time ms"],
            [[
                row["event_count"], row["trace_count"], row["median_python_time_us"],
                row["p95_python_time_us"], row["median_lean_time_ms"],
            ] for row in scalability_results],
        ),
        encoding="utf-8",
    )
    return

    # Kept unreachable only for compatibility with older source references.
    trace_rows = []
    for record in records:
        row = record["row"]
        trace_rows.append([
            row["trace_id"], row["dataset_source"], row["artifact_name"], row["expected_label"],
            row["predicted_status"], row["correct"], row["failed_requirements"] or "None",
            row["validation_time_ms"], row["lean_check_status"],
        ])
    (output_dir / "table_trace_results.md").write_text(_table(
        ["Trace", "Dataset Source", "Artifact", "Expected Label", "Predicted Status",
         "Correct", "Failed Requirements", "Validation Time ms", "Lean Status"],
        trace_rows,
    ), encoding="utf-8")
    metric_values = [
        ("Lean Available", experiment_manifest["lean_available"]),
        ("Lake Available", experiment_manifest["lake_available"]),
        ("Lean Check Mode", experiment_manifest["lean_check_mode"]),
        ("Lean Checked Traces", summary["lean_checked_traces"]),
        ("Lean Passed Artifacts", summary["lean_passed_artifacts"]),
        ("Lean Failed Artifacts", summary["lean_failed_artifacts"]),
        ("Mean Lean Check Time ms", summary["mean_lean_check_time_ms"]),
        ("Median Lean Check Time ms", summary["median_lean_check_time_ms"]),
        ("Public Sources Used", summary["public_sources_used"]),
        ("Public Artifacts Used", summary["public_artifacts_used"]),
        ("Strict Artifact Mode", experiment_manifest["strict_artifacts"]),
        ("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"),
        ("Specificity", "specificity"), ("F1", "f1"),
        ("False Acceptance Rate", "false_acceptance_rate"),
        ("False Rejection Rate", "false_rejection_rate"),
        ("Mean Validation Time ms", "mean_validation_time_ms"),
        ("Median Validation Time ms", "median_validation_time_ms"),
    ]
    metric_rows = []
    for label, value in metric_values:
        metric_rows.append([label, summary[value] if isinstance(value, str) and value in summary else value])
    (output_dir / "table_metrics.md").write_text(
        _table(["Metric", "Value"], metric_rows),
        encoding="utf-8",
    )
    (output_dir / "table_requirement_failures.md").write_text(_table(
        ["Requirement", "Failed Traces", "Failure Rate"],
        [[item["requirement"], item["affected_traces"] or "None", item["failure_rate"]]
         for item in failures],
    ), encoding="utf-8")
    direct_map = {item["requirement"]: item for item in direct_failures}
    cascading_map = {item["requirement"]: item for item in cascading_failures}
    (output_dir / "table_direct_vs_cascading_failures.md").write_text(_table(
        ["Requirement", "Direct Failed Traces", "Cascading Failed Traces"],
        [[
            requirement,
            direct_map[requirement]["affected_traces"] or "None",
            cascading_map[requirement]["affected_traces"] or "None",
        ] for requirement in RESULT_REQUIREMENTS],
    ), encoding="utf-8")
    scenarios = []
    for record in records:
        raw = record["raw"] if isinstance(record["raw"], dict) else {}
        metadata = raw.get("evaluation_metadata", {})
        origin = raw.get("dataset_origin", {})
        scenarios.append([
            metadata.get("scenario", "Malformed trace"),
            origin.get("source_name", ""),
            metadata.get("injected_violation", record["report"].get("parse_error", "")),
            metadata.get("expected_outcome", "FAILED"),
            metadata.get("target_requirement", "SchemaValidation"),
        ])
    (output_dir / "table_validation_scenarios.md").write_text(_table(
        ["Scenario", "Dataset Source", "Injected Violation", "Expected Outcome",
         "Detected By Requirement"], scenarios,
    ), encoding="utf-8")
    manifest_path = PROJECT_ROOT / "datasets" / "manifests" / "download_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else []
    dataset_rows = [[
        item.get("source_name", ""), item.get("artifact_name", ""), item.get("artifact_kind", ""),
        item.get("source_url", ""), item.get("sha256", ""), item.get("size_bytes", 0),
        item.get("download_status", ""), item.get("license_or_usage_note", ""),
    ] for item in manifest]
    (output_dir / "table_dataset_sources.md").write_text(_table(
        ["Dataset Source", "Artifact Name", "Artifact Kind", "Source URL", "SHA-256",
         "Size Bytes", "Download Status", "Usage Note"], dataset_rows,
    ), encoding="utf-8")
    (output_dir / "table_lean_checking.md").write_text(_table(
        ["Trace", "Lean Artifact", "Lean Status", "Lean Check Time ms", "Notes"],
        [[
            record["row"]["trace_id"], record["row"]["lean_artifact"] or "Not generated",
            record["row"]["lean_check_status"], record["row"]["lean_check_time_ms"],
            (
                "Generated artifact proof-checked."
                if record["row"]["lean_check_status"] == "PASSED"
                else record["report"].get("lean_stderr", "") or "Proof checking not run."
            ),
        ] for record in records],
    ), encoding="utf-8")
    limitations = []
    for item in manifest:
        status = item.get("download_status", "")
        if item.get("source_name") == "NIST CFReDS" and status == "manual_download_required":
            limitation = "No stable small direct artifact URL is configured."
            action = "Download a public CFReDS artifact and register it locally."
        elif item.get("artifact_kind") == "report":
            limitation = "Scenario documentation broadens provenance, not binary evidence-type coverage."
            action = "Interpret separately from disk, memory, and packet artifacts."
        else:
            limitation = "Small public sample; it does not represent all forensic evidence."
            action = "Add further attributed public artifacts for broader coverage."
        limitations.append([
            item.get("source_name", ""), status, limitation, action,
        ])
    (output_dir / "table_dataset_limitations.md").write_text(_table(
        ["Source", "Status", "Limitation", "Action Needed"], limitations,
    ), encoding="utf-8")
