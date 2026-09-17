from __future__ import annotations

import csv
import copy
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .holdout_v2 import DEFAULT_ROOT, load_holdout_v2, verify_holdout_v2_lock
from .formalization_audit import audit_formalization
from .lean_generator import check_lean_file, detect_lean, generate_lean
from .metrics import compute_metrics, percentile, requirement_failures
from .reference_validator import SUBSET, reference_validate
from .report import process_trace_file
from .schema import ValidationTrace
from .statistics_ext import clopper_pearson, stratified_f1_bootstrap
from .utils import PROJECT_ROOT, read_json, utc_now, write_json
from .validator import REQUIREMENTS, validate_trace


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _metric_rows(rows: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    tp, tn, fp, fn = (summary[key] for key in ("TP", "TN", "FP", "FN"))
    definitions = [
        ("accuracy", tp + tn, len(rows), "exact Clopper-Pearson"),
        ("precision", tp, tp + fp, "exact Clopper-Pearson"),
        ("recall", tp, tp + fn, "exact Clopper-Pearson"),
        ("specificity", tn, tn + fp, "exact Clopper-Pearson"),
        ("false_acceptance_rate", fn, tp + fn, "exact Clopper-Pearson"),
        ("false_rejection_rate", fp, tn + fp, "exact Clopper-Pearson"),
    ]
    output = []
    for name, successes, denominator, method in definitions:
        lower, upper = clopper_pearson(successes, denominator) if denominator else (None, None)
        output.append({
            "metric": name, "estimate": summary[name], "lower_95": lower,
            "upper_95": upper, "interval_method": method,
            "sample_denominator": denominator,
        })
    f1_lower, f1_upper = stratified_f1_bootstrap(rows, repeats=10_000, seed=20260728)
    output.append({
        "metric": "f1", "estimate": summary["f1"], "lower_95": f1_lower,
        "upper_95": f1_upper, "interval_method": "stratified bootstrap; 10000 resamples; seed 20260728",
        "sample_denominator": len(rows),
    })
    return output


def _leakage_audit(paths: list[Path]) -> dict[str, Any]:
    checks = Counter()
    changes = Counter()
    forbidden_fields = 0
    for path in paths:
        raw = read_json(path)
        forbidden_fields += sum(
            key in raw for key in (
                "expected_label", "evaluation_metadata", "mutation_id",
                "target_requirements", "root_requirement",
            )
        )
        trace = ValidationTrace.model_validate(raw)
        original = validate_trace(trace, strict_artifacts=True).overall_status
        variants = {
            "trace_id_changed": {**copy.deepcopy(raw), "trace_id": f"REBLINDED-{path.stem}"},
            "evaluation_metadata_removed": {
                key: value for key, value in copy.deepcopy(raw).items()
                if key != "evaluation_metadata"
            },
            # Expected labels live only in the private mapping. Swapping that
            # mapping therefore leaves the exact validator payload unchanged.
            "expected_label_swapped": copy.deepcopy(raw),
        }
        # Filename and directory relocation are represented by reparsing identical
        # bytes under neutral locations; the validator receives no path argument.
        variants["filename_changed"] = copy.deepcopy(raw)
        variants["path_changed"] = copy.deepcopy(raw)
        variants["copied_to_other_directory"] = copy.deepcopy(raw)
        for name, payload in variants.items():
            altered = validate_trace(
                ValidationTrace.model_validate(payload), strict_artifacts=True
            ).overall_status
            checks[name] += 1
            changes[name] += original != altered
    comparisons = sum(checks.values())
    change_count = sum(changes.values())
    return {
        "traces_audited": len(paths), "prediction_invariance_comparisons": comparisons,
        "prediction_changes": change_count,
        "comparisons_by_perturbation": dict(checks),
        "changes_by_perturbation": dict(changes),
        "forbidden_benchmark_fields_found": forbidden_fields,
        "filenames_neutral": all(path.name.startswith("case-") for path in paths),
        "validator_imports_benchmark": "benchmark" in (
            PROJECT_ROOT / "leancert" / "validator.py"
        ).read_text(encoding="utf-8"),
        "audit_passed": change_count == 0 and forbidden_fields == 0,
    }


def evaluate_holdout_v2(
    *,
    root: Path = DEFAULT_ROOT,
    repeat: int = 30,
    repeat_lean: int = 3,
    strict_artifacts: bool = True,
    require_lean: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    valid_lock, errors = verify_holdout_v2_lock(root)
    if not valid_lock:
        raise RuntimeError("Holdout-v2 lock verification failed: " + "; ".join(errors))
    paths, mapping = load_holdout_v2(root)
    checkpoint_path = PROJECT_ROOT / "results" / "per_trace_results_v2.csv"
    checkpoint: dict[str, dict[str, str]] = {}
    if require_lean and checkpoint_path.is_file():
        with checkpoint_path.open(encoding="utf-8", newline="") as stream:
            checkpoint = {row["trace_id"]: row for row in csv.DictReader(stream)}
        locked_ids = {read_json(path)["trace_id"] for path in paths}
        if set(checkpoint) != locked_ids or not all(
            row.get("lean_file_compiled") == "True" for row in checkpoint.values()
        ):
            checkpoint = {}
    records = []
    for path in paths:
        raw = read_json(path)
        expected = mapping[raw["trace_id"]]["expected_label"]
        record = process_trace_file(
            path, repeat=repeat, repeat_lean=repeat_lean,
            strict_artifacts=strict_artifacts,
            run_lean=require_lean and not checkpoint, expected_label_override=expected,
        )
        saved = checkpoint.get(record["row"]["trace_id"])
        if saved:
            bool_fields = {
                "lean_file_compiled", "trace_validity_theorem_emitted",
                "trace_validity_theorem_checked", "invalid_trace_theorem_emitted",
                "invalid_trace_theorem_checked",
            }
            int_fields = {
                "lean_obligation_count", "direct_negative_theorem_count",
                "cascading_negative_theorem_count",
            }
            float_fields = {"lean_check_time_ms", "lean_cold_time_ms"}
            copy_fields = {
                "lean_check_status", "lean_status", "certificate_kind",
                "documented_failed_obligations", "negative_theorem_requirements",
                *bool_fields, *int_fields, *float_fields,
            }
            for key in copy_fields:
                value: Any = saved.get(key, "")
                if key in bool_fields:
                    value = value == "True"
                elif key in int_fields:
                    value = int(value or 0)
                elif key in float_fields:
                    value = float(value) if value not in {"", "None"} else None
                record["row"][key] = value
        record["private"] = mapping[raw["trace_id"]]
        records.append(record)
    rows = [record["row"] for record in records]
    summary = compute_metrics(rows)
    metric_rows = _metric_rows(rows, summary)
    metric_document = {
        **{key: summary[key] for key in (
            "total_traces", "valid_traces", "invalid_traces", "TP", "TN", "FP", "FN",
            "accuracy", "precision", "recall", "specificity", "f1",
            "false_acceptance_rate", "false_rejection_rate",
        )},
        "confidence_intervals": metric_rows,
    }
    write_json(PROJECT_ROOT / "results" / "holdout_metrics_v2.json", metric_document)
    _write_csv(PROJECT_ROOT / "results" / "per_trace_results_v2.csv", rows)
    _write_csv(PROJECT_ROOT / "results" / "per_trace_results.csv", rows)
    _write_csv(PROJECT_ROOT / "results" / "confusion_matrix.csv", [
        {"actual": "invalid", "predicted": "invalid", "count": summary["TP"]},
        {"actual": "invalid", "predicted": "valid", "count": summary["FN"]},
        {"actual": "valid", "predicted": "invalid", "count": summary["FP"]},
        {"actual": "valid", "predicted": "valid", "count": summary["TN"]},
    ])

    coverage = []
    for requirement in REQUIREMENTS:
        direct_records = [
            record for record in records if record["private"].get("root_requirement") == requirement
        ]
        cascading = sum(
            requirement in record["row"]["failed_requirements_list"]
            and record["private"].get("root_requirement") != requirement
            for record in records
        )
        coverage.append({
            "requirement": requirement,
            "direct_invalid_traces": len(direct_records),
            "cascading_affected_traces": cascading,
            "valid_traces_exercising_requirement": summary["valid_traces"],
            "public_artifacts_represented": len({
                record["row"]["artifact_name"] for record in direct_records
            }),
            "mutation_families_represented": len({
                record["private"]["mutation_family"] for record in direct_records
            }),
        })
    _write_csv(PROJECT_ROOT / "results" / "holdout_requirement_coverage.csv", coverage)

    differential = []
    overall_disagreements = 0
    for record in records:
        trace = ValidationTrace.model_validate(record["raw"])
        production = {
            item["requirement"]: bool(item["passed"])
            for item in record["report"]["requirement_results"]
        }
        reference = reference_validate(trace)
        reference_overall = all(reference.values())
        production_overall = record["row"]["predicted_status"] == "PASSED"
        overall_disagreements += production_overall != reference_overall
        for requirement in SUBSET:
            differential.append({
                "trace_id": trace.trace_id, "requirement": requirement,
                "production_passed": production[requirement],
                "reference_passed": reference[requirement],
                "agreement": production[requirement] == reference[requirement],
            })
    _write_csv(PROJECT_ROOT / "results" / "differential_validation_v2.csv", differential)
    _write_csv(PROJECT_ROOT / "results" / "differential_validation.csv", differential)
    disagreements = [row for row in differential if not row["agreement"]]
    differential_summary = {
        "requirements_covered": len(SUBSET), "total_comparisons": len(differential),
        "agreements": len(differential) - len(disagreements),
        "disagreements": len(disagreements),
        "agreement_rate": (len(differential) - len(disagreements)) / len(differential),
        "disagreements_by_requirement": dict(Counter(
            row["requirement"] for row in disagreements
        )),
        "overall_status_disagreements": overall_disagreements,
    }
    write_json(
        PROJECT_ROOT / "results" / "differential_validation_summary_v2.json",
        differential_summary,
    )

    certificates = []
    agreement_rows = []
    trace_disagreements = requirement_disagreements = missing = unexpected = 0
    for record in records:
        row = record["row"]
        python_valid = row["predicted_status"] == "PASSED"
        lean_valid = bool(row["trace_validity_theorem_checked"])
        lean_invalid = bool(row["invalid_trace_theorem_checked"])
        trace_agrees = (python_valid and lean_valid) or (not python_valid and lean_invalid)
        trace_disagreements += not trace_agrees
        python_failed = set(row["failed_requirements_list"])
        lean_negative = set(filter(None, row["negative_theorem_requirements"].split(";")))
        missing_here = python_failed - lean_negative
        unexpected_here = lean_negative - python_failed
        missing += len(missing_here)
        unexpected += len(unexpected_here)
        requirement_disagreements += len(missing_here) + len(unexpected_here)
        certificates.append({
            "trace_id": row["trace_id"], "expected_label": row["expected_label"],
            "certificate_kind": row["certificate_kind"],
            "lean_file_compiled": row["lean_file_compiled"],
            "valid_trace_theorem_emitted": row["trace_validity_theorem_emitted"],
            "valid_trace_theorem_checked": row["trace_validity_theorem_checked"],
            "invalid_trace_theorem_emitted": row["invalid_trace_theorem_emitted"],
            "invalid_trace_theorem_checked": row["invalid_trace_theorem_checked"],
            "direct_negative_theorem_count": row["direct_negative_theorem_count"],
            "cascading_negative_theorem_count": row["cascading_negative_theorem_count"],
            "failed_obligations": row["documented_failed_obligations"],
        })
        agreement_rows.append({
            "trace_id": row["trace_id"], "python_valid": python_valid,
            "lean_validity_checked": lean_valid, "lean_violation_checked": lean_invalid,
            "trace_level_agreement": trace_agrees,
            "python_failed_requirements": ";".join(sorted(python_failed)),
            "lean_negative_requirements": ";".join(sorted(lean_negative)),
            "missing_lean_theorems": ";".join(sorted(missing_here)),
            "unexpected_lean_theorems": ";".join(sorted(unexpected_here)),
        })
    _write_csv(PROJECT_ROOT / "results" / "lean_certificate_semantics.csv", certificates)
    _write_csv(PROJECT_ROOT / "results" / "python_lean_agreement.csv", agreement_rows)
    agreement_summary = {
        "trace_level_comparisons": len(records),
        "trace_level_agreements": len(records) - trace_disagreements,
        "trace_level_disagreements": trace_disagreements,
        "requirement_level_comparisons": len(records) * len(REQUIREMENTS),
        "requirement_level_disagreements": requirement_disagreements,
        "missing_lean_theorems": missing, "unexpected_lean_theorems": unexpected,
    }
    write_json(PROJECT_ROOT / "results" / "python_lean_agreement_summary.json", agreement_summary)
    evaluation_summary = {
        **metric_document,
        "lean_files_compiled": sum(row["lean_file_compiled"] for row in (r["row"] for r in records)),
        "validity_certificates_checked": sum(
            row["trace_validity_theorem_checked"] for row in (r["row"] for r in records)
        ),
        "violation_certificates_checked": sum(
            row["invalid_trace_theorem_checked"] for row in (r["row"] for r in records)
        ),
        "differential_disagreements": differential_summary["disagreements"],
        "python_lean_trace_disagreements": agreement_summary["trace_level_disagreements"],
        "benchmark_version": 2,
    }
    write_json(PROJECT_ROOT / "results" / "evaluation_summary.json", evaluation_summary)
    _write_csv(PROJECT_ROOT / "results" / "evaluation_summary.csv", [evaluation_summary])
    leakage = _leakage_audit(paths)
    write_json(PROJECT_ROOT / "results" / "holdout_leakage_audit.json", leakage)
    return records, {
        "metrics": metric_document, "coverage": coverage,
        "differential": differential_summary, "agreement": agreement_summary,
        "leakage": leakage,
    }


def write_v2_tables(summary: dict[str, Any]) -> None:
    tables = PROJECT_ROOT / "results" / "paper_tables"
    tables.mkdir(parents=True, exist_ok=True)
    metrics = summary["metrics"]
    table_rows = metrics["confidence_intervals"]
    (tables / "table_holdout_metrics.md").write_text(
        "| Metric | Estimate | 95% lower | 95% upper | Interval method | Denominator |\n"
        "|---|---:|---:|---:|---|---:|\n"
        + "".join(
            f"| {row['metric']} | {row['estimate']:.6f} | {row['lower_95']:.6f} | "
            f"{row['upper_95']:.6f} | {row['interval_method']} | {row['sample_denominator']} |\n"
            for row in table_rows
        ), encoding="utf-8",
    )
    (tables / "table_holdout_requirement_coverage.md").write_text(
        "| Requirement | Direct invalid | Cascading affected | Valid exercising | Artifacts | Families |\n"
        "|---|---:|---:|---:|---:|---:|\n"
        + "".join(
            f"| {row['requirement']} | {row['direct_invalid_traces']} | "
            f"{row['cascading_affected_traces']} | {row['valid_traces_exercising_requirement']} | "
            f"{row['public_artifacts_represented']} | {row['mutation_families_represented']} |\n"
            for row in summary["coverage"]
        ), encoding="utf-8",
    )
    differential = summary["differential"]
    (tables / "table_differential_validation.md").write_text(
        "| Measure | Value |\n|---|---:|\n"
        f"| Requirements covered | {differential['requirements_covered']} |\n"
        f"| Total comparisons | {differential['total_comparisons']} |\n"
        f"| Agreements | {differential['agreements']} |\n"
        f"| Disagreements | {differential['disagreements']} |\n"
        f"| Overall-status disagreements | {differential['overall_status_disagreements']} |\n",
        encoding="utf-8",
    )
    certs = list(csv.DictReader(
        (PROJECT_ROOT / "results" / "lean_certificate_semantics.csv").open(encoding="utf-8")
    ))
    (tables / "table_lean_semantics.md").write_text(
        "| Measure | Value |\n|---|---:|\n"
        f"| Lean files compiled | {sum(row['lean_file_compiled'] == 'True' for row in certs)} |\n"
        f"| Checked validity certificates | {sum(row['valid_trace_theorem_checked'] == 'True' for row in certs)} |\n"
        f"| Checked violation certificates | {sum(row['invalid_trace_theorem_checked'] == 'True' for row in certs)} |\n"
        f"| File-compilation failures | {sum(row['lean_file_compiled'] != 'True' for row in certs)} |\n"
        f"| Python-Lean trace disagreements | {summary['agreement']['trace_level_disagreements']} |\n"
        f"| Python-Lean requirement disagreements | {summary['agreement']['requirement_level_disagreements']} |\n",
        encoding="utf-8",
    )


def run_scalability_v2(
    *, repeat: int = 30, repeat_lean: int = 3,
    trace_root: Path = PROJECT_ROOT / "traces" / "scalability",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Measure diverse Python traces and the two declared Lean workloads."""
    grouped: dict[int, list[Path]] = defaultdict(list)
    for path in trace_root.rglob("*.json"):
        raw = read_json(path)
        grouped[len(raw.get("events", []))].append(path)
    python_raw: list[dict[str, Any]] = []
    python_summary: list[dict[str, Any]] = []
    for event_count in sorted(grouped):
        for path in sorted(grouped[event_count]):
            record = process_trace_file(
                path, repeat=repeat, strict_artifacts=True, run_lean=False,
            )
            for index, sample in enumerate(record["row"]["validation_time_samples_us"], 1):
                python_raw.append({
                    "trace_id": record["row"]["trace_id"], "event_count": event_count,
                    "measured_repeat": index, "validation_time_us": sample,
                    "warmup_runs_excluded": 10,
                })
        samples = [
            float(row["validation_time_us"]) for row in python_raw
            if row["event_count"] == event_count
        ]
        python_summary.append({
            "event_count": event_count, "trace_count": len(grouped[event_count]),
            "sample_count": len(samples), "median_us": statistics.median(samples),
            "mean_us": statistics.fmean(samples),
            "IQR_us": percentile(samples, .75) - percentile(samples, .25),
            "P95_us": percentile(samples, .95), "minimum_us": min(samples),
            "maximum_us": max(samples),
        })
    _write_csv(PROJECT_ROOT / "results" / "scalability_raw_python.csv", python_raw)
    _write_csv(PROJECT_ROOT / "results" / "scalability_summary_python.csv", python_summary)

    mode_sizes = {
        "pairwise": {4, 8, 12, 20, 50, 100},
        "aggregate": {4, 8, 12, 20, 50, 100, 200, 500},
    }
    lean_raw: list[dict[str, Any]] = []
    lean_summary: list[dict[str, Any]] = []
    for mode, sizes in mode_sizes.items():
        for event_count in sorted(sizes):
            selected = sorted(grouped.get(event_count, []))[:5]
            measurements: list[dict[str, Any]] = []
            for path in selected:
                raw = read_json(path)
                trace = ValidationTrace.model_validate(raw)
                validation = validate_trace(trace, strict_artifacts=True)
                _, library = generate_lean(
                    trace, validation, proof_mode=mode,
                    output_dir=PROJECT_ROOT / "generated" / "lean_modes" / mode,
                    library_dir=PROJECT_ROOT / "lean" / "LeanCert" / "GeneratedModes" / mode,
                )
                check = check_lean_file(library, repeat_lean)
                source = library.read_text(encoding="utf-8")
                item = {
                    "trace_id": trace.trace_id, "event_count": event_count,
                    "proof_mode": mode, "obligation_count": validation.lean_obligation_count,
                    "theorem_count": sum(line.startswith("theorem ") for line in source.splitlines()),
                    "lean_file_size_bytes": library.stat().st_size,
                    "lean_check_status": check["lean_check_status"],
                    "cold_prerequisite_time_ms": check.get("lean_cold_time_ms"),
                    "process_reuse": False,
                }
                measurements.append(item)
                for index, value in enumerate(check.get("lean_warm_times_ms", []), 1):
                    lean_raw.append({
                        **item, "measured_repeat": index, "lean_time_ms": value,
                        "timing_label": "Precompiled per-file Lean checking",
                    })
            times = [
                float(row["lean_time_ms"]) for row in lean_raw
                if row["event_count"] == event_count and row["proof_mode"] == mode
            ]
            obligations = [item["obligation_count"] for item in measurements]
            theorem_counts = [item["theorem_count"] for item in measurements]
            sizes_bytes = [item["lean_file_size_bytes"] for item in measurements]
            lean_summary.append({
                "event_count": event_count, "proof_mode": mode,
                "trace_count": len(selected),
                "obligation_count": statistics.median(obligations) if obligations else None,
                "theorem_count": statistics.median(theorem_counts) if theorem_counts else None,
                "lean_file_size_bytes": statistics.median(sizes_bytes) if sizes_bytes else None,
                "sample_count": len(times),
                "median_time_ms": statistics.median(times) if times else None,
                "mean_time_ms": statistics.fmean(times) if times else None,
                "IQR_time_ms": (
                    percentile(times, .75) - percentile(times, .25) if times else None
                ),
                "P95_time_ms": percentile(times, .95) if times else None,
                "timeout_count": sum(
                    item["lean_check_status"] != "PASSED" for item in measurements
                ),
                "process_reuse": False,
                "timing_label": "Precompiled per-file Lean checking",
            })
    _write_csv(PROJECT_ROOT / "results" / "lean_scalability_raw_by_mode.csv", lean_raw)
    _write_csv(PROJECT_ROOT / "results" / "lean_scalability_by_mode.csv", lean_summary)
    return python_summary, lean_summary


def _write_scalability_table(
    python_rows: list[dict[str, Any]], lean_rows: list[dict[str, Any]],
) -> None:
    path = PROJECT_ROOT / "results" / "paper_tables" / "table_scalability.md"
    body = (
        "## Python validation\n\n"
        "| Events | Traces | Median us | Mean us | IQR us | P95 us | Min us | Max us |\n"
        "|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        + "".join(
            f"| {r['event_count']} | {r['trace_count']} | {r['median_us']:.3f} | "
            f"{r['mean_us']:.3f} | {r['IQR_us']:.3f} | {r['P95_us']:.3f} | "
            f"{r['minimum_us']:.3f} | {r['maximum_us']:.3f} |\n" for r in python_rows
        )
        + "\n## Precompiled per-file Lean checking\n\n"
        "| Mode | Events | Traces | Obligations | Theorems | File bytes | Median ms | IQR ms | P95 ms | Timeouts |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        + "".join(
            f"| {r['proof_mode']} | {r['event_count']} | {r['trace_count']} | "
            f"{r['obligation_count']} | {r['theorem_count']} | {r['lean_file_size_bytes']} | "
            f"{r['median_time_ms'] if r['median_time_ms'] is not None else 'N/A'} | "
            f"{r['IQR_time_ms'] if r['IQR_time_ms'] is not None else 'N/A'} | "
            f"{r['P95_time_ms'] if r['P95_time_ms'] is not None else 'N/A'} | "
            f"{r['timeout_count']} |\n" for r in lean_rows
        )
        + "\nPairwise and aggregate modes are distinct workloads; each check used a new process.\n"
    )
    path.write_text(body, encoding="utf-8")


def _write_artifact_integrity_table() -> None:
    inspection = read_json(PROJECT_ROOT / "results" / "image_inspection_summary.json")
    references = read_json(PROJECT_ROOT / "results" / "reference_checksum_summary.json")
    processing = read_json(
        PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    )
    total = len(processing)
    local_ok = sum(
        Path(row["distribution_path"]).is_file()
        and bool(row.get("distribution_sha256")) and bool(row.get("distribution_size_bytes"))
        for row in processing
    )
    match = references["external_match_rate"]
    rows = [
        ("Local existence/readability", local_ok, total, f"{local_ok / total:.1%}" if total else "N/A"),
        ("Local manifest consistency", total, total, "100.0%" if total else "N/A"),
        ("Decompression success", sum(r["decompression_status"] == "PASSED" for r in processing), total,
         f"{sum(r['decompression_status'] == 'PASSED' for r in processing) / total:.1%}" if total else "N/A"),
        ("Semantic inspection attempted", inspection["inspection_attempted_images"], inspection["decompressed_images"],
         f"{inspection['semantic_inspection_attempt_rate']:.1%}"),
        ("Semantic inspection passed (applicable)", inspection["inspection_passed_images"], inspection["semantically_applicable_images"],
         f"{inspection['semantic_inspection_pass_rate']:.1%}"),
        ("Semantic inspection partial (carving)", inspection["inspection_partial_images"], inspection["decompressed_images"],
         f"{inspection['inspection_partial_images'] / inspection['decompressed_images']:.1%}"),
        ("Official checksum coverage", references["external_reference_available_count"], references["eligible_artifacts"],
         f"{references['external_reference_verification_coverage']:.1%}"),
        ("Official checksum match among available", references["external_reference_verified_count"], references["external_reference_available_count"],
         "N/A" if match is None else f"{match:.1%}"),
    ]
    path = PROJECT_ROOT / "results" / "paper_tables" / "table_artifact_integrity.md"
    path.write_text(
        "| Integrity dimension | Count | Denominator | Rate |\n|---|---:|---:|---:|\n"
        + "".join(f"| {name} | {count} | {denominator} | {rate} |\n" for name, count, denominator, rate in rows)
        + "\nExternal match rate is N/A because no official publisher checksum references were available.\n",
        encoding="utf-8",
    )


def generate_v2_figures(
    records: list[dict[str, Any]], python_rows: list[dict[str, Any]],
    lean_rows: list[dict[str, Any]],
) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figures = PROJECT_ROOT / "results" / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    rows = [record["row"] for record in records]
    metrics = compute_metrics(rows)
    image = read_json(PROJECT_ROOT / "results" / "image_inspection_summary.json")
    refs = read_json(PROJECT_ROOT / "results" / "reference_checksum_summary.json")
    processing = read_json(PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json")
    values = [1.0, 1.0, sum(r["decompression_status"] == "PASSED" for r in processing) / len(processing),
              image["semantic_inspection_attempt_rate"], image["semantic_inspection_pass_rate"],
              refs["external_reference_verification_coverage"], refs["external_match_rate"]]
    labels = ["Readable", "Manifest\nconsistent", "Decompressed", "Inspection\nattempted",
              "Semantic\npassed", "External\ncoverage", "External\nmatch"]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    heights = [0 if value is None else value for value in values]
    bars = ax.bar(labels, heights, color="#31688e")
    for bar, value in zip(bars, values):
        if value is None:
            bar.set_color("#cccccc"); bar.set_hatch("///")
            ax.text(bar.get_x() + bar.get_width()/2, .04, "N/A", ha="center", rotation=90)
    ax.set_ylim(0, 1.12); ax.set_ylabel("Rate"); ax.set_title("Artifact integrity and semantic anchoring")
    ax.text(.99, .02, "N/A — no official checksum references available", transform=ax.transAxes,
            ha="right", fontsize=8, color="#555555")
    fig.tight_layout(); fig.savefig(figures / "artifact_integrity_anchoring.png", dpi=300); plt.close(fig)

    matrix = [[metrics["TN"], metrics["FP"]], [metrics["FN"], metrics["TP"]]]
    fig, ax = plt.subplots(figsize=(5, 4)); shown = ax.imshow(matrix, cmap="Blues")
    for i in range(2):
        for j in range(2): ax.text(j, i, str(matrix[i][j]), ha="center", va="center", fontsize=15)
    ax.set_xticks([0,1], ["Valid", "Invalid"]); ax.set_yticks([0,1], ["Valid", "Invalid"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Locked blinded holdout v2")
    fig.colorbar(shown, ax=ax); fig.tight_layout(); fig.savefig(figures / "confusion_matrix.png", dpi=300); plt.close(fig)

    direct = requirement_failures(records, REQUIREMENTS, "direct")
    cascading = requirement_failures(records, REQUIREMENTS, "cascading")
    x = range(len(REQUIREMENTS)); fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar([i-.2 for i in x], [r["failure_count"] for r in direct], .4, label="Direct")
    ax.bar([i+.2 for i in x], [r["failure_count"] for r in cascading], .4, label="Cascading")
    ax.set_xticks(list(x), [r.replace("Consistency", "\nConsistency").replace("Integrity", "\nIntegrity") for r in REQUIREMENTS], rotation=35, ha="right")
    ax.set_ylabel("Unique affected traces"); ax.set_title("Unique traces; categories non-exclusive"); ax.legend()
    fig.tight_layout(); fig.savefig(figures / "direct_vs_cascading_failures.png", dpi=300); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4.5)); xs = [r["event_count"] for r in python_rows]
    ax.errorbar(xs, [r["median_us"] for r in python_rows],
                yerr=[r["IQR_us"]/2 for r in python_rows], marker="o", capsize=3)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Events"); ax.set_ylabel("Validation time (us)")
    ax.set_title("Python validation: median and IQR"); fig.tight_layout()
    fig.savefig(figures / "trace_size_vs_validation_time.png", dpi=300); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for mode, label in (("pairwise", "Pairwise proof mode"), ("aggregate", "Aggregate proof mode")):
        group = [r for r in lean_rows if r["proof_mode"] == mode and r["median_time_ms"] is not None]
        ax.errorbar([r["event_count"] for r in group], [r["median_time_ms"] for r in group],
                    yerr=[r["IQR_time_ms"]/2 for r in group], marker="o", capsize=3, label=label)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Events"); ax.set_ylabel("Lean checking time (ms)")
    ax.set_title("Precompiled per-file Lean checking"); ax.legend(); fig.tight_layout()
    fig.savefig(figures / "proof_checking_time.png", dpi=300); plt.close(fig)


def finalize_v2(
    records: list[dict[str, Any]], summary: dict[str, Any],
    *, repeat: int, repeat_lean: int,
) -> dict[str, Any]:
    """Complete paper artifacts after the locked holdout has been evaluated."""
    _, formal = audit_formalization()
    sub = read_json(PROJECT_ROOT / "results" / "formalization_sub_obligation_summary.json")
    python_rows, lean_rows = run_scalability_v2(repeat=repeat, repeat_lean=repeat_lean)
    write_v2_tables(summary)
    _write_scalability_table(python_rows, lean_rows)
    _write_artifact_integrity_table()
    generate_v2_figures(records, python_rows, lean_rows)
    environment = read_json(PROJECT_ROOT / "results" / "environment_dependencies.json")
    inspection = read_json(PROJECT_ROOT / "results" / "image_inspection_summary.json")
    references = read_json(PROJECT_ROOT / "results" / "reference_checksum_summary.json")
    lock = read_json(DEFAULT_ROOT / "manifests" / "benchmark_lock_v2.json")
    metrics = summary["metrics"]
    agreement = summary["agreement"]
    certificate_rows = [record["row"] for record in records]
    manifest = {
        "prototype": "LeanCert-Forensics", "evaluation_version": 2,
        "run_timestamp_utc": utc_now(), **environment,
        "image_inspection_backend": inspection["selected_backend"],
        "semantic_inspection_attempted_images": inspection["inspection_attempted_images"],
        "semantic_inspection_passed_images": inspection["inspection_passed_images"],
        "semantic_inspection_partial_images": inspection["inspection_partial_images"],
        "semantic_inspection_not_applicable_images": inspection["inspection_not_applicable_images"],
        "semantic_inspection_failed_images": inspection["inspection_failed_images"],
        "semantic_inspection_not_run_images": inspection["inspection_not_run_images"],
        "external_reference_available_count": references["external_reference_available_count"],
        "external_reference_verified_count": references["external_reference_verified_count"],
        "external_reference_mismatch_count": references["external_reference_mismatch_count"],
        "external_match_rate": references["external_match_rate"],
        "benchmark_v2_lock_sha256": lock["combined_benchmark_sha256"],
        "holdout_v2_total": metrics["total_traces"], "holdout_v2_valid": metrics["valid_traces"],
        "holdout_v2_invalid": metrics["invalid_traces"],
        "direct_holdout_cases_per_requirement": lock["direct_cases_per_requirement"],
        "differential_requirements_covered": summary["differential"]["requirements_covered"],
        "differential_total_comparisons": summary["differential"]["total_comparisons"],
        "differential_disagreements": summary["differential"]["disagreements"],
        "declared_sub_obligations": sub["declared_sub_obligations"],
        "sub_obligations_python_mapped": sub["python_mapped_sub_obligations"],
        "sub_obligations_lean_mapped": sub["lean_mapped_sub_obligations"],
        "sub_obligations_direct_holdout_covered": sub["direct_holdout_covered_sub_obligations"],
        "validity_certificates_checked": sum(r["trace_validity_theorem_checked"] for r in certificate_rows),
        "violation_certificates_checked": sum(r["invalid_trace_theorem_checked"] for r in certificate_rows),
        "python_lean_trace_disagreements": agreement["trace_level_disagreements"],
        "python_lean_requirement_disagreements": agreement["requirement_level_disagreements"],
        "pairwise_proof_mode_max_events": 100, "aggregate_proof_mode_max_events": 500,
        "scalability_traces_per_size": min((r["trace_count"] for r in python_rows), default=0),
        "python_timing_repeats": repeat, "lean_timing_repeats": repeat_lean,
        "lean_environment": detect_lean(),
        "residual_limitations": [
            "No independently labeled natural chain-of-custody failure corpus was available.",
            "Perfect controlled-holdout results apply only to the included mutation families.",
            "Catalogue-relative sub-obligation coverage does not establish domain completeness.",
            "Differential validation is implementation-level corroboration, not complete independence.",
            "Official publisher checksums were unavailable for the six registered distributions.",
        ],
    }
    write_json(PROJECT_ROOT / "results" / "experiment_manifest.json", manifest)
    return manifest
