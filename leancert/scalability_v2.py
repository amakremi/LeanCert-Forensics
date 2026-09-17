from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from .lean_generator import check_lean_file, generate_lean
from .metrics import percentile
from .report import process_trace_file
from .schema import ForensicTrace
from .utils import PROJECT_ROOT, read_json
from .validator import validate_trace

SIZES = (4, 8, 12, 20, 50, 100, 200, 500)
PAIRWISE_SIZES = (4, 8, 12, 20, 50, 100)
TRACE_ROOT = PROJECT_ROOT / "traces" / "scalability"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _iqr(values: list[float]) -> float:
    return percentile(values, 0.75) - percentile(values, 0.25)


def _paths_by_size(root: Path = TRACE_ROOT) -> dict[int, list[Path]]:
    output: dict[int, list[Path]] = defaultdict(list)
    for path in root.rglob("*.json"):
        raw = read_json(path)
        output[len(raw.get("events", []))].append(path)
    return {size: sorted(paths) for size, paths in output.items()}


def audit_scalability_corpus(root: Path = TRACE_ROOT) -> dict[str, Any]:
    by_size = _paths_by_size(root)
    counts = {size: len(by_size.get(size, [])) for size in SIZES}
    distinct = {}
    for size, paths in by_size.items():
        signatures = {
            (
                tuple(event["action"] for event in read_json(path)["events"]),
                tuple(event["timestamp"] for event in read_json(path)["events"]),
                tuple(actor["actor_id"] for actor in read_json(path)["actors"]),
                len(read_json(path)["report_claims"]),
                read_json(path)["dataset_origin"]["artifact_name"],
            )
            for path in paths
        }
        distinct[size] = len(signatures)
    valid = all(counts[size] == 15 and distinct.get(size, 0) == 15 for size in SIZES)
    return {
        "sizes": list(SIZES), "trace_counts_by_size": counts,
        "structurally_distinct_counts_by_size": distinct,
        "total_trace_count": sum(counts.values()),
        "fifteen_structurally_distinct_per_size": valid,
    }


def run_python_scalability(
    root: Path = TRACE_ROOT, *, measured_repeats: int = 30
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    by_size = _paths_by_size(root)
    for size in SIZES:
        paths = by_size.get(size, [])
        samples: list[float] = []
        for path in paths:
            record = process_trace_file(
                path, repeat=measured_repeats, strict_artifacts=True, run_lean=False,
            )
            if record["row"]["predicted_status"] != "PASSED":
                raise RuntimeError(f"Scalability trace failed validation: {path}")
            trace_samples = [float(value) for value in record["row"]["validation_time_samples_us"]]
            if len(trace_samples) != measured_repeats:
                raise RuntimeError(f"Wrong measured timing count for {path}")
            samples.extend(trace_samples)
            raw_rows.extend({
                "trace_id": record["row"]["trace_id"], "event_count": size,
                "measured_repeat": index, "validation_time_us": value,
                "warmup_runs_excluded": 10, "clock": "time.perf_counter_ns",
            } for index, value in enumerate(trace_samples, 1))
        summary_rows.append({
            "event_count": size, "trace_count": len(paths),
            "measured_runs_per_trace": measured_repeats, "warmup_runs_excluded": 10,
            "median_us": statistics.median(samples) if samples else None,
            "mean_us": statistics.fmean(samples) if samples else None,
            "IQR_us": _iqr(samples) if samples else None,
            "P95_us": percentile(samples, 0.95) if samples else None,
            "minimum_us": min(samples) if samples else None,
            "maximum_us": max(samples) if samples else None,
        })
    _write_csv(PROJECT_ROOT / "results" / "scalability_raw_python.csv", raw_rows)
    _write_csv(PROJECT_ROOT / "results" / "scalability_summary_python.csv", summary_rows)
    return raw_rows, summary_rows


def run_lean_scalability(
    root: Path = TRACE_ROOT, *, traces_per_size: int = 5, measured_repeats: int = 3
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_size = _paths_by_size(root)
    raw_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    modes = (("pairwise", PAIRWISE_SIZES), ("aggregate", SIZES))
    for mode, sizes in modes:
        for size in sizes:
            group_rows: list[dict[str, Any]] = []
            for path in by_size.get(size, [])[:traces_per_size]:
                trace = ForensicTrace.model_validate(read_json(path))
                result = validate_trace(trace, strict_artifacts=True)
                if result.overall_status != "PASSED":
                    raise RuntimeError(f"Scalability trace failed validation: {path}")
                primary, library = generate_lean(
                    trace, result, proof_mode=mode,
                    output_dir=PROJECT_ROOT / "generated" / "lean_modes" / mode,
                    library_dir=PROJECT_ROOT / "lean" / "LeanCert" / "GeneratedModes" / mode,
                )
                source = primary.read_text(encoding="utf-8")
                theorem_count = sum(line.startswith("theorem ") for line in source.splitlines())
                obligation_count = sum(
                    line.startswith("example :") or line.startswith("theorem ")
                    for line in source.splitlines()
                )
                check = check_lean_file(library, repeat=measured_repeats)
                samples = [float(value) for value in check.get("lean_warm_times_ms", [])]
                base = {
                    "trace_id": trace.trace_id, "event_count": size, "proof_mode": mode,
                    "obligation_count": obligation_count, "theorem_count": theorem_count,
                    "lean_file_size_bytes": primary.stat().st_size,
                    "timing_label": "Precompiled per-file Lean checking",
                    "process_reuse": False,
                    "check_status": check["lean_check_status"],
                }
                group_rows.append({**base, "samples": samples})
                raw_rows.extend({
                    **base, "measured_repeat": index, "validation_time_ms": sample,
                } for index, sample in enumerate(samples, 1))
            measured = [sample for row in group_rows for sample in row["samples"]]
            summary_rows.append({
                "event_count": size, "proof_mode": mode, "trace_count": len(group_rows),
                "obligation_count": statistics.fmean(
                    row["obligation_count"] for row in group_rows
                ) if group_rows else None,
                "theorem_count": statistics.fmean(
                    row["theorem_count"] for row in group_rows
                ) if group_rows else None,
                "lean_file_size_bytes": statistics.fmean(
                    row["lean_file_size_bytes"] for row in group_rows
                ) if group_rows else None,
                "median_time_ms": statistics.median(measured) if measured else None,
                "mean_time_ms": statistics.fmean(measured) if measured else None,
                "IQR_time_ms": _iqr(measured) if measured else None,
                "P95_time_ms": percentile(measured, 0.95) if measured else None,
                "timeout_count": 0,
                "failed_check_count": sum(
                    row["check_status"] != "PASSED" for row in group_rows
                ),
                "measured_checks": len(measured),
                "timing_label": "Precompiled per-file Lean checking",
                "process_reuse": False,
            })
    _write_csv(PROJECT_ROOT / "results" / "lean_scalability_raw_by_mode.csv", raw_rows)
    _write_csv(PROJECT_ROOT / "results" / "lean_scalability_by_mode.csv", summary_rows)
    return raw_rows, summary_rows


def run_scalability_experiments() -> dict[str, Any]:
    corpus = audit_scalability_corpus()
    if not corpus["fifteen_structurally_distinct_per_size"]:
        raise RuntimeError(f"Scalability corpus audit failed: {corpus}")
    _, python_rows = run_python_scalability()
    _, lean_rows = run_lean_scalability()
    return {"corpus": corpus, "python": python_rows, "lean": lean_rows}
