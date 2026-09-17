from __future__ import annotations

import statistics


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile_value
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + ((ordered[upper] - ordered[lower]) * fraction)


def compute_metrics(rows: list[dict]) -> dict:
    tp = tn = fp = fn = 0
    for row in rows:
        expected_valid = bool(row["is_expected_valid"])
        predicted_valid = bool(row["is_predicted_valid"])
        if not expected_valid and not predicted_valid:
            tp += 1
        elif expected_valid and predicted_valid:
            tn += 1
        elif expected_valid and not predicted_valid:
            fp += 1
        else:
            fn += 1
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    validation_times = [
        float(sample)
        for row in rows
        for sample in (
            row.get("validation_time_samples_us")
            or [row.get("validation_time_us", float(row.get("validation_time_ms", 0)) * 1000)]
        )
    ]
    lean_times = [
        float(row["lean_check_time_ms"]) for row in rows
        if row.get("lean_check_time_ms") not in (None, "")
    ]
    sources = {row["dataset_source"] for row in rows if row.get("dataset_source")}
    artifacts = {
        (row["dataset_source"], row["artifact_name"], row["artifact_sha256"])
        for row in rows if row.get("artifact_name")
    }
    scalability_rows = [
        row for row in rows
        if "traces/scalability/" in str(row.get("file_path", "")).replace("\\", "/").casefold()
    ]
    nist_artifacts = {
        (row["artifact_name"], row["artifact_sha256"])
        for row in rows if row.get("dataset_source") == "NIST CFReDS"
    }
    mean_validation = statistics.fmean(validation_times) if validation_times else 0.0
    lean_checked = sum(row.get("lean_check_status") != "NOT_RUN" for row in rows)
    lean_passed = sum(row.get("lean_check_status") == "PASSED" for row in rows)
    lean_failed = sum(row.get("lean_check_status") == "FAILED" for row in rows)
    return {
        "total_traces": len(rows),
        "valid_traces": sum(bool(row["is_expected_valid"]) for row in rows),
        "invalid_traces": sum(not bool(row["is_expected_valid"]) for row in rows),
        "public_sources_used": len(sources),
        "public_artifacts_used": len(artifacts),
        "nist_cfreds_artifacts_used": len(nist_artifacts),
        "scalability_trace_count": len(scalability_rows),
        "distinct_event_counts": sorted({int(row.get("event_count", 0)) for row in rows}),
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": safe_div(tp + tn, len(rows)),
        "precision": precision,
        "recall": recall,
        "specificity": safe_div(tn, tn + fp),
        "f1": safe_div(2 * precision * recall, precision + recall),
        "false_acceptance_rate": safe_div(fn, tp + fn),
        "false_rejection_rate": safe_div(fp, tn + fp),
        "mean_validation_time_us": mean_validation,
        "median_validation_time_us": statistics.median(validation_times) if validation_times else 0.0,
        "p95_validation_time_us": percentile(validation_times, 0.95),
        "validation_throughput_traces_per_second": safe_div(1_000_000, mean_validation),
        "lean_checked_traces": lean_checked,
        "lean_passed_artifacts": lean_passed,
        "lean_failed_artifacts": lean_failed,
        "lean_success_rate": safe_div(lean_passed, lean_checked),
        "mean_lean_check_time_ms": statistics.fmean(lean_times) if lean_times else None,
        "median_lean_check_time_ms": statistics.median(lean_times) if lean_times else None,
    }


def requirement_failures(
    records: list[dict], requirements: list[str], classification: str = "all"
) -> list[dict]:
    total = len(records)
    output = []
    for requirement in requirements:
        affected = []
        for record in records:
            result = next(
                (
                    item for item in record["report"].get("requirement_results", [])
                    if item.get("requirement") == requirement
                ),
                None,
            )
            if not result or result.get("passed", True):
                continue
            failures = result.get("failures", [])
            if classification == "all":
                include = True
            elif classification == "direct":
                include = any(not item.get("is_cascading", False) for item in failures)
            elif classification == "cascading":
                include = any(item.get("is_cascading", False) for item in failures)
            else:
                raise ValueError(f"Unknown failure classification: {classification}")
            if include:
                affected.append(record["row"]["trace_id"])
        output.append({
            "requirement": requirement,
            "failure_count": len(affected),
            "affected_traces": ";".join(affected),
            "failure_rate": safe_div(len(affected), total),
        })
    return output


def classified_failure_entry_counts(records: list[dict]) -> tuple[int, int]:
    direct = cascading = 0
    for record in records:
        for result in record["report"].get("requirement_results", []):
            for failure in result.get("failures", []):
                if failure.get("is_cascading", False):
                    cascading += 1
                else:
                    direct += 1
    return direct, cascading
