from __future__ import annotations

import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


FIGURE_NAMES = {
    "confusion_matrix.png",
    "artifact_integrity_anchoring.png",
    "direct_vs_cascading_failures.png",
    "trace_size_vs_validation_time.png",
    "proof_checking_time.png",
}


def _save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def generate_figures(
    rows: list[dict],
    summary: dict,
    direct_failures: list[dict],
    cascading_failures: list[dict],
    artifact_rows: list[dict],
    scalability_rows: list[dict] | Path,
    output_dir: Path | None = None,
) -> dict:
    # Preserve the pre-publication-package call shape used by downstream callers.
    if output_dir is None:
        output_dir = Path(scalability_rows)
        artifact_rows = []
        scalability_rows = []
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("*.png"):
        if stale.name not in FIGURE_NAMES:
            stale.unlink()
    warnings: dict[str, str] = {}

    matrix = [[summary["TP"], summary["FN"]], [summary["FP"], summary["TN"]]]
    fig, ax = plt.subplots(figsize=(6.2, 5.2), constrained_layout=True)
    image = ax.imshow(matrix, cmap="Blues")
    fig.colorbar(image, ax=ax, shrink=0.85)
    ax.set_xticks([0, 1], ["Predicted invalid", "Predicted valid"])
    ax.set_yticks([0, 1], ["Actual invalid", "Actual valid"])
    labels = [["TP", "FN"], ["FP", "TN"]]
    for row_index in range(2):
        for column_index in range(2):
            ax.text(
                column_index, row_index,
                f"{labels[row_index][column_index]}\n{matrix[row_index][column_index]}",
                ha="center", va="center", fontsize=12,
            )
    ax.set_title("Locked Blinded Holdout Confusion Matrix")
    _save(fig, output_dir / "confusion_matrix.png")

    project_root = Path(__file__).resolve().parents[1]
    processing_path = project_root / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    inspection_path = project_root / "results" / "image_inspection_summary.json"
    reference_path = project_root / "results" / "reference_checksum_summary.json"
    processing = json.loads(processing_path.read_text(encoding="utf-8")) if processing_path.is_file() else []
    inspection = json.loads(inspection_path.read_text(encoding="utf-8")) if inspection_path.is_file() else {}
    references = json.loads(reference_path.read_text(encoding="utf-8")) if reference_path.is_file() else {}
    cfreds_native = [row for row in artifact_rows if row.get("source_name") == "NIST CFReDS"]
    local_readable = (
        sum(row["artifact_exists"] and row["artifact_readable"] for row in cfreds_native) / len(cfreds_native)
        if cfreds_native else 0.0
    )
    local_manifest = (
        sum(row["artifact_hash_match"] and row["artifact_size_match"] for row in cfreds_native) / len(cfreds_native)
        if cfreds_native else 0.0
    )
    decompression = (
        sum(row.get("decompression_status") == "PASSED" for row in processing) / len(processing)
        if processing else 0.0
    )
    inspection_coverage = float(inspection.get("semantic_inspection_coverage", 0.0))
    external_coverage = float(references.get("external_reference_verification_coverage", 0.0))
    match_rate = references.get("match_rate_among_available_references")
    native_checks = [
        "Local existence/\nreadability", "Local manifest\nconsistency",
        "Decompression\nsuccess", "Content inspection\ncoverage",
        "External checksum\ncoverage", "External match rate\n(available only)",
    ]
    native_rates = [
        100 * local_readable, 100 * local_manifest, 100 * decompression,
        100 * inspection_coverage, 100 * external_coverage,
        100 * float(match_rate) if match_rate is not None else 0.0,
    ]
    colors = ["#2878B5"] * 4 + ["#E69F00", "#E69F00"]
    fig, ax = plt.subplots(figsize=(10.4, 5.2), constrained_layout=True)
    bars = ax.bar(native_checks, native_rates, color=colors)
    ax.bar_label(bars, fmt="%.1f%%", padding=3)
    ax.set_ylim(0, 108)
    ax.set_ylabel("Pass rate (%)")
    ax.set_title("Artifact Integrity and External Anchoring")
    if match_rate is None:
        ax.text(5, 3, "unavailable", ha="center", va="bottom", rotation=90, fontsize=9)
    _save(fig, output_dir / "artifact_integrity_anchoring.png")

    names = [item["requirement"] for item in direct_failures]
    direct_by_name = {item["requirement"]: item["failure_count"] for item in direct_failures}
    cascade_by_name = {
        item["requirement"]: item["failure_count"] for item in cascading_failures
    }
    positions = list(range(len(names)))
    fig, ax = plt.subplots(figsize=(11, 5.2), constrained_layout=True)
    ax.bar(
        [position - 0.2 for position in positions],
        [direct_by_name.get(name, 0) for name in names],
        width=0.4, label="Direct", color="#D55E00",
    )
    ax.bar(
        [position + 0.2 for position in positions],
        [cascade_by_name.get(name, 0) for name in names],
        width=0.4, label="Cascading", color="#0072B2",
    )
    ax.set_xticks(positions, names, rotation=38, ha="right")
    ax.set_ylabel("Affected traces")
    ax.set_title("Direct vs Cascading Failures (Unique Traces; Non-exclusive)")
    ax.legend()
    _save(fig, output_dir / "direct_vs_cascading_failures.png")

    scalability_groups: dict[int, list[float]] = {}
    for row in scalability_rows:
        scalability_groups.setdefault(int(row["event_count"]), []).append(
            float(row["validation_time_us"])
        )
    sizes = sorted(scalability_groups)
    medians = [statistics.median(scalability_groups[size]) for size in sizes]
    q1 = [
        sorted(scalability_groups[size])[max(0, int(0.25 * (len(scalability_groups[size]) - 1)))]
        for size in sizes
    ]
    q3 = [
        sorted(scalability_groups[size])[int(0.75 * (len(scalability_groups[size]) - 1))]
        for size in sizes
    ]
    fig, ax = plt.subplots(figsize=(7.2, 4.8), constrained_layout=True)
    if sizes:
        ax.errorbar(
            sizes, medians,
            yerr=[[median - lower for median, lower in zip(medians, q1)],
                  [upper - median for median, upper in zip(medians, q3)]],
            marker="o", linewidth=2, capsize=4, color="#009E73",
        )
        ax.set_xticks(sizes)
    else:
        warnings["trace_size_vs_validation_time"] = "No dedicated scalability traces were available."
    ax.set_xlabel("Event count")
    ax.set_ylabel("Median Python validation time (µs)")
    ax.set_title("Trace Size vs Python Validation Time")
    ax.grid(alpha=0.25)
    _save(fig, output_dir / "trace_size_vs_validation_time.png")

    lean_groups: dict[int, list[float]] = {}
    for row in rows:
        if "traces/scalability/" not in str(row.get("file_path", "")).replace("\\", "/").casefold():
            continue
        for sample in row.get("lean_warm_times_ms", []):
            lean_groups.setdefault(int(row["event_count"]), []).append(float(sample))
    lean_sizes = sorted(lean_groups)
    lean_medians = [statistics.median(lean_groups[size]) for size in lean_sizes]
    lean_q1 = [
        sorted(lean_groups[size])[max(0, int(0.25 * (len(lean_groups[size]) - 1)))]
        for size in lean_sizes
    ]
    lean_q3 = [
        sorted(lean_groups[size])[int(0.75 * (len(lean_groups[size]) - 1))]
        for size in lean_sizes
    ]
    fig, ax = plt.subplots(figsize=(7.8, 4.8), constrained_layout=True)
    if lean_sizes:
        ax.errorbar(
            lean_sizes, lean_medians,
            yerr=[[median - lower for median, lower in zip(lean_medians, lean_q1)],
                  [upper - median for median, upper in zip(lean_medians, lean_q3)]],
            marker="o", linewidth=2, capsize=4, color="#CC79A7",
        )
        ax.set_xticks(lean_sizes)
    else:
        warnings["proof_checking_time"] = "Lean proof-checking timing was not available."
    ax.set_xlabel("Event count")
    ax.set_ylabel("Median Lean proof-checking time (ms)")
    ax.set_title("Warm Lean Checking Time by Trace Size")
    ax.grid(alpha=0.25)
    _save(fig, output_dir / "proof_checking_time.png")
    return warnings
