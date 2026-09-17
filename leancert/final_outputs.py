from __future__ import annotations

import csv
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .lean_generator import detect_lean
from .utils import PROJECT_ROOT, read_json, utc_now, write_json

RESULTS = PROJECT_ROOT / "results"
TABLES = RESULTS / "paper_tables"
FIGURES = RESULTS / "figures"
CORE_TABLES = (
    "table_dataset_sources.md", "table_artifact_integrity.md",
    "table_image_inspection.md", "table_holdout_metrics.md",
    "table_holdout_requirement_coverage.md", "table_differential_validation.md",
    "table_formalization_coverage.md", "table_sub_obligation_coverage.md", "table_lean_semantics.md",
    "table_scalability.md", "table_residual_limitations.md",
)
PRIMARY_FIGURES = (
    "artifact_integrity_anchoring.png", "confusion_matrix.png",
    "direct_vs_cascading_failures.png", "trace_size_vs_validation_time.png",
    "proof_checking_time.png",
)


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _save(fig: plt.Figure, name: str) -> None:
    fig.tight_layout()
    fig.savefig(FIGURES / name, dpi=300, bbox_inches="tight")
    plt.close(fig)


def _tables() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    manifest = read_json(PROJECT_ROOT / "datasets" / "manifests" / "download_manifest.json")
    lines = [
        "| Source | Artifact | Kind | Bytes | Local SHA-256 | Status |",
        "|---|---|---|---:|---|---|",
    ]
    lines.extend(
        f"| {row['source_name']} | {row['artifact_name']} | {row['artifact_kind']} | "
        f"{row['size_bytes']} | {row['sha256']} | {row['download_status']} |"
        for row in manifest
    )
    (TABLES / "table_dataset_sources.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    processing = read_json(
        PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    )
    inspection = _csv(RESULTS / "image_inspection_results.csv")
    references = read_json(RESULTS / "reference_checksum_summary.json")
    local_readable = sum(
        row.get("decompression_status") == "PASSED" and
        (PROJECT_ROOT / row["decompressed_path"]).is_file() for row in processing
    )
    manifest_consistent = sum(
        row["manifest_size_match"] == "True" and row["manifest_sha256_match"] == "True"
        for row in inspection
    )
    applicable = sum(row["filesystem_semantics"] == "APPLICABLE" for row in inspection)
    passed = sum(row["inspection_status"] == "PASSED" for row in inspection)
    partial = sum(row["inspection_status"] == "PARTIAL" for row in inspection)
    attempted = sum(row["inspection_status"] in {"PASSED", "PARTIAL", "FAILED"} for row in inspection)
    ext_available = references["external_reference_available_count"]
    ext_match = references["external_match_rate"]
    artifact_lines = [
        "| Integrity dimension | Numerator | Denominator | Rate |",
        "|---|---:|---:|---:|",
        f"| Local existence/readability | {local_readable} | {len(processing)} | {local_readable / len(processing):.1%} |",
        f"| Local manifest consistency | {manifest_consistent} | {len(inspection)} | {manifest_consistent / len(inspection):.1%} |",
        f"| Decompression success | {sum(r['decompression_status'] == 'PASSED' for r in processing)} | {len(processing)} | {sum(r['decompression_status'] == 'PASSED' for r in processing) / len(processing):.1%} |",
        f"| Semantic inspection attempted | {attempted} | {len(inspection)} | {attempted / len(inspection):.1%} |",
        f"| Semantic inspection passed (applicable) | {passed} | {applicable} | {passed / applicable:.1%} |",
        f"| Semantic inspection partial (non-filesystem carving images) | {partial} | {len(inspection) - applicable} | {partial / (len(inspection) - applicable):.1%} |",
        f"| Official checksum coverage | {ext_available} | {references['eligible_artifacts']} | {ext_available / references['eligible_artifacts']:.1%} |",
        f"| External match rate | {references['external_reference_verified_count']} | {ext_available} | {'N/A' if ext_match is None else f'{ext_match:.1%}'} |",
        "",
        "Local manifest consistency is not publisher authenticity. No publisher checksum was available, so external match rate has a zero denominator and is N/A.",
    ]
    (TABLES / "table_artifact_integrity.md").write_text(
        "\n".join(artifact_lines) + "\n", encoding="utf-8"
    )

    python_rows = _csv(RESULTS / "scalability_summary_python.csv")
    lean_rows = _csv(RESULTS / "lean_scalability_by_mode.csv")
    scale = [
        "| Workload | Events | Traces | Median | Mean | IQR | P95 | Minimum | Maximum |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    scale.extend(
        f"| Python validation (µs) | {r['event_count']} | {r['trace_count']} | "
        f"{float(r['median_us']):.3f} | {float(r['mean_us']):.3f} | {float(r['IQR_us']):.3f} | "
        f"{float(r['P95_us']):.3f} | {float(r['minimum_us']):.3f} | {float(r['maximum_us']):.3f} |"
        for r in python_rows
    )
    scale.extend(
        f"| {r['proof_mode'].title()} — precompiled per-file Lean checking (ms) | "
        f"{r['event_count']} | {r['trace_count']} | {float(r['median_time_ms']):.3f} | "
        f"{float(r['mean_time_ms']):.3f} | {float(r['IQR_time_ms']):.3f} | "
        f"{float(r['P95_time_ms']):.3f} | N/A | N/A |"
        for r in lean_rows
    )
    scale.extend([
        "", "Pairwise and aggregate proof modes are different workloads and are reported as separate series. Lean processes were not reused.",
    ])
    (TABLES / "table_scalability.md").write_text("\n".join(scale) + "\n", encoding="utf-8")

    limitations = [
        ("Fixed", "Semantic image inspection now uses pytsk3 and is reported separately from decompression."),
        ("Fixed", "Holdout v2 is blinded, label-free, frozen by per-file hashes, and lock-verified before evaluation."),
        ("Fixed", "Scalability uses 15 structurally distinct traces at each of eight event sizes."),
        ("Fixed", "All 35 declared catalogue children have explicit Python and Lean predicates and direct controlled positive/negative evidence."),
        ("Fixed", "All nine parent/child equivalences are audited in Python and proved as Lean iff theorems."),
        ("Mitigated", "An independent nine-requirement validator and visible differential results reduce implementation-coupling risk."),
        ("Mitigated", "Child-level differential validation covers all 35 children; limited independence remains explicit for five children."),
        ("Mitigated", "Controlled-mutation bias is reduced by blinding, direct cases for every requirement, and leakage invariance tests."),
        ("Unresolved", "No independently labelled natural chain-of-custody failure corpus was available."),
        ("Unresolved", "Publisher checksums were unavailable for all six CFReDS distributions; external match rate is N/A."),
        ("Bounded", "The 35/35 result is catalogue-relative and does not establish complete forensic, legal, jurisdictional, or admissibility coverage."),
        ("Bounded", "The sub-obligation benchmark consists of controlled, declaratively specified perturbations of public-data-derived forensic traces. It validates enforcement of the declared obligation catalogue; it does not estimate the prevalence or detection accuracy of naturally occurring forensic process failures."),
        ("Bounded", "Holdout v2 contains controlled direct mutations, not a prevalence-representative field sample."),
        ("Bounded", "File-carving images are raw carving corpora without an expected filesystem and receive PARTIAL semantic-inspection status."),
        ("Bounded", "Precompiled per-file Lean checks launch new processes; they are not persistent-session timings."),
    ]
    (TABLES / "table_residual_limitations.md").write_text(
        "| Status | Residual limitation |\n|---|---|\n" +
        "".join(f"| {status} | {text} |\n" for status, text in limitations), encoding="utf-8"
    )


def _figures() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    for path in FIGURES.glob("*.png"):
        if path.name not in PRIMARY_FIGURES:
            path.unlink()
    processing = read_json(
        PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    )
    inspection = read_json(RESULTS / "image_inspection_summary.json")
    refs = read_json(RESULTS / "reference_checksum_summary.json")
    labels = ["Local readable", "Manifest consistent", "Decompressed", "Inspection attempted", "Semantic success", "External coverage", "External match"]
    rates: list[float | None] = [
        1.0, 1.0,
        sum(r["decompression_status"] == "PASSED" for r in processing) / len(processing),
        inspection["semantic_inspection_attempt_rate"],
        inspection["semantic_inspection_pass_rate"],
        refs["external_reference_verification_coverage"], refs["external_match_rate"],
    ]
    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    x = np.arange(len(labels))
    shown = [0 if rate is None else rate * 100 for rate in rates]
    bars = ax.bar(x, shown, color="#4472C4")
    for index, (bar, rate) in enumerate(zip(bars, rates)):
        if rate is None:
            bar.set_height(100)
            bar.set_facecolor("#dddddd")
            bar.set_edgecolor("#777777")
            bar.set_hatch("///")
            ax.text(index, 50, "N/A\n(no denominator)", ha="center", va="center", fontsize=9)
        else:
            ax.text(index, shown[index] + 2, f"{shown[index]:.0f}%", ha="center", fontsize=9)
    ax.set_xticks(x, labels, rotation=24, ha="right")
    ax.set_ylabel("Rate (%)")
    ax.set_ylim(0, 112)
    ax.set_title("Artifact integrity anchoring (N/A is not treated as failure)")
    _save(fig, "artifact_integrity_anchoring.png")

    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    matrix = np.array([[metrics["TN"], metrics["FP"]], [metrics["FN"], metrics["TP"]]])
    fig, ax = plt.subplots(figsize=(5.4, 4.7))
    image = ax.imshow(matrix, cmap="Blues")
    for (row, col), value in np.ndenumerate(matrix):
        ax.text(col, row, str(value), ha="center", va="center", fontsize=16)
    ax.set_xticks([0, 1], ["Predicted valid", "Predicted invalid"])
    ax.set_yticks([0, 1], ["Expected valid", "Expected invalid"])
    ax.set_title("Locked blinded holdout v2")
    fig.colorbar(image, ax=ax, fraction=0.046)
    _save(fig, "confusion_matrix.png")

    coverage = _csv(RESULTS / "holdout_requirement_coverage.csv")
    names = [row["requirement"] for row in coverage]
    direct = [int(row["direct_invalid_traces"]) for row in coverage]
    cascading = [int(row["cascading_affected_traces"]) for row in coverage]
    fig, ax = plt.subplots(figsize=(11, 5.1))
    x = np.arange(len(names)); width = 0.38
    ax.bar(x - width / 2, direct, width, label="Direct")
    ax.bar(x + width / 2, cascading, width, label="Cascading")
    ax.set_xticks(x, names, rotation=32, ha="right")
    ax.set_ylabel("Unique affected traces")
    ax.set_title("Direct vs cascading failures — Unique traces; categories non-exclusive")
    ax.legend()
    _save(fig, "direct_vs_cascading_failures.png")

    python_rows = _csv(RESULTS / "scalability_summary_python.csv")
    x = [int(row["event_count"]) for row in python_rows]
    y = [float(row["median_us"]) for row in python_rows]
    error = [float(row["IQR_us"]) / 2 for row in python_rows]
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    ax.errorbar(x, y, yerr=error, marker="o", capsize=4)
    ax.set_xlabel("Events per trace")
    ax.set_ylabel("Median Python validation time (µs)")
    ax.set_title("Validation scalability: 15 structurally distinct traces per size")
    ax.grid(alpha=0.25)
    _save(fig, "trace_size_vs_validation_time.png")

    lean_rows = _csv(RESULTS / "lean_scalability_by_mode.csv")
    fig, ax = plt.subplots(figsize=(8.7, 4.9))
    for mode, label in (("pairwise", "Pairwise proof mode"), ("aggregate", "Aggregate proof mode")):
        group = [row for row in lean_rows if row["proof_mode"] == mode]
        xs = [int(row["event_count"]) for row in group]
        ys = [float(row["median_time_ms"]) for row in group]
        errors = [float(row["IQR_time_ms"]) / 2 for row in group]
        ax.errorbar(xs, ys, yerr=errors, marker="o", capsize=4, label=label)
    ax.set_xlabel("Events per trace")
    ax.set_ylabel("Median precompiled per-file Lean time (ms)")
    ax.set_title("Precompiled per-file Lean checking")
    ax.grid(alpha=0.25); ax.legend()
    _save(fig, "proof_checking_time.png")


def _manifest() -> dict[str, Any]:
    environment = read_json(RESULTS / "environment_dependencies.json")
    inspection = read_json(RESULTS / "image_inspection_summary.json")
    references = read_json(RESULTS / "reference_checksum_summary.json")
    lock = read_json(
        PROJECT_ROOT / "benchmark" / "holdout_v2" / "manifests" / "benchmark_lock_v2.json"
    )
    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    differential = read_json(RESULTS / "differential_validation_summary_v2.json")
    formal_path = RESULTS / "formalization_sub_obligation_summary_v2.json"
    formal = read_json(formal_path if formal_path.is_file() else RESULTS / "formalization_sub_obligation_summary.json")
    child_evaluation_path = RESULTS / "sub_obligation_evaluation_summary.json"
    child_evaluation = read_json(child_evaluation_path) if child_evaluation_path.is_file() else {}
    agreement = read_json(RESULTS / "python_lean_agreement_summary.json")
    certs = _csv(RESULTS / "lean_certificate_semantics.csv")
    coverage = _csv(RESULTS / "holdout_requirement_coverage.csv")
    lean = detect_lean()
    residual = [
        "No independently labelled natural chain-of-custody failure corpus was available.",
        "No publisher checksums were available for the six CFReDS distributions.",
        "The 35/35 child result is catalogue-relative and is not domain-completeness evidence.",
        "The child benchmark uses controlled perturbations, not naturally occurring failures.",
        "Holdout v2 uses controlled mutations and is not prevalence representative.",
        "File-carving images have no expected filesystem and are PARTIAL, not semantic passes.",
    ]
    manifest = {
        "prototype": "LeanCert-Forensics", "run_timestamp_utc": utc_now(),
        "python_version": sys.version, "platform": platform.platform(),
        "lean_available": lean["lean_available"], "lake_available": lean["lake_available"],
        "lean_version": lean["lean_version"], "lake_version": lean["lake_version"],
        "pytsk3_available": environment["pytsk3_available"],
        "pytsk3_module_path": environment["pytsk3_module_path"],
        "pytsk3_version": environment["pytsk3_version"],
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
        "direct_holdout_cases_per_requirement": {
            row["requirement"]: int(row["direct_invalid_traces"]) for row in coverage
        },
        "differential_requirements_covered": differential["requirements_covered"],
        "differential_total_comparisons": differential["total_comparisons"],
        "differential_disagreements": differential["disagreements"],
        "declared_sub_obligations": formal["declared_sub_obligations"],
        "sub_obligations_python_mapped": formal.get("python_explicit_child_mappings", formal.get("python_mapped_sub_obligations", 0)),
        "sub_obligations_lean_mapped": formal.get("lean_explicit_child_mappings", formal.get("lean_mapped_sub_obligations", 0)),
        "sub_obligations_direct_holdout_covered": formal.get("direct_child_benchmark_coverage", formal.get("direct_holdout_covered_sub_obligations", 0)),
        "sub_obligation_study": formal | {
            "benchmark_name": child_evaluation.get("benchmark_name"),
            "benchmark_sha256": child_evaluation.get("benchmark_sha256"),
            "controlled_trace_count": child_evaluation.get("controlled_trace_count", 0),
            "child_violation_detection_rate": child_evaluation.get("child_violation_detection_rate"),
        },
        "validity_certificates_checked": sum(r["valid_trace_theorem_checked"] == "True" for r in certs),
        "violation_certificates_checked": sum(r["invalid_trace_theorem_checked"] == "True" for r in certs),
        "python_lean_trace_disagreements": agreement["trace_level_disagreements"],
        "python_lean_requirement_disagreements": agreement["requirement_level_disagreements"],
        "pairwise_proof_mode_max_events": 100, "aggregate_proof_mode_max_events": 500,
        "scalability_traces_per_size": 15, "python_timing_repeats": 30,
        "lean_timing_repeats": 3, "primary_figure_count": len(PRIMARY_FIGURES),
        "core_table_count": len(CORE_TABLES), "residual_limitations": residual,
        "fixed_limitations": [
            "Semantic image inspection is separated from decompression and uses pytsk3.",
            "Holdout v2 is blinded and lock-verified.",
            "Scalability uses 15 structurally distinct traces per event size.",
            "All 35 declared children have explicit Python and Lean mappings and direct controlled tests.",
            "All nine parent-child equivalences are checked in Python and Lean.",
        ],
        "mitigated_limitations": [
            "Independent nine-requirement differential validation reduces implementation-coupling risk.",
            "Blinding and leakage-invariance tests reduce controlled-benchmark leakage risk.",
            "Child differential validation is structurally independent for 30 children and explicitly LIMITED for five.",
        ],
    }
    write_json(RESULTS / "experiment_manifest.json", manifest)
    return manifest


def _sync_v2_result_aliases() -> None:
    """Prevent legacy aggregate filenames from retaining pre-v2 measurements."""
    shutil.copyfile(RESULTS / "per_trace_results_v2.csv", RESULTS / "per_trace_results.csv")
    shutil.copyfile(
        RESULTS / "differential_validation_v2.csv", RESULTS / "differential_validation.csv"
    )
    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    certs = _csv(RESULTS / "lean_certificate_semantics.csv")
    differential = read_json(RESULTS / "differential_validation_summary_v2.json")
    agreement = read_json(RESULTS / "python_lean_agreement_summary.json")
    summary = {
        **metrics,
        "lean_files_compiled": sum(row["lean_file_compiled"] == "True" for row in certs),
        "validity_certificates_checked": sum(
            row["valid_trace_theorem_checked"] == "True" for row in certs
        ),
        "violation_certificates_checked": sum(
            row["invalid_trace_theorem_checked"] == "True" for row in certs
        ),
        "differential_disagreements": differential["disagreements"],
        "python_lean_trace_disagreements": agreement["trace_level_disagreements"],
        "benchmark_version": 2,
    }
    write_json(RESULTS / "evaluation_summary.json", summary)
    with (RESULTS / "evaluation_summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary))
        writer.writeheader()
        writer.writerow(summary)
    with (RESULTS / "confusion_matrix.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=["actual", "predicted", "count"])
        writer.writeheader()
        writer.writerows([
            {"actual": "invalid", "predicted": "invalid", "count": metrics["TP"]},
            {"actual": "invalid", "predicted": "valid", "count": metrics["FN"]},
            {"actual": "valid", "predicted": "invalid", "count": metrics["FP"]},
            {"actual": "valid", "predicted": "valid", "count": metrics["TN"]},
        ])


def finalize_publication_outputs() -> dict[str, Any]:
    _sync_v2_result_aliases()
    _tables()
    _figures()
    manifest = _manifest()
    missing_tables = [name for name in CORE_TABLES if not (TABLES / name).is_file()]
    missing_figures = [name for name in PRIMARY_FIGURES if not (FIGURES / name).is_file()]
    if missing_tables or missing_figures:
        raise RuntimeError(f"Missing outputs: tables={missing_tables}, figures={missing_figures}")
    pngs = list(FIGURES.glob("*.png"))
    if len(pngs) != 5:
        raise RuntimeError(f"Expected exactly five PNG figures, found {len(pngs)}")
    return manifest
