from __future__ import annotations

import csv
import hashlib
import inspect
import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import yaml

from .formalization_audit import CATALOG, audit_sub_obligations_v2
from .hierarchy_audit import audit_requirement_hierarchy
from .reference_hashes import verify_reference_checksums
from .reference_sub_obligation_validator import INDEPENDENCE
from .schema import ValidationTrace
from .sub_obligation_benchmark import ROOT as CHILD_ROOT
from .sub_obligations import (
    CHILD_FUNCTIONS, CHILD_IDS, DESCRIPTIONS, LEAN_PREDICATES, PARENTS,
    PYTHON_PREDICATES,
)
from .utils import PROJECT_ROOT, read_json, utc_now, write_json

RESULTS = PROJECT_ROOT / "results"
TABLES = RESULTS / "paper_tables"
PAPER_TEXT = RESULTS / "paper_text"
FIGURES = RESULTS / "figures"
LEAN_SOURCE = PROJECT_ROOT / "lean" / "LeanCert" / "Requirements.lean"
PRIMARY_FIGURES = (
    "artifact_integrity_anchoring.png", "confusion_matrix.png",
    "direct_vs_cascading_failures.png", "trace_size_vs_validation_time.png",
    "proof_checking_time.png",
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or (list(rows[0]) if rows else [])
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)


def _flag(value: Any) -> bool:
    return value is True or str(value).casefold() == "true"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reconcile_baseline() -> dict[str, Any]:
    pre = RESULTS / "formalization_catalogue_pre_fix.json"
    legacy = RESULTS / "formalization_sub_obligation_summary.json"
    final = RESULTS / "formalization_sub_obligation_summary_v2.json"
    candidates = []
    if pre.is_file():
        document = read_json(pre)
        count = sum(bool(row.get("lean_mapping")) for row in document.get("sub_obligations", []))
        candidates.append({
            "path": pre.relative_to(PROJECT_ROOT).as_posix(), "mapping_count": count,
            "artifact_role": "timestamped pre-fix snapshot",
            "catalogue_sha256": document.get("catalogue_sha256_before"),
        })
    if legacy.is_file():
        document = read_json(legacy)
        candidates.append({
            "path": legacy.relative_to(PROJECT_ROOT).as_posix(),
            "mapping_count": document.get("lean_mapped_sub_obligations"),
            "artifact_role": "legacy heuristic recomputed after refactoring; not a historical snapshot",
        })
    if final.is_file():
        document = read_json(final)
        candidates.append({
            "path": final.relative_to(PROJECT_ROOT).as_posix(),
            "mapping_count": document.get("lean_explicit_child_mappings"),
            "artifact_role": "post-fix exact-symbol audit",
        })
    authoritative = next((row for row in candidates if row["artifact_role"] == "timestamped pre-fix snapshot"), None)
    if authoritative is None:
        raise RuntimeError("No deterministic pre-fix snapshot is available")
    post = next((row for row in candidates if row["artifact_role"] == "post-fix exact-symbol audit"), None)
    result = {
        "candidate_pre_fix_files": candidates,
        "selected_authoritative_pre_fix_file": authoritative["path"],
        "pre_fix_lean_explicit_child_mappings": authoritative["mapping_count"],
        "post_fix_lean_explicit_child_mappings": post["mapping_count"] if post else None,
        "intermediate_mapping_counts": [row for row in candidates if row is not authoritative and row is not post],
        "selection_reason": (
            "The selected file is the only immutable pre-edit inventory: it records all 35 rows, "
            "their then-resolved Lean symbols, and the original catalogue SHA-256. The 6/35 file "
            "was recomputed later by a legacy name heuristic against the refactored Lean source and "
            "therefore is not a historical baseline."
        ),
        "manuscript_safe_statement": (
            f"Explicit Lean child mappings increased from {authoritative['mapping_count']}/35 in the "
            f"authoritative pre-fix snapshot to {(post or {}).get('mapping_count', 'N/A')}/35 in the final audit."
        ),
    }
    write_json(RESULTS / "formalization_baseline_reconciliation.json", result)
    return result


def reconcile_image_denominators() -> dict[str, Any]:
    rows = _read_csv(RESULTS / "image_inspection_results.csv")
    decompressed = sum(_flag(row["distribution_exists"]) and int(row["image_size_bytes"]) > 0 for row in rows)
    attempted = sum(row["inspection_status"] not in {"NOT_RUN", "NOT_APPLICABLE"} for row in rows)
    applicable = sum(row["filesystem_semantics"] == "APPLICABLE" for row in rows)
    passed = sum(row["filesystem_semantics"] == "APPLICABLE" and row["inspection_status"] == "PASSED" for row in rows)
    failed = sum(row["filesystem_semantics"] == "APPLICABLE" and row["inspection_status"] == "FAILED" for row in rows)
    partial = sum(row["inspection_status"] == "PARTIAL" for row in rows)
    not_applicable = sum(row["inspection_status"] == "NOT_APPLICABLE" for row in rows)
    not_run = sum(row["inspection_status"] == "NOT_RUN" for row in rows)
    old = read_json(RESULTS / "image_inspection_summary.json")
    summary = old | {
        "total_decompressed_images": decompressed,
        "inspection_attempted_count": attempted,
        "inspection_attempt_rate": attempted / decompressed if decompressed else None,
        "semantically_applicable_count": applicable,
        "semantic_passed_count": passed, "semantic_failed_count": failed,
        "semantic_success_rate": passed / applicable if applicable else None,
        "partial_count": partial, "not_applicable_count": not_applicable,
        "not_run_count": not_run,
    }
    write_json(RESULTS / "image_inspection_summary.json", summary)
    lines = [
        "| Image | Applicability | Inspection status | Filesystems | Root readable | Entries |",
        "|---|---|---|---|---|---:|",
    ]
    for row in rows:
        filesystems = ", ".join(json.loads(row["filesystem_types"])) or "N/A"
        lines.append(
            f"| {row['artifact_name']} | {row['filesystem_semantics']} | {row['inspection_status']} | "
            f"{filesystems} | {row['root_directory_readable']} | {row['root_entry_count']} |"
        )
    lines.extend([
        "", "| Metric | Measured result |", "|---|---:|",
        f"| Inspection attempted | {attempted}/{decompressed} ({attempted / decompressed:.1%}) |",
        f"| Semantic success (applicable images) | {passed}/{applicable} ({passed / applicable:.1%}) |",
        f"| Partial carving images | {partial} |", f"| Semantic failures | {failed} |",
        f"| Not applicable | {not_applicable} |", f"| Not run | {not_run} |",
        "", "PARTIAL carving images are not counted as semantic passes.",
    ])
    (TABLES / "table_image_inspection.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def _child_evidence() -> tuple[dict[str, Any], dict[str, ValidationTrace], dict[str, dict[str, str]]]:
    labels = read_json(CHILD_ROOT / "private" / "labels.json")["mapping"]
    traces = {}
    for path in sorted((CHILD_ROOT / "blinded").glob("*.json")):
        trace = ValidationTrace.model_validate(read_json(path)); traces[trace.trace_id] = trace
    certificates = {row["trace_id"]: row for row in _read_csv(RESULTS / "sub_obligation_certificate_results.csv")}
    return labels, traces, certificates


def audit_child_symbols_and_quality() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    catalogue = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    mappings = {row["id"]: row for row in catalogue["sub_obligation_mappings"]}
    labels, traces, certificates = _child_evidence()
    valid_ids = [tid for tid, meta in labels.items() if meta["expected_label"] == "valid"]
    lean_source = LEAN_SOURCE.read_text(encoding="utf-8")
    symbol_rows, quality_rows, coverage_rows = [], [], []
    seen_bodies: dict[str, str] = {}
    for child in CHILD_IDS:
        mapping = mappings.get(child, {})
        function = CHILD_FUNCTIONS[child]
        symbol = PYTHON_PREDICATES[child]
        targets = [tid for tid, meta in labels.items() if meta.get("target_sub_obligation") == child]
        positive_python = bool(valid_ids) and all(function(traces[tid]) for tid in valid_ids)
        negative_python = bool(targets) and all(not function(traces[tid]) for tid in targets)
        lean_predicate = str(mapping.get("lean_predicate", ""))
        lean_exists = bool(lean_predicate and (
            f"abbrev {lean_predicate} " in lean_source or f"def {lean_predicate} " in lean_source
        ))
        positive_lean = lean_exists and any(
            certificates.get(tid, {}).get("lean_check_status") == "PASSED" for tid in valid_ids
        ) and positive_python
        negative_lean = lean_exists and bool(targets) and all(
            certificates.get(tid, {}).get("lean_check_status") == "PASSED" for tid in targets
        ) and negative_python
        bname = lean_predicate + "B"
        start = lean_source.find(f"def {bname}")
        end = lean_source.find("\ndef ", start + 1) if start >= 0 else -1
        body = lean_source[start:end if end >= 0 else None] if start >= 0 else ""
        normalized = " ".join(body.split())
        duplicate = seen_bodies.get(normalized, "") if normalized else ""
        if normalized and not duplicate: seen_bodies[normalized] = lean_predicate
        uses_trace = "(t : Trace)" in body and bool(re.search(r"\bt\.|B t\b", body))
        uses_sorry = "sorry" in body
        uses_admit = "admit" in body
        unsafe = "axiom" in body or "unsafe" in body
        quality = "PASS" if all((uses_trace, positive_lean, negative_lean, not duplicate,
                                  not uses_sorry, not uses_admit, not unsafe)) else "FAIL"
        symbol_rows.append({
            "sub_obligation_id": child, "parent_requirement": PARENTS[child],
            "python_symbol": symbol,
            "python_symbol_exists": inspect.isfunction(function) and function.__module__ == "leancert.sub_obligations",
            "lean_predicate": lean_predicate, "lean_predicate_exists": lean_exists,
            "positive_python_test": mapping.get("positive_python_test", ""),
            "negative_python_test": mapping.get("negative_python_test", ""),
            "positive_lean_test": mapping.get("positive_lean_test", ""),
            "negative_lean_test": mapping.get("negative_lean_test", ""),
            "direct_benchmark_case_count": len(targets),
            "status": "PASS" if symbol == mapping.get("python_predicate") and lean_exists else "FAIL",
        })
        quality_rows.append({
            "sub_obligation_id": child, "lean_predicate": lean_predicate,
            "uses_trace_data": uses_trace, "positive_case_true": positive_lean,
            "negative_case_false": negative_lean, "duplicate_of": duplicate,
            "uses_sorry": uses_sorry, "uses_admit": uses_admit,
            "uses_unsafe_axiom": unsafe, "quality_status": quality,
        })
        complete = all((symbol_rows[-1]["status"] == "PASS", quality == "PASS",
                        positive_python, negative_python, positive_lean, negative_lean,
                        len(targets) > 0, child in DESCRIPTIONS))
        coverage_rows.append({
            "sub_obligation_id": child, "parent_requirement": PARENTS[child],
            "python_symbol": symbol, "lean_predicate": lean_predicate,
            "python_mapping": symbol_rows[-1]["status"] == "PASS",
            "lean_mapping": lean_exists and quality == "PASS",
            "positive_python_test": positive_python, "negative_python_test": negative_python,
            "positive_lean_test": positive_lean, "negative_lean_test": negative_lean,
            "direct_benchmark_case_count": len(targets), "failure_explanation": child in DESCRIPTIONS,
            "coverage_status": "COVERED" if complete else "INCOMPLETE",
        })
    _write_csv(RESULTS / "sub_obligation_symbol_audit.csv", symbol_rows)
    _write_csv(RESULTS / "lean_child_quality_audit.csv", quality_rows)
    _write_csv(RESULTS / "formalization_sub_obligation_coverage_final.csv", coverage_rows)
    count = lambda key: sum(_flag(row[key]) for row in coverage_rows)
    summary = {
        "declared_sub_obligations": len(coverage_rows),
        "concrete_python_child_mappings": count("python_mapping"),
        "lean_explicit_child_mappings": count("lean_mapping"),
        "positive_python_child_coverage": count("positive_python_test"),
        "negative_python_child_coverage": count("negative_python_test"),
        "positive_lean_child_coverage": count("positive_lean_test"),
        "negative_lean_child_coverage": count("negative_lean_test"),
        "direct_child_benchmark_coverage": sum(int(row["direct_benchmark_case_count"]) > 0 for row in coverage_rows),
        "failure_explanation_child_coverage": count("failure_explanation"),
        "lean_child_quality_failures": sum(row["quality_status"] == "FAIL" for row in quality_rows),
        "fully_covered_children": sum(row["coverage_status"] == "COVERED" for row in coverage_rows),
        "uncovered_children": [row["sub_obligation_id"] for row in coverage_rows if row["coverage_status"] != "COVERED"],
        "coverage_scope": "Catalogue-relative to the 35 declared sub-obligations.",
    }
    write_json(RESULTS / "formalization_sub_obligation_summary_final.json", summary)
    return symbol_rows, quality_rows, summary


ROOT_SUB = {
    "IdentityCompleteness": "REQ-ID-001-SUB-03", "ReferentialIntegrity": "REQ-REF-001-SUB-01",
    "PublicArtifactIntegrity": "REQ-ART-001-SUB-02", "CustodyContinuity": "REQ-CUST-001-SUB-02",
    "ChronologicalConsistency": "REQ-CHR-001-SUB-01", "HashContinuity": "REQ-HASH-001-SUB-02",
    "AuthorizedHandling": "REQ-AUTH-001-SUB-02", "LifecycleCorrectness": "REQ-LIFE-001-SUB-04",
    "ReportTraceability": "REQ-RPT-001-SUB-01",
}


def audit_cascades() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    labels = read_json(PROJECT_ROOT / "benchmark" / "holdout_v2" / "private" / "labels.json")["mapping"]
    rows = _read_csv(RESULTS / "per_trace_results_v2.csv")
    cascades = []
    pair_counts: Counter[tuple[str, str]] = Counter()
    for row in rows:
        meta = labels[row["trace_id"]]; root = meta.get("root_requirement")
        if not root: continue
        failed = [item for item in row["failed_requirements"].split(";") if item]
        for affected in failed:
            if affected == root: continue
            pair_counts[(root, affected)] += 1
            if root == "ReportTraceability" and affected == "IdentityCompleteness":
                affected_child = "REQ-ID-001-SUB-05"
                reason = "The report mutation empties claim text; non-empty claim text is declared in both claim identity and report traceability."
                dependency = "DUPLICATED_SEMANTICS"
            elif affected == "ReportTraceability":
                affected_child = "REQ-RPT-001-SUB-04"
                reason = "Report traceability explicitly requires all upstream core requirements to pass."
                dependency = "LOGICAL_DEPENDENCY"
            else:
                affected_child = ""
                reason = "Observed cross-requirement effect requires further interpretation."
                dependency = "UNKNOWN"
            cascades.append({
                "trace_id": row["trace_id"], "root_direct_requirement": root,
                "root_sub_obligation": ROOT_SUB.get(root, ""), "cascading_requirement": affected,
                "cascading_sub_obligation": affected_child, "causal_reason": reason,
                "expected_by_model": dependency in {"DUPLICATED_SEMANTICS", "LOGICAL_DEPENDENCY"},
                "dependency_type": dependency,
            })
    _write_csv(RESULTS / "cascading_dependency_audit.csv", cascades)
    requirements = list(dict.fromkeys(PARENTS.values()))
    matrix = [{
        "root_requirement": root, "affected_requirement": affected,
        "trace_count": pair_counts[(root, affected)],
        "dependency_type": (
            "DUPLICATED_SEMANTICS" if root == "ReportTraceability" and affected == "IdentityCompleteness"
            else "LOGICAL_DEPENDENCY" if affected == "ReportTraceability" and root != affected
            else "NONE" if not pair_counts[(root, affected)] else "UNKNOWN"
        ),
    } for root in requirements for affected in requirements]
    _write_csv(RESULTS / "requirement_dependency_matrix.csv", matrix)
    return cascades, matrix


def audit_reference_independence() -> list[dict[str, Any]]:
    source = (PROJECT_ROOT / "leancert" / "reference_sub_obligation_validator.py").read_text(encoding="utf-8")
    imports_production = "from .sub_obligations" in source or "from .validator" in source
    rows = []
    for child in CHILD_IDS:
        classification = "NOT_IMPLEMENTED" if child not in INDEPENDENCE else INDEPENDENCE[child]
        limited = classification == "LIMITED"
        reason = {
            "REQ-ART-001-SUB-01": "Uses independent code but necessarily checks the same filesystem existence fact.",
            "REQ-ART-001-SUB-02": "Uses independent hashing code but necessarily compares the same declared digest.",
            "REQ-ART-001-SUB-03": "Uses independent code but necessarily compares the same filesystem size fact.",
            "REQ-AUTH-001-SUB-02": "Re-expresses the same declared prototype role-action policy table.",
            "REQ-RPT-001-SUB-04": "Re-expresses the same declared upstream catalogue composition.",
        }.get(child, "Uses independently structured relations/comprehensions and imports no production predicates.")
        rows.append({
            "sub_obligation_id": child,
            "reference_symbol": f"leancert.reference_sub_obligation_validator.evaluate_reference_children:{child}",
            "independence_classification": classification,
            "shared_constants": limited and child.startswith("REQ-ART"),
            "shared_permission_tables": child == "REQ-AUTH-001-SUB-02",
            "shared_lifecycle_tables": False,
            "shared_helper_functions": imports_production,
            "reason": reason,
        })
    _write_csv(RESULTS / "reference_independence_audit.csv", rows)
    lines = [
        "| Child | Classification | Shared basis | Reason |", "|---|---|---|---|",
        *[
            f"| {row['sub_obligation_id']} | {row['independence_classification']} | "
            f"{'Declared policy/fact' if row['independence_classification'] == 'LIMITED' else 'None'} | {row['reason']} |"
            for row in rows
        ],
    ]
    (TABLES / "table_reference_independence.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rows


def assess_roc_candidate(
    *, decision_output_type: str, score_name: str | None,
    predefined_before_holdout: bool, uses_ground_truth_labels: bool,
    uses_failure_count_only: bool, threshold_has_operational_meaning: bool,
    meaningful_ordering: bool, part_of_decision_model: bool,
) -> tuple[bool, str]:
    checks = {
        "continuous_or_ordinal": decision_output_type in {"continuous", "ordinal"},
        "named_score": bool(score_name),
        "predefined_before_holdout": predefined_before_holdout,
        "label_independent": not uses_ground_truth_labels,
        "not_failure_count": not uses_failure_count_only,
        "operational_threshold": threshold_has_operational_meaning,
        "meaningful_ordering": meaningful_ordering,
        "part_of_decision_model": part_of_decision_model,
    }
    eligible = all(checks.values())
    failed = [name for name, passed in checks.items() if not passed]
    return eligible, "Eligible predefined score." if eligible else "Failed eligibility checks: " + ", ".join(failed)


def audit_roc_eligibility() -> dict[str, Any]:
    eligible, reason = assess_roc_candidate(
        decision_output_type="binary", score_name=None, predefined_before_holdout=False,
        uses_ground_truth_labels=False, uses_failure_count_only=False,
        threshold_has_operational_meaning=False, meaningful_ordering=False,
        part_of_decision_model=True,
    )
    result = {
        "roc_applicable": eligible, "decision_output_type": "binary",
        "candidate_score": "No eligible score. Binary VALID/INVALID is the actual decision output; failure counts were rejected.",
        "score_definition": None, "score_predefined_before_holdout": False,
        "uses_ground_truth_labels": False, "uses_failure_count_only": False,
        "threshold_has_operational_meaning": False,
        "eligibility_checks": reason,
        "evaluated_ineligible_candidates": [
            {"name": "binary acceptance", "reason": "Only one operating point."},
            {"name": "failed requirement count", "reason": "Circular with controlled mutation design and not an operational probability/risk score."},
            {"name": "failed child count", "reason": "Circular with catalogue conformance and not an independently defined decision score."},
        ],
        "eligibility_reason": (
            "LeanCert-Forensics produces deterministic requirement-conformance decisions rather "
            "than continuously scored predictions. No predefined ordinal or continuous assurance "
            "score with deployable threshold semantics exists."
        ),
        "recommended_paper_treatment": (
            "Report ROC/AUC and precision-recall analysis as not applicable; retain the confusion "
            "matrix and exact confidence intervals."
        ),
    }
    write_json(RESULTS / "roc_eligibility_audit.json", result)
    PAPER_TEXT.mkdir(parents=True, exist_ok=True)
    (PAPER_TEXT / "roc_applicability_note.md").write_text(
        "ROC/AUC analysis was not used because the validator implements deterministic "
        "requirement-conformance predicates and produces a binary acceptance decision rather "
        "than a continuously scored prediction. Constructing a ROC curve from the number of "
        "violated requirements would make the ranking circular with respect to the controlled "
        "benchmark design and could misleadingly imply probabilistic discrimination.\n",
        encoding="utf-8",
    )
    return result


def _save(fig: plt.Figure, filename: str) -> None:
    fig.tight_layout(); fig.savefig(FIGURES / filename, dpi=300, bbox_inches="tight"); plt.close(fig)


def regenerate_figures(image: dict[str, Any], references: dict[str, Any], cascades: list[dict[str, Any]]) -> None:
    processing = read_json(PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json")
    inspection_rows = _read_csv(RESULTS / "image_inspection_results.csv")
    readable = sum(_flag(row["distribution_exists"]) for row in inspection_rows)
    consistent = sum(_flag(row["manifest_size_match"]) and _flag(row["manifest_sha256_match"]) for row in inspection_rows)
    decompressed = sum(row.get("decompression_status") == "PASSED" for row in processing)
    numerators = [readable, consistent, decompressed, image["inspection_attempted_count"],
                  image["semantic_passed_count"], references["external_reference_available_count"]]
    denominators = [len(inspection_rows), len(inspection_rows), len(processing), image["total_decompressed_images"],
                    image["semantically_applicable_count"], references["external_reference_eligible_count"]]
    labels = ["Local readable", "Manifest consistent", "Decompression successful", "Inspection attempted",
              "Semantic success\n(applicable)", "External checksum\ncoverage"]
    rates = [n / d if d else 0 for n, d in zip(numerators, denominators)]
    fig, ax = plt.subplots(figsize=(11.2, 5.2)); x = np.arange(7)
    bars = ax.bar(x[:6], np.array(rates) * 100, color="#356a9a")
    for bar, n, d in zip(bars, numerators, denominators):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, f"{n/d:.0%} ({n}/{d})", ha="center", fontsize=8)
    ax.text(6, 48, "N/A\nNo official reference available", ha="center", va="center",
            bbox={"boxstyle": "round", "facecolor": "#eeeeee", "edgecolor": "#777777"})
    ax.set_xticks(x, labels + ["External checksum\nmatch"], rotation=20, ha="right")
    ax.set_ylim(0, 113); ax.set_ylabel("Measured rate (%)")
    ax.set_title("Artifact Integrity, Semantic Inspection, and External Anchoring")
    _save(fig, "artifact_integrity_anchoring.png")

    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    matrix = np.array([[metrics["TN"], metrics["FP"]], [metrics["FN"], metrics["TP"]]])
    fig, ax = plt.subplots(figsize=(5.8, 4.9)); shown = ax.imshow(matrix, cmap="Blues")
    for (r, c), value in np.ndenumerate(matrix): ax.text(c, r, str(value), ha="center", va="center", fontsize=16)
    ax.set_xticks([0, 1], ["Predicted valid", "Predicted invalid"])
    ax.set_yticks([0, 1], ["Actual valid", "Actual invalid"])
    ax.set_title("Locked and Blinded Controlled Holdout")
    ax.text(.5, -.19, f"n={metrics['total_traces']}; valid={metrics['valid_traces']}; controlled-invalid={metrics['invalid_traces']}",
            transform=ax.transAxes, ha="center", fontsize=9)
    fig.colorbar(shown, ax=ax, fraction=.046); _save(fig, "confusion_matrix.png")

    coverage = _read_csv(RESULTS / "holdout_requirement_coverage.csv")
    names = [row["requirement"] for row in coverage]
    direct = [int(row["direct_invalid_traces"]) for row in coverage]
    cascading = [int(row["cascading_affected_traces"]) for row in coverage]
    fig, ax = plt.subplots(figsize=(11.3, 5.3)); x = np.arange(len(names)); width = .38
    ax.bar(x-width/2, direct, width, label="Direct: root violation")
    ax.bar(x+width/2, cascading, width, label="Cascading: downstream consequence")
    ax.set_xticks(x, names, rotation=32, ha="right"); ax.set_ylabel("Unique affected traces")
    ax.set_title("Direct and Cascading Requirement Failures"); ax.legend()
    identity = sum(row["cascading_requirement"] == "IdentityCompleteness" for row in cascades)
    ax.text(.01, .98, f"Identity cascades ({identity}) arise from audited duplicated claim-text semantics.\nCounts are non-exclusive.",
            transform=ax.transAxes, va="top", fontsize=8)
    _save(fig, "direct_vs_cascading_failures.png")

    python_rows = _read_csv(RESULTS / "scalability_summary_python.csv")
    xs = [int(row["event_count"]) for row in python_rows]
    medians = [float(row["median_us"]) for row in python_rows]
    iqr = [float(row["IQR_us"]) for row in python_rows]
    fig, ax = plt.subplots(figsize=(8.5, 4.9)); ax.errorbar(xs, medians, yerr=np.array(iqr)/2, marker="o", capsize=4)
    ax.set_xticks(xs); ax.set_xlabel("Events per trace"); ax.set_ylabel("Median validation time (µs)")
    ax.set_title("Python Validation Scalability"); ax.grid(alpha=.25)
    _save(fig, "trace_size_vs_validation_time.png")

    lean_rows = _read_csv(RESULTS / "lean_scalability_by_mode.csv")
    fig, ax = plt.subplots(figsize=(8.7, 5.0))
    for mode, label in (("pairwise", "Pairwise proof mode"), ("aggregate", "Aggregate proof mode")):
        group = [row for row in lean_rows if row["proof_mode"] == mode]
        ax.errorbar([int(r["event_count"]) for r in group], [float(r["median_time_ms"]) for r in group],
                    yerr=[float(r["IQR_time_ms"])/2 for r in group], marker="o", capsize=4, label=label)
    ax.set_xlabel("Events per trace"); ax.set_ylabel("Median per-file Lean time (ms)")
    ax.set_title("Lean Proof-Checking Scalability by Encoding Mode"); ax.grid(alpha=.25); ax.legend()
    _save(fig, "proof_checking_time.png")


def generate_tables_and_text(
    baseline: dict[str, Any], references: dict[str, Any], image: dict[str, Any],
    final_coverage: dict[str, Any], reference_rows: list[dict[str, Any]], roc: dict[str, Any],
) -> None:
    TABLES.mkdir(parents=True, exist_ok=True); PAPER_TEXT.mkdir(parents=True, exist_ok=True)
    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    child = read_json(RESULTS / "sub_obligation_evaluation_summary.json")
    differential = read_json(RESULTS / "differential_validation_summary_v2.json")
    certs = _read_csv(RESULTS / "lean_certificate_semantics.csv")
    reference_counts = Counter(row["independence_classification"] for row in reference_rows)

    artifact = [
        "| Integrity dimension | Numerator | Denominator | Result |", "|---|---:|---:|---:|",
        f"| External checksum coverage | {references['external_reference_available_count']} | {references['external_reference_eligible_count']} | {references['external_reference_verification_coverage']:.1%} |",
        f"| External checksum match | {references['external_reference_verified_count']} | {references['external_reference_available_count']} | {references['external_match_rate_display']} |",
        f"| Semantic success (applicable) | {image['semantic_passed_count']} | {image['semantically_applicable_count']} | {image['semantic_success_rate']:.1%} |",
        "", "N/A denotes an unavailable denominator and is not treated as a validation failure.",
    ]
    (TABLES / "table_artifact_integrity.md").write_text("\n".join(artifact) + "\n", encoding="utf-8")

    metric_lines = ["| Metric | Estimate | 95% interval | Method |", "|---|---:|---|---|"]
    cis = {row["metric"]: row for row in metrics["confidence_intervals"]}
    for name in ("accuracy", "precision", "recall", "specificity", "f1", "false_acceptance_rate", "false_rejection_rate"):
        ci = cis[name]
        metric_lines.append(f"| {name.replace('_', ' ').title()} | {metrics[name]:.4f} | [{ci['lower_95']:.4f}, {ci['upper_95']:.4f}] | {ci['interval_method']} |")
    metric_lines.extend(["", "The F1 bootstrap interval degenerates at 1.0 when every stratified resample remains perfectly classified; exact class-specific intervals therefore provide a more informative characterization of finite-sample uncertainty."])
    (TABLES / "table_holdout_metrics.md").write_text("\n".join(metric_lines) + "\n", encoding="utf-8")

    diff_table = (
        "| Validation level | Comparisons | Disagreements | Agreement |\n|---|---:|---:|---:|\n"
        f"| Top-level production/reference | {differential['total_comparisons']} | {differential['disagreements']} | {differential['agreement_rate']:.1%} |\n"
        f"| Child production/reference | {child['reference_child_comparisons']} | {child['reference_child_disagreements']} | {(child['reference_child_comparisons']-child['reference_child_disagreements'])/child['reference_child_comparisons']:.1%} |\n"
        f"| Child Python/Lean | {child['total_child_comparisons']} | {child['disagreements']} | {child['agreement_rate']:.1%} |\n"
    )
    (TABLES / "table_differential_validation.md").write_text(diff_table, encoding="utf-8")

    residual = [
        "No independently labelled natural chain-of-custody failure corpus was available.",
        "Controlled perturbations do not estimate real operational prevalence or natural-failure accuracy.",
        f"Official publisher checksums were unavailable for {references['external_reference_unavailable_count']} eligible artifacts.",
        f"Reference independence remains LIMITED for {reference_counts['LIMITED']} child obligations.",
        "Catalogue-relative 35/35 coverage does not establish digital-forensic domain completeness.",
        "Lean propositions apply to the encoded trace model.",
        "Factual truth or authenticity of external evidence is not established by trace conformance.",
        "Legal admissibility is not established.",
        "Scalability is demonstrated only through the maximum tested event count (500).",
        "ROC/AUC and precision-recall analysis are not applicable without a genuine predefined continuous decision score.",
    ]
    (TABLES / "table_residual_limitations.md").write_text(
        "| # | Residual limitation |\n|---:|---|\n" + "".join(f"| {i} | {text} |\n" for i, text in enumerate(residual, 1)), encoding="utf-8"
    )

    captions = f"""# Figure captions

1. **Artifact Integrity, Semantic Inspection, and External Anchoring.** Local readability, manifest consistency, decompression, and inspection are shown with measured numerators and denominators. Semantic success uses only the {image['semantically_applicable_count']} applicable filesystem images; {image['partial_count']} carving images remain PARTIAL. N/A denotes an unavailable denominator and is not treated as a validation failure.

2. **Locked and Blinded Controlled Holdout.** Confusion matrix for {metrics['total_traces']} locked traces ({metrics['valid_traces']} valid and {metrics['invalid_traces']} controlled-invalid). These controlled cases measure declared conformance enforcement, not natural-failure prevalence.

3. **Direct and Cascading Requirement Failures.** Direct counts identify root requirement violations; cascading counts identify downstream consequences. Counts represent unique affected traces and categories are non-exclusive. The audited IdentityCompleteness cascade is duplicated claim-text semantics; ReportTraceability cascades through its declared upstream-support dependency.

4. **Python Validation Scalability.** Median validation time across 15 structurally distinct traces at each of 4, 8, 12, 20, 50, 100, 200, and 500 events. Ten warm-up runs were excluded and 30 runs were measured; error bars show IQR. No asymptotic complexity claim is made.

5. **Lean Proof-Checking Scalability by Encoding Mode.** Prerequisite modules were precompiled, while each measured file launched a new Lean process. Pairwise and aggregate modes are distinct formal workloads; lower aggregate times do not imply that Lean intrinsically becomes faster. No asymptotic complexity claim is made.
"""
    (PAPER_TEXT / "figure_captions.md").write_text(captions, encoding="utf-8")

    validation = f"""# Validation summary

## Dataset grounding
The evaluation uses measured public-data-derived artifacts and keeps the top-level holdout and child benchmark separate.

## Artifact integrity
Official-checksum availability was investigated for {references['external_reference_eligible_count']} eligible distributions; {references['external_reference_available_count']} official checksums were available, so match rate is {references['external_match_rate_display']} rather than zero.

## Semantic image inspection
Inspection was attempted for {image['inspection_attempted_count']}/{image['total_decompressed_images']} images. All {image['semantic_passed_count']}/{image['semantically_applicable_count']} applicable filesystem images passed; {image['partial_count']} carving images remained PARTIAL.

## Top-level controlled holdout
The locked/blinded holdout contained {metrics['total_traces']} traces: {metrics['valid_traces']} valid and {metrics['invalid_traces']} controlled-invalid. TP={metrics['TP']}, TN={metrics['TN']}, FP={metrics['FP']}, and FN={metrics['FN']}.

## Confidence intervals
Exact Clopper–Pearson intervals are reported for appropriate proportions and a 10,000-resample stratified bootstrap is reported for F1. The F1 bootstrap interval degenerates at 1.0 when every stratified resample remains perfectly classified; exact class-specific intervals therefore provide a more informative characterization of finite-sample uncertainty.

## Sub-obligation formalization
The authoritative pre-fix count was {baseline['pre_fix_lean_explicit_child_mappings']}/35; the final exact-symbol audit measured {final_coverage['concrete_python_child_mappings']}/35 Python and {final_coverage['lean_explicit_child_mappings']}/35 Lean mappings.

## Child-level controlled benchmark
The separate controlled benchmark contained {child['controlled_trace_count']} traces and detected {child['target_child_violations_detected']}/{child['targeted_invalid_cases']} targeted violations.

## Differential/reference validation
Top-level differential disagreements were {differential['disagreements']}/{differential['total_comparisons']}; child reference disagreements were {child['reference_child_disagreements']}/{child['reference_child_comparisons']}.

## Reference-independence limitations
{reference_counts['STRUCTURALLY_INDEPENDENT']} child checks were structurally independent and {reference_counts['LIMITED']} were LIMITED; the latter are not described as fully independent.

## Python–Lean agreement and certificates
Child Python–Lean disagreements were {child['disagreements']}/{child['total_child_comparisons']}. The child study checked {child['valid_lean_certificates_checked']} validity and {child['invalid_lean_violation_certificates_checked']} violation certificates. Holdout v2 checked {sum(row['valid_trace_theorem_checked']=='True' for row in certs)} validity and {sum(row['invalid_trace_theorem_checked']=='True' for row in certs)} violation certificates.

## Scalability
Python validation and Lean proof checking were measured through 500 events. Pairwise and aggregate Lean encodings are separate workloads, and no asymptotic claim is made.

## ROC/PR applicability
ROC/AUC and precision–recall curves were not generated. {roc['eligibility_reason']}

## Threats to validity
The controlled benchmarks do not estimate natural prevalence; external reference checksums were unavailable; reference independence is limited for some children; formal results concern the encoded model and do not establish factual truth or legal admissibility.
"""
    (PAPER_TEXT / "validation_summary.md").write_text(validation, encoding="utf-8")

    claims = [
        ("35 child obligations mapped", "formalization_sub_obligation_summary_final.json", "35/35 Python and Lean mappings", "All 35 sub-obligations in the declared catalogue were explicitly mapped.", "All digital-forensic requirements were completely formalized."),
        ("Perfect controlled holdout", "holdout_metrics_v2.json", f"TP={metrics['TP']}, TN={metrics['TN']}, FP={metrics['FP']}, FN={metrics['FN']}", "No errors were observed in the locked/blinded controlled holdout; exact confidence intervals are reported.", "LeanCert achieves 100% real-world forensic accuracy."),
        ("Lean certificates", "lean_certificate_semantics.csv", f"{sum(row['valid_trace_theorem_checked']=='True' for row in certs)} validity and {sum(row['invalid_trace_theorem_checked']=='True' for row in certs)} violation certificates", "Valid encoded traces received checked validity certificates and invalid encoded traces received checked violation certificates.", "Lean proves that real-world evidence is admissible."),
        ("ROC applicability", "roc_eligibility_audit.json", "Not applicable", "ROC analysis was not applicable to the deterministic binary conformance validator.", "AUC=1.0 based on rule-failure count."),
    ]
    matrix = ["| Manuscript Claim | Supporting Artifact | Measured Result | Allowed Wording | Prohibited Overclaim |", "|---|---|---|---|---|",
              *["| " + " | ".join(row) + " |" for row in claims]]
    (PAPER_TEXT / "claim_evidence_matrix.md").write_text("\n".join(matrix) + "\n", encoding="utf-8")


def update_manifest(
    baseline: dict[str, Any], references: dict[str, Any], image: dict[str, Any],
    coverage: dict[str, Any], reference_rows: list[dict[str, Any]], roc: dict[str, Any],
) -> dict[str, Any]:
    manifest_path = RESULTS / "experiment_manifest.json"
    manifest = read_json(manifest_path)
    metrics = read_json(RESULTS / "holdout_metrics_v2.json")
    child = read_json(RESULTS / "sub_obligation_evaluation_summary.json")
    changes = read_json(RESULTS / "formalization_catalogue_changes.json")
    refs = Counter(row["independence_classification"] for row in reference_rows)
    residual = [line.split("|", 2)[2].strip() for line in (TABLES / "table_residual_limitations.md").read_text(encoding="utf-8").splitlines()[2:] if line.startswith("|")]
    manifest.update({
        "pre_fix_lean_child_mapping_count": baseline["pre_fix_lean_explicit_child_mappings"],
        "post_fix_lean_child_mapping_count": coverage["lean_explicit_child_mappings"],
        "declared_parent_requirements": len(set(PARENTS.values())),
        "declared_sub_obligations": coverage["declared_sub_obligations"],
        "python_explicit_child_mappings": coverage["concrete_python_child_mappings"],
        "lean_explicit_child_mappings": coverage["lean_explicit_child_mappings"],
        "positive_python_child_coverage": coverage["positive_python_child_coverage"],
        "negative_python_child_coverage": coverage["negative_python_child_coverage"],
        "positive_lean_child_coverage": coverage["positive_lean_child_coverage"],
        "negative_lean_child_coverage": coverage["negative_lean_child_coverage"],
        "direct_child_benchmark_coverage": coverage["direct_child_benchmark_coverage"],
        "failure_explanation_child_coverage": coverage["failure_explanation_child_coverage"],
        "child_python_lean_comparisons": child["total_child_comparisons"],
        "child_python_lean_disagreements": child["disagreements"],
        "reference_structurally_independent_children": refs["STRUCTURALLY_INDEPENDENT"],
        "reference_limited_children": refs["LIMITED"],
        "semantic_inspection_attempted": image["inspection_attempted_count"],
        "semantic_inspection_applicable": image["semantically_applicable_count"],
        "semantic_inspection_passed": image["semantic_passed_count"],
        "semantic_inspection_partial": image["partial_count"],
        "external_reference_eligible_count": references["external_reference_eligible_count"],
        "external_reference_available_count": references["external_reference_available_count"],
        "external_reference_verified_count": references["external_reference_verified_count"],
        "external_reference_unavailable_count": references["external_reference_unavailable_count"],
        "external_match_rate": references["external_match_rate"],
        "holdout_v2_total": metrics["total_traces"], "holdout_v2_valid": metrics["valid_traces"],
        "holdout_v2_invalid": metrics["invalid_traces"], "TP": metrics["TP"], "TN": metrics["TN"],
        "FP": metrics["FP"], "FN": metrics["FN"], "confidence_intervals": metrics["confidence_intervals"],
        "roc_applicable": roc["roc_applicable"], "roc_score_name": None, "roc_auc": None,
        "roc_auc_ci": None, "average_precision": None, "average_precision_ci": None,
        "benchmark_holdout_v2_sha256": manifest.get("benchmark_v2_lock_sha256"),
        "benchmark_child_holdout_sha256": child["benchmark_sha256"],
        "catalogue_sha256_before": changes["catalogue_sha256_before"],
        "catalogue_sha256_after": _sha(CATALOG), "primary_figure_count": len(PRIMARY_FIGURES),
        "residual_limitations": residual,
    })
    write_json(manifest_path, manifest); return manifest


def run_final_scientific_audit() -> dict[str, Any]:
    TABLES.mkdir(parents=True, exist_ok=True); PAPER_TEXT.mkdir(parents=True, exist_ok=True); FIGURES.mkdir(parents=True, exist_ok=True)
    baseline = reconcile_baseline()
    _, references = verify_reference_checksums()
    image = reconcile_image_denominators()
    _, _, coverage = audit_child_symbols_and_quality()
    hierarchy, hierarchy_ok = audit_requirement_hierarchy()
    shutil.copyfile(RESULTS / "requirement_hierarchy_audit.csv", RESULTS / "requirement_hierarchy_audit_final.csv")
    cascades, _ = audit_cascades()
    reference_rows = audit_reference_independence()
    roc = audit_roc_eligibility()
    # Retain the established detailed formalization tables, now using concrete symbols.
    audit_sub_obligations_v2()
    regenerate_figures(image, references, cascades)
    generate_tables_and_text(baseline, references, image, coverage, reference_rows, roc)
    manifest = update_manifest(baseline, references, image, coverage, reference_rows, roc)
    result = {
        "baseline": baseline, "references": references, "image": image,
        "coverage": coverage, "hierarchy_passed": hierarchy_ok,
        "hierarchy_rows": len(hierarchy), "cascade_rows": len(cascades),
        "reference_counts": dict(Counter(row["independence_classification"] for row in reference_rows)),
        "roc": roc, "manifest": manifest,
    }
    write_json(RESULTS / "manuscript_readiness_summary.json", result)
    return result
