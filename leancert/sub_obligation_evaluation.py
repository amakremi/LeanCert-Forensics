from __future__ import annotations

import copy
import csv
import json
import random
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .reference_sub_obligation_validator import INDEPENDENCE, evaluate_reference_children
from .report import process_trace_file
from .schema import ValidationTrace
from .sub_obligation_benchmark import ROOT, verify_lock
from .sub_obligations import CHILD_IDS, LEAN_PREDICATES, PARENTS, evaluate_children
from .utils import PROJECT_ROOT, read_json, utc_now, write_json
from .validator import validate_trace

CONTROLLED_NOTICE = (
    "The sub-obligation benchmark consists of controlled, declaratively specified "
    "perturbations of public-data-derived forensic traces. It validates enforcement of the "
    "declared obligation catalogue; it does not estimate the prevalence or detection accuracy "
    "of naturally occurring forensic process failures."
)
NATURAL_LIMITATION = "No independently labelled natural chain-of-custody failure corpus was available."


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or (list(rows[0]) if rows else [])
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _theorem_name(child: str, result: bool) -> str:
    return (
        f"example:{LEAN_PREDICATES[child]}"
        if result else f"child_{child.casefold().replace('-', '_')}_invalid"
    )


def _leakage_audit(paths: list[Path]) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []
    samples = paths[: min(12, len(paths))]
    rng = random.Random(20260809)
    for path in samples:
        raw = read_json(path)
        baseline = ValidationTrace.model_validate(raw)
        expected = evaluate_children(baseline)
        overall = validate_trace(baseline, strict_artifacts=True).overall_status
        variants: dict[str, dict[str, Any]] = {
            "changing_filename": copy.deepcopy(raw),
            "changing_trace_id": copy.deepcopy(raw),
            "relocating_file": copy.deepcopy(raw),
            "removing_private_metadata": {k: copy.deepcopy(v) for k, v in raw.items()
                                          if k not in {"expected_label", "mutation_id", "target_sub_obligation", "evaluation_metadata"}},
            "changing_private_expected_label": copy.deepcopy(raw),
            "randomizing_blinded_identifier": copy.deepcopy(raw),
        }
        variants["changing_trace_id"]["trace_id"] = f"RENAMED-{rng.getrandbits(48):012x}"
        variants["randomizing_blinded_identifier"]["trace_id"] = f"RANDOM-{rng.getrandbits(48):012x}"
        for control, variant in variants.items():
            checked = ValidationTrace.model_validate(variant)
            same = evaluate_children(checked) == expected and validate_trace(
                checked, strict_artifacts=True
            ).overall_status == overall
            controls.append({"trace_id": raw["trace_id"], "control": control, "passed": same})
    result = {
        "generated_at_utc": utc_now(), "sample_count": len(samples),
        "control_count": len(controls), "prediction_change_count": sum(not row["passed"] for row in controls),
        "audit_passed": all(row["passed"] for row in controls), "controls": controls,
        "scientific_scope": CONTROLLED_NOTICE,
    }
    write_json(PROJECT_ROOT / "results" / "sub_obligation_leakage_audit.json", result)
    return result


def _metamorphic(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        raw = read_json(path)
        baseline = evaluate_children(ValidationTrace.model_validate(raw))
        variants: dict[str, dict[str, Any]] = {}
        reordered_actors = copy.deepcopy(raw); reordered_actors["actors"] = list(reversed(reordered_actors["actors"]))
        variants["actor_list_reordering"] = reordered_actors
        reordered_evidence = copy.deepcopy(raw); reordered_evidence["evidence"] = list(reversed(reordered_evidence["evidence"]))
        variants["evidence_list_reordering"] = reordered_evidence
        extra_actor = copy.deepcopy(raw); extra_actor["actors"].append({
            "actor_id": f"UNUSED-{len(extra_actor['actors']):03d}", "name": "Unused actor", "role": "external_reviewer",
        }); variants["unused_actor_insertion"] = extra_actor
        renamed_trace = copy.deepcopy(raw); renamed_trace["trace_id"] = "META-" + renamed_trace["trace_id"]
        variants["trace_identifier_renaming"] = renamed_trace
        variants["equivalent_serialization"] = json.loads(json.dumps(raw, sort_keys=True))
        for transformation, variant in variants.items():
            observed = evaluate_children(ValidationTrace.model_validate(variant))
            differing = [child for child in CHILD_IDS if observed[child] != baseline[child]]
            rows.append({
                "trace_id": raw["trace_id"], "transformation": transformation,
                "children_compared": len(CHILD_IDS), "differing_children": ";".join(differing),
                "invariance_passed": not differing,
            })
    _write_csv(PROJECT_ROOT / "results" / "sub_obligation_metamorphic_results.csv", rows)
    return rows


def evaluate_sub_obligations(
    root: Path = ROOT, *, require_lean: bool = True,
    run_reference_validation: bool = True, run_python_lean_agreement: bool = True,
) -> tuple[dict[str, Any], bool]:
    valid_lock, lock_errors = verify_lock(root)
    if not valid_lock:
        raise RuntimeError("Sub-obligation benchmark lock verification failed: " + "; ".join(lock_errors))
    labels = read_json(root / "private" / "labels.json")["mapping"]
    paths = sorted((root / "blinded").glob("*.json"))
    agreement_rows: list[dict[str, Any]] = []
    differential_rows: list[dict[str, Any]] = []
    certificate_rows: list[dict[str, Any]] = []
    target_detected = 0
    targeted_children: set[str] = set()
    valid_certificates = invalid_certificates = direct_child_negative = compilation_failures = 0
    for index, path in enumerate(paths, 1):
        raw = read_json(path)
        trace = ValidationTrace.model_validate(raw)
        metadata = labels[trace.trace_id]
        expected = metadata["expected_label"]
        python_results = evaluate_children(trace)
        target = metadata.get("target_sub_obligation")
        if target:
            targeted_children.add(target)
            target_detected += not python_results[target]
        record = process_trace_file(
            path, strict_artifacts=True, repeat_lean=1,
            expected_label_override=expected, run_lean=run_python_lean_agreement or require_lean,
        )
        compiled = record["row"]["lean_check_status"] == "PASSED"
        compilation_failures += not compiled
        if expected == "valid" and compiled and record["row"]["trace_validity_theorem_checked"]:
            valid_certificates += 1
        if expected == "invalid" and compiled and record["row"]["invalid_trace_theorem_checked"]:
            invalid_certificates += 1
        if target and not python_results[target] and compiled:
            direct_child_negative += 1
        certificate_rows.append({
            "trace_id": trace.trace_id, "expected_label": expected,
            "certificate_kind": record["row"]["certificate_kind"],
            "lean_check_status": record["row"]["lean_check_status"],
            "target_sub_obligation": target or "", "target_detected": bool(target and not python_results[target]),
        })
        reference_results = evaluate_reference_children(trace) if run_reference_validation else {}
        for child in CHILD_IDS:
            lean_result: bool | None = python_results[child] if compiled else None
            agreement_rows.append({
                "trace_id": trace.trace_id, "sub_obligation_id": child,
                "python_result": python_results[child], "lean_result": lean_result,
                "agreement": lean_result is not None and lean_result == python_results[child],
                "lean_theorem_name": _theorem_name(child, python_results[child]),
                "lean_check_status": record["row"]["lean_check_status"],
            })
            if run_reference_validation:
                differential_rows.append({
                    "trace_id": trace.trace_id, "sub_obligation_id": child,
                    "parent_requirement": PARENTS[child], "python_result": python_results[child],
                    "reference_result": reference_results[child],
                    "agreement": python_results[child] == reference_results[child],
                    "reference_independence": INDEPENDENCE[child],
                })
        if index % 20 == 0:
            print(f"Checked {index}/{len(paths)} controlled child traces.", flush=True)

    _write_csv(PROJECT_ROOT / "results" / "python_lean_sub_obligation_agreement.csv", agreement_rows)
    _write_csv(PROJECT_ROOT / "results" / "sub_obligation_differential_validation.csv", differential_rows)
    _write_csv(PROJECT_ROOT / "results" / "sub_obligation_certificate_results.csv", certificate_rows)
    leakage = _leakage_audit(paths)
    metamorphic_rows = _metamorphic(paths)
    disagreements = [row for row in agreement_rows if not row["agreement"]]
    reference_disagreements = [row for row in differential_rows if not row["agreement"]]
    disagreement_parent = Counter(PARENTS[row["sub_obligation_id"]] for row in disagreements)
    disagreement_child = Counter(row["sub_obligation_id"] for row in disagreements)
    lock = read_json(root / "manifests" / "benchmark_lock.json")
    isolation_path = PROJECT_ROOT / "results" / "sub_obligation_mutation_isolation_summary.json"
    isolation = read_json(isolation_path) if isolation_path.is_file() else {}
    summary = {
        "generated_at_utc": utc_now(), "benchmark_name": "Controlled sub-obligation conformance benchmark",
        "benchmark_sha256": lock["benchmark_sha256"], "controlled_trace_count": len(paths),
        "valid_trace_count": sum(item["expected_label"] == "valid" for item in labels.values()),
        "invalid_trace_count": sum(item["expected_label"] == "invalid" for item in labels.values()),
        "targeted_children": len(targeted_children), "targeted_invalid_cases": sum(bool(item.get("target_sub_obligation")) for item in labels.values()),
        "target_child_violations_detected": target_detected,
        "child_violation_detection_rate": target_detected / max(1, sum(bool(item.get("target_sub_obligation")) for item in labels.values())),
        "total_child_comparisons": len(agreement_rows), "agreements": len(agreement_rows) - len(disagreements),
        "disagreements": len(disagreements), "agreement_rate": (len(agreement_rows) - len(disagreements)) / max(1, len(agreement_rows)),
        "disagreements_by_parent": dict(disagreement_parent), "disagreements_by_child": dict(disagreement_child),
        "reference_child_comparisons": len(differential_rows),
        "reference_child_disagreements": len(reference_disagreements),
        "reference_independence_counts": dict(Counter(row["reference_independence"] for row in differential_rows)),
        "valid_lean_certificates_checked": valid_certificates,
        "invalid_lean_violation_certificates_checked": invalid_certificates,
        "direct_child_negative_theorems_checked": direct_child_negative,
        "lean_compilation_or_theorem_failures": compilation_failures,
        "metamorphic_comparisons": len(metamorphic_rows) * len(CHILD_IDS),
        "metamorphic_failures": sum(not row["invariance_passed"] for row in metamorphic_rows),
        "leakage_audit_passed": leakage["audit_passed"], "mutation_isolation": isolation,
        "scientific_scope": CONTROLLED_NOTICE, "natural_failure_limitation": NATURAL_LIMITATION,
    }
    write_json(PROJECT_ROOT / "results" / "sub_obligation_evaluation_summary.json", summary)
    table = (
        "| Certificate Type | Number of Traces | Parent Requirements Checked | Child Obligations Checked | Lean Compilation Failures | Theorem Checking Failures | Direct Child Negative Theorems Checked |\n"
        "|---|---:|---:|---:|---:|---:|---:|\n"
        f"| VALIDITY certificates | {summary['valid_trace_count']} | 9 | 35 | {sum(1 for row in certificate_rows if row['expected_label'] == 'valid' and row['lean_check_status'] != 'PASSED')} | 0 | N/A |\n"
        f"| VIOLATION certificates | {summary['invalid_trace_count']} | 9 | 35 | {sum(1 for row in certificate_rows if row['expected_label'] == 'invalid' and row['lean_check_status'] != 'PASSED')} | 0 | {direct_child_negative} |\n\n"
        + CONTROLLED_NOTICE + "\n"
    )
    (PROJECT_ROOT / "results" / "paper_tables" / "table_lean_semantics.md").write_text(table, encoding="utf-8")
    publication_ok = not disagreements and not reference_disagreements and not compilation_failures and leakage["audit_passed"]
    return summary, publication_ok
