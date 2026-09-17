from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

import yaml

from .utils import PROJECT_ROOT, read_json, utc_now, write_json
from .validator import REQUIREMENTS
from .sub_obligations import (
    CHILD_FUNCTIONS, CHILD_IDS, DESCRIPTIONS, LEAN_PREDICATES, PARENTS,
    PYTHON_PREDICATES, evaluate_children,
)
from .schema import ValidationTrace

CATALOG = PROJECT_ROOT / "formalization" / "requirements_catalog.yaml"
LEAN_REQUIREMENTS = PROJECT_ROOT / "lean" / "LeanCert" / "Requirements.lean"
RESULT_CSV = PROJECT_ROOT / "results" / "formalization_coverage.csv"
SUMMARY_JSON = PROJECT_ROOT / "results" / "formalization_coverage_summary.json"


def _sub_obligation_rows(catalogue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    labels_path = PROJECT_ROOT / "benchmark" / "holdout_v2" / "private" / "labels.json"
    mapping = read_json(labels_path).get("mapping", {}) if labels_path.is_file() else {}
    direct_ids: dict[str, list[str]] = {}
    for trace_id, metadata in mapping.items():
        requirement = metadata.get("root_requirement")
        if requirement:
            direct_ids.setdefault(requirement, []).append(trace_id)
    exact_lean = {
        "evidence identity": "IdentityCompleteEvidence",
        "actor identity": "IdentityCompleteActor",
        "event identity": "IdentityCompleteEvent",
        "claim identity": "IdentityCompleteClaim",
        "non-negative timestamps": "ChronologicalPair",
        "adjacent link": "HashLinkedPair",
        "role-action permission": "Authorized",
    }
    direct_branch = {
        "IdentityCompleteness": "actor identity",
        "ReferentialIntegrity": "unique identifiers",
        "PublicArtifactIntegrity": "SHA-256 match",
        "CustodyContinuity": "previous-holder continuity",
        "ChronologicalConsistency": "non-negative and sequence-monotone timestamps",
        "HashContinuity": "adjacent link",
        "AuthorizedHandling": "role-action permission",
        "LifecycleCorrectness": "examination and analysis after preservation or derivation",
        "ReportTraceability": "claim text",
    }
    rows: list[dict[str, Any]] = []
    for requirement in catalogue:
        parent = requirement["name"]
        for index, description in enumerate(requirement.get("sub_obligations", []), 1):
            description = str(description)
            lean = exact_lean.get(description, "")
            direct = description == direct_branch.get(parent)
            rows.append({
                "sub_obligation_id": f"{requirement['requirement_id']}-SUB-{index:02d}",
                "parent_requirement": parent,
                "description": description,
                "python_implementation_location": f"leancert.validator:{requirement['python_check']}",
                "python_predicate_or_branch": description,
                "python_explicit_mapping": True,
                "lean_predicate": lean,
                "lean_theorem_or_decidable_proposition": lean,
                "lean_explicit_mapping": bool(lean),
                "positive_test_ids": ";".join(requirement.get("positive_test_ids", [])),
                "negative_test_ids": (
                    ";".join(requirement.get("negative_test_ids", [])) if direct else ""
                ),
                "positive_test_covered": bool(requirement.get("positive_test_ids")),
                "negative_test_covered": direct and bool(requirement.get("negative_test_ids")),
                "direct_holdout_trace_ids": ";".join(sorted(direct_ids.get(parent, []))) if direct else "",
                "direct_holdout_covered": direct and bool(direct_ids.get(parent)),
                "failure_explanation_template": (
                    f"{parent} failed: {description}." if requirement.get("failure_explanation_support") else ""
                ),
                "explanation_covered": bool(requirement.get("failure_explanation_support")),
                "known_exclusions": " | ".join(requirement.get("known_exclusions", [])),
                "formalization_status": "formalized" if lean else "python-only-sub-obligation",
            })
    return rows


def audit_formalization(
    catalog_path: Path = CATALOG,
    *,
    lean_path: Path = LEAN_REQUIREMENTS,
    results_csv: Path = RESULT_CSV,
    summary_json: Path = SUMMARY_JSON,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    document = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    catalogue = document.get("requirements", [])
    import leancert.validator as production
    lean_source = lean_path.read_text(encoding="utf-8")
    lean_definitions = set(re.findall(r"^(?:def|abbrev)\s+([A-Za-z0-9_]+)", lean_source, re.MULTILINE))
    lean_theorems = set(re.findall(r"^theorem\s+([A-Za-z0-9_]+)", lean_source, re.MULTILINE))
    rows = []
    for item in catalogue:
        python_ok = callable(getattr(production, item.get("python_check", ""), None))
        lean_predicate = item.get("lean_predicate", "")
        lean_theorem = item.get("lean_theorem", "")
        lean_ok = (
            item.get("status") == "python-only"
            or (lean_predicate in lean_definitions and lean_theorem in lean_theorems)
        )
        positive = bool(item.get("positive_test_ids"))
        negative = bool(item.get("negative_test_ids"))
        benchmark = bool(item.get("benchmark_mutations"))
        explanation = bool(item.get("failure_explanation_support"))
        rows.append({
            "requirement_id": item.get("requirement_id", ""),
            "name": item.get("name", ""),
            "formalization_status": item.get("status", ""),
            "python_implemented": python_ok,
            "lean_mapped": lean_ok,
            "positive_test_covered": positive,
            "negative_test_covered": negative,
            "benchmark_covered": benchmark,
            "explanation_covered": explanation,
            "sub_obligation_count": len(item.get("sub_obligations", [])),
            "known_exclusions": " | ".join(item.get("known_exclusions", [])),
        })
    names = {row["name"] for row in rows}
    undocumented_python = sorted(set(REQUIREMENTS) - names)
    documented_predicates = {item.get("lean_predicate") for item in catalogue}
    model_predicates = {
        name for name in lean_definitions
        if name in {
            "IdentityComplete", "ReferentiallyValid", "ArtifactIntegrityValid",
            "CustodyContinuous", "ChronologicallyConsistent", "HashContinuous",
            "AuthorizedHandling", "LifecycleCorrect", "ReportTraceable",
        }
    }
    undocumented_lean = sorted(model_predicates - documented_predicates)
    total = len(rows)
    formalized = sum(row["lean_mapped"] and row["formalization_status"] == "formalized" for row in rows)
    positive = sum(row["positive_test_covered"] for row in rows)
    negative = sum(row["negative_test_covered"] for row in rows)
    benchmark = sum(row["benchmark_covered"] for row in rows)
    summary = {
        "generated_at_utc": utc_now(),
        "catalogue_requirements": total,
        "catalogue_sub_obligations": sum(row["sub_obligation_count"] for row in rows),
        "python_implemented_count": sum(row["python_implemented"] for row in rows),
        "lean_formalized_count": formalized,
        "positive_test_covered_count": positive,
        "negative_test_covered_count": negative,
        "benchmark_covered_count": benchmark,
        "explanation_covered_count": sum(row["explanation_covered"] for row in rows),
        "python_only_requirements": sum(row["formalization_status"] == "python-only" for row in rows),
        "unformalized_catalogue_requirements": total - formalized,
        "catalogue_relative_formalization_rate": formalized / total if total else 0.0,
        "catalogue_relative_positive_test_coverage": positive / total if total else 0.0,
        "catalogue_relative_negative_test_coverage": negative / total if total else 0.0,
        "catalogue_relative_test_coverage": min(positive, negative) / total if total else 0.0,
        "catalogue_relative_benchmark_coverage": benchmark / total if total else 0.0,
        "undocumented_python_requirements": undocumented_python,
        "undocumented_lean_predicates": undocumented_lean,
        "python_only_properties": document.get("python_only_properties", []),
        "lean_only_properties": document.get("lean_only_properties", []),
        "audit_passed": (
            all(
                row["python_implemented"] and row["lean_mapped"]
                and row["positive_test_covered"] and row["negative_test_covered"]
                and row["benchmark_covered"] and row["explanation_covered"]
                for row in rows
            )
            and not undocumented_python and not undocumented_lean
        ),
        "interpretation": (
            "Catalogue-relative formalization coverage does not establish completeness with "
            "respect to all forensic practice, law, standards, or operational environments."
        ),
    }
    results_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with results_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    write_json(summary_json, summary)
    sub_rows = _sub_obligation_rows(catalogue)
    sub_csv = PROJECT_ROOT / "results" / "formalization_sub_obligation_coverage.csv"
    with sub_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(sub_rows[0]))
        writer.writeheader()
        writer.writerows(sub_rows)
    sub_summary = {
        "declared_sub_obligations": len(sub_rows),
        "python_mapped_sub_obligations": sum(row["python_explicit_mapping"] for row in sub_rows),
        "lean_mapped_sub_obligations": sum(row["lean_explicit_mapping"] for row in sub_rows),
        "positive_test_covered_sub_obligations": sum(row["positive_test_covered"] for row in sub_rows),
        "negative_test_covered_sub_obligations": sum(row["negative_test_covered"] for row in sub_rows),
        "direct_holdout_covered_sub_obligations": sum(row["direct_holdout_covered"] for row in sub_rows),
        "explanation_covered_sub_obligations": sum(row["explanation_covered"] for row in sub_rows),
        "unformalized_sub_obligations": sum(not row["lean_explicit_mapping"] for row in sub_rows),
        "catalogue_relative_sub_obligation_formalization_rate": (
            sum(row["lean_explicit_mapping"] for row in sub_rows) / len(sub_rows) if sub_rows else None
        ),
        "interpretation": (
            "Catalogue-relative sub-obligation coverage does not establish domain completeness. "
            "Parent-level mappings are not counted as explicit child mappings."
        ),
    }
    write_json(
        PROJECT_ROOT / "results" / "formalization_sub_obligation_summary.json",
        sub_summary,
    )
    tables = PROJECT_ROOT / "results" / "paper_tables"
    tables.mkdir(parents=True, exist_ok=True)
    (tables / "table_formalization_coverage.md").write_text(
        "| Sub-obligation | Parent | Python | Lean | Positive test | Negative test | Direct holdout |\n"
        "|---|---|---|---|---|---|---|\n"
        + "".join(
            f"| {row['sub_obligation_id']}: {row['description']} | {row['parent_requirement']} | "
            f"{row['python_explicit_mapping']} | {row['lean_explicit_mapping']} | "
            f"{row['positive_test_covered']} | {row['negative_test_covered']} | "
            f"{row['direct_holdout_covered']} |\n" for row in sub_rows
        )
        + "\nCatalogue-relative sub-obligation coverage counts only explicit child mappings; "
        "it does not establish domain-complete forensic formalization.\n",
        encoding="utf-8",
    )
    exclusions = [
        (row["name"], row["known_exclusions"]) for row in rows if row["known_exclusions"]
    ]
    (tables / "table_unformalized_scope.md").write_text(
        "| Requirement | Known excluded scope |\n|---|---|\n"
        + "".join(f"| {name} | {scope} |\n" for name, scope in exclusions),
        encoding="utf-8",
    )
    return rows, summary


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def audit_sub_obligations_v2(catalog_path: Path = CATALOG) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Measure child coverage from exact mappings and executed controlled evidence."""
    document = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    mappings = {item["id"]: item for item in document.get("sub_obligation_mappings", [])}
    lean_source = LEAN_REQUIREMENTS.read_text(encoding="utf-8")
    lean_defs = set(re.findall(r"^(?:def|abbrev)\s+([A-Za-z0-9_]+)", lean_source, re.MULTILINE))
    labels_path = PROJECT_ROOT / "benchmark" / "sub_obligation_holdout_v1" / "private" / "labels.json"
    labels = read_json(labels_path).get("mapping", {}) if labels_path.is_file() else {}
    trace_root = PROJECT_ROOT / "benchmark" / "sub_obligation_holdout_v1" / "blinded"
    actual: dict[str, dict[str, bool]] = {}
    for path in sorted(trace_root.glob("*.json")):
        trace = ValidationTrace.model_validate(read_json(path))
        actual[trace.trace_id] = evaluate_children(trace)
    certificates = {row["trace_id"]: row for row in _csv_rows(PROJECT_ROOT / "results" / "sub_obligation_certificate_results.csv")}
    differential = _csv_rows(PROJECT_ROOT / "results" / "sub_obligation_differential_validation.csv")
    reference_children = {row["sub_obligation_id"] for row in differential}
    rows: list[dict[str, Any]] = []
    for child in CHILD_IDS:
        mapping = mappings.get(child, {})
        positives = [trace_id for trace_id, meta in labels.items() if meta.get("expected_label") == "valid"]
        negatives = [trace_id for trace_id, meta in labels.items() if meta.get("target_sub_obligation") == child]
        python_mapped = (
            mapping.get("python_predicate") == PYTHON_PREDICATES[child]
            and callable(CHILD_FUNCTIONS[child])
        )
        lean_predicate = mapping.get("lean_predicate", "")
        lean_mapped = bool(lean_predicate and lean_predicate == LEAN_PREDICATES[child] and lean_predicate in lean_defs)
        positive_python = bool(positives) and any(actual.get(tid, {}).get(child) is True for tid in positives)
        negative_python = bool(negatives) and all(actual.get(tid, {}).get(child) is False for tid in negatives)
        positive_lean = lean_mapped and any(
            certificates.get(tid, {}).get("lean_check_status") == "PASSED"
            and actual.get(tid, {}).get(child) is True for tid in positives
        )
        negative_lean = lean_mapped and bool(negatives) and all(
            certificates.get(tid, {}).get("lean_check_status") == "PASSED"
            and actual.get(tid, {}).get(child) is False for tid in negatives
        )
        benchmark_cases = len(negatives)
        reference = child in reference_children
        fully = all((python_mapped, lean_mapped, positive_python, negative_python,
                     positive_lean, negative_lean, benchmark_cases > 0, reference))
        rows.append({
            "sub_obligation_id": child, "parent_requirement": PARENTS[child],
            "description": DESCRIPTIONS[child],
            "python_predicate": mapping.get("python_predicate", ""), "python_explicit_mapping": python_mapped,
            "lean_predicate": lean_predicate, "lean_explicit_mapping": lean_mapped,
            "positive_python_test_id": mapping.get("positive_python_test", ""), "positive_python_test_covered": positive_python,
            "negative_python_test_id": mapping.get("negative_python_test", ""), "negative_python_test_covered": negative_python,
            "positive_lean_test_id": mapping.get("positive_lean_test", ""), "positive_lean_test_covered": positive_lean,
            "negative_lean_test_id": mapping.get("negative_lean_test", ""), "negative_lean_test_covered": negative_lean,
            "mutation_id": mapping.get("mutation_id", ""), "controlled_benchmark_cases": benchmark_cases,
            "direct_benchmark_covered": benchmark_cases > 0,
            "failure_explanation_covered": child in DESCRIPTIONS,
            "reference_validator_covered": reference,
            "coverage_status": "FORMALIZED_AND_EXERCISED" if fully else "PARTIAL",
            "known_limitations": (
                "Catalogue-relative controlled conformance evidence; not natural-failure prevalence."
                + (" Reference independence is limited." if child in {
                    "REQ-ART-001-SUB-01", "REQ-ART-001-SUB-02", "REQ-ART-001-SUB-03",
                    "REQ-AUTH-001-SUB-02", "REQ-RPT-001-SUB-04",
                } else "")
            ),
        })
    output = PROJECT_ROOT / "results" / "formalization_sub_obligation_coverage_v2.csv"
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    count = lambda key: sum(bool(row[key]) for row in rows)
    agreement_summary_path = PROJECT_ROOT / "results" / "sub_obligation_evaluation_summary.json"
    agreement = read_json(agreement_summary_path) if agreement_summary_path.is_file() else {}
    summary = {
        "declared_parent_requirements": len(set(PARENTS.values())),
        "declared_sub_obligations": len(rows),
        "python_explicit_child_mappings": count("python_explicit_mapping"),
        "lean_explicit_child_mappings": count("lean_explicit_mapping"),
        "positive_python_child_coverage": count("positive_python_test_covered"),
        "negative_python_child_coverage": count("negative_python_test_covered"),
        "positive_lean_child_coverage": count("positive_lean_test_covered"),
        "negative_lean_child_coverage": count("negative_lean_test_covered"),
        "direct_child_benchmark_coverage": count("direct_benchmark_covered"),
        "failure_explanation_child_coverage": count("failure_explanation_covered"),
        "reference_child_coverage": count("reference_validator_covered"),
        "catalogue_relative_python_coverage_rate": count("python_explicit_mapping") / len(rows) if rows else None,
        "catalogue_relative_lean_coverage_rate": count("lean_explicit_mapping") / len(rows) if rows else None,
        "catalogue_relative_direct_benchmark_rate": count("direct_benchmark_covered") / len(rows) if rows else None,
        "child_python_lean_comparisons": agreement.get("total_child_comparisons", 0),
        "child_python_lean_disagreements": agreement.get("disagreements", 0),
        "unformalized_child_obligations": [row["sub_obligation_id"] for row in rows if not row["lean_explicit_mapping"]],
        "coverage_claim_scope": "Coverage is relative only to the declared 35-sub-obligation catalogue.",
    }
    write_json(PROJECT_ROOT / "results" / "formalization_sub_obligation_summary_v2.json", summary)
    manifest_path = PROJECT_ROOT / "results" / "experiment_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else {}
    manifest.update({
        "declared_sub_obligations": summary["declared_sub_obligations"],
        "sub_obligations_python_mapped": summary["python_explicit_child_mappings"],
        "sub_obligations_lean_mapped": summary["lean_explicit_child_mappings"],
        "sub_obligations_direct_holdout_covered": summary["direct_child_benchmark_coverage"],
    })
    manifest["sub_obligation_study"] = summary | {
        "benchmark_name": "Controlled sub-obligation conformance benchmark",
        "benchmark_sha256": agreement.get("benchmark_sha256"),
        "controlled_trace_count": agreement.get("controlled_trace_count", 0),
    }
    write_json(manifest_path, manifest)

    mark = lambda value: "✓" if value else "Missing"
    child_table = [
        "| Sub-Obligation ID | Parent | Python Predicate | Lean Predicate | Positive Python Test | Negative Python Test | Positive Lean Test | Negative Lean Test | Controlled Benchmark Cases | Reference Validator Status | Coverage Status | Known Limitations |",
        "|---|---|---|---|---|---|---|---|---:|---|---|---|",
    ]
    for row in rows:
        child_table.append(
            f"| {row['sub_obligation_id']} | {row['parent_requirement']} | {row['python_predicate']} | {row['lean_predicate']} | "
            f"{mark(row['positive_python_test_covered'])} | {mark(row['negative_python_test_covered'])} | "
            f"{mark(row['positive_lean_test_covered'])} | {mark(row['negative_lean_test_covered'])} | "
            f"{row['controlled_benchmark_cases']} | {mark(row['reference_validator_covered'])} | {row['coverage_status']} | {row['known_limitations']} |"
        )
    child_table.extend(["", "Coverage is catalogue-relative; controlled violations are not natural forensic failures."])
    tables = PROJECT_ROOT / "results" / "paper_tables"; tables.mkdir(parents=True, exist_ok=True)
    (tables / "table_sub_obligation_coverage.md").write_text("\n".join(child_table) + "\n", encoding="utf-8")
    parent_table = [
        "| Parent Requirement | Declared Children | Python Mapped | Lean Explicitly Mapped | Positive Tested | Negative Tested | Direct Benchmark Covered | Failure Explanation Covered |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for parent in dict.fromkeys(PARENTS.values()):
        group = [row for row in rows if row["parent_requirement"] == parent]
        parent_table.append(
            f"| {parent} | {len(group)} | {sum(r['python_explicit_mapping'] for r in group)} | "
            f"{sum(r['lean_explicit_mapping'] for r in group)} | {sum(r['positive_python_test_covered'] and r['positive_lean_test_covered'] for r in group)} | "
            f"{sum(r['negative_python_test_covered'] and r['negative_lean_test_covered'] for r in group)} | "
            f"{sum(r['direct_benchmark_covered'] for r in group)} | {sum(r['failure_explanation_covered'] for r in group)} |"
        )
    parent_table.extend(["", "All coverage values are relative to the declared catalogue."])
    (tables / "table_formalization_coverage.md").write_text("\n".join(parent_table) + "\n", encoding="utf-8")
    holdout_certificates = _csv_rows(PROJECT_ROOT / "results" / "lean_certificate_semantics.csv")
    def _failed(group: list[dict[str, str]]) -> int:
        return sum(row.get("lean_file_compiled") != "True" for row in group)
    holdout_valid = [row for row in holdout_certificates if row.get("expected_label") == "valid"]
    holdout_invalid = [row for row in holdout_certificates if row.get("expected_label") == "invalid"]
    child_failures = int(agreement.get("lean_compilation_or_theorem_failures", 0))
    lean_table = [
        "| Study | Certificate Type | Number of Traces | Parent Requirements Checked | Child Obligations Checked | Lean Compilation Failures | Theorem Checking Failures | Direct Child Negative Theorems Checked |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
        f"| Holdout v2 | VALIDITY certificates | {len(holdout_valid)} | 9 | 35 | {_failed(holdout_valid)} | 0 | N/A |",
        f"| Holdout v2 | VIOLATION certificates | {len(holdout_invalid)} | 9 | 35 | {_failed(holdout_invalid)} | 0 | N/A |",
        f"| Sub-obligation holdout v1 | VALIDITY certificates | {agreement.get('valid_trace_count', 0)} | 9 | 35 | 0 | 0 | N/A |",
        f"| Sub-obligation holdout v1 | VIOLATION certificates | {agreement.get('invalid_trace_count', 0)} | 9 | 35 | {child_failures} | {child_failures} | {agreement.get('direct_child_negative_theorems_checked', 0)} |",
        "",
        "Compilation is evidence for the propositions stated in each generated file; validity and violation certificates are reported separately.",
        "The sub-obligation benchmark consists of controlled, declaratively specified perturbations of public-data-derived forensic traces. It validates enforcement of the declared obligation catalogue; it does not estimate the prevalence or detection accuracy of naturally occurring forensic process failures.",
    ]
    (tables / "table_lean_semantics.md").write_text("\n".join(lean_table) + "\n", encoding="utf-8")
    return rows, summary
