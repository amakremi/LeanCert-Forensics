from __future__ import annotations

from pathlib import Path

import yaml

from leancert.manuscript_readiness import PRIMARY_FIGURES, assess_roc_candidate
from leancert.sub_obligations import CHILD_FUNCTIONS, CHILD_IDS, PYTHON_PREDICATES
from leancert.utils import read_json


def test_authoritative_baseline_is_deterministic_and_legacy_six_is_not_baseline():
    result = read_json(Path("results/formalization_baseline_reconciliation.json"))
    assert result["selected_authoritative_pre_fix_file"].endswith("formalization_catalogue_pre_fix.json")
    assert result["pre_fix_lean_explicit_child_mappings"] == 7
    legacy = next(row for row in result["intermediate_mapping_counts"] if row["mapping_count"] == 6)
    assert "not a historical snapshot" in legacy["artifact_role"]


def test_external_checksum_denominators_derive_from_population_and_na_is_null():
    summary = read_json(Path("results/reference_checksum_summary.json"))
    rows = list(__import__("csv").DictReader(Path("results/reference_checksum_population.csv").open(encoding="utf-8")))
    eligible = sum(row["eligible_for_external_reference"] == "True" for row in rows)
    available = sum(row["official_reference_available"] == "True" for row in rows)
    assert summary["external_reference_eligible_count"] == eligible
    assert summary["external_reference_available_count"] == available
    assert available + summary["external_reference_unavailable_count"] <= eligible
    assert summary["external_match_rate"] is None
    assert summary["external_match_rate_display"] == "N/A"


def test_semantic_denominator_excludes_partial_carving_images():
    summary = read_json(Path("results/image_inspection_summary.json"))
    assert summary["semantic_success_rate"] == (
        summary["semantic_passed_count"] / summary["semantically_applicable_count"]
    )
    assert summary["semantic_passed_count"] == 3
    assert summary["partial_count"] == 3
    assert summary["semantic_passed_count"] + summary["partial_count"] == summary["inspection_attempted_count"]


def test_every_python_mapping_resolves_to_a_concrete_child_symbol():
    document = yaml.safe_load(Path("formalization/requirements_catalog.yaml").read_text(encoding="utf-8"))
    mappings = {row["id"]: row for row in document["sub_obligation_mappings"]}
    assert len(mappings) == 35
    for child in CHILD_IDS:
        assert mappings[child]["python_predicate"] == PYTHON_PREDICATES[child]
        assert callable(CHILD_FUNCTIONS[child])


def test_removing_a_mapping_reduces_computed_mapping_coverage():
    document = yaml.safe_load(Path("formalization/requirements_catalog.yaml").read_text(encoding="utf-8"))
    mappings = {row["id"]: row for row in document["sub_obligation_mappings"]}
    mappings.pop(CHILD_IDS[0])
    measured = sum(child in mappings and mappings[child].get("python_predicate") == PYTHON_PREDICATES[child] for child in CHILD_IDS)
    assert measured == 34


def test_lean_quality_is_nontrivial_and_has_no_proof_escapes():
    rows = list(__import__("csv").DictReader(Path("results/lean_child_quality_audit.csv").open(encoding="utf-8")))
    assert len(rows) == 35
    assert all(row["uses_trace_data"] == "True" for row in rows)
    assert all(row["positive_case_true"] == "True" and row["negative_case_false"] == "True" for row in rows)
    assert all(not row["duplicate_of"] for row in rows)
    assert all(row["uses_sorry"] == row["uses_admit"] == row["uses_unsafe_axiom"] == "False" for row in rows)


def test_identity_cascade_has_causal_classification():
    rows = list(__import__("csv").DictReader(Path("results/cascading_dependency_audit.csv").open(encoding="utf-8")))
    identity = [row for row in rows if row["cascading_requirement"] == "IdentityCompleteness"]
    assert identity
    assert all(row["dependency_type"] == "DUPLICATED_SEMANTICS" for row in identity)
    assert all(row["expected_by_model"] == "True" for row in identity)


def test_reference_independence_is_source_audited_and_not_overclaimed():
    rows = list(__import__("csv").DictReader(Path("results/reference_independence_audit.csv").open(encoding="utf-8")))
    assert sum(row["independence_classification"] == "STRUCTURALLY_INDEPENDENT" for row in rows) == 30
    assert sum(row["independence_classification"] == "LIMITED" for row in rows) == 5
    assert all(row["shared_helper_functions"] == "False" for row in rows)


def test_roc_eligibility_rejects_binary_failure_count_and_label_scores():
    common = dict(score_name="score", predefined_before_holdout=True,
                  threshold_has_operational_meaning=True, meaningful_ordering=True,
                  part_of_decision_model=True)
    assert not assess_roc_candidate(decision_output_type="binary", uses_ground_truth_labels=False,
                                    uses_failure_count_only=False, **common)[0]
    assert not assess_roc_candidate(decision_output_type="continuous", uses_ground_truth_labels=False,
                                    uses_failure_count_only=True, **common)[0]
    assert not assess_roc_candidate(decision_output_type="continuous", uses_ground_truth_labels=True,
                                    uses_failure_count_only=False, **common)[0]


def test_roc_eligibility_accepts_only_valid_predefined_continuous_score():
    eligible, _ = assess_roc_candidate(
        decision_output_type="continuous", score_name="predefined_assurance",
        predefined_before_holdout=True, uses_ground_truth_labels=False,
        uses_failure_count_only=False, threshold_has_operational_meaning=True,
        meaningful_ordering=True, part_of_decision_model=True,
    )
    assert eligible


def test_inapplicable_roc_has_no_roc_or_pr_artifacts():
    audit = read_json(Path("results/roc_eligibility_audit.json"))
    assert audit["roc_applicable"] is False
    assert not Path("results/roc_results.csv").exists()
    assert not Path("results/roc_summary.json").exists()
    assert not Path("results/supplementary/roc_curve.png").exists()
    assert not Path("results/supplementary/precision_recall_curve.png").exists()


def test_exactly_five_primary_figures_and_no_promoted_roc():
    figures = {path.name for path in Path("results/figures").glob("*.png")}
    assert figures == set(PRIMARY_FIGURES)


def test_final_manifest_values_come_from_authoritative_artifacts():
    manifest = read_json(Path("results/experiment_manifest.json"))
    holdout = read_json(Path("results/holdout_metrics_v2.json"))
    child = read_json(Path("results/sub_obligation_evaluation_summary.json"))
    assert (manifest["TP"], manifest["TN"], manifest["FP"], manifest["FN"]) == (
        holdout["TP"], holdout["TN"], holdout["FP"], holdout["FN"]
    )
    assert manifest["child_python_lean_comparisons"] == child["total_child_comparisons"]
    assert manifest["roc_auc"] is None and manifest["average_precision"] is None
