from __future__ import annotations

import copy

import pytest

from leancert.schema import ForensicTrace
from leancert.validator import validate_trace


def validate(data: dict, **kwargs):
    return validate_trace(ForensicTrace.model_validate(data), **kwargs)


def test_valid_public_data_trace_passes(valid_data):
    assert validate(valid_data).overall_status == "PASSED"


def test_expected_label_is_not_used_for_valid_trace(valid_data):
    valid_data["expected_label"] = "invalid"
    assert validate(valid_data).overall_status == "PASSED"


def test_expected_label_is_not_used_for_invalid_trace(valid_data):
    valid_data["expected_label"] = "valid"
    valid_data["events"][1]["prev_hash"] = "broken"
    assert validate(valid_data).overall_status == "FAILED"


def test_evaluation_metadata_is_not_used(valid_data):
    valid_data["evaluation_metadata"] = {
        "scenario": "claim failure", "injected_violation": "everything",
        "expected_outcome": "FAILED", "target_requirement": "All requirements",
    }
    assert validate(valid_data).overall_status == "PASSED"


def test_dataset_source_name_is_not_a_shortcut(valid_data):
    valid_data["dataset_origin"]["source_name"] = "Definitely Invalid Dataset"
    valid_data["evidence"][0]["dataset_source"] = "Definitely Invalid Dataset"
    assert validate(valid_data).overall_status == "PASSED"


@pytest.mark.parametrize(
    ("section", "id_field"),
    [
        ("evidence", "evidence_id"), ("actors", "actor_id"),
        ("events", "event_id"), ("report_claims", "claim_id"),
    ],
)
def test_duplicate_ids_fail(valid_data, section, id_field):
    valid_data[section].append(copy.deepcopy(valid_data[section][0]))
    result = validate(valid_data)
    assert "ReferentialIntegrity" in result.failed_requirements


def test_public_artifact_hash_integrity(valid_data):
    valid_data["evidence"][0]["hash"] = "sha256:" + "0" * 64
    result = validate(valid_data)
    assert "PublicArtifactIntegrity" in result.failed_requirements


def test_missing_artifact_warns_in_non_strict_mode(valid_data):
    valid_data["evidence"][0]["artifact_path"] += ".missing"
    result = validate(valid_data)
    assert result.overall_status == "PASSED"
    assert result.warnings


def test_missing_artifact_fails_in_strict_mode(valid_data):
    valid_data["evidence"][0]["artifact_path"] += ".missing"
    result = validate(valid_data, strict_artifacts=True)
    assert "PublicArtifactIntegrity" in result.failed_requirements


def test_authorization_matrix_rejects_analyst_transfer(valid_data):
    valid_data["events"][1]["actor_id"] = "ANA-001"
    assert "AuthorizedHandling" in validate(valid_data).failed_requirements


def test_hash_continuity_is_per_evidence(valid_data):
    valid_data["events"][1]["prev_hash"] = "wrong"
    assert "HashContinuity" in validate(valid_data).failed_requirements


def test_chronology_is_per_evidence(valid_data):
    valid_data["events"][2]["timestamp"] = 90
    assert "ChronologicalConsistency" in validate(valid_data).failed_requirements


def test_custody_continuity_is_per_evidence(valid_data):
    valid_data["events"][2]["prev_holder"] = "INV-001"
    assert "CustodyContinuity" in validate(valid_data).failed_requirements


def test_report_claim_rejects_invalid_evidence(valid_data):
    valid_data["events"][1]["prev_hash"] = "wrong"
    result = validate(valid_data)
    assert "ReportTraceability" in result.failed_requirements


def test_derived_artifact_requires_parent(valid_data):
    derived = copy.deepcopy(valid_data["evidence"][0])
    derived["evidence_id"] += "-D"
    derived["kind"] = "derived_artifact"
    derived["parent_evidence_id"] = None
    valid_data["evidence"].append(derived)
    assert "ReferentialIntegrity" in validate(valid_data).failed_requirements
