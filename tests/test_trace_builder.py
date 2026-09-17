from __future__ import annotations

from leancert.schema import ForensicTrace
from leancert.trace_builder import invalid_variants
from leancert.validator import validate_trace


def test_invalid_variants_are_content_perturbations(valid_data):
    variants = invalid_variants(valid_data)
    assert len(variants) >= 8
    for index, item in enumerate(variants):
        item["trace_id"] = f"NEUTRAL-{index}"
        result = validate_trace(ForensicTrace.model_validate(item))
        assert result.overall_status == "FAILED"


def test_variants_preserve_public_origin(valid_data):
    for item in invalid_variants(valid_data):
        assert item["dataset_origin"] == valid_data["dataset_origin"]


def test_evidence_id_is_hash_derived(valid_data):
    assert valid_data["evidence"][0]["evidence_id"] == (
        "EVD-" + valid_data["dataset_origin"]["sha256"][:12]
    )

