from __future__ import annotations

import copy
from pathlib import Path

import pytest

import leancert.image_inspection as image_inspection
from leancert.environment_dependencies import capture_environment_dependencies
from leancert.formalization_audit import audit_formalization
from leancert.holdout_v2 import (
    build_holdout_v2, freeze_holdout_v2, verify_holdout_v2_lock,
)
from leancert.lean_generator import render_lean
from leancert.reference_hashes import verify_reference_checksums
from leancert.reference_validator import SUBSET, reference_validate
from leancert.schema import ForensicTrace, ValidationTrace
from leancert.statistics_ext import clopper_pearson, stratified_f1_bootstrap
from leancert.trace_builder import invalid_variants
from leancert.utils import read_json, write_json
from leancert.validator import REQUIREMENTS, validate_trace


def test_pytsk3_dependency_record_selects_pytsk3_when_importable(tmp_path: Path):
    record = capture_environment_dependencies(tmp_path / "environment.json")
    assert record["pytsk3_available"] is True
    assert record["selected_image_inspection_backend"] == "pytsk3"
    assert record["pytsk3_module_path"].endswith((".pyd", ".so"))


@pytest.mark.parametrize(
    ("name", "family"),
    [("DFR-01 FAT deleted-file-recovery image", "FAT"),
     ("DFR-02 FAT deleted-file-recovery image", "FAT"),
     ("DFR-01 NTFS deleted-file-recovery image", "NTFS")],
)
def test_dfr_dataset_semantics(name: str, family: str):
    expected, applicable = image_inspection._expected_semantics(name)
    assert (expected, applicable) == (family, True)


def test_carving_dataset_has_non_applicable_filesystem_semantics():
    assert image_inspection._expected_semantics("L0 Graphic file-carving image") == (None, False)


def test_parser_exception_cannot_become_passed(tmp_path: Path, monkeypatch):
    image = tmp_path / "dfr-01-fat.dd"
    image.write_bytes(b"fixture")
    manifest = tmp_path / "processing.json"
    write_json(manifest, [{
        "artifact_name": "DFR-01 FAT deleted-file-recovery image",
        "decompressed_path": str(image), "decompression_status": "PASSED",
        "decompressed_size_bytes": image.stat().st_size,
        "decompressed_sha256": "not-used", "distribution_path": "",
    }])
    monkeypatch.setattr(image_inspection, "_pytsk3_backend", lambda path: True)
    monkeypatch.setattr(
        image_inspection, "_inspect_pytsk3",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("parser failure")),
    )
    rows, _ = image_inspection.inspect_images(
        manifest, results_csv=tmp_path / "out.csv", summary_json=tmp_path / "out.json",
        table_path=tmp_path / "out.md",
    )
    assert rows[0]["inspection_status"] == "FAILED"


def test_zero_official_checksum_denominator_is_null_and_na(tmp_path: Path):
    refs = tmp_path / "refs.yaml"
    refs.write_text("references:\n  - artifact_name: fixture\n    expected_value: ''\n", encoding="utf-8")
    _, summary = verify_reference_checksums(
        refs, results_csv=tmp_path / "out.csv", summary_json=tmp_path / "out.json",
        table_path=tmp_path / "out.md",
    )
    assert summary["external_match_rate"] is None
    assert summary["external_match_rate_display"] == "N/A"


def test_holdout_v2_has_direct_cases_for_every_requirement(tmp_path: Path):
    manifest = Path("datasets/manifests/download_manifest.json")
    build = build_holdout_v2(root=tmp_path / "v2", manifest_path=manifest)
    assert build["total_trace_count"] == 120
    assert set(build["direct_cases_per_requirement"]) == set(REQUIREMENTS)
    assert all(value == 10 for value in build["direct_cases_per_requirement"].values())
    for path in (tmp_path / "v2" / "blinded").glob("*.json"):
        raw = read_json(path)
        assert not ({"expected_label", "evaluation_metadata", "root_requirement"} & raw.keys())


def test_holdout_v2_lock_detects_tampering(tmp_path: Path):
    root = tmp_path / "v2"
    build_holdout_v2(root=root, manifest_path=Path("datasets/manifests/download_manifest.json"))
    freeze_holdout_v2(root)
    assert verify_holdout_v2_lock(root)[0]
    target = next((root / "blinded").glob("*.json"))
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert not verify_holdout_v2_lock(root)[0]


def test_exact_clopper_pearson_boundary_values():
    low, high = clopper_pearson(10, 10)
    assert low == pytest.approx(0.691502892, rel=1e-7)
    assert high == 1.0
    low, high = clopper_pearson(0, 10)
    assert low == 0.0
    assert high == pytest.approx(0.308497108, rel=1e-7)


def test_stratified_f1_bootstrap_is_deterministic():
    rows = [
        {"is_expected_valid": False, "is_predicted_valid": False},
        {"is_expected_valid": False, "is_predicted_valid": True},
        {"is_expected_valid": True, "is_predicted_valid": True},
        {"is_expected_valid": True, "is_predicted_valid": False},
    ]
    assert stratified_f1_bootstrap(rows, repeats=500, seed=20260728) == \
           stratified_f1_bootstrap(rows, repeats=500, seed=20260728)


def test_reference_validator_covers_all_nine_requirements(valid_data):
    trace = ValidationTrace.model_validate({
        key: value for key, value in valid_data.items()
        if key not in {"expected_label", "evaluation_metadata"}
    })
    assert SUBSET == REQUIREMENTS
    assert set(reference_validate(trace)) == set(REQUIREMENTS)


def test_all_35_sub_obligations_are_separate_and_parent_not_inherited(tmp_path: Path):
    audit_formalization(results_csv=tmp_path / "parents.csv", summary_json=tmp_path / "parents.json")
    rows = list(__import__("csv").DictReader(Path("results/formalization_sub_obligation_coverage.csv").open(encoding="utf-8")))
    assert len(rows) == 35
    assert len({row["sub_obligation_id"] for row in rows}) == 35
    assert sum(row["direct_holdout_covered"] == "True" for row in rows) == 9


def test_valid_and_invalid_certificate_semantics_and_proof_modes(valid_trace, valid_data):
    valid_result = validate_trace(valid_trace)
    pairwise = render_lean(valid_trace, valid_result, proof_mode="pairwise")
    aggregate = render_lean(valid_trace, valid_result, proof_mode="aggregate")
    assert "theorem trace_validity : LeanCert.ValidTrace traceData" in pairwise
    assert "IdentityCompleteEvent" in pairwise
    assert "Aggregate proof mode" in aggregate
    invalid = ForensicTrace.model_validate(invalid_variants(copy.deepcopy(valid_data))[0])
    invalid_source = render_lean(invalid, validate_trace(invalid), proof_mode="pairwise")
    assert "theorem trace_not_valid" in invalid_source
    assert "theorem trace_validity" not in invalid_source
