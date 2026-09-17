from __future__ import annotations

import bz2
import copy
import json
from pathlib import Path

import yaml

import leancert.benchmark as benchmark
import leancert.image_inspection as image_inspection
import leancert.report as report_module
from leancert.artifact_processing import CHUNK_SIZE, decompress_bz2
from leancert.benchmark import build_blinded_holdout, freeze_benchmark, verify_benchmark_lock
from leancert.formalization_audit import audit_formalization
from leancert.lean_generator import render_lean
from leancert.reference_hashes import verify_reference_checksums
from leancert.reference_validator import reference_validate
from leancert.schema import ForensicTrace, ValidationTrace
from leancert.trace_builder import build_scalability_traces, invalid_variants
from leancert.utils import read_json, sha256_file, write_json
from leancert.validator import validate_trace


def test_streaming_decompression_preserves_distribution_and_separates_hashes(tmp_path: Path):
    source = tmp_path / "sample.dd.bz2"
    original = (b"forensic-sector-data" * 100_000)
    source.write_bytes(bz2.compress(original))
    compressed_hash = sha256_file(source)
    destination = tmp_path / "derived" / "sample.dd"
    row = decompress_bz2(source, destination, chunk_size=CHUNK_SIZE)
    assert row["decompression_status"] == "PASSED"
    assert destination.read_bytes() == original
    assert sha256_file(source) == compressed_hash
    assert row["distribution_sha256"] != row["decompressed_sha256"]


def test_truncated_bzip2_fails_without_publishing_partial_image(tmp_path: Path):
    source = tmp_path / "truncated.dd.bz2"
    source.write_bytes(bz2.compress(b"x" * 100_000)[:-7])
    destination = tmp_path / "truncated.dd"
    row = decompress_bz2(source, destination)
    assert row["decompression_status"] == "FAILED"
    assert not destination.exists()
    assert row["decompression_error"]


def test_existing_decompressed_image_is_not_overwritten_without_force(tmp_path: Path):
    source = tmp_path / "sample.dd.bz2"
    source.write_bytes(bz2.compress(b"new"))
    destination = tmp_path / "sample.dd"
    destination.write_bytes(b"existing")
    row = decompress_bz2(source, destination)
    assert row["decompression_status"] == "NOT_RUN"
    assert destination.read_bytes() == b"existing"


def test_metadata_only_inspection_is_not_a_pass(tmp_path: Path, monkeypatch):
    image = tmp_path / "image.dd"
    image.write_bytes(b"raw-image")
    manifest = tmp_path / "processing.json"
    write_json(manifest, [{
        "artifact_name": "Fixture", "decompressed_path": str(image),
        "decompression_status": "PASSED",
    }])
    monkeypatch.setattr(image_inspection, "_pytsk3_backend", lambda path: None)
    monkeypatch.setattr(image_inspection, "_tsk_backend", lambda path: None)
    rows, summary = image_inspection.inspect_images(
        manifest, results_csv=tmp_path / "results.csv",
        summary_json=tmp_path / "summary.json", table_path=tmp_path / "table.md",
    )
    assert rows[0]["status"] == "NOT_RUN"
    assert summary["successfully_inspected_images"] == 0


def _reference_fixture(tmp_path: Path, expected: str) -> Path:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"publisher-reference-fixture")
    references = tmp_path / "references.yaml"
    references.write_text(yaml.safe_dump({"references": [{
        "source_name": "Official Publisher", "artifact_name": "Fixture",
        "file_name": artifact.name, "local_path": str(artifact),
        "algorithm": "sha256", "expected_value": expected,
        "reference_url": "https://publisher.invalid/checksums",
        "retrieval_date_utc": "2026-01-01", "verification_note": "test fixture",
    }]}), encoding="utf-8")
    return references


def test_official_checksum_verifies_when_reference_matches(tmp_path: Path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"publisher-reference-fixture")
    references = _reference_fixture(tmp_path, sha256_file(artifact))
    rows, summary = verify_reference_checksums(
        references, results_csv=tmp_path / "out.csv",
        summary_json=tmp_path / "out.json", table_path=tmp_path / "out.md",
    )
    assert rows[0]["status"] == "VERIFIED"
    assert summary["external_reference_verified_count"] == 1


def test_unavailable_checksum_is_not_treated_as_pass(tmp_path: Path):
    references = _reference_fixture(tmp_path, "")
    rows, _ = verify_reference_checksums(
        references, results_csv=tmp_path / "out.csv",
        summary_json=tmp_path / "out.json", table_path=tmp_path / "out.md",
    )
    assert rows[0]["status"] == "UNAVAILABLE"


def test_publisher_checksum_mismatch_is_reported(tmp_path: Path):
    references = _reference_fixture(tmp_path, "0" * 64)
    rows, summary = verify_reference_checksums(
        references, results_csv=tmp_path / "out.csv",
        summary_json=tmp_path / "out.json", table_path=tmp_path / "out.md",
    )
    assert rows[0]["status"] == "MISMATCH"
    assert summary["external_reference_mismatch_count"] == 1


def _temporary_benchmark(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "benchmark"
    for track in ("development", "holdout"):
        path = root / track / "mutations.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(yaml.safe_dump({"mutations": [{
            "mutation_id": f"{track}-1", "family": f"{track}-family",
            "operation": "replace_value",
            "selector": {"collection": "actors", "match": {"role": "investigator"}},
            "field": "name", "value": "", "expected_class": "invalid",
            "target_requirements": ["IdentityCompleteness"],
        }]}), encoding="utf-8")
    monkeypatch.setattr(benchmark, "BENCHMARK_ROOT", root)
    return root


def test_benchmark_lock_generation_and_tamper_detection(tmp_path: Path, monkeypatch):
    root = _temporary_benchmark(tmp_path, monkeypatch)
    lock_path = root / "manifests" / "benchmark_lock.json"
    lock = freeze_benchmark(lock_path)
    assert len(lock["benchmark_sha256"]) == 64
    assert verify_benchmark_lock(lock_path)[0]
    with (root / "holdout" / "mutations.yaml").open("a", encoding="utf-8") as stream:
        stream.write("\n# tampered\n")
    valid, errors = verify_benchmark_lock(lock_path)
    assert not valid
    assert errors


def test_blinded_holdout_payload_excludes_labels_and_metadata(valid_data, tmp_path: Path):
    source = tmp_path / "valid.json"
    write_json(source, valid_data)
    paths, mapping = build_blinded_holdout(
        [source], output_dir=tmp_path / "blinded", mapping_path=tmp_path / "mapping.json",
    )
    raw = read_json(paths[0])
    assert "expected_label" not in raw
    assert "evaluation_metadata" not in raw
    assert raw["trace_id"] in mapping
    ValidationTrace.model_validate(raw)


def test_production_validator_does_not_import_benchmark_modules():
    source = Path("leancert/validator.py").read_text(encoding="utf-8")
    assert "benchmark" not in source
    assert "expected_label" not in source


def test_reference_validator_agrees_on_valid_and_invalid_subset(valid_data):
    valid = ValidationTrace.model_validate({
        key: value for key, value in valid_data.items()
        if key not in {"expected_label", "evaluation_metadata"}
    })
    production = {item.requirement: item.passed for item in validate_trace(valid).requirement_results}
    assert all(production[key] == value for key, value in reference_validate(valid).items())
    invalid = copy.deepcopy(valid_data)
    invalid["events"][1]["prev_hash"] = "BROKEN"
    blinded = ValidationTrace.model_validate({
        key: value for key, value in invalid.items()
        if key not in {"expected_label", "evaluation_metadata"}
    })
    production = {item.requirement: item.passed for item in validate_trace(blinded).requirement_results}
    assert all(production[key] == value for key, value in reference_validate(blinded).items())


def test_scalability_builder_writes_fifteen_structurally_distinct_traces(
    valid_data, tmp_path: Path,
):
    origin = valid_data["dataset_origin"]
    manifest = tmp_path / "manifest.json"
    write_json(manifest, [{
        "source_name": origin["source_name"], "artifact_name": origin["artifact_name"],
        "artifact_kind": valid_data["evidence"][0]["kind"], "source_url": origin["source_url"],
        "local_path": origin["local_path"], "sha256": origin["sha256"],
        "size_bytes": origin["size_bytes"], "retrieved_at_utc": origin["retrieved_at_utc"],
        "download_status": "existing",
    }])
    paths = build_scalability_traces(
        [8], traces_per_size=15, seed=20260726,
        manifest_path=manifest, output_dir=tmp_path / "scale",
    )
    structures = {
        json.dumps({
            "actions": [event["action"] for event in read_json(path)["events"]],
            "actor_count": len(read_json(path)["actors"]),
            "claim_count": len(read_json(path)["report_claims"]),
            "spacing": read_json(path)["events"][1]["timestamp"] - read_json(path)["events"][0]["timestamp"],
        }, sort_keys=True)
        for path in paths
    }
    assert len(paths) == 15
    assert len(structures) == 15


def test_timing_warmup_is_excluded_from_measured_samples(valid_data, tmp_path: Path, monkeypatch):
    path = tmp_path / "trace.json"
    write_json(path, valid_data)
    calls = 0
    original = report_module.validate_trace

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(report_module, "validate_trace", counted)
    record = report_module.process_trace_file(path, repeat=3, run_lean=False)
    assert calls == 13
    assert len(record["row"]["validation_time_samples_us"]) == 3


def test_formalization_catalogue_audit_has_no_undocumented_requirements(tmp_path: Path):
    _, summary = audit_formalization(
        results_csv=tmp_path / "coverage.csv", summary_json=tmp_path / "summary.json",
    )
    assert summary["catalogue_relative_formalization_rate"] == 1.0
    assert summary["undocumented_python_requirements"] == []
    assert summary["undocumented_lean_predicates"] == []


def test_validtrace_theorem_emitted_only_for_valid_trace(valid_trace, valid_data):
    valid_result = validate_trace(valid_trace)
    valid_source = render_lean(valid_trace, valid_result)
    assert "theorem trace_validity : LeanCert.ValidTrace traceData" in valid_source
    invalid_data = invalid_variants(valid_data)[0]
    invalid_trace = ForensicTrace.model_validate(invalid_data)
    invalid_result = validate_trace(invalid_trace)
    invalid_source = render_lean(invalid_trace, invalid_result)
    assert "theorem trace_validity" not in invalid_source
    assert invalid_result.failed_requirements
