from __future__ import annotations

import bz2
import json
from pathlib import Path

from leancert.artifact_native import evaluate_artifact_native
from leancert.datasets import discover_local_artifacts, register_cfreds_batch
from leancert.plots import FIGURE_NAMES, generate_figures
from leancert.schema import ForensicTrace
from leancert.trace_builder import invalid_variants, scalability_trace
from leancert.utils import sha256_file
from leancert.validator import validate_trace


def test_discovery_excludes_partial_downloads(tmp_path):
    complete = tmp_path / "image.dd.bz2"
    partial = tmp_path / "image.dd.bz2.crdownload"
    complete.write_bytes(bz2.compress(b"image"))
    partial.write_bytes(b"partial")
    assert discover_local_artifacts([tmp_path]) == [complete.resolve()]


def test_six_cfreds_records_and_native_checks(tmp_path):
    paths = []
    for index in range(6):
        path = tmp_path / f"artifact-{index}.dd.bz2"
        path.write_bytes(bz2.compress(f"image-{index}".encode()))
        paths.append(path)
    manifest = tmp_path / "manifest.json"
    records = register_cfreds_batch(
        dfr_fat=paths[0], dfr_ntfs=paths[1], l0_graphic=paths[2],
        dfr_02_fat=paths[3], l0_documents=paths[4], l0_archive=paths[5],
        manifest_path=manifest,
    )
    assert len(records) == 6
    assert all(record["artifact_kind"] == "disk_image" for record in records)
    assert all(record["distribution_format"] == "dd.bz2" for record in records)
    assert all(record["sha256"] == sha256_file(Path(record["local_path"])) for record in records)
    native = evaluate_artifact_native(json.loads(manifest.read_text(encoding="utf-8")))
    assert len(native) == 6
    assert all(row["overall_pass"] for row in native)


def test_standard_variants_and_scalability_are_content_valid(valid_data):
    variants = invalid_variants(valid_data, "standard")
    names = {
        item["trace_id"].rsplit("-", 1)[-1].casefold()
        for item in variants
    }
    assert len(variants) == 12
    assert {
        "missing_identity", "broken_reference", "artifact_hash_mismatch",
        "broken_custody", "timestamp_rollback", "hash_discontinuity",
        "unauthorized_handling", "lifecycle_violation", "unsupported_report_claim",
        "custody_authorization", "hash_chronology", "lifecycle_report_traceability",
    } == names
    record = {
        "source_name": valid_data["dataset_origin"]["source_name"],
        "artifact_name": valid_data["dataset_origin"]["artifact_name"],
        "artifact_kind": "disk_image",
        "source_url": valid_data["dataset_origin"]["source_url"],
        "local_path": valid_data["dataset_origin"]["local_path"],
        "sha256": valid_data["dataset_origin"]["sha256"],
        "size_bytes": valid_data["dataset_origin"]["size_bytes"],
        "retrieved_at_utc": valid_data["dataset_origin"]["retrieved_at_utc"],
    }
    for size in (4, 8, 12, 20, 50, 100):
        trace = scalability_trace(record, size)
        assert len(trace["events"]) == size
        assert validate_trace(ForensicTrace.model_validate(trace)).overall_status == "PASSED"


def test_publication_figure_package_has_exactly_five_files(tmp_path):
    rows = [{
        "trace_id": "S", "event_count": 4, "validation_time_us": 10.0,
        "lean_check_time_ms": 2.0,
    }]
    summary = {"TP": 1, "TN": 1, "FP": 0, "FN": 0}
    failures = [{"requirement": "IdentityCompleteness", "failure_count": 1}]
    artifact = [{
        "artifact_exists": True, "artifact_readable": True,
        "artifact_hash_match": True, "artifact_size_match": True,
        "artifact_provenance_complete": True, "artifact_signature_consistent": True,
    }]
    generate_figures(rows, summary, failures, failures, artifact, rows, tmp_path)
    assert {path.name for path in tmp_path.glob("*.png")} == FIGURE_NAMES
