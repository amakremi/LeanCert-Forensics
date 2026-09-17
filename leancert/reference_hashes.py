from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any

import yaml

from .utils import PROJECT_ROOT, read_json, resolve_project_path, utc_now, write_json

DEFAULT_REFERENCES = PROJECT_ROOT / "datasets" / "reference_checksums.yaml"
RESULTS_CSV = PROJECT_ROOT / "results" / "reference_checksum_results.csv"
SUMMARY_JSON = PROJECT_ROOT / "results" / "reference_checksum_summary.json"
TABLE_MD = PROJECT_ROOT / "results" / "paper_tables" / "table_reference_checksum_verification.md"
ARTIFACT_SUMMARY = PROJECT_ROOT / "results" / "artifact_integrity_summary.json"
POPULATION_CSV = PROJECT_ROOT / "results" / "reference_checksum_population.csv"
ALGORITHMS = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}


def _hash(path: Path, algorithm: str) -> str:
    digest = hashlib.new(ALGORITHMS[algorithm])
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_reference_checksums(
    reference_file: Path = DEFAULT_REFERENCES,
    *,
    results_csv: Path = RESULTS_CSV,
    summary_json: Path = SUMMARY_JSON,
    table_path: Path = TABLE_MD,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = yaml.safe_load(reference_file.read_text(encoding="utf-8")) if reference_file.is_file() else {}
    rows: list[dict[str, Any]] = []
    for item in (data or {}).get("references", []):
        algorithm = str(item.get("algorithm", "")).lower()
        expected = str(item.get("expected_value") or "").strip().lower()
        path_text = str(item.get("local_path") or f"datasets/raw/nist_cfreds/{item.get('file_name', '')}")
        path = resolve_project_path(path_text)
        eligible = bool(
            str(item.get("artifact_name") or "").strip()
            and str(item.get("source_name") or "").strip()
            and str(item.get("reference_url") or "").strip()
        )
        official_available = bool(expected and algorithm in ALGORITHMS)
        status = "UNAVAILABLE"
        actual = ""
        note = str(item.get("verification_note") or "")
        if not eligible:
            status = "NOT_APPLICABLE"
            note = note or "Artifact lacks the documented source/reference investigation needed for eligibility."
        elif algorithm not in ALGORITHMS:
            status = "NOT_APPLICABLE" if not expected else "UNAVAILABLE"
            note = note or "No supported official checksum algorithm was supplied."
        elif not expected:
            status = "UNAVAILABLE"
            note = note or "No official publisher checksum was located."
        elif not path.is_file():
            status = "NOT_APPLICABLE"
            note = "The local distribution file was unavailable."
        else:
            actual = _hash(path, algorithm)
            status = "VERIFIED" if actual.casefold() == expected.casefold() else "MISMATCH"
        rows.append({
            "source_name": item.get("source_name", ""),
            "artifact_name": item.get("artifact_name", ""),
            "file_name": item.get("file_name", ""),
            "algorithm": algorithm,
            "expected_value": expected,
            "computed_value": actual,
            "reference_url": item.get("reference_url", ""),
            "retrieval_date_utc": item.get("retrieval_date_utc", ""),
            "status": status,
            "verification_note": note,
            "eligible_for_external_reference": eligible,
            "official_reference_available": official_available,
        })
    counts = {status: sum(row["status"] == status for row in rows) for status in (
        "VERIFIED", "MISMATCH", "UNAVAILABLE", "NOT_APPLICABLE"
    )}
    eligible = sum(row["eligible_for_external_reference"] for row in rows)
    available = sum(
        row["eligible_for_external_reference"] and row["official_reference_available"]
        for row in rows
    )
    unavailable = eligible - available
    external_match_rate = counts["VERIFIED"] / available if available else None
    summary = {
        "generated_at_utc": utc_now(),
        "artifact_count": len(rows),
        "eligible_artifacts": eligible,
        "external_reference_eligible_count": eligible,
        "external_reference_available_count": available,
        "external_reference_verified_count": counts["VERIFIED"],
        "external_reference_mismatch_count": counts["MISMATCH"],
        "external_reference_unavailable_count": unavailable,
        "external_reference_not_applicable_count": counts["NOT_APPLICABLE"],
        "external_reference_verification_coverage": available / eligible if eligible else None,
        "external_match_rate": external_match_rate,
        "external_match_rate_display": (
            f"{external_match_rate:.1%}" if external_match_rate is not None else "N/A"
        ),
        "match_rate_among_available_references": external_match_rate,
    }
    results_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else [
        "source_name", "artifact_name", "file_name", "algorithm", "expected_value",
        "computed_value", "reference_url", "retrieval_date_utc", "status", "verification_note",
    ]
    with results_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    write_json(summary_json, summary)
    population_rows = [{
        "artifact_name": row["artifact_name"], "source_name": row["source_name"],
        "eligible_for_external_reference": row["eligible_for_external_reference"],
        "official_reference_available": row["official_reference_available"],
        "reference_algorithm": row["algorithm"], "reference_value": row["expected_value"],
        "reference_url": row["reference_url"], "verification_status": row["status"],
    } for row in rows]
    with POPULATION_CSV.open("w", encoding="utf-8", newline="") as stream:
        fields = list(population_rows[0]) if population_rows else [
            "artifact_name", "source_name", "eligible_for_external_reference",
            "official_reference_available", "reference_algorithm", "reference_value",
            "reference_url", "verification_status",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader(); writer.writerows(population_rows)
    processing_path = PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
    inspection_path = PROJECT_ROOT / "results" / "image_inspection_summary.json"
    processing = read_json(processing_path) if processing_path.is_file() else []
    inspection = read_json(inspection_path) if inspection_path.is_file() else {}
    artifact_summary = {
        "generated_at_utc": utc_now(),
        "decompression_success_rate": (
            sum(row.get("decompression_status") == "PASSED" for row in processing) / len(processing)
            if processing else None
        ),
        "semantic_inspection_attempt_rate": inspection.get("semantic_inspection_attempt_rate"),
        "semantic_inspection_pass_rate": inspection.get("semantic_inspection_pass_rate"),
        **{key: summary[key] for key in (
            "eligible_artifacts", "external_reference_eligible_count", "external_reference_available_count",
            "external_reference_verified_count", "external_reference_mismatch_count",
            "external_reference_unavailable_count", "external_reference_verification_coverage",
            "external_match_rate", "external_match_rate_display",
        )},
    }
    write_json(ARTIFACT_SUMMARY, artifact_summary)
    table_path.parent.mkdir(parents=True, exist_ok=True)
    header = "| Artifact | Algorithm | Status | Official reference | Note |\n|---|---|---|---|---|\n"
    body = "".join(
        f"| {row['artifact_name']} | {row['algorithm'] or '—'} | {row['status']} | "
        f"{row['reference_url']} | {row['verification_note']} |\n" for row in rows
    )
    table_path.write_text(header + body, encoding="utf-8")
    return rows, summary
