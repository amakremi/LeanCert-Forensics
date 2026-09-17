from __future__ import annotations

from pathlib import Path

from .datasets import usable_manifest_records
from .utils import PROJECT_ROOT, sha256_file

CHECK_COLUMNS = [
    "artifact_exists",
    "artifact_readable",
    "artifact_hash_match",
    "artifact_size_match",
    "artifact_provenance_complete",
    "artifact_signature_consistent",
]


def _resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _signature_consistent(path: Path, record: dict) -> bool:
    try:
        with path.open("rb") as stream:
            header = stream.read(16)
    except OSError:
        return False
    name = path.name.casefold()
    distribution = str(record.get("distribution_format", "")).casefold()
    if name.endswith(".bz2") or distribution.endswith("bz2"):
        return header.startswith(b"BZh")
    if name.endswith(".gz") or distribution.endswith("gz"):
        return header.startswith(b"\x1f\x8b")
    if name.endswith(".zip") or distribution == "zip":
        return header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    if name.endswith(".7z") or distribution == "7z":
        return header.startswith(b"7z\xbc\xaf\x27\x1c")
    if name.endswith(".pdf"):
        return header.startswith(b"%PDF")
    if name.endswith((".pcap", ".pcapng")):
        return header[:4] in {
            b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        }
    if name.endswith((".log", ".txt")):
        try:
            path.read_text(encoding="utf-8")
            return True
        except (OSError, UnicodeDecodeError):
            return False
    # Raw image formats do not have one universal magic value. A readable,
    # non-empty byte stream is consistent with their declared container.
    return bool(header) if name.endswith((".dd", ".raw", ".img", ".e01", ".001")) else False


def evaluate_artifact_native(manifest: list[dict]) -> list[dict]:
    results = []
    for record in usable_manifest_records(manifest):
        path = _resolve(str(record.get("local_path", "")))
        exists = path.is_file()
        readable = False
        computed_hash = ""
        actual_size = 0
        if exists:
            try:
                with path.open("rb") as stream:
                    stream.read(1)
                readable = True
                computed_hash = sha256_file(path)
                actual_size = path.stat().st_size
            except OSError:
                readable = False
        provenance_fields = (
            "source_name", "artifact_name", "artifact_kind", "source_url",
            "local_path", "sha256", "size_bytes", "download_status",
            "license_or_usage_note",
        )
        row = {
            "source_name": record.get("source_name", ""),
            "dataset_family": record.get("dataset_family", ""),
            "artifact_name": record.get("artifact_name", ""),
            "artifact_kind": record.get("artifact_kind", ""),
            "local_path": record.get("local_path", ""),
            "artifact_exists": exists,
            "artifact_readable": readable,
            "artifact_hash_match": (
                readable and computed_hash.casefold() == str(record.get("sha256", "")).casefold()
            ),
            "artifact_size_match": readable and actual_size == int(record.get("size_bytes", -1)),
            "artifact_provenance_complete": all(
                record.get(field) not in (None, "") for field in provenance_fields
            ),
            "artifact_signature_consistent": readable and _signature_consistent(path, record),
            "computed_sha256": computed_hash,
            "actual_size_bytes": actual_size,
        }
        row["overall_pass"] = all(row[column] for column in CHECK_COLUMNS)
        results.append(row)
    return results


def artifact_native_metrics(rows: list[dict]) -> dict:
    count = len(rows)
    rate = lambda field: (sum(bool(row[field]) for row in rows) / count) if count else 0.0
    return {
        "artifacts_checked": count,
        "artifacts_passed": sum(bool(row["overall_pass"]) for row in rows),
        "artifacts_failed": sum(not bool(row["overall_pass"]) for row in rows),
        "existence_rate": rate("artifact_exists"),
        "readability_rate": rate("artifact_readable"),
        "hash_match_rate": rate("artifact_hash_match"),
        "size_match_rate": rate("artifact_size_match"),
        "provenance_completeness_rate": rate("artifact_provenance_complete"),
        "signature_consistency_rate": rate("artifact_signature_consistent"),
    }
