from __future__ import annotations

import csv
import importlib.metadata
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .artifact_processing import PROCESSING_MANIFEST
from .environment_dependencies import capture_environment_dependencies
from .utils import PROJECT_ROOT, read_json, resolve_project_path, sha256_file, utc_now, write_json

RESULTS_CSV = PROJECT_ROOT / "results" / "image_inspection_results.csv"
SUMMARY_JSON = PROJECT_ROOT / "results" / "image_inspection_summary.json"
TABLE_MD = PROJECT_ROOT / "results" / "paper_tables" / "table_image_inspection.md"


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00 ")
    return str(value).strip("\x00 ")


def _fs_type_name(pytsk3: Any, fs_type: int) -> str:
    names = []
    for name in dir(pytsk3):
        if name.startswith("TSK_FS_TYPE_") and name not in {"TSK_FS_TYPE_DETECT", "TSK_FS_TYPE_UNSUPP"}:
            try:
                if int(getattr(pytsk3, name)) == int(fs_type):
                    names.append(name.removeprefix("TSK_FS_TYPE_"))
            except (TypeError, ValueError):
                pass
    return "/".join(sorted(set(names))) or str(fs_type)


def _expected_semantics(artifact_name: str) -> tuple[str | None, bool]:
    folded = artifact_name.casefold()
    if "dfr-01 fat" in folded or "dfr-02 fat" in folded:
        return "FAT", True
    if "dfr-01 ntfs" in folded:
        return "NTFS", True
    return None, False


def _stream_readable(path: Path) -> bool:
    with path.open("rb") as stream:
        stream.read(1024 * 1024)
        if path.stat().st_size > 1024 * 1024:
            stream.seek(max(0, path.stat().st_size - (1024 * 1024)))
            stream.read(1024 * 1024)
    return True


def _inspect_pytsk3(path: Path, artifact_name: str, *, timeout_seconds: float = 120.0) -> dict[str, Any]:
    import pytsk3  # type: ignore

    started = time.monotonic()
    warnings: list[str] = []
    error: str | None = None
    partitions: list[dict[str, Any]] = []
    filesystems: list[dict[str, Any]] = []
    image_opened = False
    volume_detected = False
    fs_attempted = False
    root_attempted = False
    root_readable = False
    root_entry_count = 0
    expected_family, filesystem_applicable = _expected_semantics(artifact_name)
    image = None
    try:
        image = pytsk3.Img_Info(str(path))
        image_opened = True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    candidate_offsets: list[int] = []
    if image is not None:
        try:
            volume = pytsk3.Volume_Info(image)
            volume_detected = True
            block_size = int(volume.info.block_size)
            for part in volume:
                description = _text(part.desc)
                row = {
                    "address": int(part.addr),
                    "start_sector": int(part.start),
                    "length_sectors": int(part.len),
                    "description": description,
                    "flags": int(part.flags),
                    "byte_offset": int(part.start) * block_size,
                }
                partitions.append(row)
                if (
                    int(part.len) > 0
                    and "unallocated" not in description.casefold()
                    and "table" not in description.casefold()
                    and int(part.start) > 0
                ):
                    candidate_offsets.append(row["byte_offset"])
        except Exception as exc:
            warnings.append(f"Volume system not detected: {type(exc).__name__}: {exc}")
            candidate_offsets = [0]

    for offset in candidate_offsets or ([0] if image is not None else []):
        if time.monotonic() - started > timeout_seconds:
            error = f"Inspection exceeded {timeout_seconds:.1f} seconds."
            break
        fs_attempted = True
        try:
            fs = pytsk3.FS_Info(image, offset=offset)
            info = fs.info
            fs_name = _fs_type_name(pytsk3, int(info.ftype))
            fs_row = {
                "byte_offset": offset,
                "filesystem_type": fs_name,
                "block_size": int(getattr(info, "block_size", 0) or 0),
                "block_count": int(getattr(info, "block_count", 0) or 0),
                "filesystem_label": _text(getattr(info, "label", b"")),
                "volume_identifier": bytes(getattr(info, "fs_id", b"")).hex(),
                "root_directory_readable": False,
                "root_entry_count": 0,
            }
            root_attempted = True
            try:
                root = fs.open_dir(path="/")
                count = sum(
                    1 for entry in root
                    if _text(getattr(entry.info.name, "name", b"")) not in {"", ".", ".."}
                )
                fs_row["root_directory_readable"] = True
                fs_row["root_entry_count"] = count
                root_readable = True
                root_entry_count += count
            except Exception as exc:
                warnings.append(
                    f"Root directory at byte offset {offset} unreadable: {type(exc).__name__}: {exc}"
                )
            filesystems.append(fs_row)
        except Exception as exc:
            warnings.append(
                f"Filesystem at byte offset {offset} not detected: {type(exc).__name__}: {exc}"
            )

    detected_types = [row["filesystem_type"] for row in filesystems]
    family_agrees: bool | None
    if expected_family is None:
        family_agrees = None
    else:
        family_agrees = any(expected_family in name.upper() for name in detected_types)
    byte_stream_readable = False
    try:
        byte_stream_readable = _stream_readable(path)
    except OSError as exc:
        warnings.append(f"Byte-stream readability failed: {type(exc).__name__}: {exc}")

    if not image_opened or not byte_stream_readable:
        status = "FAILED"
    elif filesystem_applicable:
        status = "PASSED" if filesystems and root_readable and family_agrees else "FAILED"
        if family_agrees is False:
            warnings.append(
                f"Detected filesystem family contradicts expected {expected_family} family."
            )
    else:
        status = "PARTIAL"

    return {
        "backend": "pytsk3",
        "backend_version": importlib.metadata.version("pytsk3"),
        "sleuthkit_version": getattr(pytsk3, "TSK_VERSION_STR", "unavailable"),
        "image_opened": image_opened,
        "byte_stream_readable": byte_stream_readable,
        "volume_system_detected": volume_detected,
        "partition_count": len(partitions),
        "partitions": partitions,
        "filesystem_detection_attempted": fs_attempted,
        "filesystem_detected": bool(filesystems),
        "filesystem_types": detected_types,
        "filesystems": filesystems,
        "expected_filesystem_family": expected_family,
        "filesystem_family_agrees": family_agrees,
        "filesystem_semantics": "APPLICABLE" if filesystem_applicable else "NOT_APPLICABLE",
        "root_directory_attempted": root_attempted,
        "root_directory_readable": root_readable,
        "root_entry_count": root_entry_count,
        "inspection_status": status,
        "warnings": warnings,
        "error": error,
        "inspection_time_ms": (time.monotonic() - started) * 1000,
    }


def _pytsk3_backend(path: Path) -> bool | None:
    """Compatibility probe retained for tests and optional backend substitution."""
    del path
    try:
        import pytsk3  # noqa: F401  # type: ignore
    except Exception:
        return None
    return True


def _tsk_backend(path: Path) -> dict[str, Any] | None:
    """Reserved CLI-backend hook; semantic results currently require pytsk3."""
    del path
    return None


def _tsk_available() -> bool:
    return bool(shutil.which("mmls") and shutil.which("fsstat"))


def _not_run(reason: str) -> dict[str, Any]:
    return {
        "backend": "sleuthkit-cli" if _tsk_available() else "none",
        "backend_version": "", "sleuthkit_version": "", "image_opened": False,
        "byte_stream_readable": False, "volume_system_detected": False,
        "partition_count": 0, "partitions": [], "filesystem_detection_attempted": False,
        "filesystem_detected": False, "filesystem_types": [], "filesystems": [],
        "expected_filesystem_family": None, "filesystem_family_agrees": None,
        "filesystem_semantics": "NOT_RUN", "root_directory_attempted": False,
        "root_directory_readable": False, "root_entry_count": 0,
        "inspection_status": "NOT_RUN", "warnings": [reason], "error": reason,
        "inspection_time_ms": 0.0,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def inspect_images(
    processing_manifest: Path = PROCESSING_MANIFEST,
    *,
    results_csv: Path = RESULTS_CSV,
    summary_json: Path = SUMMARY_JSON,
    table_path: Path = TABLE_MD,
    force: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    del force  # Inspection is read-only; force means recompute rather than reuse.
    environment = capture_environment_dependencies()
    records = read_json(processing_manifest) if processing_manifest.is_file() else []
    rows: list[dict[str, Any]] = []
    for record in records:
        path = resolve_project_path(record.get("decompressed_path", ""))
        base = {
            "artifact_name": record.get("artifact_name", path.name),
            "image_path": record.get("decompressed_path", ""),
            "image_size_bytes": path.stat().st_size if path.is_file() else 0,
            "manifest_size_match": bool(
                path.is_file() and path.stat().st_size == record.get("decompressed_size_bytes")
            ),
            "manifest_sha256_match": bool(
                path.is_file() and sha256_file(path) == record.get("decompressed_sha256")
            ),
            "distribution_exists": resolve_project_path(
                record.get("distribution_path", "")
            ).is_file(),
        }
        if record.get("decompression_status") != "PASSED" or not path.is_file():
            result = _not_run("A verified decompressed image was unavailable.")
            result["inspection_status"] = "NOT_APPLICABLE"
        elif environment["pytsk3_available"] and _pytsk3_backend(path) is not None:
            try:
                result = _inspect_pytsk3(path, base["artifact_name"])
            except Exception as exc:
                result = _not_run(f"Unrecoverable pytsk3 exception: {type(exc).__name__}: {exc}")
                result["backend"] = "pytsk3"
                result["inspection_status"] = "FAILED"
        else:
            fallback = _tsk_backend(path)
            result = fallback or _not_run(
                environment.get("import_exception") or "No semantic inspection backend available."
            )
        combined = {**base, **result}
        combined["status"] = combined["inspection_status"]
        rows.append(combined)

    statuses = ("PASSED", "PARTIAL", "FAILED", "NOT_RUN", "NOT_APPLICABLE")
    counts = {status: sum(row["inspection_status"] == status for row in rows) for status in statuses}
    attempted = sum(row["inspection_status"] not in {"NOT_RUN", "NOT_APPLICABLE"} for row in rows)
    applicable = sum(row["filesystem_semantics"] == "APPLICABLE" for row in rows)
    fs_attempted_applicable = sum(
        row["filesystem_semantics"] == "APPLICABLE" and row["filesystem_detection_attempted"]
        for row in rows
    )
    fs_detected_applicable = sum(
        row["filesystem_semantics"] == "APPLICABLE" and row["filesystem_detected"]
        for row in rows
    )
    root_attempted_count = sum(row["root_directory_attempted"] for row in rows)
    root_readable_count = sum(row["root_directory_readable"] for row in rows)
    summary = {
        "generated_at_utc": utc_now(),
        "image_count": len(rows),
        "decompressed_images": len(rows),
        "inspection_attempted_images": attempted,
        "inspection_passed_images": counts["PASSED"],
        "successfully_inspected_images": counts["PASSED"],
        "inspection_partial_images": counts["PARTIAL"],
        "inspection_failed_images": counts["FAILED"],
        "inspection_not_applicable_images": counts["NOT_APPLICABLE"],
        "inspection_not_run_images": counts["NOT_RUN"],
        "semantically_applicable_images": applicable,
        "image_open_rate": _ratio(sum(row["image_opened"] for row in rows), len(rows)),
        "semantic_inspection_attempt_rate": _ratio(attempted, len(rows)),
        "semantic_inspection_pass_rate": _ratio(counts["PASSED"], applicable),
        "filesystem_detection_rate": _ratio(fs_detected_applicable, fs_attempted_applicable),
        "root_directory_readability_rate": _ratio(root_readable_count, root_attempted_count),
        "selected_backend": environment["selected_image_inspection_backend"],
    }
    results_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with results_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else value
                for key, value in row.items()
            })
    write_json(summary_json, summary)
    table_path.parent.mkdir(parents=True, exist_ok=True)
    def display(value: float | None) -> str:
        return "N/A" if value is None else f"{value:.1%}"
    table_path.write_text(
        "| Image | Status | Volume system | Partitions | Filesystems | Root readable | Entries | Warnings |\n"
        "|---|---|---|---:|---|---|---:|---|\n"
        + "".join(
            f"| {row['artifact_name']} | {row['inspection_status']} | "
            f"{row['volume_system_detected']} | {row['partition_count']} | "
            f"{', '.join(row['filesystem_types']) or 'N/A'} | "
            f"{row['root_directory_readable']} | {row['root_entry_count']} | "
            f"{' ; '.join(row['warnings']) or '—'} |\n" for row in rows
        )
        + "\n| Metric | Value |\n|---|---:|\n"
        + f"| Semantic inspection attempt rate | {display(summary['semantic_inspection_attempt_rate'])} |\n"
        + f"| Semantic inspection pass rate (applicable images) | {display(summary['semantic_inspection_pass_rate'])} |\n"
        + f"| Filesystem detection rate (applicable attempts) | {display(summary['filesystem_detection_rate'])} |\n"
        + f"| Root-directory readability rate | {display(summary['root_directory_readability_rate'])} |\n",
        encoding="utf-8",
    )
    return rows, summary
