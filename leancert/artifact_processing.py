from __future__ import annotations

import bz2
import hashlib
import os
import time
from pathlib import Path
from typing import Any

from .datasets import DEFAULT_MANIFEST, usable_manifest_records
from .utils import PROJECT_ROOT, read_json, relative_to_project, sha256_file, write_json

CHUNK_SIZE = 8 * 1024 * 1024
PROCESSING_MANIFEST = PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"
DECOMPRESSED_DIR = PROJECT_ROOT / "datasets" / "derived" / "nist_cfreds" / "decompressed"


def _distribution_records(manifest_path: Path = DEFAULT_MANIFEST) -> list[dict[str, Any]]:
    if not manifest_path.is_file():
        return []
    return [
        item for item in usable_manifest_records(read_json(manifest_path))
        if item.get("source_name") == "NIST CFReDS"
        and str(item.get("local_path", "")).lower().endswith(".dd.bz2")
    ]


def decompress_bz2(
    source: Path,
    destination: Path,
    *,
    force: bool = False,
    chunk_size: int = CHUNK_SIZE,
) -> dict[str, Any]:
    """Stream a bzip2 distribution to an atomically published raw image."""
    if chunk_size < CHUNK_SIZE:
        raise ValueError("CFReDS decompression chunks must be at least 8 MiB")
    source = source.resolve()
    destination = destination.resolve()
    started = time.perf_counter_ns()
    base = {
        "distribution_path": relative_to_project(source),
        "distribution_format": "bzip2",
        "distribution_sha256": sha256_file(source),
        "distribution_size_bytes": source.stat().st_size,
        "decompressed_path": relative_to_project(destination),
        "content_format": "raw_dd",
        "decompressed_sha256": "",
        "decompressed_size_bytes": 0,
        "decompression_status": "NOT_RUN",
        "decompression_time_ms": 0.0,
        "decompression_error": None,
    }
    if destination.exists() and not force:
        base.update({
            "decompressed_sha256": sha256_file(destination),
            "decompressed_size_bytes": destination.stat().st_size,
            "decompression_time_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "decompression_error": "Destination exists; use --force to replace it.",
        })
        return base
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    digest = hashlib.sha256()
    size = 0
    try:
        with bz2.open(source, "rb") as compressed, temporary.open("xb") as output:
            while chunk := compressed.read(chunk_size):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        base.update({
            "decompressed_sha256": digest.hexdigest(),
            "decompressed_size_bytes": size,
            "decompression_status": "PASSED",
        })
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        base.update({
            "decompression_status": "FAILED",
            "decompression_error": f"{type(exc).__name__}: {exc}",
        })
    base["decompression_time_ms"] = (time.perf_counter_ns() - started) / 1_000_000
    return base


def process_cfreds_images(
    *,
    force: bool = False,
    manifest_path: Path = DEFAULT_MANIFEST,
    output_dir: Path = DECOMPRESSED_DIR,
    processing_manifest: Path = PROCESSING_MANIFEST,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _distribution_records(manifest_path):
        source = PROJECT_ROOT / record["local_path"]
        destination = output_dir / Path(record["local_path"]).name.removesuffix(".bz2")
        if not source.is_file():
            rows.append({
                "distribution_path": relative_to_project(source),
                "distribution_format": "bzip2",
                "distribution_sha256": "",
                "distribution_size_bytes": 0,
                "decompressed_path": relative_to_project(destination),
                "content_format": "raw_dd",
                "decompressed_sha256": "",
                "decompressed_size_bytes": 0,
                "decompression_status": "FAILED",
                "decompression_time_ms": 0.0,
                "decompression_error": "Distribution file does not exist.",
            })
            continue
        row = decompress_bz2(source, destination, force=force)
        row["source_name"] = record.get("source_name", "")
        row["artifact_name"] = record.get("artifact_name", "")
        rows.append(row)
    write_json(processing_manifest, rows)
    return rows
