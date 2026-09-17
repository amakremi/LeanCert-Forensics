from __future__ import annotations

import re
import shutil
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import yaml

from .utils import (
    PROJECT_ROOT, read_json, relative_to_project, safe_filename, sha256_file,
    slugify, utc_now, write_json,
)

DEFAULT_CONFIG = PROJECT_ROOT / "datasets" / "public_sources.yaml"
DEFAULT_MANIFEST = PROJECT_ROOT / "datasets" / "manifests" / "download_manifest.json"
SUPPORTED_LOCAL_SUFFIXES = {".dd", ".raw", ".img", ".e01", ".001", ".zip", ".gz", ".bz2", ".7z"}

CFREDS_ARTIFACTS = {
    "dfr_fat": {
        "artifact_name": "DFR-01 FAT deleted-file-recovery image",
        "dataset_family": "Deleted File Recovery",
        "source_url": "https://cfreds-archive.nist.gov/dfr-images/dfr-01-fat.dd.bz2",
        "content_format": "dd",
    },
    "dfr_ntfs": {
        "artifact_name": "DFR-01 NTFS deleted-file-recovery image",
        "dataset_family": "Deleted File Recovery",
        "source_url": "https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2",
        "content_format": "dd",
    },
    "dfr_02_fat": {
        "artifact_name": "DFR-02 FAT deleted-file-recovery image",
        "dataset_family": "Deleted File Recovery",
        "source_url": "https://cfreds-archive.nist.gov/dfr-images/dfr-02-fat.dd.bz2",
        "content_format": "dd",
    },
    "l0_graphic": {
        "artifact_name": "L0 Graphic file-carving image",
        "dataset_family": "File Carving",
        "source_url": "https://cfreds-archive.nist.gov/FileCarving/Images/L0_Graphic.dd.bz2",
        "content_format": "dd",
    },
    "l0_documents": {
        "artifact_name": "L0 Documents file-carving image",
        "dataset_family": "File Carving",
        "source_url": "https://cfreds-archive.nist.gov/FileCarving/Images/L0_Documents.dd.bz2",
        "content_format": "dd",
    },
    "l0_archive": {
        "artifact_name": "L0 Archive file-carving image",
        "dataset_family": "File Carving",
        "source_url": "https://cfreds-archive.nist.gov/FileCarving/Images/L0_Archive.dd.bz2",
        "content_format": "dd",
    },
}


def load_sources(config_path: Path = DEFAULT_CONFIG) -> dict:
    return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {"sources": []}


def _download_name(artifact: dict) -> str:
    configured = artifact.get("filename")
    if configured:
        return safe_filename(str(configured))
    url_name = unquote(Path(urlparse(str(artifact.get("url", ""))).path).name)
    if not url_name:
        extension = str(artifact.get("expected_format", "bin")).split("_")[0].lstrip(".")
        url_name = f"{artifact.get('artifact_name', 'artifact')}.{extension}"
    return safe_filename(url_name)


def _manual_record(source: dict, artifact: dict, status: str, note: str) -> dict:
    return {
        "source_name": source.get("source_name", ""),
        "artifact_name": artifact.get("artifact_name", ""),
        "artifact_kind": artifact.get("kind", "unknown_public_artifact"),
        "source_url": artifact.get("manual_download_url") or artifact.get("url", ""),
        "local_path": "",
        "sha256": "",
        "size_bytes": 0,
        "download_status": status,
        "license_or_usage_note": artifact.get("usage_note", source.get("usage_note", "")),
        "retrieved_at_utc": "",
        "message": note,
    }


def fetch_datasets(
    *,
    config_path: Path = DEFAULT_CONFIG,
    manifest_path: Path = DEFAULT_MANIFEST,
    allow_large_downloads: bool = False,
    timeout: tuple[float, float] = (10.0, 60.0),
) -> list[dict]:
    config = load_sources(config_path)
    previous = read_json(manifest_path) if manifest_path.is_file() else []
    records: list[dict] = []
    for source in config.get("sources", []):
        source_dir = PROJECT_ROOT / "datasets" / "raw" / slugify(source.get("source_name", "source"))
        source_dir.mkdir(parents=True, exist_ok=True)
        for artifact in source.get("artifacts", []):
            if not artifact.get("enabled", True):
                records.append(_manual_record(source, artifact, "disabled", "Artifact is disabled in configuration."))
                continue
            url = str(artifact.get("url", "")).strip()
            if not url or url.startswith("PUT_") or url == "MANUAL_DOWNLOAD_REQUIRED":
                records.append(_manual_record(
                    source, artifact, "manual_download_required",
                    "No stable direct-download URL is configured. See datasets/README.md.",
                ))
                continue
            destination = source_dir / _download_name(artifact)
            max_bytes = int(float(artifact.get("max_size_mb", 100)) * 1024 * 1024)
            if destination.is_file():
                records.append({
                    "source_name": source.get("source_name", ""),
                    "artifact_name": artifact.get("artifact_name", destination.stem),
                    "artifact_kind": artifact.get("kind", "unknown_public_artifact"),
                    "source_url": url,
                    "local_path": relative_to_project(destination),
                    "sha256": sha256_file(destination),
                    "size_bytes": destination.stat().st_size,
                    "download_status": "existing",
                    "license_or_usage_note": artifact.get("usage_note", source.get("usage_note", "")),
                    "retrieved_at_utc": utc_now(),
                })
                continue
            try:
                with requests.get(url, stream=True, timeout=timeout, allow_redirects=True) as response:
                    response.raise_for_status()
                    content_length = int(response.headers.get("Content-Length", "0") or 0)
                    if content_length > max_bytes and not allow_large_downloads:
                        print(f"Skipped {artifact.get('artifact_name')}: {content_length} bytes exceeds "
                              f"{artifact.get('max_size_mb', 100)} MB.")
                        records.append(_manual_record(
                            source, artifact, "skipped_too_large",
                            f"Content-Length {content_length} exceeds configured maximum {max_bytes}.",
                        ))
                        continue
                    downloaded = 0
                    with destination.open("wb") as output:
                        for chunk in response.iter_content(chunk_size=1024 * 1024):
                            if not chunk:
                                continue
                            downloaded += len(chunk)
                            if downloaded > max_bytes and not allow_large_downloads:
                                output.close()
                                destination.unlink(missing_ok=True)
                                raise ValueError(
                                    f"stream exceeded configured maximum of {artifact.get('max_size_mb', 100)} MB"
                                )
                            output.write(chunk)
                records.append({
                    "source_name": source.get("source_name", ""),
                    "artifact_name": artifact.get("artifact_name", destination.stem),
                    "artifact_kind": artifact.get("kind", "unknown_public_artifact"),
                    "source_url": url,
                    "local_path": relative_to_project(destination),
                    "sha256": sha256_file(destination),
                    "size_bytes": destination.stat().st_size,
                    "download_status": "downloaded",
                    "license_or_usage_note": artifact.get("usage_note", source.get("usage_note", "")),
                    "retrieved_at_utc": utc_now(),
                })
                print(f"Downloaded {artifact.get('artifact_name')} -> {relative_to_project(destination)}")
            except ValueError as exc:
                destination.unlink(missing_ok=True)
                status = "skipped_too_large" if "maximum" in str(exc) else "download_failed"
                records.append(_manual_record(source, artifact, status, str(exc)))
                print(f"Could not download {artifact.get('artifact_name')}: {exc}")
            except requests.RequestException as exc:
                destination.unlink(missing_ok=True)
                records.append(_manual_record(source, artifact, "download_failed", str(exc)))
                print(f"Could not download {artifact.get('artifact_name')}: {exc}")
    configured_keys = {
        (record.get("source_name"), record.get("artifact_name")) for record in records
    }
    for record in previous:
        key = (record.get("source_name"), record.get("artifact_name"))
        if (
            record.get("download_status") in {"local_registered", "manual_local"}
            and key not in configured_keys
            and Path(str(record.get("local_path", ""))).is_file()
        ):
            records.append(record)
    write_json(manifest_path, records)
    return records


def usable_manifest_records(records: list[dict]) -> list[dict]:
    usable = []
    for record in records:
        if record.get("download_status") not in {
            "downloaded", "existing", "manual_local", "local_registered"
        }:
            continue
        candidate = Path(str(record.get("local_path", "")))
        path = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        if path.is_file():
            usable.append(record)
    return usable


def register_unlisted_local_artifacts(
    records: list[dict],
    *,
    config_path: Path = DEFAULT_CONFIG,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[dict]:
    """Register real files manually placed under a configured source folder."""
    config = load_sources(config_path)
    known_paths = {
        str(record.get("local_path", "")).replace("\\", "/").lower()
        for record in records if record.get("local_path")
    }
    changed = False
    extension_kinds = {
        ".e01": "disk_image", ".raw": "disk_image", ".dd": "disk_image",
        ".mem": "memory_dump", ".dmp": "memory_dump",
        ".pcap": "network_capture", ".pcapng": "network_capture",
        ".log": "log_file", ".txt": "log_file", ".pdf": "report",
    }
    for source in config.get("sources", []):
        source_dir = PROJECT_ROOT / "datasets" / "raw" / slugify(source.get("source_name", "source"))
        if not source_dir.is_dir():
            continue
        configured_artifacts = source.get("artifacts", [])
        fallback = configured_artifacts[0] if configured_artifacts else {}
        for path in sorted(item for item in source_dir.rglob("*") if item.is_file()):
            relative = relative_to_project(path)
            if relative.replace("\\", "/").lower() in known_paths:
                continue
            records.append({
                "source_name": source.get("source_name", ""),
                "artifact_name": path.stem,
                "artifact_kind": extension_kinds.get(
                    path.suffix.lower(), fallback.get("kind", "unknown_public_artifact")
                ),
                "source_url": fallback.get("manual_download_url") or fallback.get("url", ""),
                "local_path": relative,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "download_status": "manual_local",
                "license_or_usage_note": source.get("usage_note", ""),
                "retrieved_at_utc": utc_now(),
                "message": "Registered from a real file manually placed under datasets/raw.",
            })
            known_paths.add(relative.replace("\\", "/").lower())
            changed = True
    if changed:
        write_json(manifest_path, records)
    return records


def register_local_artifact(
    *,
    source_name: str,
    artifact_name: str,
    kind: str,
    path: Path,
    source_url: str = "",
    usage_note: str = "Locally registered public forensic artifact; review source terms.",
    extra_metadata: dict | None = None,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict:
    """Hash and register a real local public artifact without implying a download."""
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Local artifact does not exist: {resolved}")
    records = read_json(manifest_path) if manifest_path.is_file() else []
    record = {
        "source_name": source_name,
        "artifact_name": artifact_name,
        "artifact_kind": kind,
        "source_url": source_url,
        "local_path": relative_to_project(resolved),
        "sha256": sha256_file(resolved),
        "size_bytes": resolved.stat().st_size,
        "download_status": "local_registered",
        "license_or_usage_note": usage_note,
        "usage_note": usage_note,
        "retrieved_at_utc": utc_now(),
        "message": "Registered from an existing local file; no download was claimed.",
    }
    if extra_metadata:
        record.update(extra_metadata)
    key = (source_name.casefold(), artifact_name.casefold())
    updated = False
    for index, existing in enumerate(records):
        if (
            str(existing.get("source_name", "")).casefold(),
            str(existing.get("artifact_name", "")).casefold(),
        ) == key:
            records[index] = record
            updated = True
            break
    if not updated:
        records.append(record)
    write_json(manifest_path, records)
    return record


def discover_local_artifacts(search_roots: list[Path]) -> list[Path]:
    """Return completed, supported artifact files under the supplied roots."""
    discovered: dict[str, Path] = {}
    for root in search_roots:
        resolved = root.expanduser().resolve()
        if not resolved.is_dir():
            continue
        for path in resolved.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in SUPPORTED_LOCAL_SUFFIXES:
                continue
            discovered[str(path.resolve()).casefold()] = path.resolve()
    return sorted(discovered.values(), key=lambda item: str(item).casefold())


def _distribution_format(path: Path) -> str:
    name = path.name.casefold()
    for suffix in (".dd.bz2", ".raw.bz2", ".img.bz2", ".pcap.gz"):
        if name.endswith(suffix):
            return suffix.lstrip(".")
    return path.suffix.casefold().lstrip(".") or "unknown"


def register_cfreds_batch(
    *,
    dfr_fat: Path,
    dfr_ntfs: Path,
    l0_graphic: Path,
    dfr_02_fat: Path | None = None,
    l0_documents: Path | None = None,
    l0_archive: Path | None = None,
    copy: bool = False,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[dict]:
    """Register the three named CFReDS artifacts from measured local bytes."""
    supplied = {
        "dfr_fat": dfr_fat,
        "dfr_ntfs": dfr_ntfs,
        "l0_graphic": l0_graphic,
        "dfr_02_fat": dfr_02_fat,
        "l0_documents": l0_documents,
        "l0_archive": l0_archive,
    }
    destination_dir = PROJECT_ROOT / "datasets" / "raw" / "nist_cfreds"
    if copy:
        destination_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for key, source_path in supplied.items():
        if source_path is None:
            continue
        source = source_path.expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"CFReDS artifact does not exist: {source}")
        if source.suffix.casefold() not in SUPPORTED_LOCAL_SUFFIXES:
            raise ValueError(f"Unsupported CFReDS distribution format: {source.name}")
        registered_path = source
        if copy:
            registered_path = destination_dir / safe_filename(source.name)
            if source != registered_path.resolve():
                shutil.copy2(source, registered_path)
        metadata = CFREDS_ARTIFACTS[key]
        distribution = _distribution_format(registered_path)
        records.append(register_local_artifact(
            source_name="NIST CFReDS",
            artifact_name=metadata["artifact_name"],
            kind="disk_image",
            path=registered_path,
            source_url=metadata["source_url"],
            usage_note=(
                "NIST Computer Forensic Reference Data Set registered from a user-downloaded "
                "public distribution for research evaluation."
            ),
            extra_metadata={
                "dataset_family": metadata["dataset_family"],
                "distribution_format": distribution,
                "content_format": metadata["content_format"],
                "is_compressed": distribution in {"bz2", "gz", "zip", "7z", "dd.bz2", "raw.bz2", "img.bz2"},
            },
            manifest_path=manifest_path,
        ))
    return records
