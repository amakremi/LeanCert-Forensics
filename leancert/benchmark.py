from __future__ import annotations

import hashlib
import json
import random
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .benchmark_transformer import apply_mutation
from .schema import ValidationTrace
from .utils import PROJECT_ROOT, read_json, utc_now, write_json

BENCHMARK_ROOT = PROJECT_ROOT / "benchmark"
LOCK_PATH = BENCHMARK_ROOT / "manifests" / "benchmark_lock.json"
SEED = 20260726


def mutation_files() -> list[Path]:
    return [
        BENCHMARK_ROOT / "development" / "mutations.yaml",
        BENCHMARK_ROOT / "holdout" / "mutations.yaml",
    ]


def _portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mutations(path: Path) -> list[dict[str, Any]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    values = (payload or {}).get("mutations", [])
    if not isinstance(values, list):
        raise ValueError(f"mutations must be a list in {path}")
    required = {"mutation_id", "family", "operation", "selector", "expected_class", "target_requirements"}
    seen: set[str] = set()
    for item in values:
        missing = required - set(item)
        if missing:
            raise ValueError(f"{path}: mutation missing {sorted(missing)}")
        if item["mutation_id"] in seen:
            raise ValueError(f"{path}: duplicate mutation_id {item['mutation_id']}")
        seen.add(item["mutation_id"])
    return values


def _git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
        capture_output=True, text=True, shell=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def freeze_benchmark(lock_path: Path = LOCK_PATH, *, seed: int = SEED) -> dict[str, Any]:
    files = mutation_files()
    file_rows = []
    combined = hashlib.sha256()
    tracks: dict[str, list[dict[str, Any]]] = {}
    for path in files:
        values = _mutations(path)
        track = path.parent.name
        tracks[track] = values
        digest = _file_hash(path)
        relative = _portable_path(path)
        file_rows.append({"path": relative, "sha256": digest, "mutation_count": len(values)})
        combined.update(relative.encode("utf-8"))
        combined.update(b"\0")
        combined.update(bytes.fromhex(digest))
    lock = {
        "creation_timestamp_utc": utc_now(),
        "random_seed": seed,
        "repository_commit": _git_commit(),
        "files": file_rows,
        "development_mutation_count": len(tracks.get("development", [])),
        "holdout_mutation_count": len(tracks.get("holdout", [])),
        "development_mutation_families": sorted({m["family"] for m in tracks.get("development", [])}),
        "holdout_mutation_families": sorted({m["family"] for m in tracks.get("holdout", [])}),
        "benchmark_sha256": combined.hexdigest(),
    }
    write_json(lock_path, lock)
    return lock


def verify_benchmark_lock(lock_path: Path = LOCK_PATH) -> tuple[bool, list[str]]:
    if not lock_path.is_file():
        return False, ["Benchmark lock does not exist."]
    lock = read_json(lock_path)
    errors: list[str] = []
    combined = hashlib.sha256()
    for item in lock.get("files", []):
        stored = Path(item["path"])
        path = stored if stored.is_absolute() else PROJECT_ROOT / stored
        if not path.is_file():
            errors.append(f"Locked mutation file is missing: {item['path']}")
            continue
        try:
            _mutations(path)
        except ValueError as exc:
            errors.append(str(exc))
        digest = _file_hash(path)
        if digest != item["sha256"]:
            errors.append(f"Locked mutation file changed: {item['path']}")
        combined.update(item["path"].encode("utf-8"))
        combined.update(b"\0")
        combined.update(bytes.fromhex(digest))
    if combined.hexdigest() != lock.get("benchmark_sha256"):
        errors.append("Combined benchmark digest does not match the lock.")
    return not errors, errors


def build_blinded_holdout(
    source_traces: list[Path],
    *,
    output_dir: Path = PROJECT_ROOT / "benchmark" / "generated" / "holdout_blinded",
    mapping_path: Path = PROJECT_ROOT / "benchmark" / "manifests" / "holdout_mapping.json",
    seed: int = SEED,
) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    """Build blinded payloads; labels remain solely in the external mapping."""
    valid_sources = []
    for path in source_traces:
        raw = read_json(path)
        if raw.get("expected_label") == "valid":
            valid_sources.append((path, raw))
    mutations = _mutations(BENCHMARK_ROOT / "holdout" / "mutations.yaml")
    rng = random.Random(seed)
    authored: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for source_path, base in valid_sources:
        authored.append((base, {
            "expected_label": "valid", "mutation_id": None, "target_requirements": [],
            "source_trace": _portable_path(source_path),
        }))
        for mutation in mutations:
            transformed = apply_mutation(base, mutation)
            authored.append((transformed, {
                "expected_label": mutation["expected_class"],
                "mutation_id": mutation["mutation_id"],
                "target_requirements": mutation["target_requirements"],
                "mutation_family": mutation["family"],
                "source_trace": _portable_path(source_path),
            }))
    rng.shuffle(authored)
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("*.json"):
        stale.unlink()
    mapping: dict[str, dict[str, Any]] = {}
    written: list[Path] = []
    for index, (raw, metadata) in enumerate(authored, 1):
        blinded_id = f"BLIND-{index:05d}-{rng.getrandbits(48):012x}"
        payload = {
            key: value for key, value in raw.items()
            if key not in {"expected_label", "evaluation_metadata"}
        }
        payload["trace_id"] = blinded_id
        # This model assertion guarantees no benchmark-only fields reach validation.
        payload = ValidationTrace.model_validate(payload).model_dump()
        path = output_dir / f"{blinded_id.lower()}.json"
        write_json(path, payload)
        mapping[blinded_id] = metadata
        written.append(path)
    write_json(mapping_path, {
        "seed": seed,
        "benchmark_sha256": read_json(LOCK_PATH).get("benchmark_sha256") if LOCK_PATH.is_file() else None,
        "mapping": mapping,
    })
    return written, mapping
