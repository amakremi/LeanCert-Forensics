from __future__ import annotations

import copy
import hashlib
import random
import subprocess
from pathlib import Path
from typing import Any

from .datasets import DEFAULT_MANIFEST, usable_manifest_records
from .schema import ForensicTrace, ValidationTrace
from .trace_builder import scalability_trace
from .utils import PROJECT_ROOT, read_json, utc_now, write_json
from .validator import REQUIREMENTS

DEFAULT_ROOT = PROJECT_ROOT / "benchmark" / "holdout_v2"
SEED = 20260728


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
        capture_output=True, text=True, shell=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _mutate(base: dict[str, Any], requirement: str, serial: int) -> dict[str, Any]:
    trace = copy.deepcopy(base)
    if requirement == "IdentityCompleteness":
        trace["actors"][0]["name"] = ""
    elif requirement == "ReferentialIntegrity":
        duplicate = copy.deepcopy(trace["actors"][0])
        trace["actors"].append(duplicate)
    elif requirement == "PublicArtifactIntegrity":
        trace["evidence"][0]["hash"] = "sha256:" + hashlib.sha256(
            f"holdout-v2-{serial}".encode("utf-8")
        ).hexdigest()
    elif requirement == "CustodyContinuity":
        trace["events"][1]["prev_holder"] = "SUP-001"
    elif requirement == "ChronologicalConsistency":
        trace["events"][3]["timestamp"] = trace["events"][2]["timestamp"] - 1
    elif requirement == "HashContinuity":
        trace["events"][1]["prev_hash"] = "BROKEN-HOLDOUT-V2-LINK"
    elif requirement == "AuthorizedHandling":
        trace["events"][1]["actor_id"] = "ANA-001"
    elif requirement == "LifecycleCorrectness":
        trace["events"][1]["action"] = "archive"
    elif requirement == "ReportTraceability":
        trace["report_claims"][0]["text"] = ""
    else:
        raise ValueError(f"Unknown requirement: {requirement}")
    return trace


def build_holdout_v2(
    *,
    valid_trace_count: int = 30,
    invalid_per_requirement: int = 10,
    seed: int = SEED,
    root: Path = DEFAULT_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    if valid_trace_count < 30 or invalid_per_requirement < 10:
        raise ValueError("Holdout v2 requires at least 30 valid and 10 direct invalid traces per requirement")
    records = usable_manifest_records(read_json(manifest_path)) if manifest_path.is_file() else []
    if not records:
        raise ValueError("No registered public artifacts are available")
    private_dir = root / "private"
    blinded_dir = root / "blinded"
    manifests_dir = root / "manifests"
    for directory in (private_dir, blinded_dir, manifests_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for stale in blinded_dir.glob("*.json"):
        stale.unlink()
    sizes = (8, 12, 20)
    valid: list[dict[str, Any]] = []
    for index in range(valid_trace_count):
        record = records[index % len(records)]
        raw = scalability_trace(
            record, sizes[index % len(sizes)], variant_index=index, seed=seed + index,
        )
        raw["trace_id"] = f"PRIVATE-V2-VALID-{index + 1:03d}"
        raw["case_id"] = f"PRIVATE-V2-CASE-{index + 1:03d}"
        for evidence in raw["evidence"]:
            evidence["case_id"] = raw["case_id"]
        valid.append(raw)
    authored: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, raw in enumerate(valid):
        authored.append((raw, {
            "expected_label": "valid", "root_requirement": None,
            "mutation_family": None, "source_artifact": raw["dataset_origin"]["artifact_name"],
            "private_trace_id": raw["trace_id"],
        }))
    mutation_specs = []
    serial = 0
    for requirement in REQUIREMENTS:
        family = f"v2-{requirement.casefold()}-direct"
        mutation_specs.append({
            "family": family, "root_requirement": requirement,
            "operation": "declarative content mutation",
            "case_count": invalid_per_requirement,
        })
        for index in range(invalid_per_requirement):
            serial += 1
            base = valid[(serial - 1) % len(valid)]
            mutated = _mutate(base, requirement, serial)
            mutated["trace_id"] = f"PRIVATE-V2-INVALID-{serial:03d}"
            authored.append((mutated, {
                "expected_label": "invalid", "root_requirement": requirement,
                "mutation_family": family,
                "source_artifact": base["dataset_origin"]["artifact_name"],
                "private_trace_id": mutated["trace_id"],
            }))
    rng = random.Random(seed)
    rng.shuffle(authored)
    mapping: dict[str, dict[str, Any]] = {}
    written = []
    for index, (raw, private) in enumerate(authored, 1):
        blinded_id = f"B2-{index:04d}-{rng.getrandbits(56):014x}"
        payload = {
            key: value for key, value in raw.items()
            if key not in {"expected_label", "evaluation_metadata"}
        }
        payload["trace_id"] = blinded_id
        payload = ValidationTrace.model_validate(payload).model_dump()
        path = blinded_dir / f"case-{index:04d}.json"
        write_json(path, payload)
        written.append(path)
        mapping[blinded_id] = private
    labels = {
        "benchmark_version": 2, "seed": seed, "generated_at_utc": utc_now(),
        "mapping": mapping,
    }
    write_json(private_dir / "labels.json", labels)
    write_json(private_dir / "mutation_specifications.json", mutation_specs)
    direct = {requirement: invalid_per_requirement for requirement in REQUIREMENTS}
    build_manifest = {
        "benchmark_version": 2, "generation_seed": seed,
        "valid_trace_count": valid_trace_count,
        "invalid_trace_count": len(REQUIREMENTS) * invalid_per_requirement,
        "total_trace_count": len(written), "direct_cases_per_requirement": direct,
        "blinded_trace_directory": str(blinded_dir.resolve()),
        "private_mapping_path": str((private_dir / "labels.json").resolve()),
    }
    write_json(manifests_dir / "build_manifest_v2.json", build_manifest)
    return build_manifest


def freeze_holdout_v2(root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    blinded = sorted((root / "blinded").glob("*.json"))
    private_files = [
        root / "private" / "labels.json",
        root / "private" / "mutation_specifications.json",
    ]
    build = read_json(root / "manifests" / "build_manifest_v2.json")
    rows = []
    combined = hashlib.sha256()
    for path in [*blinded, *private_files]:
        digest = _sha(path)
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        rows.append({"path": relative, "sha256": digest})
        combined.update(relative.encode("utf-8") + b"\0" + bytes.fromhex(digest))
    lock = {
        "benchmark_version": 2,
        "generation_seed": build["generation_seed"],
        "valid_trace_count": build["valid_trace_count"],
        "invalid_trace_count": build["invalid_trace_count"],
        "total_trace_count": build["total_trace_count"],
        "direct_cases_per_requirement": build["direct_cases_per_requirement"],
        "files": rows, "combined_benchmark_sha256": combined.hexdigest(),
        "generation_timestamp_utc": utc_now(), "repository_commit": _git_commit(),
    }
    write_json(root / "manifests" / "benchmark_lock_v2.json", lock)
    return lock


def verify_holdout_v2_lock(root: Path = DEFAULT_ROOT) -> tuple[bool, list[str]]:
    lock_path = root / "manifests" / "benchmark_lock_v2.json"
    if not lock_path.is_file():
        return False, ["Holdout-v2 benchmark lock is missing."]
    lock = read_json(lock_path)
    errors: list[str] = []
    combined = hashlib.sha256()
    for item in lock.get("files", []):
        path = root / item["path"]
        if not path.is_file():
            errors.append(f"Locked file missing: {item['path']}")
            continue
        digest = _sha(path)
        if digest != item["sha256"]:
            errors.append(f"Locked file changed: {item['path']}")
        combined.update(item["path"].encode("utf-8") + b"\0" + bytes.fromhex(digest))
    if combined.hexdigest() != lock.get("combined_benchmark_sha256"):
        errors.append("Combined holdout-v2 digest does not match.")
    return not errors, errors


def load_holdout_v2(root: Path = DEFAULT_ROOT) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    labels = read_json(root / "private" / "labels.json")
    return sorted((root / "blinded").glob("*.json")), labels["mapping"]
