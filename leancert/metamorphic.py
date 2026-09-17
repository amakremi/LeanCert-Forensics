from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
from typing import Any, Callable

from .reference_validator import SUBSET, reference_validate
from .schema import ValidationTrace
from .utils import PROJECT_ROOT, read_json, write_json
from .validator import validate_trace


def _rename_ids(raw: dict[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(raw)
    evidence_map = {item["evidence_id"]: f"REN-E-{index}" for index, item in enumerate(output["evidence"])}
    actor_map = {item["actor_id"]: f"REN-A-{index}" for index, item in enumerate(output["actors"])}
    event_map = {item["event_id"]: f"REN-V-{index}" for index, item in enumerate(output["events"])}
    for item in output["evidence"]:
        item["evidence_id"] = evidence_map[item["evidence_id"]]
        if item.get("parent_evidence_id"):
            item["parent_evidence_id"] = evidence_map[item["parent_evidence_id"]]
    for item in output["actors"]:
        item["actor_id"] = actor_map[item["actor_id"]]
    for item in output["events"]:
        item["event_id"] = event_map[item["event_id"]]
        item["evidence_id"] = evidence_map.get(item["evidence_id"], item["evidence_id"])
        item["actor_id"] = actor_map.get(item["actor_id"], item["actor_id"])
        for field in ("prev_holder", "new_holder"):
            if item.get(field) in actor_map:
                item[field] = actor_map[item[field]]
    for claim in output["report_claims"]:
        claim["supporting_evidence_ids"] = [
            evidence_map.get(value, value) for value in claim["supporting_evidence_ids"]
        ]
    output["trace_id"] = "RENAMED-TRACE"
    return output


def _reverse_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _reverse_keys(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reverse_keys(item) for item in value]
    return value


def run_metamorphic_and_differential(
    blinded_paths: list[Path],
    mapping: dict[str, dict[str, Any]],
    *,
    results_dir: Path = PROJECT_ROOT / "results",
    strict_artifacts: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    valid_path = next(path for path in blinded_paths if mapping[read_json(path)["trace_id"]]["expected_label"] == "valid")
    invalid_path = next(path for path in blinded_paths if mapping[read_json(path)["trace_id"]]["expected_label"] == "invalid")
    valid = read_json(valid_path)
    invalid = read_json(invalid_path)
    valid_transforms: list[tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = [
        ("consistent_identifier_rename", _rename_ids),
        ("json_object_key_reorder", _reverse_keys),
        ("artifact_path_normalization", lambda raw: {
            **copy.deepcopy(raw),
            "evidence": [
                {**item, "artifact_path": str(Path(item["artifact_path"]))}
                for item in copy.deepcopy(raw)["evidence"]
            ],
        }),
        ("add_unused_actor", lambda raw: {
            **copy.deepcopy(raw),
            "actors": [*copy.deepcopy(raw)["actors"], {
                "actor_id": "UNUSED-ACTOR", "name": "Unused benchmark actor", "role": "external_reviewer",
            }],
        }),
        ("event_list_reversal", lambda raw: {**copy.deepcopy(raw), "events": list(reversed(copy.deepcopy(raw)["events"]))}),
    ]
    invalid_transforms: list[tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = [
        ("rename_invalid_trace_id", lambda raw: {**copy.deepcopy(raw), "trace_id": "RELOCATED-INVALID"}),
        ("json_object_key_reorder_invalid", _reverse_keys),
        ("event_list_reversal_invalid", lambda raw: {**copy.deepcopy(raw), "events": list(reversed(copy.deepcopy(raw)["events"]))}),
    ]
    rows = []
    for expected, source, transforms in (
        ("PASSED", valid, valid_transforms), ("FAILED", invalid, invalid_transforms)
    ):
        for name, transform in transforms:
            transformed = ValidationTrace.model_validate(transform(source))
            actual = validate_trace(transformed, strict_artifacts=strict_artifacts).overall_status
            rows.append({
                "test_id": name, "source_expected_status": expected,
                "transformed_status": actual, "passed": actual == expected,
            })
    summary = {
        "metamorphic_test_count": len(rows),
        "metamorphic_tests_passed": sum(row["passed"] for row in rows),
        "metamorphic_tests_failed": sum(not row["passed"] for row in rows),
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    with (results_dir / "metamorphic_test_results.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    write_json(results_dir / "metamorphic_summary.json", summary)

    differential = []
    for path in blinded_paths:
        trace = ValidationTrace.model_validate(read_json(path))
        production = validate_trace(trace, strict_artifacts=strict_artifacts)
        production_map = {item.requirement: item.passed for item in production.requirement_results}
        reference = reference_validate(trace)
        for requirement in SUBSET:
            differential.append({
                "trace_id": trace.trace_id,
                "requirement": requirement,
                "production_passed": production_map[requirement],
                "reference_passed": reference[requirement],
                "agreement": production_map[requirement] == reference[requirement],
            })
    with (results_dir / "differential_validation.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(differential[0]))
        writer.writeheader()
        writer.writerows(differential)
    differential_summary = {
        "production_reference_comparisons": len(differential),
        "production_reference_agreements": sum(row["agreement"] for row in differential),
        "production_reference_disagreements": sum(not row["agreement"] for row in differential),
    }
    return summary, differential_summary
