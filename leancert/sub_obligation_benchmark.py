from __future__ import annotations

import copy
import csv
import hashlib
import json
import random
from pathlib import Path
from typing import Any

import yaml

from .datasets import DEFAULT_MANIFEST, usable_manifest_records
from .schema import ValidationTrace
from .sub_obligations import CHILD_IDS, DESCRIPTIONS, PARENTS, evaluate_children
from .trace_builder import scalability_trace
from .utils import PROJECT_ROOT, read_json, utc_now, write_json

ROOT = PROJECT_ROOT / "benchmark" / "sub_obligation_holdout_v1"
SPEC_PATH = PROJECT_ROOT / "benchmark" / "sub_obligations" / "mutation_specs.yaml"
SEED = 20260809


def _ensure_action(raw: dict[str, Any], action: str) -> dict[str, Any]:
    match = next((event for event in raw["events"] if event["action"] == action), None)
    if match is None:
        raise ValueError(f"Baseline has no {action} event")
    return match


def _ensure_derived(raw: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    existing = next((e for e in raw["evidence"] if e["kind"] == "derived_artifact"), None)
    if existing:
        return existing, [e for e in raw["events"] if e["evidence_id"] == existing["evidence_id"]]
    parent = raw["evidence"][0]
    derived = copy.deepcopy(parent)
    derived.update({
        "evidence_id": parent["evidence_id"] + "-DER", "kind": "derived_artifact",
        "parent_evidence_id": parent["evidence_id"],
    })
    raw["evidence"].append(derived)
    start = max(e["timestamp"] for e in raw["events"]) + 10
    holder = None
    events = []
    for offset, (action, actor) in enumerate((
        ("derive", "ANA-001"), ("examine", "ANA-001"),
        ("analyze", "ANA-001"), ("report", "SUP-001"),
    )):
        event = {
            "event_id": f"EVT-DER-{offset + 1:03d}", "evidence_id": derived["evidence_id"],
            "actor_id": actor, "action": action, "timestamp": start + offset * 10,
            "prev_holder": holder, "new_holder": "ANA-001",
            "prev_hash": "DER-GENESIS" if offset == 0 else derived["hash"],
            "curr_hash": derived["hash"], "hash_change_allowed": action == "derive",
        }
        events.append(event); holder = "ANA-001"
    raw["events"].extend(events)
    return derived, events


def mutate(raw: dict[str, Any], child: str, serial: int) -> dict[str, Any]:
    out = copy.deepcopy(raw)
    if child == "REQ-ID-001-SUB-01": out["case_id"] = ""
    elif child == "REQ-ID-001-SUB-02": out["evidence"][0]["source"] = ""
    elif child == "REQ-ID-001-SUB-03": out["actors"][0]["name"] = ""
    elif child == "REQ-ID-001-SUB-04": out["events"][-1]["event_id"] = ""
    elif child == "REQ-ID-001-SUB-05": out["report_claims"][0]["claim_id"] = ""
    elif child == "REQ-REF-001-SUB-01":
        duplicate = copy.deepcopy(out["report_claims"][0]); out["report_claims"].append(duplicate)
    elif child == "REQ-REF-001-SUB-02": out["events"][0]["evidence_id"] = "UNKNOWN-EVIDENCE"
    elif child == "REQ-REF-001-SUB-03": out["events"][0]["actor_id"] = "UNKNOWN-ACTOR"
    elif child == "REQ-REF-001-SUB-04": out["report_claims"][0]["supporting_evidence_ids"] = ["UNKNOWN-EVIDENCE"]
    elif child == "REQ-REF-001-SUB-05":
        derived, _ = _ensure_derived(out); derived["parent_evidence_id"] = "UNKNOWN-EVIDENCE"
    elif child == "REQ-ART-001-SUB-01": out["evidence"][0]["artifact_path"] = f"missing/child-{serial}.bin"
    elif child == "REQ-ART-001-SUB-02": out["evidence"][0]["hash"] = "sha256:" + hashlib.sha256(f"child-{serial}".encode()).hexdigest()
    elif child == "REQ-ART-001-SUB-03": out["evidence"][0]["size_bytes"] += 1
    elif child == "REQ-CUST-001-SUB-01": _ensure_action(out, "acquire")["prev_holder"] = "SUP-001"
    elif child == "REQ-CUST-001-SUB-02": out["events"][1]["prev_holder"] = "SUP-001"
    elif child == "REQ-CUST-001-SUB-03": _ensure_action(out, "transfer")["new_holder"] = None
    elif child == "REQ-CUST-001-SUB-04": _ensure_action(out, "preserve")["new_holder"] = None
    elif child == "REQ-CHR-001-SUB-01": out["events"][0]["timestamp"] = -1
    elif child == "REQ-CHR-001-SUB-02":
        for event in out["events"]:
            if event["action"] == "analyze": event["action"] = "examine"
    elif child == "REQ-CHR-001-SUB-03":
        _, events = _ensure_derived(out); events[0]["timestamp"] = out["events"][0]["timestamp"] - 1
    elif child == "REQ-HASH-001-SUB-01": _ensure_action(out, "acquire")["prev_hash"] = "NOT-GENESIS"
    elif child == "REQ-HASH-001-SUB-02": out["events"][1]["prev_hash"] = "BROKEN-ADJACENT-LINK"
    elif child == "REQ-HASH-001-SUB-03": out["events"][-1]["curr_hash"] = "UNAUTHORIZED-HASH"
    elif child == "REQ-HASH-001-SUB-04":
        derived, _ = _ensure_derived(out); derived["parent_evidence_id"] = None
    elif child == "REQ-AUTH-001-SUB-01": out["events"][0]["actor_id"] = "UNKNOWN-ACTOR"
    elif child == "REQ-AUTH-001-SUB-02": out["events"][0]["actor_id"] = "SUP-001"
    elif child == "REQ-LIFE-001-SUB-01":
        acquire = _ensure_action(out, "acquire"); acquire["action"] = "examine"; acquire["actor_id"] = "INV-001"
    elif child == "REQ-LIFE-001-SUB-02":
        preserve = _ensure_action(out, "preserve"); preserve["action"] = "transfer"
    elif child == "REQ-LIFE-001-SUB-03":
        for event in out["events"]:
            if event["action"] == "analyze": event["action"] = "examine"
    elif child == "REQ-LIFE-001-SUB-04":
        # Turn the sole report event into an authorized archive event.  The archive now
        # lacks its prerequisite without introducing an authorization violation.
        report = _ensure_action(out, "report"); report["action"] = "archive"
    elif child == "REQ-LIFE-001-SUB-05":
        _ensure_derived(out)
        out["events"] = [e for e in out["events"] if not (
            e["evidence_id"] == out["evidence"][0]["evidence_id"] and e["action"] in {"analyze", "report", "archive"}
        )]
    elif child == "REQ-RPT-001-SUB-01": out["report_claims"][0]["text"] = ""
    elif child == "REQ-RPT-001-SUB-02": out["report_claims"][0]["supporting_evidence_ids"] = []
    elif child == "REQ-RPT-001-SUB-03": out["report_claims"][0]["supporting_evidence_ids"] = ["UNKNOWN-EVIDENCE"]
    elif child == "REQ-RPT-001-SUB-04": out["events"][1]["prev_hash"] = "BROKEN-UPSTREAM-LINK"
    else: raise KeyError(child)
    return out


EXPECTED_CASCADES = {
    "REQ-ID-001-SUB-05": ["REQ-RPT-001-SUB-04"],
    "REQ-REF-001-SUB-02": ["REQ-CHR-001-SUB-02", "REQ-CUST-001-SUB-02", "REQ-LIFE-001-SUB-01", "REQ-RPT-001-SUB-04"],
    "REQ-REF-001-SUB-03": ["REQ-AUTH-001-SUB-01", "REQ-RPT-001-SUB-04"],
    "REQ-REF-001-SUB-04": ["REQ-RPT-001-SUB-03", "REQ-RPT-001-SUB-04"],
    "REQ-REF-001-SUB-05": ["REQ-CHR-001-SUB-03", "REQ-LIFE-001-SUB-05", "REQ-RPT-001-SUB-04"],
    "REQ-ART-001-SUB-01": ["REQ-ART-001-SUB-02", "REQ-ART-001-SUB-03", "REQ-RPT-001-SUB-04"],
    "REQ-CUST-001-SUB-04": ["REQ-CUST-001-SUB-02", "REQ-RPT-001-SUB-04"],
    "REQ-CHR-001-SUB-02": ["REQ-LIFE-001-SUB-03", "REQ-RPT-001-SUB-04"],
    "REQ-HASH-001-SUB-04": ["REQ-REF-001-SUB-05", "REQ-RPT-001-SUB-04"],
    "REQ-AUTH-001-SUB-01": ["REQ-REF-001-SUB-03", "REQ-RPT-001-SUB-04"],
    "REQ-LIFE-001-SUB-01": ["REQ-CHR-001-SUB-02", "REQ-LIFE-001-SUB-02", "REQ-RPT-001-SUB-04"],
    "REQ-LIFE-001-SUB-03": ["REQ-CHR-001-SUB-02", "REQ-RPT-001-SUB-04"],
    "REQ-RPT-001-SUB-01": ["REQ-ID-001-SUB-05", "REQ-RPT-001-SUB-04"],
    "REQ-RPT-001-SUB-02": ["REQ-ID-001-SUB-05", "REQ-RPT-001-SUB-04"],
    "REQ-RPT-001-SUB-03": ["REQ-REF-001-SUB-04", "REQ-RPT-001-SUB-04"],
    "REQ-RPT-001-SUB-04": ["REQ-HASH-001-SUB-02"],
}
for _child in CHILD_IDS:
    if PARENTS[_child] != "ReportTraceability":
        EXPECTED_CASCADES.setdefault(_child, []).append("REQ-RPT-001-SUB-04")
        EXPECTED_CASCADES[_child] = sorted(set(EXPECTED_CASCADES[_child]))


def mutation_specs() -> list[dict[str, Any]]:
    return [{
        "mutation_id": f"SUBMUT-{index:03d}", "sub_obligation_id": child,
        "parent_requirement": PARENTS[child],
        "declarative_transformation": f"Targeted transformation for {DESCRIPTIONS[child]}",
        "expected_direct_violation": child,
        "known_expected_cascades": EXPECTED_CASCADES.get(child, []),
        "scientific_rationale": (
            "Controlled content perturbation targeting the exact declared child; any coupled "
            "failures are measured rather than suppressed."
        ),
    } for index, child in enumerate(CHILD_IDS, 1)]


def build_benchmark(*, invalid_per_child: int = 3, valid_traces: int = 35,
                    seed: int = SEED, root: Path = ROOT) -> dict[str, Any]:
    if invalid_per_child < 3 or valid_traces < 35:
        raise ValueError("At least 3 invalid cases per child and 35 valid traces are required")
    records = usable_manifest_records(read_json(DEFAULT_MANIFEST))
    private, blinded, manifests = root / "private", root / "blinded", root / "manifests"
    for directory in (private, blinded, manifests, SPEC_PATH.parent): directory.mkdir(parents=True, exist_ok=True)
    for path in blinded.glob("*.json"): path.unlink()
    specs = mutation_specs(); SPEC_PATH.write_text(yaml.safe_dump({"mutations": specs}, sort_keys=False), encoding="utf-8")
    baselines = []
    for index in range(valid_traces):
        raw = scalability_trace(records[index % len(records)], 20, variant_index=index, seed=seed + index)
        raw["trace_id"] = f"PRIVATE-SUB-VALID-{index + 1:03d}"; raw["case_id"] = f"PRIVATE-SUB-CASE-{index + 1:03d}"
        for evidence in raw["evidence"]: evidence["case_id"] = raw["case_id"]
        baselines.append(raw)
    authored: list[tuple[dict, dict]] = [(raw, {
        "expected_label": "valid", "target_sub_obligation": None, "mutation_id": None,
    }) for raw in baselines]
    serial = 0
    for child in CHILD_IDS:
        for repeat in range(invalid_per_child):
            serial += 1; raw = mutate(baselines[(serial - 1) % len(baselines)], child, serial)
            raw["trace_id"] = f"PRIVATE-SUB-INVALID-{serial:03d}"
            authored.append((raw, {
                "expected_label": "invalid", "target_sub_obligation": child,
                "mutation_id": f"SUBMUT-{CHILD_IDS.index(child) + 1:03d}",
            }))
    rng = random.Random(seed); rng.shuffle(authored); mapping = {}
    for index, (raw, metadata) in enumerate(authored, 1):
        blinded_id = f"SC-{index:04d}-{rng.getrandbits(56):014x}"
        payload = {k: v for k, v in raw.items() if k not in {"expected_label", "evaluation_metadata"}}
        payload["trace_id"] = blinded_id; payload = ValidationTrace.model_validate(payload).model_dump()
        write_json(blinded / f"case-{index:04d}.json", payload); mapping[blinded_id] = metadata
    write_json(private / "labels.json", {"seed": seed, "mapping": mapping})
    build = {"seed": seed, "valid_traces": valid_traces,
             "invalid_traces": len(CHILD_IDS) * invalid_per_child,
             "total_traces": len(authored), "invalid_per_sub_obligation": invalid_per_child}
    write_json(manifests / "build_manifest.json", build); return build


def freeze_benchmark(root: Path = ROOT) -> dict[str, Any]:
    paths = sorted((root / "blinded").glob("*.json")) + [root / "private" / "labels.json", SPEC_PATH]
    combined = hashlib.sha256(); files = []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
        files.append({"path": relative, "sha256": digest}); combined.update(relative.encode() + b"\0" + bytes.fromhex(digest))
    lock = {"created_at_utc": utc_now(), "files": files, "benchmark_sha256": combined.hexdigest()}
    write_json(root / "manifests" / "benchmark_lock.json", lock); return lock


def verify_lock(root: Path = ROOT) -> tuple[bool, list[str]]:
    lock_path = root / "manifests" / "benchmark_lock.json"
    if not lock_path.is_file(): return False, ["benchmark lock missing"]
    lock = read_json(lock_path); combined = hashlib.sha256(); errors = []
    for item in lock["files"]:
        path = PROJECT_ROOT / item["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        if digest != item["sha256"]: errors.append(f"changed or missing: {item['path']}")
        if digest: combined.update(item["path"].encode() + b"\0" + bytes.fromhex(digest))
    if combined.hexdigest() != lock["benchmark_sha256"]: errors.append("combined digest mismatch")
    return not errors, errors


def audit_isolation(root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mapping = read_json(root / "private" / "labels.json")["mapping"]
    rows = []
    for path in sorted((root / "blinded").glob("*.json")):
        raw = read_json(path); metadata = mapping[raw["trace_id"]]
        target = metadata.get("target_sub_obligation")
        if not target: continue
        failed = {child for child, passed in evaluate_children(ValidationTrace.model_validate(raw)).items() if not passed}
        expected = set(EXPECTED_CASCADES.get(target, [])); unexpected = failed - {target} - expected
        rows.append({
            "mutation_id": metadata["mutation_id"], "sub_obligation_id": target,
            "parent_requirement": PARENTS[target], "intended_direct_failure": target,
            "observed_direct_failures": ";".join(sorted(failed)),
            "unexpected_direct_failures": ";".join(sorted(unexpected)),
            "expected_cascades": ";".join(sorted(expected)),
            "observed_cascades": ";".join(sorted(failed - {target})),
            "is_isolated": target in failed and not unexpected,
            "notes": "Coupling is retained and reported." if failed - {target} else "Target-only failure.",
        })
    out = PROJECT_ROOT / "results" / "sub_obligation_mutation_isolation.csv"; out.parent.mkdir(exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    summary = {"mutation_case_count": len(rows), "isolated_mutation_count": sum(r["is_isolated"] for r in rows),
               "coupled_mutation_count": sum(not r["is_isolated"] for r in rows),
               "unexpected_direct_failure_count": sum(bool(r["unexpected_direct_failures"]) for r in rows)}
    write_json(PROJECT_ROOT / "results" / "sub_obligation_mutation_isolation_summary.json", summary)
    return rows, summary
