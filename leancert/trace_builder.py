from __future__ import annotations

import copy
import hashlib
import random
from pathlib import Path

from .datasets import DEFAULT_MANIFEST, register_unlisted_local_artifacts, usable_manifest_records
from .utils import PROJECT_ROOT, read_json, safe_filename, slugify, write_json


def _deterministic_id(source: str, artifact: str) -> str:
    digest = hashlib.sha256(f"{source}\0{artifact}".encode("utf-8")).hexdigest()[:12].upper()
    return digest


def baseline_trace(record: dict) -> dict:
    sha = str(record["sha256"]).lower()
    evidence_id = f"EVD-{sha[:12]}"
    suffix = _deterministic_id(record["source_name"], record["artifact_name"])
    case_id = f"CASE-PUBLIC-{suffix}"
    trace_id = f"TRACE-PUBLIC-{suffix}-VALID"
    registered_hash = f"sha256:{sha}"
    actors = [
        {"actor_id": "INV-001", "name": "Dataset Acquisition Investigator", "role": "investigator"},
        {"actor_id": "CUS-001", "name": "Evidence Custodian", "role": "custodian"},
        {"actor_id": "ANA-001", "name": "Forensic Analyst", "role": "analyst"},
        {"actor_id": "SUP-001", "name": "Supervising Reviewer", "role": "supervisor"},
    ]
    kind = record.get("artifact_kind", "unknown_public_artifact")
    base_evidence = {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "kind": kind,
        "source": f"{record['source_name']} {record['artifact_name']}",
        "hash": registered_hash,
        "size_bytes": int(record["size_bytes"]),
        "parent_evidence_id": None,
        "artifact_path": record["local_path"],
        "dataset_source": record["source_name"],
    }
    evidence = [base_evidence]
    events: list[dict] = []
    holders: dict[str, str | None] = {}
    hashes: dict[str, str | None] = {}

    def add_event(
        evidence_ref: str, action: str, actor_id: str, timestamp: int,
        *, new_holder: str | None = None, first_prev_hash: str = "GENESIS",
    ) -> None:
        previous_holder = holders.get(evidence_ref)
        assigned_holder = new_holder if new_holder is not None else previous_holder
        previous_hash = hashes.get(evidence_ref) or first_prev_hash
        events.append({
            "event_id": f"EVT-{len(events) + 1:03d}",
            "evidence_id": evidence_ref, "actor_id": actor_id, "action": action,
            "timestamp": timestamp, "prev_holder": previous_holder,
            "new_holder": assigned_holder, "prev_hash": previous_hash,
            "curr_hash": registered_hash, "hash_change_allowed": False,
        })
        holders[evidence_ref] = assigned_holder
        hashes[evidence_ref] = registered_hash

    if kind == "derived_artifact":
        parent_id = f"{evidence_id}-PARENT"
        parent = copy.deepcopy(base_evidence)
        parent.update({
            "evidence_id": parent_id, "kind": "unknown_public_artifact",
            "source": f"Registered parent for {record['artifact_name']}",
        })
        base_evidence["parent_evidence_id"] = parent_id
        evidence = [parent, base_evidence]
        add_event(parent_id, "acquire", "INV-001", 100, new_holder="INV-001")
        add_event(parent_id, "preserve", "CUS-001", 120, new_holder="CUS-001")
        add_event(parent_id, "analyze", "ANA-001", 140)
        add_event(evidence_id, "derive", "ANA-001", 160, new_holder="ANA-001",
                  first_prev_hash=registered_hash)
        add_event(evidence_id, "examine", "ANA-001", 180)
        add_event(evidence_id, "report", "SUP-001", 200)
        claim_evidence_id = evidence_id
    else:
        add_event(evidence_id, "acquire", "INV-001", 100, new_holder="INV-001")
        add_event(evidence_id, "preserve", "CUS-001", 120, new_holder="CUS-001")
        if kind == "network_capture":
            add_event(evidence_id, "transfer", "CUS-001", 140, new_holder="CUS-001")
            add_event(evidence_id, "examine", "ANA-001", 160)
            add_event(evidence_id, "analyze", "ANA-001", 180)
            add_event(evidence_id, "report", "SUP-001", 200)
        elif kind == "disk_image":
            add_event(evidence_id, "transfer", "CUS-001", 140, new_holder="CUS-001")
            add_event(evidence_id, "examine", "ANA-001", 160)
            add_event(evidence_id, "analyze", "ANA-001", 180)
            child_id = f"{evidence_id}-DERIVED"
            child = copy.deepcopy(base_evidence)
            child.update({
                "evidence_id": child_id, "kind": "derived_artifact",
                "source": f"Controlled derivative registration for {record['artifact_name']}",
                "parent_evidence_id": evidence_id,
            })
            evidence.append(child)
            add_event(child_id, "derive", "ANA-001", 200, new_holder="ANA-001",
                      first_prev_hash=registered_hash)
            add_event(evidence_id, "report", "SUP-001", 220)
            add_event(evidence_id, "archive", "CUS-001", 240)
        elif kind == "memory_dump":
            add_event(evidence_id, "examine", "ANA-001", 140)
            add_event(evidence_id, "analyze", "ANA-001", 160)
            add_event(evidence_id, "report", "SUP-001", 180)
        else:
            add_event(evidence_id, "examine", "ANA-001", 140)
            add_event(evidence_id, "report", "SUP-001", 160)
        claim_evidence_id = evidence_id
    return {
        "case_id": case_id,
        "trace_id": trace_id,
        "expected_label": "valid",
        "dataset_origin": {
            "source_name": record["source_name"],
            "artifact_name": record["artifact_name"],
            "source_url": record.get("source_url", ""),
            "local_path": record["local_path"],
            "sha256": sha,
            "size_bytes": int(record["size_bytes"]),
            "retrieved_at_utc": record.get("retrieved_at_utc", ""),
        },
        "evaluation_metadata": {
            "scenario": "Valid public forensic artifact lifecycle",
            "injected_violation": "None",
            "expected_outcome": "PASSED",
            "target_requirement": "All requirements",
        },
        "evidence": evidence,
        "actors": actors,
        "events": events,
        "report_claims": [{
            "claim_id": "CLM-001",
            "text": "The public forensic artifact was acquired, preserved, analyzed, and reported.",
            "supporting_evidence_ids": [claim_evidence_id],
        }],
    }


def invalid_variants(base: dict, mode: str = "standard") -> list[dict]:
    variants: list[dict] = []

    def variant(name: str, requirement: str, description: str) -> dict:
        item = copy.deepcopy(base)
        item["trace_id"] = base["trace_id"].removesuffix("-VALID") + f"-{name.upper()}"
        item["expected_label"] = "invalid"
        item["evaluation_metadata"] = {
            "scenario": name.replace("_", " ").title(),
            "injected_violation": description,
            "expected_outcome": "FAILED",
            "target_requirement": requirement,
        }
        variants.append(item)
        return item

    variant("missing_identity", "IdentityCompleteness", "Removed an actor name.")["actors"][0]["name"] = ""
    broken_reference = variant(
        "broken_reference", "ReferentialIntegrity", "Changed an event to reference missing evidence."
    )
    broken_reference["events"][-1]["evidence_id"] = "EVD-NONEXISTENT"
    variant("broken_custody", "CustodyContinuity", "Changed a previous holder to the wrong actor.")[
        "events"][1]["prev_holder"] = "SUP-001"
    variant("timestamp_rollback", "ChronologicalConsistency", "Rolled an analysis timestamp backward.")[
        "events"][2]["timestamp"] = 90
    variant("hash_discontinuity", "HashContinuity", "Changed an event previous hash.")[
        "events"][1]["prev_hash"] = "sha256:" + ("0" * 64)
    unauthorized = variant(
        "unauthorized_handling", "AuthorizedHandling",
        "Assigned preservation or transfer handling to an analyst.",
    )
    unauthorized_event = next(
        (event for event in unauthorized["events"] if event["action"] == "transfer"),
        next(event for event in unauthorized["events"] if event["action"] == "preserve"),
    )
    unauthorized_event["actor_id"] = "ANA-001"
    lifecycle = variant(
        "lifecycle_violation", "LifecycleCorrectness",
        "Moved reporting before its analysis or examination prerequisite.",
    )
    report_event = next(event for event in lifecycle["events"] if event["action"] == "report")
    report_event["timestamp"] = 110
    variant("unsupported_report_claim", "ReportTraceability", "Referenced nonexistent evidence in a report claim.")[
        "report_claims"][0]["supporting_evidence_ids"] = ["EVD-NONEXISTENT"]
    mismatch = variant(
        "artifact_hash_mismatch", "PublicArtifactIntegrity", "Registered a controlled incorrect artifact hash."
    )
    wrong = "sha256:" + ("f" * 64)
    mismatch["evidence"][0]["hash"] = wrong
    for index, event in enumerate(mismatch["events"]):
        event["curr_hash"] = wrong
        if event["prev_hash"] != "GENESIS":
            event["prev_hash"] = wrong
    custody_authorization = variant(
        "custody_authorization", "CustodyContinuity;AuthorizedHandling",
        "Combined controlled custody-continuity and authorization violations.",
    )
    custody_authorization["events"][1]["prev_holder"] = "SUP-001"
    custody_authorization["events"][1]["actor_id"] = "ANA-001"
    hash_chronology = variant(
        "hash_chronology", "HashContinuity;ChronologicalConsistency",
        "Combined controlled hash-link and timestamp rollback violations.",
    )
    hash_chronology["events"][1]["prev_hash"] = "BROKEN"
    hash_chronology["events"][2]["timestamp"] = 90
    lifecycle_report = variant(
        "lifecycle_report_traceability", "LifecycleCorrectness;ReportTraceability",
        "Combined controlled lifecycle-order and unsupported-claim violations.",
    )
    next(event for event in lifecycle_report["events"] if event["action"] == "report")[
        "timestamp"
    ] = 110
    lifecycle_report["report_claims"][0]["supporting_evidence_ids"] = ["EVD-NONEXISTENT"]
    full_multi = variant(
        "multi_violation", "Multiple requirements",
        "Combined controlled identity, custody, and hash-chain violations.",
    )
    full_multi["actors"][0]["name"] = ""
    full_multi["events"][1]["prev_holder"] = "SUP-001"
    full_multi["events"][1]["prev_hash"] = "BROKEN"
    if mode == "minimal":
        return variants[:1] + variants[4:5] + variants[8:9]
    if mode == "standard":
        return variants[:-1]
    if mode == "full":
        return variants
    raise ValueError(f"Unknown variant mode: {mode}")


def build_traces_from_manifest(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    valid_dir: Path = PROJECT_ROOT / "traces" / "public_valid",
    invalid_dir: Path = PROJECT_ROOT / "traces" / "public_invalid",
    force: bool = False,
    variants: str = "standard",
) -> list[Path]:
    if not manifest_path.is_file():
        return []
    all_records = register_unlisted_local_artifacts(
        read_json(manifest_path), manifest_path=manifest_path
    )
    records = usable_manifest_records(all_records)
    if not records:
        return []
    valid_dir.mkdir(parents=True, exist_ok=True)
    invalid_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    desired: set[Path] = set()
    for record in records:
        base = baseline_trace(record)
        items = [
            (base, valid_dir),
            *((item, invalid_dir) for item in invalid_variants(base, variants)),
        ]
        for trace, directory in items:
            filename = safe_filename(f"{trace['trace_id'].lower()}.json")
            path = directory / filename
            desired.add(path.resolve())
            if path.exists() and not force:
                continue
            write_json(path, trace)
            written.append(path)
    if force:
        for directory in (valid_dir, invalid_dir):
            for path in directory.glob("trace-public-*.json"):
                if path.resolve() not in desired:
                    path.unlink()
    return written


def scalability_trace(
    record: dict, event_count: int, *, variant_index: int = 0, seed: int = 20260726
) -> dict:
    if event_count < 4:
        raise ValueError("Scalability traces require at least four meaningful events.")
    trace = baseline_trace(record)
    rng = random.Random(seed + variant_index + (event_count * 1000))
    trace["trace_id"] = f"TRACE-SCALABILITY-{event_count:03d}-{variant_index + 1:02d}"
    trace["case_id"] = f"CASE-SCALABILITY-{event_count:03d}-{variant_index + 1:02d}"
    trace["expected_label"] = "valid"
    trace["evaluation_metadata"] = {
        "scenario": f"Valid scalability trace with {event_count} forensic events",
        "injected_violation": "None",
        "expected_outcome": "PASSED",
        "target_requirement": "All requirements",
    }
    evidence = copy.deepcopy(trace["evidence"][0])
    evidence["case_id"] = trace["case_id"]
    evidence["kind"] = "disk_image"
    evidence["parent_evidence_id"] = None
    trace["evidence"] = [evidence]
    trace["report_claims"][0]["supporting_evidence_ids"] = [evidence["evidence_id"]]
    registered_hash = evidence["hash"]
    middle_templates = [
        ["examine", "analyze", "preserve", "transfer"],
        ["transfer", "examine", "preserve", "analyze"],
        ["analyze", "examine", "transfer", "preserve"],
        ["preserve", "analyze", "transfer", "examine"],
    ]
    middle_actions = middle_templates[variant_index % len(middle_templates)]
    archival = event_count >= 5 and variant_index % 3 == 0
    fixed_tail = ["analyze", "report", "archive"] if archival else ["analyze", "report"]
    actions = ["acquire", "preserve"]
    actions.extend(
        middle_actions[(index + variant_index) % len(middle_actions)]
        for index in range(event_count - len(actions) - len(fixed_tail))
    )
    actions.extend(fixed_tail)
    actor_for = {
        "acquire": "INV-001",
        "preserve": "CUS-001",
        "transfer": "CUS-001",
        "examine": "ANA-001",
        "analyze": "ANA-001",
        "report": "SUP-001",
        "archive": "CUS-001",
    }
    holder: str | None = None
    events = []
    # A distinct spacing per variant makes structural diversity auditable.
    spacing = 6 + variant_index
    timestamp_origin = 100 + rng.randrange(0, 25)
    for index, action in enumerate(actions):
        new_holder = holder
        if action == "acquire":
            new_holder = "INV-001"
        elif action in {"preserve", "transfer"}:
            new_holder = "CUS-001"
        events.append({
            "event_id": f"EVT-{index + 1:03d}",
            "evidence_id": evidence["evidence_id"],
            "actor_id": actor_for[action],
            "action": action,
            "timestamp": timestamp_origin + (index * spacing),
            "prev_holder": holder,
            "new_holder": new_holder,
            "prev_hash": "GENESIS" if index == 0 else registered_hash,
            "curr_hash": registered_hash,
            "hash_change_allowed": False,
        })
        holder = new_holder
    trace["events"] = events
    for extra in range(variant_index % 3):
        trace["actors"].append({
            "actor_id": f"REV-{variant_index:02d}-{extra:02d}",
            "name": f"Unused independent reviewer {variant_index}-{extra}",
            "role": "external_reviewer",
        })
    trace["report_claims"] = [
        {
            "claim_id": f"CLM-{index + 1:03d}",
            "text": f"Scalability workflow observation {index + 1}.",
            "supporting_evidence_ids": [evidence["evidence_id"]],
        }
        for index in range(1 + (variant_index % 3))
    ]
    return trace


def build_scalability_traces(
    sizes: list[int],
    *,
    traces_per_size: int = 15,
    seed: int = 20260726,
    manifest_path: Path = DEFAULT_MANIFEST,
    output_dir: Path = PROJECT_ROOT / "traces" / "scalability",
) -> list[Path]:
    records = usable_manifest_records(read_json(manifest_path)) if manifest_path.is_file() else []
    if not records:
        return []
    # Prefer a registered disk image, while remaining deterministic if none is available.
    records.sort(key=lambda item: (
        item.get("artifact_kind") != "disk_image",
        item.get("source_name") != "NIST CFReDS",
        str(item.get("artifact_name", "")),
    ))
    if traces_per_size < 1:
        raise ValueError("traces_per_size must be at least one")
    output_dir.mkdir(parents=True, exist_ok=True)
    desired = set()
    written = []
    for size in sorted(set(sizes)):
        size_dir = output_dir / str(size)
        size_dir.mkdir(parents=True, exist_ok=True)
        for index in range(traces_per_size):
            record = records[index % len(records)]
            trace = scalability_trace(record, size, variant_index=index, seed=seed + index)
            path = size_dir / f"trace-scalability-{size:03d}-{index + 1:02d}.json"
            write_json(path, trace)
            desired.add(path.resolve())
            written.append(path)
    for stale in output_dir.rglob("trace-scalability-*.json"):
        if stale.resolve() not in desired:
            stale.unlink()
    return written
