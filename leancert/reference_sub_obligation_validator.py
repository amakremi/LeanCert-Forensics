"""Independent child-level oracle used only for differential evaluation.

This module deliberately does not import the production validator, child predicates,
permission table, or mutation machinery.  It expresses the catalogue as relations over
the trace model.  The classifications below disclose where an independent implementation
still necessarily shares the declared policy or the same filesystem/hash primitives.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from .schema import ValidationTrace
from .utils import PROJECT_ROOT

CHILD_IDS = [
    *(f"REQ-ID-001-SUB-{i:02d}" for i in range(1, 6)),
    *(f"REQ-REF-001-SUB-{i:02d}" for i in range(1, 6)),
    *(f"REQ-ART-001-SUB-{i:02d}" for i in range(1, 4)),
    *(f"REQ-CUST-001-SUB-{i:02d}" for i in range(1, 5)),
    *(f"REQ-CHR-001-SUB-{i:02d}" for i in range(1, 4)),
    *(f"REQ-HASH-001-SUB-{i:02d}" for i in range(1, 5)),
    *(f"REQ-AUTH-001-SUB-{i:02d}" for i in range(1, 3)),
    *(f"REQ-LIFE-001-SUB-{i:02d}" for i in range(1, 6)),
    *(f"REQ-RPT-001-SUB-{i:02d}" for i in range(1, 5)),
]

INDEPENDENCE = {child: "STRUCTURALLY_INDEPENDENT" for child in CHILD_IDS}
for _child in (
    "REQ-ART-001-SUB-01", "REQ-ART-001-SUB-02", "REQ-ART-001-SUB-03",
    "REQ-AUTH-001-SUB-02", "REQ-RPT-001-SUB-04",
):
    INDEPENDENCE[_child] = "LIMITED"


def _path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@lru_cache(maxsize=64)
def _digest(path_text: str, size: int, modified_ns: int) -> str:
    digest = hashlib.sha256()
    with Path(path_text).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _number(event_id: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", event_id)
    return (int(match.group(1)) if match else 2**63 - 1, event_id)


def _earlier(actions: dict[str, list[int]], action: str, prerequisite: str) -> bool:
    return all(bool(actions[prerequisite]) and min(actions[prerequisite]) <= time
               for time in actions[action])


def evaluate_reference_children(trace: ValidationTrace) -> dict[str, bool]:
    """Evaluate all declared children without calling any production predicate."""
    answer: dict[str, bool] = {}
    evidence_ids = [item.evidence_id for item in trace.evidence]
    actor_ids = [item.actor_id for item in trace.actors]
    event_ids = [item.event_id for item in trace.events]
    claim_ids = [item.claim_id for item in trace.report_claims]
    evidence_set, actor_set = set(evidence_ids), set(actor_ids)

    answer.update({
        "REQ-ID-001-SUB-01": all(map(bool, (trace.case_id.strip(), trace.trace_id.strip()))),
        "REQ-ID-001-SUB-02": all(
            all(str(value).strip() for value in (
                item.evidence_id, item.case_id, item.kind, item.source, item.hash,
                item.artifact_path, item.dataset_source,
            )) for item in trace.evidence
        ),
        "REQ-ID-001-SUB-03": all(
            item.actor_id.strip() and item.name.strip() and item.role.strip()
            for item in trace.actors
        ),
        "REQ-ID-001-SUB-04": all(
            item.event_id.strip() and item.evidence_id.strip() and item.actor_id.strip()
            and item.action.strip() and item.curr_hash.strip() for item in trace.events
        ),
        "REQ-ID-001-SUB-05": all(
            item.claim_id.strip() and item.text.strip() and item.supporting_evidence_ids
            for item in trace.report_claims
        ),
        "REQ-REF-001-SUB-01": all(
            len(values) == len(set(values))
            for values in (evidence_ids, actor_ids, event_ids, claim_ids)
        ),
        "REQ-REF-001-SUB-02": not any(e.evidence_id not in evidence_set for e in trace.events),
        "REQ-REF-001-SUB-03": not any(e.actor_id not in actor_set for e in trace.events),
        "REQ-REF-001-SUB-04": not any(
            support not in evidence_set for claim in trace.report_claims
            for support in claim.supporting_evidence_ids
        ),
        "REQ-REF-001-SUB-05": not any(
            item.kind == "derived_artifact"
            and (not item.parent_evidence_id or item.parent_evidence_id not in evidence_set)
            for item in trace.evidence
        ),
    })

    available = hash_matches = size_matches = True
    for index, item in enumerate(trace.evidence):
        if not item.artifact_path:
            continue
        path = _path(item.artifact_path)
        exists = path.is_file()
        available = available and exists
        if not exists:
            hash_matches = size_matches = False
            continue
        stat = path.stat()
        digest = _digest(str(path.resolve()), stat.st_size, stat.st_mtime_ns).casefold()
        hash_matches = hash_matches and digest == item.hash.removeprefix("sha256:").casefold()
        if index == 0 and trace.dataset_origin.sha256:
            hash_matches = hash_matches and digest == trace.dataset_origin.sha256.removeprefix("sha256:").casefold()
        size_matches = size_matches and stat.st_size == item.size_bytes
    answer.update({
        "REQ-ART-001-SUB-01": available,
        "REQ-ART-001-SUB-02": hash_matches,
        "REQ-ART-001-SUB-03": size_matches,
    })

    by_evidence: dict[str, list] = defaultdict(list)
    for event in trace.events:
        by_evidence[event.evidence_id].append(event)
    origin = continuity = transfer = preservation = True
    for events in by_evidence.values():
        ordered = sorted(events, key=lambda event: event.timestamp)
        current = None
        for index, event in enumerate(ordered):
            if index == 0 and event.action == "acquire":
                origin = origin and event.prev_holder is None
            if index > 0 or event.action != "acquire":
                continuity = continuity and event.prev_holder == current
            transfer = transfer and (event.action != "transfer" or bool(event.new_holder))
            preservation = preservation and (event.action != "preserve" or bool(event.new_holder))
            current = event.new_holder if event.new_holder is not None else current
    answer.update({
        "REQ-CUST-001-SUB-01": origin,
        "REQ-CUST-001-SUB-02": continuity,
        "REQ-CUST-001-SUB-03": transfer,
        "REQ-CUST-001-SUB-04": preservation,
    })

    evidence_by_id = {item.evidence_id: item for item in trace.evidence}
    nonnegative_sequence = report_prerequisites = parent_before_derivative = True
    genesis = adjacent = unchanged = derivative_parent = True
    preserve_after = analyze_after = report_after = archive_after = parent_ready = True
    for evidence_id, events in by_evidence.items():
        sequence_order = sorted(events, key=lambda event: _number(event.event_id))
        nonnegative_sequence = nonnegative_sequence and all(e.timestamp >= 0 for e in events)
        nonnegative_sequence = nonnegative_sequence and all(
            left.timestamp <= right.timestamp for left, right in zip(sequence_order, sequence_order[1:])
        )
        chronological = sorted(events, key=lambda event: event.timestamp)
        for index, event in enumerate(chronological):
            if index == 0 and event.action == "acquire":
                genesis = genesis and event.prev_hash == "GENESIS"
            if index:
                previous = chronological[index - 1]
                adjacent = adjacent and event.prev_hash == previous.curr_hash
                if event.action != "derive" and not event.hash_change_allowed:
                    unchanged = unchanged and event.curr_hash == previous.curr_hash
            if event.action == "derive":
                derivative_parent = derivative_parent and bool(
                    evidence_by_id.get(evidence_id) and evidence_by_id[evidence_id].parent_evidence_id
                )
        actions: dict[str, list[int]] = defaultdict(list)
        for event in events:
            actions[event.action].append(event.timestamp)
        evidence = evidence_by_id.get(evidence_id)
        derived_kind = bool(evidence and evidence.kind == "derived_artifact")
        report_needs = ["derive", "examine"] if derived_kind else [
            "acquire", "preserve",
            "examine" if evidence and evidence.kind in {"log_file", "report", "unknown_public_artifact"} else "analyze",
        ]
        report_prerequisites = report_prerequisites and all(
            _earlier(actions, "report", need) for need in report_needs
        )
        if derived_kind:
            analyze_after = analyze_after and _earlier(actions, "examine", "derive") and _earlier(actions, "analyze", "derive")
            report_after = report_after and _earlier(actions, "report", "examine")
        else:
            preserve_after = preserve_after and _earlier(actions, "preserve", "acquire") and _earlier(actions, "transfer", "acquire")
            analyze_after = analyze_after and _earlier(actions, "examine", "preserve") and _earlier(actions, "analyze", "preserve")
            report_need = "examine" if evidence and evidence.kind in {"log_file", "report", "unknown_public_artifact"} else "analyze"
            report_after = report_after and _earlier(actions, "report", report_need)
        archive_after = archive_after and _earlier(actions, "archive", "report")

    for item in trace.evidence:
        if item.kind != "derived_artifact" or not item.parent_evidence_id:
            continue
        child_derives = [e.timestamp for e in by_evidence.get(item.evidence_id, []) if e.action == "derive"]
        parent_acquires = [e.timestamp for e in by_evidence.get(item.parent_evidence_id, []) if e.action == "acquire"]
        parent_before_derivative = parent_before_derivative and (
            not child_derives or bool(parent_acquires and min(parent_acquires) <= min(child_derives))
        )
        parent_actions = {e.action for e in by_evidence.get(item.parent_evidence_id, [])}
        parent_ready = parent_ready and {"acquire", "analyze"} <= parent_actions
    answer.update({
        "REQ-CHR-001-SUB-01": nonnegative_sequence,
        "REQ-CHR-001-SUB-02": report_prerequisites,
        "REQ-CHR-001-SUB-03": parent_before_derivative,
        "REQ-HASH-001-SUB-01": genesis,
        "REQ-HASH-001-SUB-02": adjacent,
        "REQ-HASH-001-SUB-03": unchanged,
        "REQ-HASH-001-SUB-04": derivative_parent,
    })

    declared_roles = {actor.actor_id: actor.role for actor in trace.actors}
    independent_permissions = {
        "investigator": {"acquire", "examine"},
        "custodian": {"preserve", "transfer", "archive"},
        "analyst": {"examine", "analyze", "derive"},
        "supervisor": {"report", "archive"},
        "external_reviewer": {"examine"},
    }
    answer.update({
        "REQ-AUTH-001-SUB-01": all(event.actor_id in declared_roles for event in trace.events),
        "REQ-AUTH-001-SUB-02": all(
            event.actor_id not in declared_roles
            or event.action in independent_permissions.get(declared_roles[event.actor_id], set())
            for event in trace.events
        ),
        "REQ-LIFE-001-SUB-01": preserve_after,
        "REQ-LIFE-001-SUB-02": analyze_after,
        "REQ-LIFE-001-SUB-03": report_after,
        "REQ-LIFE-001-SUB-04": archive_after,
        "REQ-LIFE-001-SUB-05": parent_ready,
        "REQ-RPT-001-SUB-01": all(bool(claim.text.strip()) for claim in trace.report_claims),
        "REQ-RPT-001-SUB-02": all(bool(claim.supporting_evidence_ids) for claim in trace.report_claims),
        "REQ-RPT-001-SUB-03": all(
            all(item in evidence_set for item in claim.supporting_evidence_ids)
            for claim in trace.report_claims
        ),
    })
    answer["REQ-RPT-001-SUB-04"] = all(answer[child] for child in CHILD_IDS[:31])
    return answer
