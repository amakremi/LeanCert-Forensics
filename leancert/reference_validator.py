from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from .schema import ValidationTrace
from .utils import PROJECT_ROOT

SUBSET = [
    "IdentityCompleteness", "ReferentialIntegrity", "PublicArtifactIntegrity",
    "CustodyContinuity", "ChronologicalConsistency", "HashContinuity",
    "AuthorizedHandling", "LifecycleCorrectness", "ReportTraceability",
]

ALLOWED_PAIRS = {
    ("investigator", "acquire"), ("investigator", "examine"),
    ("custodian", "preserve"), ("custodian", "transfer"), ("custodian", "archive"),
    ("analyst", "examine"), ("analyst", "analyze"), ("analyst", "derive"),
    ("supervisor", "report"), ("supervisor", "archive"),
    ("external_reviewer", "examine"),
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sequence(event: object) -> tuple[int, str]:
    event_id = str(getattr(event, "event_id", ""))
    match = re.search(r"(\d+)$", event_id)
    return (int(match.group(1)) if match else 2**63 - 1, event_id)


def reference_validate(trace: ValidationTrace) -> dict[str, bool]:
    """Independent relational/state implementation of all catalogue requirements."""
    evidence_ids = [item.evidence_id for item in trace.evidence]
    actor_ids = [item.actor_id for item in trace.actors]
    event_ids = [item.event_id for item in trace.events]
    claim_ids = [item.claim_id for item in trace.report_claims]
    evidence_set, actor_set = set(evidence_ids), set(actor_ids)
    required_strings = [trace.case_id, trace.trace_id]
    required_strings += [
        value for item in trace.evidence for value in (
            item.evidence_id, item.case_id, item.kind, item.source, item.hash,
            item.artifact_path, item.dataset_source,
        )
    ]
    required_strings += [
        value for item in trace.actors for value in (item.actor_id, item.name, item.role)
    ]
    required_strings += [
        value for item in trace.events for value in (
            item.event_id, item.evidence_id, item.actor_id, item.action, item.curr_hash,
        )
    ]
    identity = all(str(value).strip() for value in required_strings) and all(
        claim.claim_id.strip() and claim.text.strip() and claim.supporting_evidence_ids
        for claim in trace.report_claims
    )
    references = (
        all(len(values) == len(set(values)) for values in (
            evidence_ids, actor_ids, event_ids, claim_ids,
        ))
        and all(event.evidence_id in evidence_set and event.actor_id in actor_set for event in trace.events)
        and all(set(claim.supporting_evidence_ids) <= evidence_set for claim in trace.report_claims)
        and all(
            item.kind != "derived_artifact"
            or bool(item.parent_evidence_id and item.parent_evidence_id in evidence_set)
            for item in trace.evidence
        )
    )
    artifact_integrity = True
    for index, evidence in enumerate(trace.evidence):
        if not evidence.artifact_path:
            continue
        candidate = Path(evidence.artifact_path)
        path = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        if not path.is_file():
            artifact_integrity = False
            continue
        computed = _file_sha256(path)
        artifact_integrity = artifact_integrity and (
            computed.casefold() == evidence.hash.removeprefix("sha256:").casefold()
            and path.stat().st_size == evidence.size_bytes
        )
        if index == 0 and trace.dataset_origin.sha256:
            artifact_integrity = artifact_integrity and (
                computed.casefold() == trace.dataset_origin.sha256.removeprefix("sha256:").casefold()
            )

    grouped: dict[str, list] = defaultdict(list)
    for event in trace.events:
        grouped[event.evidence_id].append(event)
    custody = True
    for events in grouped.values():
        holder = None
        for index, event in enumerate(sorted(events, key=lambda item: item.timestamp)):
            if index == 0 and event.action == "acquire":
                custody = custody and event.prev_holder is None
            else:
                custody = custody and event.prev_holder == holder
            if event.action in {"transfer", "preserve"}:
                custody = custody and bool(event.new_holder)
            if event.new_holder is not None:
                holder = event.new_holder

    chronology = all(event.timestamp >= 0 for event in trace.events)
    for evidence_id, events in grouped.items():
        ordered = sorted(events, key=_sequence)
        chronology = chronology and all(
            left.timestamp <= right.timestamp for left, right in zip(ordered, ordered[1:])
        )
        action_times: dict[str, list[int]] = defaultdict(list)
        for event in events:
            action_times[event.action].append(event.timestamp)
        evidence = next((item for item in trace.evidence if item.evidence_id == evidence_id), None)
        prerequisites = ["derive", "examine"] if evidence and evidence.kind == "derived_artifact" else [
            "acquire", "preserve",
            "examine" if evidence and evidence.kind in {"log_file", "report", "unknown_public_artifact"}
            else "analyze",
        ]
        chronology = chronology and all(
            action_times[required] and min(action_times[required]) <= report_time
            for report_time in action_times["report"] for required in prerequisites
        )
    parent_events = {
        evidence_id: sorted(events, key=lambda event: event.timestamp)
        for evidence_id, events in grouped.items()
    }
    for item in trace.evidence:
        if item.kind == "derived_artifact" and item.parent_evidence_id:
            derives = [e.timestamp for e in grouped.get(item.evidence_id, []) if e.action == "derive"]
            acquires = [
                e.timestamp for e in parent_events.get(item.parent_evidence_id, []) if e.action == "acquire"
            ]
            chronology = chronology and not (
                derives and (not acquires or min(derives) < min(acquires))
            )

    evidence_map = {item.evidence_id: item for item in trace.evidence}
    hashes = True
    for evidence_id, events in grouped.items():
        ordered = sorted(events, key=lambda event: event.timestamp)
        for index, event in enumerate(ordered):
            if index == 0 and event.action == "acquire":
                hashes = hashes and event.prev_hash == "GENESIS"
            elif index:
                previous = ordered[index - 1]
                hashes = hashes and event.prev_hash == previous.curr_hash
                if event.action != "derive" and not event.hash_change_allowed:
                    hashes = hashes and event.curr_hash == previous.curr_hash
            if event.action == "derive":
                hashes = hashes and bool(
                    evidence_map.get(evidence_id) and evidence_map[evidence_id].parent_evidence_id
                )
    roles = {actor.actor_id: actor.role for actor in trace.actors}
    authorization = all(
        event.actor_id not in roles or (roles[event.actor_id], event.action) in ALLOWED_PAIRS
        for event in trace.events
    )

    lifecycle = True
    for evidence_id, events in grouped.items():
        times: dict[str, list[int]] = defaultdict(list)
        for event in events:
            times[event.action].append(event.timestamp)
        evidence = evidence_map.get(evidence_id)
        pairs = []
        if evidence and evidence.kind == "derived_artifact":
            pairs.extend((("examine", "derive"), ("analyze", "derive"), ("report", "examine")))
        else:
            pairs.extend((("preserve", "acquire"), ("transfer", "acquire"),
                          ("examine", "preserve"), ("analyze", "preserve")))
            prerequisite = "examine" if evidence and evidence.kind in {
                "log_file", "report", "unknown_public_artifact"
            } else "analyze"
            pairs.append(("report", prerequisite))
        pairs.append(("archive", "report"))
        lifecycle = lifecycle and all(
            all(times[before] and min(times[before]) <= when for when in times[action])
            for action, before in pairs
        )
    for item in trace.evidence:
        if item.kind == "derived_artifact" and item.parent_evidence_id:
            parent_actions = {e.action for e in grouped.get(item.parent_evidence_id, [])}
            lifecycle = lifecycle and {"acquire", "analyze"} <= parent_actions

    core = [identity, references, artifact_integrity, custody, chronology, hashes, authorization, lifecycle]
    claims_intrinsic = all(
        claim.text.strip() and claim.supporting_evidence_ids
        and set(claim.supporting_evidence_ids) <= evidence_set
        for claim in trace.report_claims
    )
    report_traceability = claims_intrinsic and all(core)
    return dict(zip(SUBSET, [*core, report_traceability]))
