from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from .schema import ValidationTrace
from .utils import resolve_project_path, sha256_file

PARENTS: dict[str, str] = {}
DESCRIPTIONS: dict[str, str] = {}


def _declare(parent_id: str, parent: str, descriptions: list[str]) -> None:
    for index, description in enumerate(descriptions, 1):
        child = f"{parent_id}-SUB-{index:02d}"
        PARENTS[child] = parent
        DESCRIPTIONS[child] = description


_declare("REQ-ID-001", "IdentityCompleteness", [
    "trace identity", "evidence identity", "actor identity", "event identity", "claim identity",
])
_declare("REQ-REF-001", "ReferentialIntegrity", [
    "unique identifiers", "event evidence reference", "event actor reference",
    "claim support reference", "derived parent reference",
])
_declare("REQ-ART-001", "PublicArtifactIntegrity", [
    "artifact availability", "SHA-256 match", "size match",
])
_declare("REQ-CUST-001", "CustodyContinuity", [
    "acquisition origin", "previous-holder continuity", "transfer assignee", "preservation assignee",
])
_declare("REQ-CHR-001", "ChronologicalConsistency", [
    "non-negative and sequence-monotone timestamps", "report prerequisites", "parent-before-derivative",
])
_declare("REQ-HASH-001", "HashContinuity", [
    "genesis link", "adjacent link", "unauthorized hash change", "derivative parent",
])
_declare("REQ-AUTH-001", "AuthorizedHandling", ["role resolution", "role-action permission"])
_declare("REQ-LIFE-001", "LifecycleCorrectness", [
    "preservation and transfer after acquisition", "examination and analysis after preservation or derivation",
    "reporting after required analysis or examination",
    "archive after report", "derivative parent readiness",
])
_declare("REQ-RPT-001", "ReportTraceability", [
    "claim text", "support presence", "support resolution", "upstream support validity",
])

CHILD_IDS = list(PARENTS)
LEAN_PREDICATES = dict(zip(CHILD_IDS, [
    "TraceIdentityPresent", "EvidenceIdentityPresent", "ActorIdentityPresent",
    "EventIdentityPresent", "ClaimIdentityPresent", "UniqueIdentifiers",
    "EventEvidenceReferenceExists", "EventActorReferenceExists",
    "ClaimSupportReferenceExists", "DerivedParentReferenceExists", "ArtifactAvailable",
    "ArtifactSha256Matches", "ArtifactSizeMatches", "AcquisitionOrigin",
    "PreviousHolderContinuity", "TransferAssignee", "PreservationAssignee",
    "NonnegativeSequenceTimestamps", "ReportPrerequisites", "ParentBeforeDerivative",
    "GenesisLink", "AdjacentHashLink", "UnauthorizedHashUnchanged", "DerivativeHashParent",
    "RoleResolution", "RoleActionPermission", "PreserveAfterAcquire", "AnalyzeAfterPreserve",
    "ReportAfterAnalysis", "ArchiveAfterReport", "DerivativeParentReady", "ClaimTextPresent",
    "ClaimSupportPresent", "ClaimSupportResolved", "UpstreamSupportValid",
]))
PYTHON_PREDICATES = {
    child: f"evaluate_children[{child}]" for child in CHILD_IDS
}


def _groups(trace: ValidationTrace, *, timestamp: bool = False) -> dict[str, list]:
    grouped: dict[str, list] = defaultdict(list)
    for event in trace.events:
        grouped[event.evidence_id].append(event)
    if timestamp:
        for events in grouped.values():
            events.sort(key=lambda event: event.timestamp)
    return grouped


def _sequence(event: object) -> tuple[int, str]:
    event_id = str(getattr(event, "event_id", ""))
    match = re.search(r"(\d+)$", event_id)
    return (int(match.group(1)) if match else 2**63 - 1, event_id)


def _identity(trace: ValidationTrace) -> dict[str, bool]:
    return {
        "REQ-ID-001-SUB-01": bool(trace.case_id.strip() and trace.trace_id.strip()),
        "REQ-ID-001-SUB-02": all(
            all(str(getattr(e, field)).strip() for field in (
                "evidence_id", "case_id", "kind", "source", "hash", "artifact_path", "dataset_source"
            )) for e in trace.evidence
        ),
        "REQ-ID-001-SUB-03": all(a.actor_id.strip() and a.name.strip() and a.role.strip() for a in trace.actors),
        "REQ-ID-001-SUB-04": all(
            e.event_id.strip() and e.evidence_id.strip() and e.actor_id.strip()
            and e.action.strip() and e.curr_hash.strip() for e in trace.events
        ),
        "REQ-ID-001-SUB-05": all(
            c.claim_id.strip() and c.text.strip() and bool(c.supporting_evidence_ids)
            for c in trace.report_claims
        ),
    }


def _references(trace: ValidationTrace) -> dict[str, bool]:
    evidence = [e.evidence_id for e in trace.evidence]
    actors = [a.actor_id for a in trace.actors]
    events = [e.event_id for e in trace.events]
    claims = [c.claim_id for c in trace.report_claims]
    evidence_set, actor_set = set(evidence), set(actors)
    return {
        "REQ-REF-001-SUB-01": all(len(ids) == len(set(ids)) for ids in (evidence, actors, events, claims)),
        "REQ-REF-001-SUB-02": all(e.evidence_id in evidence_set for e in trace.events),
        "REQ-REF-001-SUB-03": all(e.actor_id in actor_set for e in trace.events),
        "REQ-REF-001-SUB-04": all(set(c.supporting_evidence_ids) <= evidence_set for c in trace.report_claims),
        "REQ-REF-001-SUB-05": all(
            e.kind != "derived_artifact" or bool(e.parent_evidence_id and e.parent_evidence_id in evidence_set)
            for e in trace.evidence
        ),
    }


def _artifacts(trace: ValidationTrace) -> dict[str, bool]:
    available = sha = size = True
    for index, evidence in enumerate(trace.evidence):
        if not evidence.artifact_path:
            continue
        path = resolve_project_path(evidence.artifact_path)
        exists = path.is_file()
        available &= exists
        if not exists:
            sha = size = False
            continue
        computed = sha256_file(path)
        sha &= computed.casefold() == evidence.hash.removeprefix("sha256:").casefold()
        if index == 0 and trace.dataset_origin.sha256:
            sha &= computed.casefold() == trace.dataset_origin.sha256.removeprefix("sha256:").casefold()
        size &= path.stat().st_size == evidence.size_bytes
    return {
        "REQ-ART-001-SUB-01": available,
        "REQ-ART-001-SUB-02": sha,
        "REQ-ART-001-SUB-03": size,
    }


def _custody(trace: ValidationTrace) -> dict[str, bool]:
    origin = continuity = transfer = preserve = True
    for events in _groups(trace, timestamp=True).values():
        holder = None
        for index, event in enumerate(events):
            if index == 0 and event.action == "acquire":
                origin &= event.prev_holder is None
            else:
                continuity &= event.prev_holder == holder
            if event.action == "transfer":
                transfer &= bool(event.new_holder)
            if event.action == "preserve":
                preserve &= bool(event.new_holder)
            if event.new_holder is not None:
                holder = event.new_holder
    return {
        "REQ-CUST-001-SUB-01": origin, "REQ-CUST-001-SUB-02": continuity,
        "REQ-CUST-001-SUB-03": transfer, "REQ-CUST-001-SUB-04": preserve,
    }


def _chronology(trace: ValidationTrace) -> dict[str, bool]:
    timestamps = all(e.timestamp >= 0 for e in trace.events)
    report_ok = parent_ok = True
    listed = _groups(trace)
    evidence_map = {e.evidence_id: e for e in trace.evidence}
    for evidence_id, events in listed.items():
        ordered = sorted(events, key=_sequence)
        timestamps &= all(a.timestamp <= b.timestamp for a, b in zip(ordered, ordered[1:]))
        by_action: dict[str, list[int]] = defaultdict(list)
        for event in events:
            by_action[event.action].append(event.timestamp)
        evidence = evidence_map.get(evidence_id)
        required = ["derive", "examine"] if evidence and evidence.kind == "derived_artifact" else [
            "acquire", "preserve", "examine" if evidence and evidence.kind in {
                "log_file", "report", "unknown_public_artifact"
            } else "analyze",
        ]
        report_ok &= all(
            by_action[item] and min(by_action[item]) <= when
            for when in by_action["report"] for item in required
        )
    for evidence in trace.evidence:
        if evidence.kind == "derived_artifact" and evidence.parent_evidence_id:
            derives = [e.timestamp for e in listed.get(evidence.evidence_id, []) if e.action == "derive"]
            acquires = [
                e.timestamp for e in listed.get(evidence.parent_evidence_id, []) if e.action == "acquire"
            ]
            parent_ok &= not derives or bool(acquires and min(derives) >= min(acquires))
    return {
        "REQ-CHR-001-SUB-01": timestamps, "REQ-CHR-001-SUB-02": report_ok,
        "REQ-CHR-001-SUB-03": parent_ok,
    }


def _hashes(trace: ValidationTrace) -> dict[str, bool]:
    genesis = adjacent = unchanged = derived = True
    evidence = {e.evidence_id: e for e in trace.evidence}
    for evidence_id, events in _groups(trace, timestamp=True).items():
        previous = None
        for index, event in enumerate(events):
            if index == 0 and event.action == "acquire":
                genesis &= event.prev_hash == "GENESIS"
            elif index:
                adjacent &= event.prev_hash == previous
                if event.action != "derive" and not event.hash_change_allowed:
                    unchanged &= event.curr_hash == previous
            if event.action == "derive":
                derived &= bool(evidence.get(evidence_id) and evidence[evidence_id].parent_evidence_id)
            previous = event.curr_hash
    return {
        "REQ-HASH-001-SUB-01": genesis, "REQ-HASH-001-SUB-02": adjacent,
        "REQ-HASH-001-SUB-03": unchanged, "REQ-HASH-001-SUB-04": derived,
    }


ALLOWED = {
    ("investigator", "acquire"), ("investigator", "examine"),
    ("custodian", "preserve"), ("custodian", "transfer"), ("custodian", "archive"),
    ("analyst", "examine"), ("analyst", "analyze"), ("analyst", "derive"),
    ("supervisor", "report"), ("supervisor", "archive"),
    ("external_reviewer", "examine"),
}


def _authorization(trace: ValidationTrace) -> dict[str, bool]:
    roles = {a.actor_id: a.role for a in trace.actors}
    return {
        "REQ-AUTH-001-SUB-01": all(e.actor_id in roles for e in trace.events),
        "REQ-AUTH-001-SUB-02": all(
            e.actor_id not in roles or (roles[e.actor_id], e.action) in ALLOWED for e in trace.events
        ),
    }


def _before(times: dict[str, list[int]], action: str, prerequisite: str) -> bool:
    return all(times[prerequisite] and min(times[prerequisite]) <= when for when in times[action])


def _lifecycle(trace: ValidationTrace) -> dict[str, bool]:
    preserve = analyze = report = archive = parent_ready = True
    evidence_map = {e.evidence_id: e for e in trace.evidence}
    grouped = _groups(trace)
    for evidence_id, events in grouped.items():
        times: dict[str, list[int]] = defaultdict(list)
        for event in events:
            times[event.action].append(event.timestamp)
        evidence = evidence_map.get(evidence_id)
        if evidence and evidence.kind == "derived_artifact":
            analyze &= _before(times, "examine", "derive") and _before(times, "analyze", "derive")
            report &= _before(times, "report", "examine")
        else:
            preserve &= _before(times, "preserve", "acquire") and _before(times, "transfer", "acquire")
            analyze &= _before(times, "examine", "preserve") and _before(times, "analyze", "preserve")
            prerequisite = "examine" if evidence and evidence.kind in {
                "log_file", "report", "unknown_public_artifact"
            } else "analyze"
            report &= _before(times, "report", prerequisite)
        archive &= _before(times, "archive", "report")
    for evidence in trace.evidence:
        if evidence.kind == "derived_artifact" and evidence.parent_evidence_id:
            actions = {e.action for e in grouped.get(evidence.parent_evidence_id, [])}
            parent_ready &= {"acquire", "analyze"} <= actions
    return {
        "REQ-LIFE-001-SUB-01": preserve, "REQ-LIFE-001-SUB-02": analyze,
        "REQ-LIFE-001-SUB-03": report, "REQ-LIFE-001-SUB-04": archive,
        "REQ-LIFE-001-SUB-05": parent_ready,
    }


def evaluate_children(trace: ValidationTrace) -> dict[str, bool]:
    output: dict[str, bool] = {}
    for function in (_identity, _references, _artifacts, _custody, _chronology, _hashes,
                     _authorization, _lifecycle):
        output.update(function(trace))
    evidence_ids = {e.evidence_id for e in trace.evidence}
    core = all(output.values())
    output.update({
        "REQ-RPT-001-SUB-01": all(c.text.strip() for c in trace.report_claims),
        "REQ-RPT-001-SUB-02": all(c.supporting_evidence_ids for c in trace.report_claims),
        "REQ-RPT-001-SUB-03": all(
            set(c.supporting_evidence_ids) <= evidence_ids for c in trace.report_claims
        ),
        "REQ-RPT-001-SUB-04": core,
    })
    return output


def parent_from_children(results: dict[str, bool]) -> dict[str, bool]:
    return {
        parent: all(results[child] for child in CHILD_IDS if PARENTS[child] == parent)
        for parent in dict.fromkeys(PARENTS.values())
    }


# Concrete, importable child symbols.  These wrappers name the exact logical branch
# without changing the grouped implementation used by the production evaluator.
def trace_identity_present(t: ValidationTrace) -> bool: return _identity(t)["REQ-ID-001-SUB-01"]
def evidence_identity_present(t: ValidationTrace) -> bool: return _identity(t)["REQ-ID-001-SUB-02"]
def actor_identity_present(t: ValidationTrace) -> bool: return _identity(t)["REQ-ID-001-SUB-03"]
def event_identity_present(t: ValidationTrace) -> bool: return _identity(t)["REQ-ID-001-SUB-04"]
def claim_identity_present(t: ValidationTrace) -> bool: return _identity(t)["REQ-ID-001-SUB-05"]
def unique_identifiers(t: ValidationTrace) -> bool: return _references(t)["REQ-REF-001-SUB-01"]
def event_evidence_reference_exists(t: ValidationTrace) -> bool: return _references(t)["REQ-REF-001-SUB-02"]
def event_actor_reference_exists(t: ValidationTrace) -> bool: return _references(t)["REQ-REF-001-SUB-03"]
def claim_support_reference_exists(t: ValidationTrace) -> bool: return _references(t)["REQ-REF-001-SUB-04"]
def derived_parent_reference_exists(t: ValidationTrace) -> bool: return _references(t)["REQ-REF-001-SUB-05"]
def artifact_available(t: ValidationTrace) -> bool: return _artifacts(t)["REQ-ART-001-SUB-01"]
def artifact_sha256_matches(t: ValidationTrace) -> bool: return _artifacts(t)["REQ-ART-001-SUB-02"]
def artifact_size_matches(t: ValidationTrace) -> bool: return _artifacts(t)["REQ-ART-001-SUB-03"]
def acquisition_origin(t: ValidationTrace) -> bool: return _custody(t)["REQ-CUST-001-SUB-01"]
def previous_holder_continuity(t: ValidationTrace) -> bool: return _custody(t)["REQ-CUST-001-SUB-02"]
def transfer_assignee(t: ValidationTrace) -> bool: return _custody(t)["REQ-CUST-001-SUB-03"]
def preservation_assignee(t: ValidationTrace) -> bool: return _custody(t)["REQ-CUST-001-SUB-04"]
def nonnegative_sequence_timestamps(t: ValidationTrace) -> bool: return _chronology(t)["REQ-CHR-001-SUB-01"]
def report_prerequisites(t: ValidationTrace) -> bool: return _chronology(t)["REQ-CHR-001-SUB-02"]
def parent_before_derivative(t: ValidationTrace) -> bool: return _chronology(t)["REQ-CHR-001-SUB-03"]
def genesis_link(t: ValidationTrace) -> bool: return _hashes(t)["REQ-HASH-001-SUB-01"]
def adjacent_hash_link(t: ValidationTrace) -> bool: return _hashes(t)["REQ-HASH-001-SUB-02"]
def unauthorized_hash_unchanged(t: ValidationTrace) -> bool: return _hashes(t)["REQ-HASH-001-SUB-03"]
def derivative_hash_parent(t: ValidationTrace) -> bool: return _hashes(t)["REQ-HASH-001-SUB-04"]
def role_resolution(t: ValidationTrace) -> bool: return _authorization(t)["REQ-AUTH-001-SUB-01"]
def role_action_permission(t: ValidationTrace) -> bool: return _authorization(t)["REQ-AUTH-001-SUB-02"]
def preserve_after_acquire(t: ValidationTrace) -> bool: return _lifecycle(t)["REQ-LIFE-001-SUB-01"]
def analyze_after_preserve(t: ValidationTrace) -> bool: return _lifecycle(t)["REQ-LIFE-001-SUB-02"]
def report_after_analysis(t: ValidationTrace) -> bool: return _lifecycle(t)["REQ-LIFE-001-SUB-03"]
def archive_after_report(t: ValidationTrace) -> bool: return _lifecycle(t)["REQ-LIFE-001-SUB-04"]
def derivative_parent_ready(t: ValidationTrace) -> bool: return _lifecycle(t)["REQ-LIFE-001-SUB-05"]
def claim_text_present(t: ValidationTrace) -> bool: return all(c.text.strip() for c in t.report_claims)
def claim_support_present(t: ValidationTrace) -> bool: return all(c.supporting_evidence_ids for c in t.report_claims)
def claim_support_resolved(t: ValidationTrace) -> bool:
    evidence = {item.evidence_id for item in t.evidence}
    return all(set(c.supporting_evidence_ids) <= evidence for c in t.report_claims)
def upstream_support_valid(t: ValidationTrace) -> bool:
    values: dict[str, bool] = {}
    for function in (_identity, _references, _artifacts, _custody, _chronology, _hashes,
                     _authorization, _lifecycle):
        values.update(function(t))
    return all(values.values())


CHILD_FUNCTIONS: dict[str, Callable[[ValidationTrace], bool]] = dict(zip(CHILD_IDS, [
    trace_identity_present, evidence_identity_present, actor_identity_present,
    event_identity_present, claim_identity_present, unique_identifiers,
    event_evidence_reference_exists, event_actor_reference_exists,
    claim_support_reference_exists, derived_parent_reference_exists, artifact_available,
    artifact_sha256_matches, artifact_size_matches, acquisition_origin,
    previous_holder_continuity, transfer_assignee, preservation_assignee,
    nonnegative_sequence_timestamps, report_prerequisites, parent_before_derivative,
    genesis_link, adjacent_hash_link, unauthorized_hash_unchanged, derivative_hash_parent,
    role_resolution, role_action_permission, preserve_after_acquire, analyze_after_preserve,
    report_after_analysis, archive_after_report, derivative_parent_ready, claim_text_present,
    claim_support_present, claim_support_resolved, upstream_support_valid,
]))

PYTHON_PREDICATES = {
    child: f"leancert.sub_obligations.{CHILD_FUNCTIONS[child].__name__}" for child in CHILD_IDS
}
