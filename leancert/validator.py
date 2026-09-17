from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import re
from typing import Callable

from .schema import RequirementResult, ValidationResult, ValidationTrace
from .sub_obligations import CHILD_IDS, DESCRIPTIONS, PARENTS, evaluate_children, parent_from_children
from .utils import resolve_project_path, sha256_file

REQUIREMENTS = [
    "IdentityCompleteness",
    "ReferentialIntegrity",
    "PublicArtifactIntegrity",
    "CustodyContinuity",
    "ChronologicalConsistency",
    "HashContinuity",
    "AuthorizedHandling",
    "LifecycleCorrectness",
    "ReportTraceability",
]

AUTHORIZATION = {
    "investigator": {"acquire", "examine"},
    "custodian": {"preserve", "transfer", "archive"},
    "analyst": {"examine", "analyze", "derive"},
    "supervisor": {"report", "archive"},
    "external_reviewer": {"examine"},
}


def _result(
    name: str, failures: list[dict], failure_type: str | None = None
) -> RequirementResult:
    return RequirementResult(
        requirement=name, passed=not failures,
        failure_type=failure_type if failures else None, failures=failures,
    )


def _events_by_evidence(trace: ValidationTrace, sort: bool = False) -> dict[str, list]:
    grouped: dict[str, list] = defaultdict(list)
    for event in trace.events:
        grouped[event.evidence_id].append(event)
    if sort:
        for values in grouped.values():
            values.sort(key=lambda item: item.timestamp)
    return grouped


def check_identity(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    for field, value in (("case_id", trace.case_id), ("trace_id", trace.trace_id)):
        if not value.strip():
            failures.append({"reason": f"{field} is empty"})
    for item in trace.evidence:
        for field in ("evidence_id", "case_id", "kind", "source", "hash", "artifact_path", "dataset_source"):
            if not str(getattr(item, field)).strip():
                failures.append({"evidence_id": item.evidence_id, "reason": f"evidence {field} is empty"})
    for actor in trace.actors:
        for field in ("actor_id", "name", "role"):
            if not str(getattr(actor, field)).strip():
                failures.append({"actor_id": actor.actor_id, "reason": f"actor {field} is empty"})
    for event in trace.events:
        for field in ("event_id", "evidence_id", "actor_id", "action", "curr_hash"):
            if not str(getattr(event, field)).strip():
                failures.append({"event_id": event.event_id, "evidence_id": event.evidence_id,
                                 "reason": f"event {field} is empty"})
    for claim in trace.report_claims:
        if not claim.claim_id.strip() or not claim.text.strip() or not claim.supporting_evidence_ids:
            failures.append({"claim_id": claim.claim_id, "reason": "claim identity or supporting evidence is empty"})
    return _result("IdentityCompleteness", failures)


def check_references(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    ids = {
        "evidence": [x.evidence_id for x in trace.evidence],
        "actor": [x.actor_id for x in trace.actors],
        "event": [x.event_id for x in trace.events],
        "claim": [x.claim_id for x in trace.report_claims],
    }
    for kind, values in ids.items():
        for duplicate, count in Counter(values).items():
            if count > 1:
                failures.append({"reason": f"duplicate {kind} ID: {duplicate}"})
    evidence_ids, actor_ids = set(ids["evidence"]), set(ids["actor"])
    for event in trace.events:
        if event.evidence_id not in evidence_ids:
            failures.append({"event_id": event.event_id, "evidence_id": event.evidence_id,
                             "reason": "event references missing evidence"})
        if event.actor_id not in actor_ids:
            failures.append({"event_id": event.event_id, "actor_id": event.actor_id,
                             "reason": "event references missing actor"})
    for claim in trace.report_claims:
        for evidence_id in claim.supporting_evidence_ids:
            if evidence_id not in evidence_ids:
                failures.append({"claim_id": claim.claim_id, "evidence_id": evidence_id,
                                 "reason": "claim references missing evidence"})
    for evidence in trace.evidence:
        if evidence.kind == "derived_artifact":
            if not evidence.parent_evidence_id:
                failures.append({"evidence_id": evidence.evidence_id,
                                 "reason": "derived artifact has no parent evidence ID"})
            elif evidence.parent_evidence_id not in evidence_ids:
                failures.append({"evidence_id": evidence.evidence_id,
                                 "reason": "derived artifact references missing parent evidence"})
    return _result("ReferentialIntegrity", failures)


def check_public_artifacts(trace: ValidationTrace, strict: bool, warnings: list[str]) -> RequirementResult:
    failures: list[dict] = []
    for evidence in trace.evidence:
        if not evidence.artifact_path:
            continue
        path = resolve_project_path(evidence.artifact_path)
        if not path.is_file():
            message = f"Local artifact unavailable: {evidence.artifact_path}"
            if strict:
                failures.append({"evidence_id": evidence.evidence_id, "reason": message})
            else:
                warnings.append(message)
            continue
        computed = sha256_file(path)
        expected = evidence.hash.removeprefix("sha256:")
        if computed.lower() != expected.lower():
            failures.append({"evidence_id": evidence.evidence_id,
                             "reason": "computed artifact SHA-256 does not match evidence hash"})
        if evidence.evidence_id == trace.evidence[0].evidence_id and trace.dataset_origin.sha256:
            if computed.lower() != trace.dataset_origin.sha256.removeprefix("sha256:").lower():
                failures.append({"evidence_id": evidence.evidence_id,
                                 "reason": "computed artifact SHA-256 does not match dataset origin"})
        if evidence.size_bytes != path.stat().st_size:
            failures.append({"evidence_id": evidence.evidence_id,
                             "reason": "artifact size does not match registered size"})
    return _result("PublicArtifactIntegrity", failures)


def check_custody(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    for evidence_id, events in _events_by_evidence(trace, sort=True).items():
        holder: str | None = None
        for index, event in enumerate(events):
            if index == 0 and event.action == "acquire":
                if event.prev_holder is not None:
                    failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                     "reason": "acquisition must begin without a previous holder"})
            elif event.prev_holder != holder:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "prev_holder does not match current holder"})
            if event.action in {"transfer", "preserve"} and not event.new_holder:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": f"{event.action} event must assign a new holder"})
            if event.new_holder is not None:
                holder = event.new_holder
    return _result("CustodyContinuity", failures)


def check_chronology(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    # Serialization order is not semantic. Numeric event-ID suffixes act as the
    # prototype's sequence indices; timestamps must be monotone in that order.
    listed = _events_by_evidence(trace)
    for evidence_id, events in listed.items():
        def sequence_key(event: object) -> tuple[int, str]:
            event_id = str(getattr(event, "event_id", ""))
            match = re.search(r"(\d+)$", event_id)
            return (int(match.group(1)) if match else 2**63 - 1, event_id)

        events = sorted(events, key=sequence_key)
        previous = -1
        for event in events:
            if event.timestamp < 0:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "timestamp is negative"})
            if event.timestamp < previous:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "timestamp decreases relative to the sequence index"})
            previous = event.timestamp
        by_action: dict[str, list[int]] = defaultdict(list)
        for event in events:
            by_action[event.action].append(event.timestamp)
        evidence = next((item for item in trace.evidence if item.evidence_id == evidence_id), None)
        report_prerequisites = ["derive", "examine"] if evidence and evidence.kind == "derived_artifact" else [
            "acquire", "preserve",
            "examine" if evidence and evidence.kind in {"log_file", "report", "unknown_public_artifact"} else "analyze",
        ]
        for report_time in by_action["report"]:
            for prerequisite in report_prerequisites:
                if not by_action[prerequisite] or min(by_action[prerequisite]) > report_time:
                    failures.append({"evidence_id": evidence_id,
                                     "reason": f"report occurs before {prerequisite}"})
    parent_events = _events_by_evidence(trace, sort=True)
    for evidence in trace.evidence:
        if evidence.kind == "derived_artifact" and evidence.parent_evidence_id:
            child_derives = [e.timestamp for e in listed.get(evidence.evidence_id, []) if e.action == "derive"]
            parent_acquires = [e.timestamp for e in parent_events.get(evidence.parent_evidence_id, [])
                               if e.action == "acquire"]
            if child_derives and (not parent_acquires or min(child_derives) < min(parent_acquires)):
                failures.append({"evidence_id": evidence.evidence_id,
                                 "reason": "derived artifact created before parent acquisition"})
    return _result("ChronologicalConsistency", failures)


def check_hashes(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    evidence_by_id = {e.evidence_id: e for e in trace.evidence}
    for evidence_id, events in _events_by_evidence(trace, sort=True).items():
        previous_hash: str | None = None
        for index, event in enumerate(events):
            if index == 0 and event.action == "acquire" and event.prev_hash != "GENESIS":
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "first acquisition prev_hash is not GENESIS"})
            elif index > 0 and event.prev_hash != previous_hash:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "prev_hash does not match previous curr_hash for this evidence"})
            if index > 0 and event.action != "derive" and not event.hash_change_allowed and event.curr_hash != previous_hash:
                failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                 "reason": "evidence hash changed without authorization"})
            if event.action == "derive":
                item = evidence_by_id.get(evidence_id)
                if item is None or not item.parent_evidence_id:
                    failures.append({"event_id": event.event_id, "evidence_id": evidence_id,
                                     "reason": "derive event has no parent evidence"})
            previous_hash = event.curr_hash
    return _result("HashContinuity", failures)


def check_authorization(trace: ValidationTrace) -> RequirementResult:
    failures: list[dict] = []
    roles = {actor.actor_id: actor.role for actor in trace.actors}
    for event in trace.events:
        role = roles.get(event.actor_id)
        if role is not None and event.action not in AUTHORIZATION[role]:
            failures.append({"event_id": event.event_id, "evidence_id": event.evidence_id,
                             "actor_id": event.actor_id,
                             "reason": f"actor role {role} is not authorized to perform {event.action}"})
    return _result("AuthorizedHandling", failures)


def check_lifecycle(trace: ValidationTrace, allow_archive_without_report: bool = False) -> RequirementResult:
    failures: list[dict] = []
    for evidence_id, events in _events_by_evidence(trace).items():
        action_times: dict[str, list[int]] = defaultdict(list)
        for event in events:
            action_times[event.action].append(event.timestamp)

        def require_before(action: str, prerequisite: str) -> None:
            for when in action_times[action]:
                if not action_times[prerequisite] or min(action_times[prerequisite]) > when:
                    failures.append({"evidence_id": evidence_id,
                                     "reason": f"{action} occurs before {prerequisite}"})

        evidence = next((item for item in trace.evidence if item.evidence_id == evidence_id), None)
        if evidence and evidence.kind == "derived_artifact":
            require_before("examine", "derive")
            require_before("analyze", "derive")
            if action_times["report"]:
                require_before("report", "examine")
        else:
            require_before("preserve", "acquire")
            require_before("transfer", "acquire")
            require_before("examine", "preserve")
            require_before("analyze", "preserve")
            report_prerequisite = (
                "examine" if evidence and evidence.kind in
                {"log_file", "report", "unknown_public_artifact"} else "analyze"
            )
            require_before("report", report_prerequisite)
        if not allow_archive_without_report:
            require_before("archive", "report")
    evidence_by_id = {e.evidence_id: e for e in trace.evidence}
    grouped = _events_by_evidence(trace)
    for evidence in trace.evidence:
        if evidence.kind != "derived_artifact" or not evidence.parent_evidence_id:
            continue
        parent = evidence_by_id.get(evidence.parent_evidence_id)
        parent_actions = {ev.action for ev in grouped.get(parent.evidence_id, [])} if parent else set()
        if not {"acquire", "analyze"}.issubset(parent_actions):
            failures.append({"evidence_id": evidence.evidence_id,
                             "reason": "derived artifact parent was not acquired and analyzed"})
    return _result("LifecycleCorrectness", failures)


def check_report_traceability(
    trace: ValidationTrace, core_results: list[RequirementResult]
) -> RequirementResult:
    failures: list[dict] = []
    evidence_ids = {item.evidence_id for item in trace.evidence}
    upstream_by_evidence: dict[str, set[str]] = defaultdict(set)
    trace_wide_requirements: set[str] = set()
    for result in core_results:
        if result.requirement == "ReportTraceability":
            continue
        if not result.passed:
            for failure in result.failures:
                evidence_id = failure.get("evidence_id")
                if evidence_id:
                    upstream_by_evidence[evidence_id].add(result.requirement)
                else:
                    trace_wide_requirements.add(result.requirement)
    if trace_wide_requirements:
        for evidence_id in evidence_ids:
            upstream_by_evidence[evidence_id].update(trace_wide_requirements)
    for claim in trace.report_claims:
        if not claim.text.strip():
            failures.append({
                "claim_id": claim.claim_id, "evidence_id": None,
                "reason": "claim text is empty",
                "upstream_failed_requirements": [], "is_cascading": False,
            })
        if not claim.supporting_evidence_ids:
            failures.append({
                "claim_id": claim.claim_id, "evidence_id": None,
                "reason": "claim has no supporting evidence",
                "upstream_failed_requirements": [], "is_cascading": False,
            })
        for evidence_id in claim.supporting_evidence_ids:
            if evidence_id not in evidence_ids:
                failures.append({
                    "claim_id": claim.claim_id, "evidence_id": evidence_id,
                    "reason": "claim references missing evidence",
                    "upstream_failed_requirements": [], "is_cascading": False,
                })
            elif upstream_by_evidence.get(evidence_id):
                failures.append({
                    "claim_id": claim.claim_id, "evidence_id": evidence_id,
                    "reason": "claim relies on evidence that failed core validation",
                    "upstream_failed_requirements": sorted(upstream_by_evidence[evidence_id]),
                    "is_cascading": True,
                })
    direct = any(not failure["is_cascading"] for failure in failures)
    cascading = any(failure["is_cascading"] for failure in failures)
    failure_type = "mixed" if direct and cascading else "cascading" if cascading else "direct"
    return _result("ReportTraceability", failures, failure_type)


def validate_trace(
    trace: ValidationTrace,
    *,
    strict_artifacts: bool = False,
    allow_archive_without_report: bool = False,
) -> ValidationResult:
    """Validate trace content. Evaluation labels and metadata are intentionally unused."""
    warnings: list[str] = []
    results = [
        check_identity(trace),
        check_references(trace),
        check_public_artifacts(trace, strict_artifacts, warnings),
        check_custody(trace),
        check_chronology(trace),
        check_hashes(trace),
        check_authorization(trace),
        check_lifecycle(trace, allow_archive_without_report),
    ]
    child_results = evaluate_children(trace)
    if not strict_artifacts:
        # Non-strict mode preserves the established warning-only artifact policy.
        # Publication evaluation uses strict mode and evaluates the measured children.
        for child in ("REQ-ART-001-SUB-01", "REQ-ART-001-SUB-02", "REQ-ART-001-SUB-03"):
            child_results[child] = True
        child_results["REQ-RPT-001-SUB-04"] = all(
            child_results[child] for child in CHILD_IDS[:31]
        )
    child_parents = parent_from_children(child_results)
    for result in results:
        if result.requirement == "PublicArtifactIntegrity" and not strict_artifacts:
            continue
        expected = child_parents[result.requirement]
        if result.passed and not expected:
            for child in CHILD_IDS:
                if PARENTS[child] == result.requirement and not child_results[child]:
                    result.failures.append({
                        "reason": f"child obligation failed: {child} ({DESCRIPTIONS[child]})",
                        "sub_obligation_id": child, "is_cascading": False,
                    })
            result.passed = False
            result.failure_type = "direct"
    results.append(check_report_traceability(trace, results))
    report = results[-1]
    if report.passed and not child_parents["ReportTraceability"]:
        for child in CHILD_IDS:
            if PARENTS[child] == "ReportTraceability" and not child_results[child]:
                report.failures.append({
                    "reason": f"child obligation failed: {child} ({DESCRIPTIONS[child]})",
                    "sub_obligation_id": child,
                    "is_cascading": child == "REQ-RPT-001-SUB-04",
                })
        report.passed = False
        report.failure_type = "cascading" if all(
            failure.get("is_cascading") for failure in report.failures
        ) else "mixed"
    failed = [item.requirement for item in results if not item.passed]
    return ValidationResult(
        case_id=trace.case_id,
        trace_id=trace.trace_id,
        overall_status="FAILED" if failed else "PASSED",
        passed_requirements=[item.requirement for item in results if item.passed],
        failed_requirements=failed,
        requirement_results=results,
        warnings=warnings,
        failure_count=sum(len(item.failures) for item in results),
        dataset_origin=trace.dataset_origin.model_dump(),
    )
