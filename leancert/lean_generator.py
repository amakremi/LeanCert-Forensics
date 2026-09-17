from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from .schema import ValidationResult, ValidationTrace
from .sub_obligations import CHILD_IDS, LEAN_PREDICATES, evaluate_children
from .utils import PROJECT_ROOT, relative_to_project, resolve_project_path, safe_filename, sha256_file

ROLE_MAP = {"external_reviewer": "externalReviewer"}
ACTION_NAMES = {"acquire", "preserve", "transfer", "examine", "analyze", "report", "archive", "derive"}
_LEAN_PROJECT_PREPARATION: dict | None = None


def _find_tool(name: str) -> str | None:
    return shutil.which(name)


def _command_version(executable: str | None) -> str | None:
    if not executable:
        return None
    result = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, shell=False
    )
    output = (result.stdout or result.stderr).strip()
    return output if result.returncode == 0 and output else None


def detect_lean() -> dict:
    lean_path = _find_tool("lean")
    lake_path = _find_tool("lake")
    hints = [
        str(Path.home() / ".elan" / "bin"),
        r"%USERPROFILE%\.elan\bin",
        "Restart PowerShell after installation so its PATH is refreshed.",
    ]
    return {
        "lean_available": lean_path is not None,
        "lean_path": lean_path,
        "lean_version": _command_version(lean_path),
        "lake_available": lake_path is not None,
        "lake_path": lake_path,
        "lake_version": _command_version(lake_path),
        "lean_check_mode": "lean file" if lean_path else "not run",
        "path_entry_hints": hints,
    }


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _identifier(value: str, prefix: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"{prefix}_{cleaned}"
    return f"{prefix}_{cleaned}"


def _option(value: str | None) -> str:
    return "none" if value is None else f"some {_lean_string(value)}"


def _sequence_number(event_id: str) -> int:
    match = re.search(r"(\d+)$", event_id)
    return int(match.group(1)) if match else 18446744073709551615


def render_lean(
    trace: ValidationTrace, validation: ValidationResult, *, proof_mode: str = "auto"
) -> str:
    def symbols(items: list, attribute: str, prefix: str) -> dict[int, str]:
        counts: dict[str, int] = {}
        output: dict[int, str] = {}
        for item in items:
            base = _identifier(str(getattr(item, attribute)), prefix)
            counts[base] = counts.get(base, 0) + 1
            output[id(item)] = base if counts[base] == 1 else f"{base}_{counts[base]}"
        return output

    actor_symbols = symbols(trace.actors, "actor_id", "actor")
    evidence_symbols = symbols(trace.evidence, "evidence_id", "evidence")
    event_symbols = symbols(trace.events, "event_id", "event")
    claim_symbols = symbols(trace.report_claims, "claim_id", "claim")
    lines = [
        "import LeanCert.Requirements",
        "",
        "namespace LeanCert.Generated",
        "",
        f"-- Generated deterministically for trace {_lean_string(trace.trace_id)}.",
    ]
    for actor in trace.actors:
        name = actor_symbols[id(actor)]
        role = ROLE_MAP.get(actor.role, actor.role)
        lines.extend([
            f"def {name} : LeanCert.Actor :=",
            "  { " + f"actorId := {_lean_string(actor.actor_id)}, "
            f"name := {_lean_string(actor.name)}, role := LeanCert.Role.{role}" + " }",
        ])
    for evidence in trace.evidence:
        name = evidence_symbols[id(evidence)]
        artifact_path = resolve_project_path(evidence.artifact_path)
        available = artifact_path.is_file()
        computed = sha256_file(artifact_path) if available else ""
        hash_matches = available and computed.casefold() == evidence.hash.removeprefix("sha256:").casefold()
        if evidence is trace.evidence[0] and trace.dataset_origin.sha256:
            hash_matches = hash_matches and computed.casefold() == trace.dataset_origin.sha256.removeprefix("sha256:").casefold()
        size_matches = available and artifact_path.stat().st_size == evidence.size_bytes
        lines.extend([
            f"def {name} : LeanCert.Evidence :=",
            "  { " + f"evidenceId := {_lean_string(evidence.evidence_id)}, "
            f"caseId := {_lean_string(evidence.case_id)}, kind := {_lean_string(evidence.kind)}, "
            f"source := {_lean_string(evidence.source)}, hash := {_lean_string(evidence.hash)}, "
            f"sizeBytes := {evidence.size_bytes}, parentEvidenceId := {_option(evidence.parent_evidence_id)}, "
            f"artifactPath := {_lean_string(evidence.artifact_path)}, "
            f"datasetSource := {_lean_string(evidence.dataset_source)}, "
            f"artifactAvailable := {str(available).lower()}, "
            f"artifactHashMatches := {str(hash_matches).lower()}, "
            f"artifactSizeMatches := {str(size_matches).lower()}" + " }",
        ])
    for event in trace.events:
        name = event_symbols[id(event)]
        lines.extend([
            f"def {name} : LeanCert.Event :=",
            "  { " + f"eventId := {_lean_string(event.event_id)}, "
            f"evidenceId := {_lean_string(event.evidence_id)}, actorId := {_lean_string(event.actor_id)}, "
            f"action := LeanCert.Action.{event.action}, sequence := {_sequence_number(event.event_id)}, "
            f"timestamp := {event.timestamp}, "
            f"prevHolder := {_option(event.prev_holder)}, newHolder := {_option(event.new_holder)}, "
            f"prevHash := {_lean_string(event.prev_hash)}, currHash := {_lean_string(event.curr_hash)}, "
            f"hashChangeAllowed := {str(event.hash_change_allowed).lower()}" + " }",
        ])
    for claim in trace.report_claims:
        name = claim_symbols[id(claim)]
        support = ", ".join(_lean_string(item) for item in claim.supporting_evidence_ids)
        lines.extend([
            f"def {name} : LeanCert.ReportClaim :=",
            "  { " + f"claimId := {_lean_string(claim.claim_id)}, text := {_lean_string(claim.text)}, "
            f"supportingEvidenceIds := [{support}]" + " }",
        ])

    requirement_to_witness = [
        ("IdentityCompleteness", "identityCompleteWitness"),
        ("ReferentialIntegrity", "referentiallyValidWitness"),
        ("PublicArtifactIntegrity", "artifactIntegrityValidWitness"),
        ("CustodyContinuity", "custodyContinuousWitness"),
        ("ChronologicalConsistency", "chronologicallyConsistentWitness"),
        ("HashContinuity", "hashContinuousWitness"),
        ("AuthorizedHandling", "authorizedHandlingWitness"),
        ("LifecycleCorrectness", "lifecycleCorrectWitness"),
        ("ReportTraceability", "reportTraceableWitness"),
    ]
    actor_names = ", ".join(actor_symbols[id(item)] for item in trace.actors)
    evidence_names = ", ".join(evidence_symbols[id(item)] for item in trace.evidence)
    event_names = ", ".join(event_symbols[id(item)] for item in trace.events)
    claim_names = ", ".join(claim_symbols[id(item)] for item in trace.report_claims)
    passed = set(validation.passed_requirements)
    child_results = evaluate_children(trace)
    lines.extend([
        "",
        "def traceData : LeanCert.Trace :=",
        "  {",
        f"    caseId := {_lean_string(trace.case_id)}",
        f"    traceId := {_lean_string(trace.trace_id)}",
        f"    actors := [{actor_names}]",
        f"    evidence := [{evidence_names}]",
        f"    events := [{', '.join(event_symbols[id(item)] for item in sorted(trace.events, key=lambda e: (e.evidence_id, e.timestamp, e.event_id)))}]",
        f"    reportClaims := [{claim_names}]",
    ])
    lines.extend(["  }", ""])

    lines.extend(["", "/-", "Python validation summary:"])
    if validation.failed_requirements:
        lines.append("Validation failures detected before proof generation:")
        for result in validation.requirement_results:
            for failure in result.failures:
                reason = str(failure.get("reason", "")).replace("-/", "- /")
                subject = failure.get("event_id") or failure.get("evidence_id") or failure.get("claim_id") or ""
                lines.append(f"- {result.requirement} {subject}: {reason}")
    else:
        lines.append("All modeled Python requirements passed.")
    lines.extend(["-/", ""])

    if proof_mode not in {"auto", "pairwise", "aggregate"}:
        raise ValueError(f"Unknown proof mode: {proof_mode}")
    aggregate_mode = proof_mode == "aggregate" or (proof_mode == "auto" and len(trace.events) > 100)
    if aggregate_mode:
        lines.append("-- Aggregate proof mode: per-event examples omitted above 100 events.")
    # Object proofs are emitted only when their own identity fields are complete.
    for actor in trace.actors:
        if actor.actor_id and actor.name:
            name = actor_symbols[id(actor)]
            lines.append(f"example : LeanCert.IdentityCompleteActor {name} := by native_decide")
    for evidence in trace.evidence:
        if all((evidence.evidence_id, evidence.case_id, evidence.kind, evidence.source,
                evidence.hash, evidence.artifact_path, evidence.dataset_source)):
            name = evidence_symbols[id(evidence)]
            lines.append(f"example : LeanCert.IdentityCompleteEvidence {name} := by native_decide")
    for event in ([] if aggregate_mode else trace.events):
        if all((event.event_id, event.evidence_id, event.actor_id, event.curr_hash)):
            name = event_symbols[id(event)]
            lines.append(f"example : LeanCert.IdentityCompleteEvent {name} := by native_decide")
    for claim in trace.report_claims:
        if claim.claim_id and claim.text and claim.supporting_evidence_ids:
            name = claim_symbols[id(claim)]
            lines.append(f"example : LeanCert.IdentityCompleteClaim {name} := by native_decide")

    actors = {a.actor_id: a for a in trace.actors}
    allowed = {
        "investigator": {"acquire", "examine"},
        "custodian": {"preserve", "transfer", "archive"},
        "analyst": {"examine", "analyze", "derive"},
        "supervisor": {"report", "archive"},
        "external_reviewer": {"examine"},
    }
    for event in ([] if aggregate_mode else trace.events):
        actor = actors.get(event.actor_id)
        if actor and event.action in allowed[actor.role]:
            actor_name = actor_symbols[id(actor)]
            event_name = event_symbols[id(event)]
            lines.append(
                f"example : LeanCert.Authorized {actor_name}.role "
                f"{event_name}.action := by "
                f"simp [{actor_name}, {event_name}, LeanCert.Authorized, LeanCert.AuthorizedB]"
            )

    grouped: dict[str, list] = {}
    for event in trace.events:
        grouped.setdefault(event.evidence_id, []).append(event)
    passed_requirements = set(validation.passed_requirements)
    for events in ([] if aggregate_mode else grouped.values()):
        ordered = sorted(events, key=lambda item: item.timestamp)
        for left, right in zip(ordered, ordered[1:]):
            left_name = event_symbols[id(left)]
            right_name = event_symbols[id(right)]
            if "ChronologicalConsistency" in passed_requirements:
                lines.append(
                    f"example : LeanCert.ChronologicalPair "
                    f"{left_name} {right_name} := by native_decide"
                )
            if right.prev_hash == left.curr_hash:
                lines.append(
                    f"example : LeanCert.HashLinkedPair "
                    f"{left_name} {right_name} := by native_decide"
                )
    if validation.overall_status == "PASSED":
        lines.extend([
            "",
            "theorem trace_validity : LeanCert.ValidTrace traceData := by",
            "  native_decide",
        ])
    else:
        predicate_names = {
            "IdentityCompleteness": "IdentityComplete",
            "ReferentialIntegrity": "ReferentiallyValid",
            "PublicArtifactIntegrity": "ArtifactIntegrityValid",
            "CustodyContinuity": "CustodyContinuous",
            "ChronologicalConsistency": "ChronologicallyConsistent",
            "HashContinuity": "HashContinuous",
            "AuthorizedHandling": "AuthorizedHandling",
            "LifecycleCorrectness": "LifecycleCorrect",
            "ReportTraceability": "ReportTraceable",
        }
        lines.extend([
            "",
            "theorem trace_not_valid : ¬ LeanCert.ValidTrace traceData := by",
            "  native_decide",
        ])
        for requirement in validation.failed_requirements:
            predicate = predicate_names.get(requirement)
            if predicate:
                theorem_name = re.sub(r"[^a-z0-9]+", "_", requirement.casefold()).strip("_")
                lines.extend([
                    "",
                    f"theorem trace_{theorem_name}_invalid : ¬ LeanCert.{predicate} traceData := by",
                    f"  native_decide",
                ])
    lines.extend(["", "-- Explicit child-level propositions derived from encoded trace data."])
    for child in CHILD_IDS:
        predicate = LEAN_PREDICATES[child]
        slug = child.casefold().replace("-", "_")
        if child_results[child]:
            lines.append(f"example : LeanCert.{predicate} traceData := by native_decide")
        else:
            lines.extend([
                "", f"theorem child_{slug}_invalid : ¬ LeanCert.{predicate} traceData := by",
                "  native_decide",
            ])
    lines.extend(["", "end LeanCert.Generated", ""])
    return "\n".join(lines)


def generate_lean(
    trace: ValidationTrace,
    validation: ValidationResult,
    *,
    output_dir: Path = PROJECT_ROOT / "generated" / "lean",
    library_dir: Path = PROJECT_ROOT / "lean" / "LeanCert" / "Generated",
    proof_mode: str = "auto",
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    library_dir.mkdir(parents=True, exist_ok=True)
    lean_stem = re.sub(r"[^A-Za-z0-9_]", "_", trace.trace_id)
    filename = safe_filename(f"{lean_stem}.lean")
    content = render_lean(trace, validation, proof_mode=proof_mode)
    primary = output_dir / filename
    library = library_dir / filename
    primary.write_text(content, encoding="utf-8")
    library.write_text(content, encoding="utf-8")
    validation.lean_artifact = relative_to_project(primary)
    validation.lean_artifact_generated = True
    validation.lean_obligation_count = sum(
        line.startswith("example :") or line.startswith("theorem trace_")
        for line in content.splitlines()
    )
    validation.trace_validity_theorem_emitted = validation.overall_status == "PASSED"
    validation.invalid_trace_theorem_emitted = validation.overall_status == "FAILED"
    validation.certificate_kind = (
        "VALIDITY_PROOF" if validation.overall_status == "PASSED" else "VIOLATION_PROOF"
    )
    validation.passed_obligation_count = len(validation.passed_requirements)
    validation.failed_obligation_count = len(validation.failed_requirements)
    validation.documented_failed_obligations = list(validation.failed_requirements)
    validation.negative_theorem_requirements = list(validation.failed_requirements)
    result_by_name = {item.requirement: item for item in validation.requirement_results}
    validation.cascading_negative_theorem_count = sum(
        result_by_name[name].failure_type == "cascading"
        for name in validation.failed_requirements if name in result_by_name
    )
    validation.direct_negative_theorem_count = (
        len(validation.failed_requirements) - validation.cascading_negative_theorem_count
    )
    return primary, library


def check_lean_file(library_file: Path, repeat: int = 1) -> dict:
    global _LEAN_PROJECT_PREPARATION
    detection = detect_lean()
    lean = detection["lean_path"]
    lake = detection["lake_path"]
    if not lean:
        return {
            "lean_check_status": "NOT_RUN", "lean_check_time_ms": None,
            "lean_stdout": "", "lean_stderr": "Lean 4 was not found in PATH.",
        }
    lean_dir = PROJECT_ROOT / "lean"
    if lake and _LEAN_PROJECT_PREPARATION is None:
        prepared = subprocess.run(
            [lake, "build", "LeanCert.Requirements"],
            cwd=lean_dir, capture_output=True, text=True, shell=False,
        )
        _LEAN_PROJECT_PREPARATION = {
            "returncode": prepared.returncode,
            "stdout": prepared.stdout,
            "stderr": prepared.stderr,
        }
    if lake and _LEAN_PROJECT_PREPARATION["returncode"] != 0:
        return {
            "lean_check_status": "FAILED",
            "lean_check_time_ms": None,
            "lean_stdout": _LEAN_PROJECT_PREPARATION["stdout"],
            "lean_stderr": (
                "LeanCert.Requirements could not be built before certificate checking.\n"
                + _LEAN_PROJECT_PREPARATION["stderr"]
            ),
        }
    try:
        relative = library_file.resolve().relative_to(lean_dir.resolve())
    except ValueError:
        relative = library_file.resolve()
    command = [lake, "env", "lean", str(relative)] if lake else [lean, str(relative)]
    started = time.perf_counter()
    cold = subprocess.run(command, cwd=lean_dir, capture_output=True, text=True, shell=False)
    cold_time = (time.perf_counter() - started) * 1000
    if cold.returncode != 0:
        return {
            "lean_check_status": "FAILED", "lean_check_time_ms": cold_time,
            "lean_cold_time_ms": cold_time, "lean_warm_times_ms": [],
            "lean_stdout": cold.stdout, "lean_stderr": cold.stderr,
        }
    times: list[float] = []
    last = cold
    for _ in range(max(1, repeat)):
        started = time.perf_counter()
        last = subprocess.run(
            command, cwd=lean_dir, capture_output=True, text=True, shell=False
        )
        times.append((time.perf_counter() - started) * 1000)
        if last.returncode != 0:
            break
    assert last is not None
    return {
        "lean_check_status": "PASSED" if last.returncode == 0 else "FAILED",
        "lean_check_time_ms": sorted(times)[len(times) // 2],
        "lean_cold_time_ms": cold_time,
        "lean_warm_times_ms": times,
        "lean_stdout": last.stdout,
        "lean_stderr": last.stderr,
    }
