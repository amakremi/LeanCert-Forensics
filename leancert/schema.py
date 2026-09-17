from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Role = Literal["investigator", "custodian", "analyst", "supervisor", "external_reviewer"]
Action = Literal["acquire", "preserve", "transfer", "examine", "analyze", "report", "archive", "derive"]
EvidenceKind = Literal[
    "disk_image", "memory_dump", "network_capture", "log_file",
    "derived_artifact", "report", "digital_twin_state", "unknown_public_artifact",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetOrigin(StrictModel):
    source_name: str
    artifact_name: str
    source_url: str
    local_path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    retrieved_at_utc: str


class EvaluationMetadata(StrictModel):
    scenario: str
    injected_violation: str
    expected_outcome: str
    target_requirement: str


class Evidence(StrictModel):
    evidence_id: str
    case_id: str
    kind: EvidenceKind
    source: str
    hash: str
    size_bytes: int = Field(ge=0)
    parent_evidence_id: str | None = None
    artifact_path: str
    dataset_source: str


class Actor(StrictModel):
    actor_id: str
    name: str
    role: Role


class Event(StrictModel):
    event_id: str
    evidence_id: str
    actor_id: str
    action: Action
    timestamp: int
    prev_holder: str | None = None
    new_holder: str | None = None
    prev_hash: str
    curr_hash: str
    hash_change_allowed: bool = False


class ReportClaim(StrictModel):
    claim_id: str
    text: str
    supporting_evidence_ids: list[str]


class ValidationTrace(StrictModel):
    case_id: str
    trace_id: str
    dataset_origin: DatasetOrigin
    evidence: list[Evidence]
    actors: list[Actor]
    events: list[Event]
    report_claims: list[ReportClaim]


class ForensicTrace(ValidationTrace):
    """Authored/evaluation trace. Validators receive ``ValidationTrace`` instead."""

    expected_label: Literal["valid", "invalid"]
    evaluation_metadata: EvaluationMetadata


class Failure(BaseModel):
    model_config = ConfigDict(extra="allow")
    reason: str
    evidence_id: str | None = None
    event_id: str | None = None
    actor_id: str | None = None
    claim_id: str | None = None


class RequirementResult(BaseModel):
    requirement: str
    passed: bool
    failure_type: Literal["direct", "cascading", "mixed"] | None = None
    failures: list[dict] = Field(default_factory=list)


class ValidationResult(BaseModel):
    case_id: str
    trace_id: str
    overall_status: Literal["PASSED", "FAILED"]
    passed_requirements: list[str]
    failed_requirements: list[str]
    requirement_results: list[RequirementResult]
    warnings: list[str]
    failure_count: int
    dataset_origin: dict
    lean_artifact: str | None = None
    lean_artifact_generated: bool = False
    lean_check_status: str = "NOT_RUN"
    lean_check_time_ms: float | None = None
    lean_cold_time_ms: float | None = None
    lean_warm_times_ms: list[float] = Field(default_factory=list)
    lean_obligation_count: int = 0
    lean_stdout: str = ""
    lean_stderr: str = ""
    lean_file_compiled: bool = False
    trace_validity_theorem_emitted: bool = False
    trace_validity_theorem_checked: bool = False
    passed_obligation_count: int = 0
    failed_obligation_count: int = 0
    documented_failed_obligations: list[str] = Field(default_factory=list)
    certificate_kind: Literal["VALIDITY_PROOF", "VIOLATION_PROOF"] | None = None
    invalid_trace_theorem_emitted: bool = False
    invalid_trace_theorem_checked: bool = False
    direct_negative_theorem_count: int = 0
    cascading_negative_theorem_count: int = 0
    negative_theorem_requirements: list[str] = Field(default_factory=list)
