import LeanCert.Basic

namespace LeanCert

abbrev NonEmpty (s : String) : Prop := s.length > 0
def nonemptyB (s : String) : Bool := !s.isEmpty
def allB (xs : List α) (p : α → Bool) : Bool := xs.all p
def uniqueB [BEq α] (xs : List α) : Bool := xs.eraseDups.length == xs.length
def memberB [BEq α] (value : α) (xs : List α) : Bool := xs.contains value

def AuthorizedB (role : Role) (action : Action) : Bool :=
  match role, action with
  | .investigator, .acquire | .investigator, .examine
  | .custodian, .preserve | .custodian, .transfer | .custodian, .archive
  | .analyst, .examine | .analyst, .analyze | .analyst, .derive
  | .supervisor, .report | .supervisor, .archive
  | .externalReviewer, .examine => true
  | _, _ => false

abbrev Authorized (role : Role) (action : Action) : Prop := AuthorizedB role action = true
abbrev IdentityCompleteEvidence (e : Evidence) : Prop :=
  nonemptyB e.evidenceId && nonemptyB e.caseId && nonemptyB e.kind && nonemptyB e.source &&
  nonemptyB e.hash && nonemptyB e.artifactPath && nonemptyB e.datasetSource = true
abbrev IdentityCompleteActor (a : Actor) : Prop := nonemptyB a.actorId && nonemptyB a.name = true
abbrev IdentityCompleteEvent (e : Event) : Prop :=
  nonemptyB e.eventId && nonemptyB e.evidenceId && nonemptyB e.actorId && nonemptyB e.currHash = true
abbrev IdentityCompleteClaim (c : ReportClaim) : Prop :=
  nonemptyB c.claimId && nonemptyB c.text && !c.supportingEvidenceIds.isEmpty = true
abbrev ChronologicalPair (a b : Event) : Prop := a.timestamp <= b.timestamp
abbrev HashLinkedPair (a b : Event) : Prop := b.prevHash = a.currHash

-- Identity (REQ-ID-001)
def TraceIdentityPresentB (t : Trace) := nonemptyB t.caseId && nonemptyB t.traceId
def EvidenceIdentityPresentB (t : Trace) := t.evidence.all fun e =>
  nonemptyB e.evidenceId && nonemptyB e.caseId && nonemptyB e.kind && nonemptyB e.source &&
  nonemptyB e.hash && nonemptyB e.artifactPath && nonemptyB e.datasetSource
def ActorIdentityPresentB (t : Trace) := t.actors.all fun a => nonemptyB a.actorId && nonemptyB a.name
def EventIdentityPresentB (t : Trace) := t.events.all fun e =>
  nonemptyB e.eventId && nonemptyB e.evidenceId && nonemptyB e.actorId && nonemptyB e.currHash
def ClaimIdentityPresentB (t : Trace) := t.reportClaims.all fun c =>
  nonemptyB c.claimId && nonemptyB c.text && !c.supportingEvidenceIds.isEmpty
abbrev TraceIdentityPresent (t : Trace) : Prop := TraceIdentityPresentB t = true
abbrev EvidenceIdentityPresent (t : Trace) : Prop := EvidenceIdentityPresentB t = true
abbrev ActorIdentityPresent (t : Trace) : Prop := ActorIdentityPresentB t = true
abbrev EventIdentityPresent (t : Trace) : Prop := EventIdentityPresentB t = true
abbrev ClaimIdentityPresent (t : Trace) : Prop := ClaimIdentityPresentB t = true
def IdentityCompleteB (t : Trace) := TraceIdentityPresentB t && EvidenceIdentityPresentB t &&
  ActorIdentityPresentB t && EventIdentityPresentB t && ClaimIdentityPresentB t
abbrev IdentityComplete (t : Trace) : Prop := IdentityCompleteB t = true

-- Referential integrity (REQ-REF-001)
def UniqueIdentifiersB (t : Trace) := uniqueB (t.evidence.map (·.evidenceId)) &&
  uniqueB (t.actors.map (·.actorId)) && uniqueB (t.events.map (·.eventId)) &&
  uniqueB (t.reportClaims.map (·.claimId))
def EventEvidenceReferenceExistsB (t : Trace) := t.events.all fun e =>
  memberB e.evidenceId (t.evidence.map (·.evidenceId))
def EventActorReferenceExistsB (t : Trace) := t.events.all fun e =>
  memberB e.actorId (t.actors.map (·.actorId))
def ClaimSupportReferenceExistsB (t : Trace) := t.reportClaims.all fun c =>
  c.supportingEvidenceIds.all fun id => memberB id (t.evidence.map (·.evidenceId))
def DerivedParentReferenceExistsB (t : Trace) := t.evidence.all fun e =>
  if e.kind == "derived_artifact" then
    match e.parentEvidenceId with | some id => memberB id (t.evidence.map (·.evidenceId)) | none => false
  else true
abbrev UniqueIdentifiers (t : Trace) : Prop := UniqueIdentifiersB t = true
abbrev EventEvidenceReferenceExists (t : Trace) : Prop := EventEvidenceReferenceExistsB t = true
abbrev EventActorReferenceExists (t : Trace) : Prop := EventActorReferenceExistsB t = true
abbrev ClaimSupportReferenceExists (t : Trace) : Prop := ClaimSupportReferenceExistsB t = true
abbrev DerivedParentReferenceExists (t : Trace) : Prop := DerivedParentReferenceExistsB t = true
def ReferentiallyValidB (t : Trace) := UniqueIdentifiersB t && EventEvidenceReferenceExistsB t &&
  EventActorReferenceExistsB t && ClaimSupportReferenceExistsB t && DerivedParentReferenceExistsB t
abbrev ReferentiallyValid (t : Trace) : Prop := ReferentiallyValidB t = true

-- Artifact integrity (REQ-ART-001). Flags encode measured local byte checks, not labels.
def ArtifactAvailableB (t : Trace) := t.evidence.all (·.artifactAvailable)
def ArtifactSha256MatchesB (t : Trace) := t.evidence.all (·.artifactHashMatches)
def ArtifactSizeMatchesB (t : Trace) := t.evidence.all (·.artifactSizeMatches)
abbrev ArtifactAvailable (t : Trace) : Prop := ArtifactAvailableB t = true
abbrev ArtifactSha256Matches (t : Trace) : Prop := ArtifactSha256MatchesB t = true
abbrev ArtifactSizeMatches (t : Trace) : Prop := ArtifactSizeMatchesB t = true
def ArtifactIntegrityValidB (t : Trace) := ArtifactAvailableB t && ArtifactSha256MatchesB t && ArtifactSizeMatchesB t
abbrev ArtifactIntegrityValid (t : Trace) : Prop := ArtifactIntegrityValidB t = true

def eventsFor (t : Trace) (id : String) := t.events.filter (·.evidenceId == id)
def firstAcquisitionOriginB : List Event → Bool
  | [] => true
  | e :: _ => if e.action == .acquire then e.prevHolder.isNone else true
def holderContinuityB : List Event → Option String → Bool
  | [], _ => true
  | e :: rest, holder =>
      (e.prevHolder == holder) && holderContinuityB rest (e.newHolder.orElse fun _ => holder)
def tailHolderContinuityB : List Event → Bool
  | [] => true
  | e :: rest => holderContinuityB rest e.newHolder
def completeHolderContinuityB : List Event → Bool
  | [] => true
  | e :: rest =>
      if e.action == .acquire then holderContinuityB rest e.newHolder
      else holderContinuityB (e :: rest) none
def AcquisitionOriginB (t : Trace) := t.evidence.all fun e => firstAcquisitionOriginB (eventsFor t e.evidenceId)
def PreviousHolderContinuityB (t : Trace) := t.evidence.all fun e =>
  completeHolderContinuityB (eventsFor t e.evidenceId)
def TransferAssigneeB (t : Trace) := t.events.all fun e => e.action != .transfer || e.newHolder.isSome
def PreservationAssigneeB (t : Trace) := t.events.all fun e => e.action != .preserve || e.newHolder.isSome
abbrev AcquisitionOrigin (t : Trace) : Prop := AcquisitionOriginB t = true
abbrev PreviousHolderContinuity (t : Trace) : Prop := PreviousHolderContinuityB t = true
abbrev TransferAssignee (t : Trace) : Prop := TransferAssigneeB t = true
abbrev PreservationAssignee (t : Trace) : Prop := PreservationAssigneeB t = true
def CustodyContinuousB (t : Trace) := AcquisitionOriginB t && PreviousHolderContinuityB t &&
  TransferAssigneeB t && PreservationAssigneeB t
abbrev CustodyContinuous (t : Trace) : Prop := CustodyContinuousB t = true

def actionBeforeB (events : List Event) (action prerequisite : Action) : Bool :=
  events.all fun e => if e.action == action then events.any fun p => p.action == prerequisite && p.timestamp <= e.timestamp else true
def NonnegativeSequenceTimestampsB (t : Trace) := t.events.all fun a =>
  a.timestamp >= 0 && t.events.all fun b =>
    if a.evidenceId == b.evidenceId && a.sequence < b.sequence then a.timestamp <= b.timestamp else true
def ReportPrerequisitesB (t : Trace) := t.evidence.all fun evidence =>
  let es := eventsFor t evidence.evidenceId
  if evidence.kind == "derived_artifact" then actionBeforeB es .report .derive && actionBeforeB es .report .examine
  else if evidence.kind == "log_file" || evidence.kind == "report" || evidence.kind == "unknown_public_artifact" then
    actionBeforeB es .report .acquire && actionBeforeB es .report .preserve && actionBeforeB es .report .examine
  else actionBeforeB es .report .acquire && actionBeforeB es .report .preserve && actionBeforeB es .report .analyze
def ParentBeforeDerivativeB (t : Trace) := t.evidence.all fun evidence =>
  if evidence.kind == "derived_artifact" then match evidence.parentEvidenceId with
    | none => true
    | some parent => (eventsFor t evidence.evidenceId).all fun d =>
        if d.action == .derive then (eventsFor t parent).any fun p => p.action == .acquire && p.timestamp <= d.timestamp else true
  else true
abbrev NonnegativeSequenceTimestamps (t : Trace) : Prop := NonnegativeSequenceTimestampsB t = true
abbrev ReportPrerequisites (t : Trace) : Prop := ReportPrerequisitesB t = true
abbrev ParentBeforeDerivative (t : Trace) : Prop := ParentBeforeDerivativeB t = true
def ChronologicallyConsistentB (t : Trace) := NonnegativeSequenceTimestampsB t && ReportPrerequisitesB t && ParentBeforeDerivativeB t
abbrev ChronologicallyConsistent (t : Trace) : Prop := ChronologicallyConsistentB t = true

def GenesisLinkB (t : Trace) := t.evidence.all fun e => match eventsFor t e.evidenceId with
  | [] => true | first :: _ => first.action != .acquire || first.prevHash == "GENESIS"
def adjacentHashB : List Event → Bool
  | [] | [_] => true
  | a :: b :: rest => (b.prevHash == a.currHash) && adjacentHashB (b :: rest)
def unchangedHashB : List Event → Bool
  | [] | [_] => true
  | a :: b :: rest =>
      (b.action == .derive || b.hashChangeAllowed || b.currHash == a.currHash) && unchangedHashB (b :: rest)
def AdjacentHashLinkB (t : Trace) := t.evidence.all fun e => adjacentHashB (eventsFor t e.evidenceId)
def UnauthorizedHashUnchangedB (t : Trace) := t.evidence.all fun e => unchangedHashB (eventsFor t e.evidenceId)
def DerivativeHashParentB (t : Trace) := t.events.all fun event =>
  if event.action == .derive then t.evidence.any fun e => e.evidenceId == event.evidenceId && e.parentEvidenceId.isSome else true
abbrev GenesisLink (t : Trace) : Prop := GenesisLinkB t = true
abbrev AdjacentHashLink (t : Trace) : Prop := AdjacentHashLinkB t = true
abbrev UnauthorizedHashUnchanged (t : Trace) : Prop := UnauthorizedHashUnchangedB t = true
abbrev DerivativeHashParent (t : Trace) : Prop := DerivativeHashParentB t = true
def HashContinuousB (t : Trace) := GenesisLinkB t && AdjacentHashLinkB t && UnauthorizedHashUnchangedB t && DerivativeHashParentB t
abbrev HashContinuous (t : Trace) : Prop := HashContinuousB t = true

def RoleResolutionB (t : Trace) := t.events.all fun e => t.actors.any fun a => a.actorId == e.actorId
def RoleActionPermissionB (t : Trace) := t.events.all fun e =>
  match t.actors.find? fun a => a.actorId == e.actorId with
  | none => true -- unresolved identity is owned by the separate RoleResolution child
  | some a => AuthorizedB a.role e.action
abbrev RoleResolution (t : Trace) : Prop := RoleResolutionB t = true
abbrev RoleActionPermission (t : Trace) : Prop := RoleActionPermissionB t = true
def AuthorizedHandlingB (t : Trace) := RoleResolutionB t && RoleActionPermissionB t
abbrev AuthorizedHandling (t : Trace) : Prop := AuthorizedHandlingB t = true

def PreserveAfterAcquireB (t : Trace) := t.evidence.all fun e =>
  actionBeforeB (eventsFor t e.evidenceId) .preserve .acquire && actionBeforeB (eventsFor t e.evidenceId) .transfer .acquire
def AnalyzeAfterPreserveB (t : Trace) := t.evidence.all fun e =>
  if e.kind == "derived_artifact" then actionBeforeB (eventsFor t e.evidenceId) .examine .derive && actionBeforeB (eventsFor t e.evidenceId) .analyze .derive
  else actionBeforeB (eventsFor t e.evidenceId) .examine .preserve && actionBeforeB (eventsFor t e.evidenceId) .analyze .preserve
def ReportAfterAnalysisB (t : Trace) := t.evidence.all fun e =>
  if e.kind == "derived_artifact" || e.kind == "log_file" || e.kind == "report" || e.kind == "unknown_public_artifact"
  then actionBeforeB (eventsFor t e.evidenceId) .report .examine else actionBeforeB (eventsFor t e.evidenceId) .report .analyze
def ArchiveAfterReportB (t : Trace) := t.evidence.all fun e => actionBeforeB (eventsFor t e.evidenceId) .archive .report
def DerivativeParentReadyB (t : Trace) := t.evidence.all fun e =>
  if e.kind == "derived_artifact" then match e.parentEvidenceId with
    | none => true -- parent existence is owned by ReferentialIntegrity/DerivativeHashParent
    | some parent => (eventsFor t parent).any (·.action == .acquire) && (eventsFor t parent).any (·.action == .analyze)
  else true
abbrev PreserveAfterAcquire (t : Trace) : Prop := PreserveAfterAcquireB t = true
abbrev AnalyzeAfterPreserve (t : Trace) : Prop := AnalyzeAfterPreserveB t = true
abbrev ReportAfterAnalysis (t : Trace) : Prop := ReportAfterAnalysisB t = true
abbrev ArchiveAfterReport (t : Trace) : Prop := ArchiveAfterReportB t = true
abbrev DerivativeParentReady (t : Trace) : Prop := DerivativeParentReadyB t = true
def LifecycleCorrectB (t : Trace) := PreserveAfterAcquireB t && AnalyzeAfterPreserveB t &&
  ReportAfterAnalysisB t && ArchiveAfterReportB t && DerivativeParentReadyB t
abbrev LifecycleCorrect (t : Trace) : Prop := LifecycleCorrectB t = true

def ClaimTextPresentB (t : Trace) := t.reportClaims.all fun c => nonemptyB c.text
def ClaimSupportPresentB (t : Trace) := t.reportClaims.all fun c => !c.supportingEvidenceIds.isEmpty
def ClaimSupportResolvedB (t : Trace) := t.reportClaims.all fun c =>
  c.supportingEvidenceIds.all fun id => memberB id (t.evidence.map (·.evidenceId))
def UpstreamSupportValidB (t : Trace) := IdentityCompleteB t && ReferentiallyValidB t &&
  ArtifactIntegrityValidB t && CustodyContinuousB t && ChronologicallyConsistentB t &&
  HashContinuousB t && AuthorizedHandlingB t && LifecycleCorrectB t
abbrev UpstreamSupportValid (t : Trace) : Prop := UpstreamSupportValidB t = true
abbrev ClaimTextPresent (t : Trace) : Prop := ClaimTextPresentB t = true
abbrev ClaimSupportPresent (t : Trace) : Prop := ClaimSupportPresentB t = true
abbrev ClaimSupportResolved (t : Trace) : Prop := ClaimSupportResolvedB t = true
def ReportTraceableB (t : Trace) := ClaimTextPresentB t && ClaimSupportPresentB t && ClaimSupportResolvedB t && UpstreamSupportValidB t
abbrev ReportTraceable (t : Trace) : Prop := ReportTraceableB t = true

abbrev ValidTrace (t : Trace) : Prop := IdentityComplete t ∧ ReferentiallyValid t ∧
  ArtifactIntegrityValid t ∧ CustodyContinuous t ∧ ChronologicallyConsistent t ∧
  HashContinuous t ∧ AuthorizedHandling t ∧ LifecycleCorrect t ∧ ReportTraceable t

-- Parent/child hierarchy is definitional; projections and iff audits are kernel checked.
theorem identity_parent_iff_children (t : Trace) : IdentityComplete t ↔
    TraceIdentityPresent t ∧ EvidenceIdentityPresent t ∧ ActorIdentityPresent t ∧ EventIdentityPresent t ∧ ClaimIdentityPresent t := by
  simp only [IdentityComplete, IdentityCompleteB, Bool.and_eq_true, and_assoc]
theorem reference_parent_iff_children (t : Trace) : ReferentiallyValid t ↔
    UniqueIdentifiers t ∧ EventEvidenceReferenceExists t ∧ EventActorReferenceExists t ∧ ClaimSupportReferenceExists t ∧ DerivedParentReferenceExists t := by
  simp only [ReferentiallyValid, ReferentiallyValidB, Bool.and_eq_true, and_assoc]
theorem artifact_parent_iff_children (t : Trace) : ArtifactIntegrityValid t ↔ ArtifactAvailable t ∧ ArtifactSha256Matches t ∧ ArtifactSizeMatches t := by
  simp only [ArtifactIntegrityValid, ArtifactIntegrityValidB, Bool.and_eq_true, and_assoc]
theorem custody_parent_iff_children (t : Trace) : CustodyContinuous t ↔ AcquisitionOrigin t ∧ PreviousHolderContinuity t ∧ TransferAssignee t ∧ PreservationAssignee t := by
  simp only [CustodyContinuous, CustodyContinuousB, Bool.and_eq_true, and_assoc]
theorem chronology_parent_iff_children (t : Trace) : ChronologicallyConsistent t ↔ NonnegativeSequenceTimestamps t ∧ ReportPrerequisites t ∧ ParentBeforeDerivative t := by
  simp only [ChronologicallyConsistent, ChronologicallyConsistentB, Bool.and_eq_true, and_assoc]
theorem hash_parent_iff_children (t : Trace) : HashContinuous t ↔ GenesisLink t ∧ AdjacentHashLink t ∧ UnauthorizedHashUnchanged t ∧ DerivativeHashParent t := by
  simp only [HashContinuous, HashContinuousB, Bool.and_eq_true, and_assoc]
theorem authorization_parent_iff_children (t : Trace) : AuthorizedHandling t ↔ RoleResolution t ∧ RoleActionPermission t := by
  simp only [AuthorizedHandling, AuthorizedHandlingB, Bool.and_eq_true]
theorem lifecycle_parent_iff_children (t : Trace) : LifecycleCorrect t ↔ PreserveAfterAcquire t ∧ AnalyzeAfterPreserve t ∧ ReportAfterAnalysis t ∧ ArchiveAfterReport t ∧ DerivativeParentReady t := by
  simp only [LifecycleCorrect, LifecycleCorrectB, Bool.and_eq_true, and_assoc]
theorem reporting_parent_iff_children (t : Trace) : ReportTraceable t ↔ ClaimTextPresent t ∧ ClaimSupportPresent t ∧ ClaimSupportResolved t ∧ UpstreamSupportValid t := by
  simp only [ReportTraceable, ReportTraceableB, Bool.and_eq_true, and_assoc]

-- Every declared catalogue child is a logical projection of its parent.
theorem identity_implies_trace_identity {t : Trace} (h : IdentityComplete t) : TraceIdentityPresent t := ((identity_parent_iff_children t).mp h).1
theorem identity_implies_evidence_identity {t : Trace} (h : IdentityComplete t) : EvidenceIdentityPresent t := ((identity_parent_iff_children t).mp h).2.1
theorem identity_implies_actor_identity {t : Trace} (h : IdentityComplete t) : ActorIdentityPresent t := ((identity_parent_iff_children t).mp h).2.2.1
theorem identity_implies_event_identity {t : Trace} (h : IdentityComplete t) : EventIdentityPresent t := ((identity_parent_iff_children t).mp h).2.2.2.1
theorem identity_implies_claim_identity {t : Trace} (h : IdentityComplete t) : ClaimIdentityPresent t := ((identity_parent_iff_children t).mp h).2.2.2.2
theorem reference_implies_unique_identifiers {t : Trace} (h : ReferentiallyValid t) : UniqueIdentifiers t := ((reference_parent_iff_children t).mp h).1
theorem reference_implies_event_evidence {t : Trace} (h : ReferentiallyValid t) : EventEvidenceReferenceExists t := ((reference_parent_iff_children t).mp h).2.1
theorem reference_implies_event_actor {t : Trace} (h : ReferentiallyValid t) : EventActorReferenceExists t := ((reference_parent_iff_children t).mp h).2.2.1
theorem reference_implies_claim_support {t : Trace} (h : ReferentiallyValid t) : ClaimSupportReferenceExists t := ((reference_parent_iff_children t).mp h).2.2.2.1
theorem reference_implies_derived_parent {t : Trace} (h : ReferentiallyValid t) : DerivedParentReferenceExists t := ((reference_parent_iff_children t).mp h).2.2.2.2
theorem artifact_implies_available {t : Trace} (h : ArtifactIntegrityValid t) : ArtifactAvailable t := ((artifact_parent_iff_children t).mp h).1
theorem artifact_implies_sha256 {t : Trace} (h : ArtifactIntegrityValid t) : ArtifactSha256Matches t := ((artifact_parent_iff_children t).mp h).2.1
theorem artifact_implies_size {t : Trace} (h : ArtifactIntegrityValid t) : ArtifactSizeMatches t := ((artifact_parent_iff_children t).mp h).2.2
theorem custody_implies_acquisition_origin {t : Trace} (h : CustodyContinuous t) : AcquisitionOrigin t := ((custody_parent_iff_children t).mp h).1
theorem custody_implies_previous_holder {t : Trace} (h : CustodyContinuous t) : PreviousHolderContinuity t := ((custody_parent_iff_children t).mp h).2.1
theorem custody_implies_transfer_assignee {t : Trace} (h : CustodyContinuous t) : TransferAssignee t := ((custody_parent_iff_children t).mp h).2.2.1
theorem custody_implies_preservation_assignee {t : Trace} (h : CustodyContinuous t) : PreservationAssignee t := ((custody_parent_iff_children t).mp h).2.2.2
theorem chronology_implies_nonnegative_sequence {t : Trace} (h : ChronologicallyConsistent t) : NonnegativeSequenceTimestamps t := ((chronology_parent_iff_children t).mp h).1
theorem chronology_implies_report_prerequisites {t : Trace} (h : ChronologicallyConsistent t) : ReportPrerequisites t := ((chronology_parent_iff_children t).mp h).2.1
theorem chronology_implies_parent_before_derivative {t : Trace} (h : ChronologicallyConsistent t) : ParentBeforeDerivative t := ((chronology_parent_iff_children t).mp h).2.2
theorem hash_implies_genesis {t : Trace} (h : HashContinuous t) : GenesisLink t := ((hash_parent_iff_children t).mp h).1
theorem hash_implies_adjacent {t : Trace} (h : HashContinuous t) : AdjacentHashLink t := ((hash_parent_iff_children t).mp h).2.1
theorem hash_implies_unchanged {t : Trace} (h : HashContinuous t) : UnauthorizedHashUnchanged t := ((hash_parent_iff_children t).mp h).2.2.1
theorem hash_implies_derivative_parent {t : Trace} (h : HashContinuous t) : DerivativeHashParent t := ((hash_parent_iff_children t).mp h).2.2.2
theorem authorization_implies_role_resolution {t : Trace} (h : AuthorizedHandling t) : RoleResolution t := ((authorization_parent_iff_children t).mp h).1
theorem authorization_implies_role_action {t : Trace} (h : AuthorizedHandling t) : RoleActionPermission t := ((authorization_parent_iff_children t).mp h).2
theorem lifecycle_implies_preserve_after_acquire {t : Trace} (h : LifecycleCorrect t) : PreserveAfterAcquire t := ((lifecycle_parent_iff_children t).mp h).1
theorem lifecycle_implies_analyze_after_preserve {t : Trace} (h : LifecycleCorrect t) : AnalyzeAfterPreserve t := ((lifecycle_parent_iff_children t).mp h).2.1
theorem lifecycle_implies_report_after_analysis {t : Trace} (h : LifecycleCorrect t) : ReportAfterAnalysis t := ((lifecycle_parent_iff_children t).mp h).2.2.1
theorem lifecycle_implies_archive_after_report {t : Trace} (h : LifecycleCorrect t) : ArchiveAfterReport t := ((lifecycle_parent_iff_children t).mp h).2.2.2.1
theorem lifecycle_implies_derivative_parent_ready {t : Trace} (h : LifecycleCorrect t) : DerivativeParentReady t := ((lifecycle_parent_iff_children t).mp h).2.2.2.2
theorem reporting_implies_claim_text {t : Trace} (h : ReportTraceable t) : ClaimTextPresent t := ((reporting_parent_iff_children t).mp h).1
theorem reporting_implies_support_present {t : Trace} (h : ReportTraceable t) : ClaimSupportPresent t := ((reporting_parent_iff_children t).mp h).2.1
theorem reporting_implies_support_resolved {t : Trace} (h : ReportTraceable t) : ClaimSupportResolved t := ((reporting_parent_iff_children t).mp h).2.2.1
theorem reporting_implies_upstream_support {t : Trace} (h : ReportTraceable t) : UpstreamSupportValid t := ((reporting_parent_iff_children t).mp h).2.2.2

theorem validTrace_implies_identity {t : Trace} (h : ValidTrace t) : IdentityComplete t := h.1
theorem validTrace_implies_referential_integrity {t : Trace} (h : ValidTrace t) : ReferentiallyValid t := h.2.1
theorem validTrace_implies_artifact_integrity {t : Trace} (h : ValidTrace t) : ArtifactIntegrityValid t := h.2.2.1
theorem validTrace_implies_custody {t : Trace} (h : ValidTrace t) : CustodyContinuous t := h.2.2.2.1
theorem validTrace_implies_chronology {t : Trace} (h : ValidTrace t) : ChronologicallyConsistent t := h.2.2.2.2.1
theorem validTrace_implies_hash_continuity {t : Trace} (h : ValidTrace t) : HashContinuous t := h.2.2.2.2.2.1
theorem validTrace_implies_authorization {t : Trace} (h : ValidTrace t) : AuthorizedHandling t := h.2.2.2.2.2.2.1
theorem validTrace_implies_lifecycle {t : Trace} (h : ValidTrace t) : LifecycleCorrect t := h.2.2.2.2.2.2.2.1
theorem validTrace_implies_report_traceability {t : Trace} (h : ValidTrace t) : ReportTraceable t := h.2.2.2.2.2.2.2.2

end LeanCert
