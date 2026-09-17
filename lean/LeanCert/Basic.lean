namespace LeanCert

inductive Role where
  | investigator | custodian | analyst | supervisor | externalReviewer
deriving DecidableEq, Repr

inductive Action where
  | acquire | preserve | transfer | examine | analyze | report | archive | derive
deriving DecidableEq, Repr

structure Actor where
  actorId : String
  name : String
  role : Role
deriving DecidableEq, Repr

structure Evidence where
  evidenceId : String
  caseId : String
  kind : String
  source : String
  hash : String
  sizeBytes : Nat
  parentEvidenceId : Option String
  artifactPath : String
  datasetSource : String
  artifactAvailable : Bool
  artifactHashMatches : Bool
  artifactSizeMatches : Bool
deriving DecidableEq, Repr

structure Event where
  eventId : String
  evidenceId : String
  actorId : String
  action : Action
  sequence : Nat
  timestamp : Int
  prevHolder : Option String
  newHolder : Option String
  prevHash : String
  currHash : String
  hashChangeAllowed : Bool
deriving DecidableEq, Repr

structure ReportClaim where
  claimId : String
  text : String
  supportingEvidenceIds : List String
deriving DecidableEq, Repr

structure Trace where
  caseId : String
  traceId : String
  actors : List Actor
  evidence : List Evidence
  events : List Event
  reportClaims : List ReportClaim
deriving DecidableEq, Repr

end LeanCert
