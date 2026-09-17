import LeanCert.Requirements

namespace LeanCert

example : Authorized Role.investigator Action.acquire := by trivial
example : ChronologicalPair
    { eventId := "1", evidenceId := "e", actorId := "a", action := Action.acquire,
      timestamp := 1, prevHolder := none, newHolder := some "a", prevHash := "GENESIS",
      currHash := "h", hashChangeAllowed := false }
    { eventId := "2", evidenceId := "e", actorId := "a", action := Action.examine,
      timestamp := 2, prevHolder := some "a", newHolder := some "a", prevHash := "h",
      currHash := "h", hashChangeAllowed := false } := by decide

end LeanCert

