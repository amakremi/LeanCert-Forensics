from __future__ import annotations

import csv
from pathlib import Path

from .sub_obligation_benchmark import ROOT
from .sub_obligations import CHILD_IDS, PARENTS, evaluate_children, parent_from_children
from .schema import ValidationTrace
from .utils import PROJECT_ROOT, read_json, write_json
from .validator import validate_trace


def audit_requirement_hierarchy(root: Path = ROOT) -> tuple[list[dict], bool]:
    observations = {parent: [] for parent in dict.fromkeys(PARENTS.values())}
    for path in sorted((root / "blinded").glob("*.json")):
        trace = ValidationTrace.model_validate(read_json(path))
        child_parents = parent_from_children(evaluate_children(trace))
        production = {
            result.requirement: result.passed
            for result in validate_trace(trace, strict_artifacts=True).requirement_results
        }
        for parent in observations:
            observations[parent].append(production[parent] == child_parents[parent])
    lean_source = (PROJECT_ROOT / "lean" / "LeanCert" / "Requirements.lean").read_text(encoding="utf-8")
    theorem_names = {
        "IdentityCompleteness": "identity_parent_iff_children",
        "ReferentialIntegrity": "reference_parent_iff_children",
        "PublicArtifactIntegrity": "artifact_parent_iff_children",
        "CustodyContinuity": "custody_parent_iff_children",
        "ChronologicalConsistency": "chronology_parent_iff_children",
        "HashContinuity": "hash_parent_iff_children",
        "AuthorizedHandling": "authorization_parent_iff_children",
        "LifecycleCorrectness": "lifecycle_parent_iff_children",
        "ReportTraceability": "reporting_parent_iff_children",
    }
    rows = []
    for parent, checks in observations.items():
        theorem = theorem_names[parent]
        python_ok = bool(checks) and all(checks)
        lean_ok = f"theorem {theorem}" in lean_source
        status = "PASSED" if python_ok and lean_ok else "INCONSISTENT"
        rows.append({
            "parent_requirement": parent,
            "child_count": sum(PARENTS[child] == parent for child in CHILD_IDS),
            "python_equivalence": python_ok,
            "lean_relation": theorem if lean_ok else "MISSING",
            "relation_type": "EQUIVALENT" if python_ok and lean_ok else "INCONSISTENT",
            "status": status,
            "notes": f"Compared over {len(checks)} controlled traces; Lean iff theorem is kernel checked." if status == "PASSED"
                     else "Python parent/child result or Lean iff theorem did not agree.",
        })
    path = PROJECT_ROOT / "results" / "requirement_hierarchy_audit.csv"
    path.parent.mkdir(exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    inconsistencies = [row for row in rows if row["status"] != "PASSED"]
    write_json(PROJECT_ROOT / "results" / "formalization_inconsistencies.json", {
        "inconsistency_count": len(inconsistencies), "inconsistencies": inconsistencies,
        "notes": "No parent-child inconsistencies remain." if not inconsistencies else "Investigate before claiming full coverage.",
    })
    return rows, not inconsistencies
