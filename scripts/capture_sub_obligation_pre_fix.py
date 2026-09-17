from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
catalogue_path = root / "formalization" / "requirements_catalog.yaml"
document = yaml.safe_load(catalogue_path.read_text(encoding="utf-8"))
current_lean = {
    "evidence identity": "IdentityCompleteEvidence",
    "actor identity": "IdentityCompleteActor",
    "event identity": "IdentityCompleteEvent",
    "claim identity": "IdentityCompleteClaim",
    "non-negative timestamps": "ChronologicalPair",
    "adjacent link": "HashLinkedPair",
    "role-action permission": "Authorized",
}
rows = []
for parent in document["requirements"]:
    for index, description in enumerate(parent.get("sub_obligations", []), 1):
        rows.append({
            "sub_obligation_id": f"{parent['requirement_id']}-SUB-{index:02d}",
            "parent_requirement": parent["name"],
            "description": description,
            "python_mapping": {
                "module": "leancert.validator", "function": parent["python_check"],
                "branch": description,
            },
            "lean_mapping": current_lean.get(description),
            "positive_tests": parent.get("positive_test_ids", []),
            "negative_tests": parent.get("negative_test_ids", []),
            "holdout_mappings": parent.get("benchmark_mutations", []),
            "known_exclusions": parent.get("known_exclusions", []),
        })
output = {
    "declared_parent_requirements": len(document["requirements"]),
    "declared_sub_obligations": len(rows),
    "catalogue_sha256_before": hashlib.sha256(catalogue_path.read_bytes()).hexdigest(),
    "sub_obligations": rows,
}
destination = root / "results" / "formalization_catalogue_pre_fix.json"
destination.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(output["catalogue_sha256_before"], len(rows))
