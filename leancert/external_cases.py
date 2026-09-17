from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .utils import PROJECT_ROOT, read_json, safe_filename, utc_now, write_json

ROOT = PROJECT_ROOT / "external_cases"
SCHEMA_PATH = ROOT / "external_case_schema.json"
SUMMARY_PATH = PROJECT_ROOT / "results" / "external_case_summary.json"
TABLE_PATH = PROJECT_ROOT / "results" / "paper_tables" / "table_external_case_status.md"


def import_external_cases(directory: Path) -> dict[str, Any]:
    schema = read_json(SCHEMA_PATH)
    required = set(schema.get("required", []))
    normalized = ROOT / "normalized"
    normalized.mkdir(parents=True, exist_ok=True)
    imported = []
    rejected = []
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                rejected.append({"file": str(path), "error": "Case must be a JSON object."})
                continue
            missing = sorted(required - set(raw))
            if missing:
                rejected.append({"file": str(path), "error": f"Missing fields: {', '.join(missing)}"})
                continue
            if not raw["labels_independently_supplied"]:
                rejected.append({"file": str(path), "error": "Labels were not independently supplied."})
                continue
            target = normalized / safe_filename(f"{raw['case_id']}.json")
            shutil.copyfile(path, target)
            imported.append(raw["case_id"])
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            rejected.append({"file": str(path), "error": str(exc)})
    summary = {
        "generated_at_utc": utc_now(),
        "natural_external_case_count": len(imported),
        "natural_external_evaluation_status": "AVAILABLE" if imported else "NOT_AVAILABLE",
        "imported_case_ids": imported,
        "rejected_inputs": rejected,
        "residual_limitation": (
            "" if imported else
            "No independently labeled natural chain-of-custody failure corpus was available."
        ),
    }
    write_json(SUMMARY_PATH, summary)
    TABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TABLE_PATH.write_text(
        "| Metric | Value |\n|---|---|\n"
        f"| Independently labeled case count | {len(imported)} |\n"
        f"| Evaluation status | {summary['natural_external_evaluation_status']} |\n"
        f"| Residual limitation | {summary['residual_limitation'] or '—'} |\n",
        encoding="utf-8",
    )
    return summary
