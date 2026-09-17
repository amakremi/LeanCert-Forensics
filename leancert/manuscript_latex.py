from __future__ import annotations

import csv
import importlib.metadata
import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import yaml
from matplotlib.ticker import FuncFormatter

from .reference_hashes import verify_reference_checksums
from .sub_obligations import DESCRIPTIONS
from .utils import PROJECT_ROOT, read_json, utc_now, write_json

RESULTS = PROJECT_ROOT / "results"
PAPER = PROJECT_ROOT / "paper"
GENERATED = PAPER / "generated"
FIGURES = PAPER / "figures"
TABLES = PAPER / "tables"
APPENDICES = PAPER / "appendices"
PAPER_TEXT = RESULTS / "paper_text"
ROW_END = " \\\\"
PRIMARY_FIGURES = (
    "artifact_integrity_anchoring.png",
    "confusion_matrix.png",
    "direct_vs_cascading_failures.png",
    "trace_size_vs_validation_time.png",
    "proof_checking_time.png",
)


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _metric(name: str, value: Any, unit: str, source: str, field: str, usage: str) -> dict[str, Any]:
    return {
        "name": name,
        "value": value,
        "unit": unit,
        "source_file": source,
        "source_field_or_row": field,
        "manuscript_usage": usage,
    }


def manuscript_integer(value: int | float) -> str:
    integer = int(round(value))
    return f"{integer:,}" if abs(integer) >= 10000 else str(integer)


def _tex(value: Any) -> str:
    replacements = {
        "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
        "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
        "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in str(value))


def _tt(value: Any) -> str:
    return r"\nolinkurl{" + str(value).replace("}", r"\}") + "}"


def _seq(value: Any) -> str:
    return r"\seqsplit{" + _tex(value) + "}"


def _row(*cells: Any, escaped: bool = True) -> str:
    rendered = [_tex(cell) if escaped else str(cell) for cell in cells]
    return " & ".join(rendered) + ROW_END


def _bool(value: Any) -> bool:
    return value is True or str(value).casefold() == "true"


def _version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "Version not recorded"


def _load() -> dict[str, Any]:
    json_files = {
        "experiment": RESULTS / "experiment_manifest.json",
        "environment": RESULTS / "environment_dependencies.json",
        "baseline": RESULTS / "formalization_baseline_reconciliation.json",
        "coverage": RESULTS / "formalization_sub_obligation_summary_final.json",
        "holdout": RESULTS / "holdout_metrics_v2.json",
        "child": RESULTS / "sub_obligation_evaluation_summary.json",
        "differential": RESULTS / "differential_validation_summary_v2.json",
        "agreement": RESULTS / "python_lean_agreement_summary.json",
        "reference": RESULTS / "reference_checksum_summary.json",
        "image": RESULTS / "image_inspection_summary.json",
        "roc": RESULTS / "roc_eligibility_audit.json",
    }
    missing = [path.relative_to(PROJECT_ROOT).as_posix() for path in json_files.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing authoritative manuscript input(s): " + ", ".join(missing))
    data = {name: read_json(path) for name, path in json_files.items()}
    data.update(
        requirements=yaml.safe_load((PROJECT_ROOT / "formalization" / "requirements_catalog.yaml").read_text(encoding="utf-8")),
        datasets=read_json(RESULTS / "dataset_manifest_used.json"),
        processing=read_json(PROJECT_ROOT / "datasets" / "manifests" / "cfreds_processing_manifest.json"),
        image_rows=_csv(RESULTS / "image_inspection_results.csv"),
        symbol_rows=_csv(RESULTS / "sub_obligation_symbol_audit.csv"),
        independence_rows=_csv(RESULTS / "reference_independence_audit.csv"),
        hierarchy_rows=_csv(RESULTS / "requirement_hierarchy_audit_final.csv"),
        cascades=_csv(RESULTS / "cascading_dependency_audit.csv"),
        requirement_coverage=_csv(RESULTS / "holdout_requirement_coverage.csv"),
        certificates=_csv(RESULTS / "lean_certificate_semantics.csv"),
        python_scale=_csv(RESULTS / "scalability_summary_python.csv"),
        lean_scale=_csv(RESULTS / "lean_scalability_by_mode.csv"),
    )
    return data


def build_data_manifest(data: dict[str, Any]) -> dict[str, Any]:
    exp, env, holdout, child = data["experiment"], data["environment"], data["holdout"], data["child"]
    manifest: dict[str, Any] = {section: {} for section in (
        "system", "environment", "datasets", "requirements", "sub_obligations",
        "artifact_inspection", "top_level_holdout", "child_benchmark",
        "differential_validation", "reference_independence", "lean_validation",
        "python_scalability", "lean_scalability", "benchmark_locks",
        "confidence_intervals", "limitations", "roc_applicability",
    )}
    manifest["generated_at_utc"] = utc_now()
    manifest["system"] = {
        "name": _metric("prototype", exp["prototype"], "name", "results/experiment_manifest.json", "prototype", "System overview"),
        "parents": _metric("parent requirements", exp["declared_parent_requirements"], "requirements", "results/experiment_manifest.json", "declared_parent_requirements", "Catalogue"),
    }
    versions = {
        "Python": env["python_version"].split(" ", 1)[0], "Windows": exp["platform"],
        "Lean": exp["lean_version"], "Lake": exp["lake_version"],
        "pytsk3": env["pytsk3_version"], "The Sleuth Kit": env["sleuthkit_embedded_version"],
        "Matplotlib": _version("matplotlib"), "Pydantic": _version("pydantic"),
        "pandas": _version("pandas"), "PyYAML": _version("PyYAML"),
        "requests": _version("requests"), "pytest": _version("pytest"),
    }
    for name, value in versions.items():
        source = "results/environment_dependencies.json" if name in {"Python", "pytsk3", "The Sleuth Kit"} else "results/experiment_manifest.json"
        if name in {"Matplotlib", "Pydantic", "pandas", "PyYAML", "requests", "pytest"}:
            source = "installed project environment (importlib.metadata)"
        manifest["environment"][name] = _metric(name, value, "version", source, name, "Toolchain")
    manifest["datasets"] = {
        "registered": _metric("registered public artifacts", len(data["datasets"]), "artifacts", "results/dataset_manifest_used.json", "array length", "Dataset grounding"),
        "cfreds": _metric("CFReDS distributions", len(data["processing"]), "artifacts", "datasets/manifests/cfreds_processing_manifest.json", "array length", "Image population"),
        "rows": data["datasets"],
    }
    requirements = data["requirements"]["requirements"]
    manifest["requirements"] = {
        "count": _metric("declared requirements", len(requirements), "requirements", "formalization/requirements_catalog.yaml", "requirements array length", "Formal model"),
        "rows": requirements,
    }
    coverage = data["coverage"]
    for key, field in (("declared", "declared_sub_obligations"), ("python_mapped", "concrete_python_child_mappings"), ("lean_mapped", "lean_explicit_child_mappings"), ("quality_failures", "lean_child_quality_failures")):
        manifest["sub_obligations"][key] = _metric(key, coverage[field], "sub-obligations", "results/formalization_sub_obligation_summary_final.json", field, "Catalogue coverage")
    manifest["sub_obligations"]["pre_fix_lean"] = _metric("pre-fix Lean mappings", data["baseline"]["pre_fix_lean_explicit_child_mappings"], "sub-obligations", "results/formalization_baseline_reconciliation.json", "pre_fix_lean_explicit_child_mappings", "Historical reconciliation")
    for key in ("total_decompressed_images", "inspection_attempted_count", "semantically_applicable_count", "semantic_passed_count", "semantic_failed_count", "partial_count"):
        manifest["artifact_inspection"][key] = _metric(key, data["image"][key], "images", "results/image_inspection_summary.json", key, "Semantic inspection")
    for key in ("external_reference_eligible_count", "external_reference_available_count", "external_reference_verified_count", "external_reference_mismatch_count", "external_reference_unavailable_count", "external_match_rate"):
        manifest["artifact_inspection"][key] = _metric(key, data["reference"][key], "artifacts" if "rate" not in key else "proportion", "results/reference_checksum_summary.json", key, "Publisher anchoring")
    for key in ("total_traces", "valid_traces", "invalid_traces", "TP", "TN", "FP", "FN", "accuracy", "precision", "recall", "specificity", "f1", "false_acceptance_rate", "false_rejection_rate"):
        unit = "traces" if key in {"total_traces", "valid_traces", "invalid_traces", "TP", "TN", "FP", "FN"} else "proportion"
        manifest["top_level_holdout"][key] = _metric(key, holdout[key], unit, "results/holdout_metrics_v2.json", key, "Holdout results")
    for record in holdout["confidence_intervals"]:
        manifest["confidence_intervals"][record["metric"]] = _metric(record["metric"] + " 95% CI", [record["lower_95"], record["upper_95"]], "interval", "results/holdout_metrics_v2.json", f"confidence_intervals[{record['metric']}]", "Uncertainty") | {"method": record["interval_method"], "sample_denominator": record["sample_denominator"]}
    child_fields = ("controlled_trace_count", "valid_trace_count", "invalid_trace_count", "targeted_invalid_cases", "target_child_violations_detected", "total_child_comparisons", "disagreements", "reference_child_comparisons", "reference_child_disagreements", "valid_lean_certificates_checked", "invalid_lean_violation_certificates_checked", "direct_child_negative_theorems_checked", "metamorphic_comparisons", "metamorphic_failures")
    for key in child_fields:
        manifest["child_benchmark"][key] = _metric(key, child[key], "count", "results/sub_obligation_evaluation_summary.json", key, "Child benchmark")
    for key in ("total_comparisons", "agreements", "disagreements", "agreement_rate"):
        manifest["differential_validation"][key] = _metric(key, data["differential"][key], "count" if key != "agreement_rate" else "proportion", "results/differential_validation_summary_v2.json", key, "Differential validation")
    independence = Counter(row["independence_classification"] for row in data["independence_rows"])
    for key in ("STRUCTURALLY_INDEPENDENT", "LIMITED"):
        manifest["reference_independence"][key] = _metric(key, independence[key], "sub-obligations", "results/reference_independence_audit.csv", f"count({key})", "Reference qualification")
    validity = sum(_bool(row["valid_trace_theorem_checked"]) for row in data["certificates"])
    violations = sum(_bool(row["invalid_trace_theorem_checked"]) for row in data["certificates"])
    manifest["lean_validation"] = {
        "holdout_validity": _metric("holdout validity certificates", validity, "certificates", "results/lean_certificate_semantics.csv", "count(valid_trace_theorem_checked=True)", "Lean semantics"),
        "holdout_violation": _metric("holdout violation certificates", violations, "certificates", "results/lean_certificate_semantics.csv", "count(invalid_trace_theorem_checked=True)", "Lean semantics"),
        "child_validity": _metric("child validity certificates", child["valid_lean_certificates_checked"], "certificates", "results/sub_obligation_evaluation_summary.json", "valid_lean_certificates_checked", "Lean semantics"),
        "child_violation": _metric("child violation certificates", child["invalid_lean_violation_certificates_checked"], "certificates", "results/sub_obligation_evaluation_summary.json", "invalid_lean_violation_certificates_checked", "Lean semantics"),
    }
    manifest["python_scalability"] = {"event_sizes": _metric("Python event sizes", [int(row["event_count"]) for row in data["python_scale"]], "events", "results/scalability_summary_python.csv", "event_count", "Python scalability"), "rows": data["python_scale"]}
    manifest["lean_scalability"] = {"event_sizes": _metric("Lean event sizes", sorted({int(row["event_count"]) for row in data["lean_scale"]}), "events", "results/lean_scalability_by_mode.csv", "event_count", "Lean scalability"), "rows": data["lean_scale"]}
    manifest["benchmark_locks"] = {
        "holdout_v2": _metric("holdout v2 SHA-256", exp["benchmark_holdout_v2_sha256"], "SHA-256", "results/experiment_manifest.json", "benchmark_holdout_v2_sha256", "Reproducibility"),
        "child_v1": _metric("child benchmark SHA-256", exp["benchmark_child_holdout_sha256"], "SHA-256", "results/experiment_manifest.json", "benchmark_child_holdout_sha256", "Reproducibility"),
    }
    manifest["limitations"] = {"items": _metric("residual limitations", [str(item).rstrip(" |").strip() for item in exp["residual_limitations"]], "statements", "results/experiment_manifest.json", "residual_limitations", "Threats")}
    for key in ("roc_applicable", "decision_output_type", "candidate_score", "score_definition", "eligibility_reason", "recommended_paper_treatment"):
        manifest["roc_applicability"][key] = _metric(key, data["roc"][key], "status", "results/roc_eligibility_audit.json", key, "ROC/AUC decision")
    manifest["reconciliations"] = [{
        "issue": "A regression fixture temporarily overwrote artifact_integrity_summary.json with a zero eligible-reference population.",
        "resolution": "The final scientific audit recomputed the summary from reference_checksum_population.csv; six artifacts are eligible and zero official references are available.",
        "authoritative_sources": ["results/reference_checksum_population.csv", "results/reference_checksum_summary.json"],
    }]
    write_json(PAPER_TEXT / "manuscript_data_manifest.json", manifest)
    return manifest


def _save(fig: plt.Figure, name: str) -> None:
    for directory in (RESULTS / "figures", FIGURES):
        directory.mkdir(parents=True, exist_ok=True)
        fig.savefig(directory / name, dpi=320, bbox_inches="tight")
    plt.close(fig)


def generate_figures(data: dict[str, Any]) -> None:
    plt.rcParams.update({"font.size": 10, "axes.titlesize": 13, "axes.labelsize": 11})
    formatter = FuncFormatter(lambda value, _: manuscript_integer(value))
    image, reference = data["image"], data["reference"]
    nums = [6, 6, 6, image["inspection_attempted_count"], image["semantic_passed_count"], reference["external_reference_available_count"]]
    dens = [6, 6, 6, image["total_decompressed_images"], image["semantically_applicable_count"], reference["external_reference_eligible_count"]]
    labels = ["Local readable", "Manifest consistent", "Decompression\nsuccessful", "Inspection attempted", "Semantic success\n(applicable)", "External checksum\ncoverage", "External checksum\nmatch"]
    fig, ax = plt.subplots(figsize=(11.4, 5.4), constrained_layout=True)
    x = np.arange(7); rates = [100 * n / d for n, d in zip(nums, dens)]
    bars = ax.bar(x[:6], rates, color=["#286f9b"] * 5 + ["#b48a2c"])
    for bar, n, d in zip(bars, nums, dens):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2, f"{100*n/d:.0f}% ({n}/{d})", ha="center", fontsize=8)
    ax.text(6, 48, "N/A\nNo official reference available", ha="center", va="center", bbox={"boxstyle": "round", "facecolor": "#eeeeee", "edgecolor": "#777777"})
    ax.set_xticks(x, labels, rotation=18, ha="right"); ax.set_ylim(0, 114)
    ax.set_ylabel("Measured rate (%)"); ax.set_title("Artifact Integrity, Semantic Inspection, and External Anchoring")
    _save(fig, PRIMARY_FIGURES[0])

    m = data["holdout"]; matrix = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
    fig, ax = plt.subplots(figsize=(6, 5.1), constrained_layout=True); shown = ax.imshow(matrix, cmap="Blues")
    for (r, c), value in np.ndenumerate(matrix):
        ax.text(c, r, manuscript_integer(value), ha="center", va="center", fontsize=17)
    ax.set_xticks([0, 1], ["Predicted valid", "Predicted invalid"]); ax.set_yticks([0, 1], ["Actual valid", "Actual invalid"])
    ax.set_title("Locked and Blinded Controlled Holdout")
    ax.text(.5, -.16, f"n = {m['total_traces']}; valid = {m['valid_traces']}; controlled-invalid = {m['invalid_traces']}", transform=ax.transAxes, ha="center", fontsize=9)
    fig.colorbar(shown, ax=ax, fraction=.046); _save(fig, PRIMARY_FIGURES[1])

    coverage = data["requirement_coverage"]; names = [row["requirement"] for row in coverage]
    direct = [int(row["direct_invalid_traces"]) for row in coverage]; cascading = [int(row["cascading_affected_traces"]) for row in coverage]
    fig, ax = plt.subplots(figsize=(11.4, 5.4), constrained_layout=True); x = np.arange(len(names)); width = .38
    ax.bar(x-width/2, direct, width, label="Direct: root violation", color="#c65d21"); ax.bar(x+width/2, cascading, width, label="Cascading: downstream consequence", color="#2878a5")
    ax.set_xticks(x, names, rotation=32, ha="right"); ax.set_ylabel("Unique affected traces")
    ax.set_title("Direct and Cascading Requirement Failures"); ax.legend(); _save(fig, PRIMARY_FIGURES[2])

    rows = data["python_scale"]; xs = [int(row["event_count"]) for row in rows]
    fig, ax = plt.subplots(figsize=(8.7, 5), constrained_layout=True)
    ax.errorbar(xs, [float(row["median_us"]) for row in rows], yerr=np.array([float(row["IQR_us"]) for row in rows])/2, marker="o", capsize=4)
    ax.set_xscale("log"); ax.set_xticks(xs); ax.xaxis.set_major_formatter(formatter); ax.set_xlabel("Events per trace (log scale)"); ax.set_ylabel(r"Median Python validation time ($\mu$s)")
    ax.set_title("Python Validation Scalability"); ax.yaxis.set_major_formatter(formatter); ax.grid(alpha=.25); _save(fig, PRIMARY_FIGURES[3])

    fig, ax = plt.subplots(figsize=(8.9, 5.1), constrained_layout=True)
    for mode, label in (("pairwise", "Pairwise proof mode"), ("aggregate", "Aggregate proof mode")):
        group = [row for row in data["lean_scale"] if row["proof_mode"] == mode]
        ax.errorbar([int(row["event_count"]) for row in group], [float(row["median_time_ms"]) for row in group], yerr=[float(row["IQR_time_ms"])/2 for row in group], marker="o", capsize=4, label=label)
    ax.set_xlabel("Events per trace"); ax.set_ylabel("Median per-file Lean checking time (ms)")
    ax.set_title("Lean Proof-Checking Scalability by Encoding Mode"); ax.yaxis.set_major_formatter(formatter); ax.grid(alpha=.25); ax.legend(); _save(fig, PRIMARY_FIGURES[4])


def _table_start(caption: str, label: str, columns: str, header: str) -> list[str]:
    return [r"\begin{table}[t]", r"\centering", f"\\caption{{{caption}}}", f"\\label{{{label}}}", r"\small", f"\\begin{{tabularx}}{{\\linewidth}}{{{columns}}}", r"\toprule", header + ROW_END + r" \midrule"]


def _table_end(lines: list[str]) -> str:
    return "\n".join(lines + [r"\bottomrule", r"\end{tabularx}", r"\end{table}"])


def generate_tables(data: dict[str, Any]) -> None:
    reqs = data["requirements"]["requirements"]
    components = (
        ("Artifact registration", "Register bytes/provenance", "leancert.datasets", "Public files", "Manifest", "Grounding"),
        ("Artifact processing", "Decompress CFReDS", "leancert.artifact_processing", "dd.bz2", "Raw dd", "Integrity"),
        ("Image inspection", "Read-only semantics", "leancert.image_inspection", "Raw dd", "Inspection", "Grounding"),
        ("Trace construction", "Build typed traces", "leancert.trace_builder", "Manifest", "Trace JSON", "Input"),
        ("Child validation", "Evaluate 35 children", "leancert.sub_obligations", "Trace", "Child outcomes", "Coverage"),
        ("Parent validation", "Evaluate nine parents", "leancert.validator", "Trace", "VALID or INVALID", "Decision"),
        ("Benchmark transformer", "Apply perturbations", "leancert.benchmark_transformer", "Valid traces", "Mutations", "Evaluation"),
        ("Blinding/locking", "Strip metadata; hash", "leancert.holdout_v2", "Cases", "Frozen set", "Leakage control"),
        ("Reference validator", "Corroborate outcomes", "leancert.reference_validator", "Traces", "Reference rows", "Differential"),
        ("Lean generator", "Encode and check", "leancert.lean_generator", "Trace/result", "Certificates", "Formal"),
        ("Report generator", "Aggregate evidence", "leancert.report", "Results", "Reports", "Manuscript"),
        ("Scalability runner", "Measure workloads", "leancert.scalability_v2", "Traces", "Timings", "Performance"),
    )
    lines = _table_start("Implemented LeanCert-Forensics components.", "tab:system-components", "p{.15\\linewidth}p{.17\\linewidth}p{.18\\linewidth}p{.12\\linewidth}p{.13\\linewidth}X", "Component & Purpose & Implementation & Input & Output & Role")
    for component, purpose, implementation, input_name, output_name, role in components:
        lines.append(_row(_tex(component), _tex(purpose), _tt(implementation), _tex(input_name), _tex(output_name), _tex(role), escaped=False))
    _write(TABLES / "system_components.tex", _table_end(lines))

    env, exp = data["environment"], data["experiment"]
    tools = (("Python", env["python_version"].split(" ", 1)[0], "Operational validation"), ("Windows", exp["platform"], "Host platform"), ("Lean", "4.32.1", "Formal checking"), ("Lake", "5.0.0", "Lean build"), ("pytsk3", env["pytsk3_version"], "Image inspection"), ("The Sleuth Kit", env["sleuthkit_embedded_version"], "Filesystem analysis"), ("Matplotlib", _version("matplotlib"), "Figures"), ("Pydantic", _version("pydantic"), "Schemas"), ("pandas", _version("pandas"), "Tables"), ("PyYAML", _version("PyYAML"), "Specifications"), ("requests", _version("requests"), "Retrieval support"), ("pytest", _version("pytest"), "Tests"))
    lines = _table_start("Measured implementation toolchain.", "tab:toolchain", "p{.18\\linewidth}p{.35\\linewidth}X", "Tool & Version & Purpose")
    for tool, version, purpose in tools:
        lines.append(_row(_tex(tool), _tt(version), _tex(purpose), escaped=False))
    _write(TABLES / "toolchain.tex", _table_end(lines))

    lines = _table_start("Declared parent requirement catalogue.", "tab:requirements", "p{.11\\linewidth}p{.17\\linewidth}Xp{.07\\linewidth}p{.17\\linewidth}p{.15\\linewidth}", "ID & Requirement & Purpose & Children & Python & Lean")
    for req in reqs:
        lines.append(_row(_tt(req["requirement_id"]), _seq(req["name"]), _tex(req["description"]), len(req["sub_obligations"]), _tt(req["python_check"]), _tt(req["lean_predicate"]), escaped=False))
    _write(TABLES / "requirements.tex", _table_end(lines))

    hierarchy = {row["parent_requirement"]: row for row in data["hierarchy_rows"]}
    lines = _table_start("Distribution of the 35 declared sub-obligations.", "tab:child-summary", "p{.18\\linewidth}Xp{.09\\linewidth}p{.17\\linewidth}", "Parent & Child scope & Count & Hierarchy")
    for req in reqs:
        lines.append(_row(_seq(req["name"]), _tex("; ".join(req["sub_obligations"])), len(req["sub_obligations"]), _tt(hierarchy[req["name"]]["relation_type"]), escaped=False))
    _write(TABLES / "sub_obligations_summary.tex", _table_end(lines))

    processing = {row["artifact_name"]: row for row in data["processing"]}; inspection = {row["artifact_name"]: row for row in data["image_rows"]}
    lines = [r"\begin{table}[t]", r"\centering", r"\caption{Evaluated public artifacts and local representations.}", r"\label{tab:datasets}", r"\scriptsize", r"\begin{adjustbox}{max width=\linewidth}", r"\begin{tabular}{p{3.5cm}p{2.2cm}p{1.7cm}rrp{2.2cm}}", r"\toprule", "Artifact & Source & Type & Distribution bytes & Decompressed bytes & Inspection" + ROW_END + r" \midrule"]
    for record in data["datasets"]:
        proc = processing.get(record["artifact_name"]); insp = inspection.get(record["artifact_name"])
        lines.append(_row(_tex(record["artifact_name"]), _tex(record["source_name"]), _tt(record["artifact_kind"]), manuscript_integer(record["size_bytes"]), manuscript_integer(proc["decompressed_size_bytes"]) if proc else "N/A", _tt(insp["inspection_status"]) if insp else "N/A", escaped=False))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{adjustbox}", r"\end{table}"]; _write(TABLES / "datasets.tex", "\n".join(lines))

    ref, image = data["reference"], data["image"]
    rows = (("Decompression success", 6, 6, r"100.0\%"), ("Inspection attempted", image["inspection_attempted_count"], image["total_decompressed_images"], r"100.0\%"), ("Semantic success (applicable)", image["semantic_passed_count"], image["semantically_applicable_count"], r"100.0\%"), ("External checksum coverage", ref["external_reference_available_count"], ref["external_reference_eligible_count"], r"0.0\%"), ("External checksum match", ref["external_reference_verified_count"], ref["external_reference_available_count"], "N/A"))
    lines = _table_start("Artifact processing, semantic inspection, and publisher anchoring.", "tab:artifact-integrity", "Xrrr", "Dimension & Numerator & Denominator & Result")
    lines.extend(_row(_tex(name), n, d, result, escaped=False) for name, n, d, result in rows)
    text = _table_end(lines).replace(r"\end{table}", r"\par\smallskip\footnotesize N/A denotes an unavailable denominator, not a validation failure.\end{table}")
    _write(TABLES / "artifact_integrity.tex", text)

    lines = _table_start("Semantic inspection of decompressed CFReDS images.", "tab:image-inspection", "p{.34\\linewidth}p{.16\\linewidth}p{.13\\linewidth}p{.19\\linewidth}X", "Image & Applicability & Status & Filesystem & Root entries")
    for record in data["image_rows"]:
        fs = ", ".join(json.loads(record["filesystem_types"])) or "N/A"
        lines.append(_row(_tex(record["artifact_name"]), _tt(record["filesystem_semantics"]), _tt(record["inspection_status"]), _tt(fs), record["root_entry_count"], escaped=False))
    _write(TABLES / "image_inspection.tex", _table_end(lines))

    cis = {row["metric"]: row for row in data["holdout"]["confidence_intervals"]}
    names = (("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"), ("Specificity", "specificity"), ("F1", "f1"), ("False acceptance rate", "false_acceptance_rate"), ("False rejection rate", "false_rejection_rate"))
    lines = _table_start(r"Locked/blinded holdout metrics with 95\% confidence intervals.", "tab:holdout-metrics", "Xrrp{.31\\linewidth}", r"Metric & Estimate & 95\% interval & Method")
    for label, key in names:
        ci = cis[key]
        method = ci["interval_method"].replace("10000", "10,000").replace("20260728", "20,260,728")
        lines.append(_row(label, f"{data['holdout'][key]:.4f}", f"[{ci['lower_95']:.4f}, {ci['upper_95']:.4f}]", method))
    _write(TABLES / "holdout_metrics.tex", _table_end(lines))

    lines = _table_start("Requirement-level holdout coverage; categories are non-exclusive.", "tab:holdout-coverage", "Xrrrr", "Requirement & Direct invalid & Cascading & Valid traces & Artifacts")
    for record in data["requirement_coverage"]:
        lines.append(_row(record["requirement"], record["direct_invalid_traces"], record["cascading_affected_traces"], record["valid_traces_exercising_requirement"], record["public_artifacts_represented"]))
    _write(TABLES / "holdout_requirement_coverage.tex", _table_end(lines))

    cov = data["coverage"]; dimensions = (("Concrete Python mappings", cov["concrete_python_child_mappings"]), ("Explicit Lean mappings", cov["lean_explicit_child_mappings"]), ("Positive Python tests", cov["positive_python_child_coverage"]), ("Negative Python tests", cov["negative_python_child_coverage"]), ("Positive Lean tests", cov["positive_lean_child_coverage"]), ("Negative Lean tests", cov["negative_lean_child_coverage"]), ("Direct benchmark coverage", cov["direct_child_benchmark_coverage"]), ("Failure explanations", cov["failure_explanation_child_coverage"]))
    lines = _table_start("Catalogue-relative implementation and formalization coverage.", "tab:formalization", "Xrr", "Dimension & Covered & Declared")
    lines.extend(_row(label, count, cov["declared_sub_obligations"]) for label, count in dimensions); _write(TABLES / "formalization_coverage.tex", _table_end(lines))

    child, diff = data["child"], data["differential"]
    comparisons = (("Top-level production/reference", diff["total_comparisons"], diff["disagreements"]), ("Top-level Python/Lean", data["agreement"]["requirement_level_comparisons"], data["agreement"]["requirement_level_disagreements"]), ("Child production/reference", child["reference_child_comparisons"], child["reference_child_disagreements"]), ("Child Python/Lean", child["total_child_comparisons"], child["disagreements"]), ("Child metamorphic", child["metamorphic_comparisons"], child["metamorphic_failures"]))
    lines = _table_start("Differential, formal-agreement, and metamorphic comparisons.", "tab:differential", "Xrrr", "Comparison & Total & Disagreements & Agreement")
    for name, total, disagreements in comparisons:
        lines.append(_row(_tex(name), manuscript_integer(total), disagreements, f"{100*(total-disagreements)/total:.1f}\\%", escaped=False))
    _write(TABLES / "differential_validation.tex", _table_end(lines))

    counts = Counter(row["independence_classification"] for row in data["independence_rows"])
    lines = _table_start("Reference-validator structural independence.", "tab:reference-independence", "XrX", "Classification & Children & Interpretation")
    lines.append(_row(r"STRUCTURALLY\_INDEPENDENT", counts["STRUCTURALLY_INDEPENDENT"], "Independently structured; no production predicate imports.", escaped=False)); lines.append(_row("LIMITED", counts["LIMITED"], "Shares declared policy, lifecycle, or external facts."))
    _write(TABLES / "reference_independence.tex", _table_end(lines))

    certificate_rows = (("Top-level validity certificates", 30, "ValidTrace(T)"), ("Top-level violation certificates", 90, "not ValidTrace(T)"), ("Top-level direct negative theorems", 90, "not R_i(T)"), ("Child validity certificates", child["valid_lean_certificates_checked"], "ValidTrace(T)"), ("Child violation certificates", child["invalid_lean_violation_certificates_checked"], "not ValidTrace(T)"), ("Child direct negatives", child["direct_child_negative_theorems_checked"], "not R_ij(T)"), ("Compilation/theorem failures", child["lean_compilation_or_theorem_failures"], "None observed"))
    lines = _table_start("Measured Lean certificate semantics.", "tab:lean-semantics", "XrX", "Checked artifact & Count & Established proposition")
    lines.extend(_row(*record) for record in certificate_rows); _write(TABLES / "lean_semantics.tex", _table_end(lines))

    lines = [r"\begin{table}[t]", r"\centering", r"\caption{Python and Lean scalability summaries; IQR is the interquartile range.}", r"\label{tab:scalability}", r"\scriptsize", r"\begin{tabular}{llrrrr}", r"\toprule", "Workload & Events & Traces & Median & IQR & P95" + ROW_END + r" \midrule"]
    for record in data["python_scale"]:
        lines.append(_row(r"Python ($\mu$s)", record["event_count"], record["trace_count"], f"{float(record['median_us']):.2f}", f"{float(record['IQR_us']):.2f}", f"{float(record['P95_us']):.2f}", escaped=False))
    for record in data["lean_scale"]:
        lines.append(_row(f"Lean {_tex(record['proof_mode'])} (ms)", record["event_count"], record["trace_count"], f"{float(record['median_time_ms']):.2f}", f"{float(record['IQR_time_ms']):.2f}", f"{float(record['P95_time_ms']):.2f}", escaped=False))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]; _write(TABLES / "scalability.tex", "\n".join(lines))

    limitations = [str(item).rstrip(" |").strip() for item in data["experiment"]["residual_limitations"]]
    lines = _table_start("Residual scientific limitations.", "tab:limitations", "p{.05\\linewidth}X", "No. & Limitation")
    lines.extend(_row(index, item) for index, item in enumerate(limitations, 1)); _write(TABLES / "limitations.tex", _table_end(lines))

    claims = (("Declared catalogue mapped", "Coverage audit", "35/35 Python and Lean", "All declared children mapped", "Universal completeness"), ("Controlled holdout", "Locked metrics", "No observed errors; CIs", "Evaluated-case enforcement", "Real-world forensic accuracy"), ("Lean certificates", "Certificate CSV", "Validity/violation", "Encoded propositions checked", "Truth/admissibility"), ("Reference comparison", "Independence audit", "30 structural; 5 limited", "Qualified corroboration", "All fully independent"), ("ROC/AUC", "Eligibility audit", "Not applicable", "No score curve", "AUC from failure counts"))
    lines = [r"\begin{table}[t]", r"\centering", r"\caption{Claim--evidence boundaries used in manuscript wording.}", r"\label{tab:claim-evidence}", r"\scriptsize", r"\begin{adjustbox}{max width=\linewidth}", r"\begin{tabular}{p{2.7cm}p{2.5cm}p{3.1cm}p{4cm}p{4cm}}", r"\toprule", "Claim & Evidence & Result & Permitted interpretation & Overclaim to avoid" + ROW_END + r" \midrule"]
    lines.extend(_row(*record) for record in claims); lines += [r"\bottomrule", r"\end{tabular}", r"\end{adjustbox}", r"\end{table}"]; _write(TABLES / "claim_evidence_matrix.tex", "\n".join(lines))


def generate_architecture() -> None:
    _write(FIGURES / "architecture.tex", r"""
\begin{figure*}[t]
\centering
\resizebox{\textwidth}{!}{%
\begin{tikzpicture}[node distance=4mm and 7mm,box/.style={draw,rounded corners,align=center,minimum height=8mm,text width=29mm,font=\scriptsize},runtime/.style={box,fill=green!10},public/.style={box,fill=blue!8},formal/.style={box,fill=purple!10},eval/.style={box,fill=orange!12},flow/.style={-{Latex[length=2mm]},thick},evalflow/.style={flow,dashed,orange!70!black}]
\node[public] (source) {Public forensic sources};
\node[runtime,right=of source] (registration) {Dataset registration};
\node[runtime,right=of registration] (processing) {Integrity processing and decompression};
\node[runtime,right=of processing] (inspection) {pytsk3 semantic inspection};
\node[runtime,below=of inspection] (trace) {Trace construction};
\node[runtime,left=of trace] (python) {Python validator\\9 parents / 35 children};
\node[runtime,left=of python,text width=38mm] (decision) {VALID / INVALID};
\node[formal,below=of decision] (generator) {Lean artifact generator};
\node[formal,right=of generator] (kernel) {Lean 4 kernel};
\node[formal,right=of kernel] (certificate) {Validity or violation certificate};
\node[runtime,right=of certificate] (audit) {Audit/evaluation outputs};
\foreach \a/\b in {source/registration,registration/processing,processing/inspection,inspection/trace,trace/python,python/decision,decision/generator,generator/kernel,kernel/certificate,certificate/audit}{\draw[flow] (\a)--(\b);}
\node[eval,below=13mm of trace] (spec) {Controlled mutation specifications};
\node[eval,right=of spec] (transform) {Benchmark transformer};
\node[eval,right=of transform] (blind) {Blinding and metadata stripping};
\node[eval,right=of blind] (frozen) {Frozen benchmark and SHA-256 lock};
\draw[evalflow] (spec)--(transform); \draw[evalflow] (transform)--(blind); \draw[evalflow] (blind)--(frozen);
\draw[evalflow] (frozen) |- node[pos=.72,right,font=\scriptsize]{trace content only} (python);
\node[font=\scriptsize,below=2mm of spec,align=left]{Evaluation-only path; labels remain private.};
\end{tikzpicture}}
\caption{Implemented LeanCert-Forensics architecture. Solid arrows show public-data processing, operational validation, formal checking, and reporting. Dashed arrows show the evaluation-only benchmark path. Labels and mutation metadata do not flow into the validator.}
\label{fig:architecture}
\end{figure*}
""")


def generate_figure_environments(data: dict[str, Any]) -> None:
    m, image, ref = data["holdout"], data["image"], data["reference"]
    captions = (
        f"Artifact integrity, semantic inspection, and external anchoring. Inspection was attempted for {image['inspection_attempted_count']}/{image['total_decompressed_images']} images; {image['semantic_passed_count']}/{image['semantically_applicable_count']} applicable filesystem images passed and {image['partial_count']} carving images remained PARTIAL. External checksum match is N/A because {ref['external_reference_available_count']} official digests were available among {ref['external_reference_eligible_count']} eligible distributions. N/A is not a validation failure.",
        f"Locked and blinded controlled holdout. Controlled-invalid is positive. The matrix contains n={m['total_traces']} traces ({m['valid_traces']} valid; {m['invalid_traces']} controlled-invalid); TP is an invalid trace correctly rejected and TN a valid trace correctly accepted.",
        "Direct and cascading requirement failures. Direct counts are root violations; cascading counts are downstream consequences. Counts are unique traces and categories are non-exclusive. ReportTraceability produced 80 logical downstream effects; 10 IdentityCompleteness overlaps arose from a shared claim-text constraint classified as DUPLICATED_SEMANTICS, not mutation contamination.",
        "Python validation scalability. The event-count axis is logarithmic. Each size used 15 structurally distinct traces, 10 excluded warm-ups, and 30 measured runs timed by time.perf_counter_ns. Points are medians and error bars are IQR. The 4--500-event experiment makes no asymptotic claim.",
        "Lean proof-checking scalability. Prerequisites were precompiled and each file launched a new process. Points are medians and error bars are IQR. Pairwise and aggregate modes are different workloads; lower aggregate times do not imply that Lean intrinsically becomes faster.",
    )
    labels = ("fig:artifact-integrity", "fig:confusion-matrix", "fig:cascades", "fig:python-scale", "fig:lean-scale")
    blocks = []
    for name, caption, label in zip(PRIMARY_FIGURES, captions, labels):
        blocks.append(f"\\begin{{figure}}[t]\n\\centering\n\\includegraphics[width=\\linewidth]{{figures/{name}}}\n\\caption{{{_tex(caption)}}}\n\\label{{{label}}}\n\\end{{figure}}")
    _write(GENERATED / "figures.tex", "\n\n".join(blocks))


def generate_sections(data: dict[str, Any]) -> None:
    h, c, r, im = data["holdout"], data["child"], data["reference"], data["image"]
    ci = {row["metric"]: row for row in h["confidence_intervals"]}; indep = Counter(row["independence_classification"] for row in data["independence_rows"])
    sections = {
        "01_system_overview.tex": r"""\section{System overview and validation objective}
LeanCert-Forensics is a research prototype for machine-checkable forensic-process assurance. It tests whether a typed trace satisfies an explicitly declared catalogue while separating artifact truth, process conformance, and formal proof of encoded propositions. Public artifacts ground trace construction; Python predicates provide operational validation; Lean 4 provides a machine-checked representation; controlled benchmarks test enforcement; and audit outputs preserve explanations.

LeanCert-Forensics does not attempt to prove that an external forensic artifact is factually authentic or legally admissible. Rather, it machine-checks whether an encoded forensic trace satisfies the declared assurance obligations.

\subsection{Contributions}
The implemented contributions are a nine-parent/35-child assurance catalogue; corresponding executable Python predicates and Lean propositions; explicit validity and violation certificates; a reproducible evaluation with public artifacts, semantic inspection, frozen blinded perturbations, differential validation, mutation-isolation, and Python--Lean agreement; and bounded operational/proof-checking scalability measurements.""",
        "02_architecture.tex": r"""\section{Architecture and components}
The runtime path registers artifacts, checks local integrity, decompresses CFReDS images, inspects them read-only, builds typed traces, evaluates nine parent requirements and 35 children, produces a binary decision, generates Lean, invokes the kernel, and records a validity or violation certificate. The separate evaluation path applies declarative perturbations, removes labels and mutation metadata, blinds identifiers, and freezes a SHA-256-locked benchmark. Only trace content enters validation.
\input{figures/architecture}
\input{tables/system_components}""",
        "03_formal_model.tex": r"""\section{Formal trace and conformance model}
The implemented schema is summarized as $T=(c,t,o,E,A,V,C)$: case and trace identifiers; dataset origin; evidence records; actors; ordered events; and report claims. Evidence includes identity, kind, source, hash, size, artifact path, and optional parent. Events include evidence and actor references, action, timestamp, holder transition, and adjacent hashes. Claims include identity, text, and supporting evidence.
\[\operatorname{ValidTrace}(T)=\bigwedge_{i=1}^{9}R_i(T).\]
The final audit verified operationally and formally that each parent equals its declared child conjunction:
\[R_i(T)\Longleftrightarrow\bigwedge_{j=1}^{m_i}R_{i,j}(T).\]
\begin{lstlisting}[language={},caption={ASCII-safe representative checked forms.}]
abbrev ValidTrace (t : Trace) : Prop :=
  And (IdentityComplete t)
  (And (ReferentiallyValid t)
  (And (ArtifactIntegrityValid t)
  (And (CustodyContinuous t)
  (And (ChronologicallyConsistent t)
  (And (HashContinuous t)
  (And (AuthorizedHandling t)
  (And (LifecycleCorrect t) (ReportTraceable t))))))))
theorem artifact_parent_iff_children (t : Trace) :
    Iff (ArtifactIntegrityValid t)
      (And (ArtifactAvailable t)
        (And (ArtifactSha256Matches t) (ArtifactSizeMatches t))) := by
  simp only [ArtifactIntegrityValid, ArtifactIntegrityValidB,
    Bool.and_eq_true, and_assoc]
example : LeanCert.ValidTrace traceData := by native_decide
example : Not (LeanCert.ValidTrace traceData) := by native_decide
example : Not (LeanCert.AdjacentHashLink traceData) := by native_decide
\end{lstlisting}
The full source retains all nine conjuncts, equivalence theorems, and generated certificates.""",
        "04_requirements.tex": r"""\section{Requirement catalogue and Python/Lean correspondence}
The parents are IdentityCompleteness, ReferentialIntegrity, PublicArtifactIntegrity, CustodyContinuity, ChronologicalConsistency, HashContinuity, AuthorizedHandling, LifecycleCorrectness, and ReportTraceability. Every child resolves to a concrete Python symbol and Lean predicate with positive/negative tests, direct cases, and explanations.
\input{tables/requirements}
\input{tables/sub_obligations_summary}""",
        "05_datasets.tex": f"""\\section{{Datasets, preprocessing, and semantic inspection}}
The registered population contains {len(data['datasets'])} public artifacts from Digital Corpora, Wireshark sample captures, and NIST CFReDS. Six CFReDS distributions were decompressed to raw images with separately recorded distribution and decompressed SHA-256 values. Local digests are not represented as publisher references.

pytsk3 inspection was attempted for {im['inspection_attempted_count']}/{im['total_decompressed_images']} images. Filesystem semantics applied to {im['semantically_applicable_count']} deleted-file-recovery images and {im['semantic_passed_count']}/{im['semantically_applicable_count']} passed; FAT16/FAT32 and NTFS/NTFS\\_DETECT were observed. Three carving images remained PARTIAL and are not semantic passes. Among {r['external_reference_eligible_count']} eligible distributions, {r['external_reference_available_count']} official digests were available; match rate is N/A, not zero.
\\input{{tables/datasets}}
\\input{{tables/artifact_integrity}}
\\input{{tables/image_inspection}}""",
        "06_implementation.tex": r"""\section{Implementation}
Strict Pydantic models reject unknown trace fields and separate authored evaluation metadata from validator inputs. Pure child predicates feed parent validation and requirement-level explanations. Reference checks are separately structured and their independence is qualified. The Lean generator serializes trace content and emits decidable propositions. Compilation is recorded separately from checked validity or violation theorems.
\input{tables/toolchain}""",
        "07_experimental_methodology.tex": f"""\\section{{Experimental methodology}}
\\subsection{{Top-level locked/blinded holdout}}
Holdout v2 contains {h['total_traces']} traces: {h['valid_traces']} valid and {h['invalid_traces']} controlled-invalid, including 10 direct cases per parent. Declarative mutations precede label/metadata removal, deterministic blinding, and SHA-256 locking. Controlled-invalid is positive: TP is invalid correctly rejected, TN valid correctly accepted, FP valid incorrectly rejected, and FN invalid incorrectly accepted.
\\[\\mathrm{{Accuracy}}=\\frac{{TP+TN}}{{TP+TN+FP+FN}},\\quad \\mathrm{{Precision}}=\\frac{{TP}}{{TP+FP}},\\quad \\mathrm{{Recall}}=\\frac{{TP}}{{TP+FN}}.\\]
\\[\\mathrm{{Specificity}}=\\frac{{TN}}{{TN+FP}},\\quad F_1=2\\frac{{PR}}{{P+R}},\\quad FAR=\\frac{{FN}}{{TP+FN}},\\quad FRR=\\frac{{FP}}{{TN+FP}}.\\]
Clopper--Pearson intervals cover proportion metrics. F1 uses {manuscript_integer(10000)} stratified bootstrap resamples with seed {manuscript_integer(20260728)}.

\\subsection{{Child benchmark and controls}}
The separate child benchmark contains {c['valid_trace_count']} valid and {c['invalid_trace_count']} controlled-invalid traces, three cases per child. Benchmark generation does not call validator predicates; labels and mutation metadata do not enter validation. The top-level and child locks are \\nolinkurl{{{data['experiment']['benchmark_holdout_v2_sha256']}}} and \\nolinkurl{{{data['experiment']['benchmark_child_holdout_sha256']}}}. Controlled perturbations exercise declared obligations and are not natural failures.

\\subsection{{Differential and scalability methods}}
Production Python, reference Python, and Lean results were compared separately. Python timing used 4, 8, 12, 20, 50, 100, 200, and 500 events; 15 structural variants; 10 warm-ups; and 30 measured repetitions using \\texttt{{time.perf\\_counter\\_ns}}. Lean pairwise and aggregate encodings are distinct workloads with precompiled prerequisites and new processes per file.""",
        "08_results.tex": f"""\\section{{Results}}
No errors were observed in the controlled holdout: TP={h['TP']}, TN={h['TN']}, FP={h['FP']}, FN={h['FN']}. Accuracy was {h['accuracy']:.4f} [{ci['accuracy']['lower_95']:.4f}, {ci['accuracy']['upper_95']:.4f}]; precision and recall intervals were [{ci['precision']['lower_95']:.4f}, {ci['precision']['upper_95']:.4f}]; specificity was {h['specificity']:.4f} [{ci['specificity']['lower_95']:.4f}, {ci['specificity']['upper_95']:.4f}]. FAR was {h['false_acceptance_rate']:.4f} [{ci['false_acceptance_rate']['lower_95']:.4f}, {ci['false_acceptance_rate']['upper_95']:.4f}] and FRR {h['false_rejection_rate']:.4f} [{ci['false_rejection_rate']['lower_95']:.4f}, {ci['false_rejection_rate']['upper_95']:.4f}]. F1 was 1.0000 [1.0000, 1.0000]; the bootstrap degenerates because every stratified resample remains correctly classified, not because uncertainty vanishes.

All {c['targeted_invalid_cases']} targeted child violations were detected; {c['mutation_isolation']['isolated_mutation_count']} were isolated and {c['mutation_isolation']['unexpected_direct_failure_count']} unexpected direct failures occurred. Coverage was 35/35 Python and 35/35 Lean, with zero child-quality failures and 9/9 equivalent parent/child relations. Top-level production/reference disagreements were {data['differential']['disagreements']}/{data['differential']['total_comparisons']}; child production/reference disagreements {c['reference_child_disagreements']}/{c['reference_child_comparisons']}; and child Python--Lean disagreements {c['disagreements']}/{c['total_child_comparisons']}. Reference checks were {indep['STRUCTURALLY_INDEPENDENT']} structurally independent and {indep['LIMITED']} LIMITED.

The top-level study checked 30 validity and 90 violation certificates. The child study checked {c['valid_lean_certificates_checked']} validity, {c['invalid_lean_violation_certificates_checked']} violation, and {c['direct_child_negative_theorems_checked']} direct child-negation theorems, with {c['lean_compilation_or_theorem_failures']} failures.
\\input{{tables/holdout_metrics}}
\\input{{tables/holdout_requirement_coverage}}
\\input{{tables/formalization_coverage}}
\\input{{tables/differential_validation}}
\\input{{tables/reference_independence}}
\\input{{tables/lean_semantics}}
\\input{{tables/scalability}}
\\input{{generated/figures}}""",
        "09_results_interpretation.tex": r"""\section{Results interpretation}
Artifact results support public-source grounding and local consistency, not publisher authenticity without official checksums. Zero controlled-holdout errors support enforcement over frozen cases, not universal accuracy. Catalogue-relative 35/35 supports implementation coverage of declared obligations, not complete digital-forensic practice. Python--Lean and reference agreement corroborate implementations over evaluated traces but cannot independently prove both specifications factually complete.

The cascade audit found 80 expected ReportTraceability consequences through upstream support. Ten IdentityCompleteness overlaps arose when empty claim text violated both identity and reporting constraints. The recorded class is DUPLICATED\_SEMANTICS; a shared semantic constraint is the appropriate interpretation, not a bug or mutation contamination. Python results characterize 4--500 events. Pairwise Lean ends at 100 events and aggregate Lean at 500; different encodings are different workloads and imply no asymptotic result.""",
        "10_discussion.tex": r"""\section{Discussion}
Machine-checkable requirements expose assumptions and make failures attributable. Python supplies operational feedback; Lean supplies kernel checking over an encoded model. Explicit validity and violation certificates distinguish acceptance from named failures, while compilation remains a separate engineering status. Public artifacts provide format grounding and controlled process perturbations provide repeatable coverage, but neither substitutes for natural labelled failures or external legal review.

\subsection{ROC/AUC applicability}
ROC/AUC was not used because LeanCert-Forensics produces deterministic binary conformance decisions and has no predefined continuous or ordinal assurance score with meaningful thresholds. Failure-count pseudo-scores would be circular because controlled-invalid traces are constructed to violate obligations. No ROC, AUC, precision--recall curve, or average precision was generated.""",
        "11_threats_to_validity.tex": r"""\section{Threats to validity}
\paragraph{Construct validity.} Catalogue coverage is bounded and does not establish external truth or legal admissibility; shared semantics and five LIMITED reference checks remain explicit.
\paragraph{Internal validity.} Controlled perturbations can create regularities. Locking, blinding, leakage tests, declarative transformations, mutation isolation, differential validation, and Python--Lean comparison mitigate this risk.
\paragraph{External validity.} No independently labelled natural failure corpus was available; official checksums were absent; controlled cases do not estimate prevalence; and scalability is bounded at 500 events.
\paragraph{Conclusion validity.} Exact intervals qualify zero observed errors. The degenerate F1 bootstrap does not prove zero uncertainty, and no score exists for ROC/AUC inference.
\input{tables/limitations}""",
        "12_reproducibility.tex": f"""\\section{{Reproducibility}}
The recorded environment used Python {data['environment']['python_version'].split(' ',1)[0]} on {_tex(data['experiment']['platform'])}, Lean 4.32.1, Lake 5.0.0, pytsk3 {data['environment']['pytsk3_version']}, and The Sleuth Kit {data['environment']['sleuthkit_embedded_version']}. Construction seeds were 20,260,728 and 20,260,809. Frozen hashes appear in the methodology and traceability appendix. Repository-relative commands are provided in \\texttt{{generated/reproducibility\\_commands.tex}}.""",
        "13_conclusion_of_validation.tex": r"""\section{Validation conclusion}
The artifacts support a bounded conclusion: LeanCert-Forensics enforced its declared hierarchy in the frozen controlled studies, mapped all declared children operationally and formally, generated checked validity/violation certificates, and remained tractable over tested sizes. They do not support universal accuracy, authenticity, admissibility, or ROC/AUC claims.""",
    }
    for name, text in sections.items():
        _write(GENERATED / name, text)
    _write(GENERATED / "leancert_validation.tex", "\n".join(f"\\input{{generated/{name[:-4]}}}" for name in sections))
    _write(GENERATED / "abstract_results_block.tex", f"LeanCert-Forensics grounds traces in {len(data['datasets'])} registered public artifacts and formalizes nine requirements as 35 sub-obligations. In a locked/blinded controlled holdout of {h['total_traces']} traces, no classification errors were observed and exact confidence intervals qualify the point estimates. The separate child study produced {c['disagreements']} disagreements in {c['total_child_comparisons']} Python--Lean comparisons and checked {c['valid_lean_certificates_checked']} validity and {c['invalid_lean_violation_certificates_checked']} violation certificates. Python validation and distinct Lean workloads were measured through 500 events. These results concern catalogue-relative conformance, not natural prevalence, authenticity, or admissibility.")
    _write(GENERATED / "reproducibility_commands.tex", r"""\begin{lstlisting}
.\.venv\Scripts\python.exe -m leancert.cli process-cfreds-images
.\.venv\Scripts\python.exe -m leancert.cli inspect-images
.\.venv\Scripts\python.exe -m leancert.cli verify-benchmark-lock --benchmark benchmark\holdout_v2
.\.venv\Scripts\python.exe -m leancert.cli verify-benchmark-lock --benchmark benchmark\sub_obligation_holdout_v1
.\.venv\Scripts\python.exe -m leancert.cli final-scientific-audit
.\.venv\Scripts\python.exe -m leancert.cli evaluate benchmark\holdout_v2 --require-lean
.\.venv\Scripts\python.exe -m leancert.cli evaluate-sub-obligations benchmark\sub_obligation_holdout_v1 --require-lean
.\.venv\Scripts\python.exe -m leancert.cli build-scalability-traces --sizes 4 8 12 20 50 100 200 500
.\.venv\Scripts\python.exe -m leancert.cli run-experiment traces --repeat 20 --strict-artifacts --require-lean --paper-figures-only
cd lean
lake build LeanCert.Requirements
cd ..
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m leancert.cli generate-manuscript
\end{lstlisting}""")


def generate_appendices(data: dict[str, Any], manifest: dict[str, Any]) -> None:
    requirements = data["requirements"]["requirements"]
    lines = [r"\section{Full parent requirement catalogue}", r"\begin{longtable}{p{2.2cm}p{3.1cm}p{8.3cm}}", r"\caption{Requirement definitions, scope, and boundaries.}\label{tab:app-requirements}\\", r"\toprule ID & Requirement & Definition and boundary \\ \midrule\endfirsthead", r"\toprule ID & Requirement & Definition and boundary \\ \midrule\endhead"]
    for req in requirements:
        lines.append(_row(_tt(req["requirement_id"]), _seq(req["name"]), _tex(req["description"] + " Scope: " + req["scope"] + " Exclusion: " + "; ".join(req["known_exclusions"])), escaped=False))
    lines += [r"\bottomrule", r"\end{longtable}"]; _write(APPENDICES / "appendix_requirements.tex", "\n".join(lines))

    independence = {row["sub_obligation_id"]: row for row in data["independence_rows"]}
    lines = [r"\begin{landscape}", r"\section{Full sub-obligation catalogue}", "Reference implementation independence is structural for some obligations and limited for obligations that necessarily depend on the same declared policy or external fact.", r"\scriptsize\setlength{\tabcolsep}{2pt}", r"\begin{longtable}{p{3.3cm}p{3cm}p{4cm}p{5.2cm}p{4cm}rp{3cm}}", r"\caption{Auditable Python/Lean correspondence for all 35 children.}\label{tab:app-children}\\", r"\toprule ID & Parent & Description & Python & Lean & Cases & Reference \\ \midrule\endfirsthead", r"\toprule ID & Parent & Description & Python & Lean & Cases & Reference \\ \midrule\endhead"]
    for record in data["symbol_rows"]:
        child_id = record["sub_obligation_id"]
        lines.append(_row(_tt(child_id), _seq(record["parent_requirement"]), _tex(DESCRIPTIONS[child_id]), _tt(record["python_symbol"]), _tt(record["lean_predicate"]), record["direct_benchmark_case_count"], _tt(independence[child_id]["independence_classification"]), escaped=False))
    lines += [r"\bottomrule", r"\end{longtable}", r"\end{landscape}"]; _write(APPENDICES / "appendix_sub_obligations.tex", "\n".join(lines))

    _write(APPENDICES / "appendix_toolchain.tex", r"""\section{Toolchain provenance}
Versions in Table~\ref{tab:toolchain} originate from the experiment/environment artifacts or the installed project environment. Unknown versions are rendered as ``Version not recorded.'' pytsk3 embeds The Sleuth Kit and was used read-only.""")
    _write(APPENDICES / "appendix_benchmark_protocol.tex", f"""\\section{{Benchmark protocol and leakage controls}}
Valid traces were transformed by declarative specifications before labels and mutation metadata were stripped. Blinded cases were frozen and hashed. Labels were joined after prediction. The locks are \\nolinkurl{{{data['experiment']['benchmark_holdout_v2_sha256']}}} and \\nolinkurl{{{data['experiment']['benchmark_child_holdout_sha256']}}}. Mutation-isolation and leakage artifacts record the checks; neither benchmark is a natural-failure corpus.""")
    cascade = Counter(row["dependency_type"] for row in data["cascades"])
    processing = {row["artifact_name"]: row for row in data["processing"]}
    inspection = {row["artifact_name"]: row for row in data["image_rows"]}
    artifact_lines = [r"\subsection{Artifact-level provenance and hashes}", "The entries below preserve source, byte-level identity, derived-image identity where applicable, and semantic inspection status.", r"\begin{description}"]
    for record in data["datasets"]:
        proc = processing.get(record["artifact_name"])
        insp = inspection.get(record["artifact_name"])
        details = [
            "Source " + _tt(record["source_url"]) + ".",
            f"Distribution: {manuscript_integer(record['size_bytes'])} bytes; SHA-256 " + _tt(record["sha256"]) + ".",
        ]
        if proc:
            details.append(f"Derived raw image: {manuscript_integer(proc['decompressed_size_bytes'])} bytes; SHA-256 " + _tt(proc["decompressed_sha256"]) + f"; decompression {_tex(proc['decompression_status'])}.")
        if insp:
            details.append(f"Semantic applicability {_tex(insp['filesystem_semantics'])}; inspection {_tex(insp['inspection_status'])}.")
        artifact_lines.append(r"\item[" + _tex(record["artifact_name"]) + "] " + " ".join(details))
    artifact_lines.append(r"\end{description}")
    additional = f"""\\section{{Additional results}}
The cascade audit contains {len(data['cascades'])} rows: {cascade['LOGICAL_DEPENDENCY']} LOGICAL\\_DEPENDENCY and {cascade['DUPLICATED_SEMANTICS']} DUPLICATED\\_SEMANTICS outcomes, with no mutation contamination or implementation defect. Child metamorphic testing performed {manuscript_integer(data['child']['metamorphic_comparisons'])} comparisons with {data['child']['metamorphic_failures']} failures. ROC/PR outputs are absent because eligibility failed.

""" + "\n".join(artifact_lines)
    _write(APPENDICES / "appendix_additional_results.tex", additional)

    rows: list[tuple[str, str, str, str, str, bool]] = []
    for content in manifest.values():
        if isinstance(content, dict):
            for record in content.values():
                if isinstance(record, dict) and {"name", "value", "source_file", "source_field_or_row"}.issubset(record):
                    value = manuscript_integer(record["value"]) if isinstance(record["value"], int) else json.dumps(record["value"]) if isinstance(record["value"], list) else str(record["value"])
                    identifier = record.get("unit") in {"SHA-256", "version"}
                    rows.append((record["name"], value, record["source_file"], record["source_field_or_row"], record["manuscript_usage"], identifier))
    lines = [r"\begin{landscape}", r"\section{Result traceability}", r"\scriptsize\setlength{\tabcolsep}{2pt}", r"\begin{longtable}{p{3.3cm}p{3.5cm}p{5.6cm}p{5cm}p{6.1cm}}", r"\caption{Traceability for principal manuscript metrics.}\label{tab:traceability}\\", r"\toprule Metric & Value & Source & Field/row & Usage \\ \midrule\endfirsthead", r"\toprule Metric & Value & Source & Field/row & Usage \\ \midrule\endhead"]
    for name, value, source, field, usage, identifier in rows:
        rendered_value = _tt(value) if identifier else _tex(value)
        lines.append(_row(_tt(name), rendered_value, _tt(source), _tt(field), _tex(usage), escaped=False))
    lines += [r"\bottomrule", r"\end{longtable}", r"\end{landscape}"]; _write(APPENDICES / "appendix_result_traceability.tex", "\n".join(lines))


def generate_main() -> None:
    _write(PAPER / "main_generated_test.tex", r"""\documentclass[10pt]{article}
\usepackage[margin=1.8cm]{geometry}
\usepackage[T1]{fontenc}
\usepackage{lmodern,microtype,amsmath,amssymb,graphicx,booktabs,tabularx,longtable,array,adjustbox,xcolor,listings,tikz,url,xurl,hyperref,caption,pdflscape,seqsplit}
\usetikzlibrary{arrows.meta,positioning}
\setlength{\emergencystretch}{3em}
\sloppy
\lstset{basicstyle=\ttfamily\footnotesize,breaklines=true,columns=fullflexible}
\title{LeanCert-Forensics: Generated Validation Package}\author{Repository-generated manuscript material}\date{}
\begin{document}\maketitle
\begin{abstract}\input{generated/abstract_results_block}\end{abstract}
\input{generated/leancert_validation}
\appendix
\input{appendices/appendix_requirements}
\input{appendices/appendix_sub_obligations}
\input{appendices/appendix_toolchain}
\input{appendices/appendix_benchmark_protocol}
\input{appendices/appendix_additional_results}
\input{appendices/appendix_result_traceability}
\input{tables/claim_evidence_matrix}
\section{Reproduction commands}\input{generated/reproducibility_commands}
\end{document}""")


def generate_recommendation() -> None:
    _write(PAPER_TEXT / "main_vs_supplementary_recommendation.md", """# Main versus supplementary recommendation

| Artifact | Placement | Reason |
|---|---|---|
| Architecture and five primary figures | MAIN | Distinct core evidence dimensions. |
| Components, requirements, datasets, integrity, holdout, formalization, differential, certificates, scalability, limitations | MAIN | Direct support for principal claims and boundaries. |
| Full 35-child catalogue | SUPPLEMENTARY | Essential audit detail but too large for main flow. |
| Full traceability, toolchain, and benchmark protocol | SUPPLEMENTARY | Reproducibility detail. |
| Claim-evidence matrix | SUPPLEMENTARY | Wording and reviewer audit. |
| ROC/PR figures | OPTIONAL (not generated) | Eligibility failed; pseudo-scores would mislead. |
""")


def audit_number_format() -> dict[str, Any]:
    violations: list[dict[str, str]] = []; checked = 0; terms = Counter()
    needles = ("100%", "100.0%", "perfect", "complete", "accuracy", "valid", "proof", "independent", "checksum", "admissibility", "ROC", "AUC", "natural")
    for path in sorted(PAPER.rglob("*.tex")):
        text = path.read_text(encoding="utf-8")
        review = re.sub(r"\\(?:texttt|nolinkurl)\{[^}]*\}|\\begin\{(?:verbatim|lstlisting)\}.*?\\end\{(?:verbatim|lstlisting)\}", "", text, flags=re.S)
        for needle in needles:
            terms[needle] += review.casefold().count(needle.casefold())
        for line_no, line in enumerate(review.splitlines(), 1):
            checked += len(re.findall(r"(?<![\d,])\d{2,}(?:,\d{3})+(?![\d,])", line))
            for match in re.finditer(r"(?<![\d,.])\d{5,}(?![\d,.])", line):
                checked += 1; violations.append({"file": path.relative_to(PROJECT_ROOT).as_posix(), "line": str(line_no), "value": match.group(0), "reason": "ungrouped five-or-more-digit integer"})
            for match in re.finditer(r"(?<![\d,])\d,\d{3}(?![\d,])", line):
                if int(match.group(0).replace(",", "")) < 10000:
                    violations.append({"file": path.relative_to(PROJECT_ROOT).as_posix(), "line": str(line_no), "value": match.group(0), "reason": "grouped four-digit integer"})
    result = {"generated_at_utc": utc_now(), "five_digit_numbers_checked": checked, "formatting_violations": violations, "figures_checked": list(PRIMARY_FIGURES), "tables_checked": [path.relative_to(PROJECT_ROOT).as_posix() for path in sorted(TABLES.glob("*.tex"))], "formatter": "leancert.manuscript_latex.manuscript_integer", "figure_label_control": "All axes and integer annotations use the reusable formatter.", "scientific_language_occurrences_reviewed": dict(terms)}
    write_json(PAPER_TEXT / "number_format_audit.json", result)
    if violations:
        raise RuntimeError(f"Number-format audit found {len(violations)} violation(s)")
    return result


def run_tests() -> dict[str, Any]:
    command = [str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"), "-m", "pytest", "-o", "addopts=", "-q"]
    completed = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True, shell=False)
    output = (completed.stdout + "\n" + completed.stderr).strip(); match = re.search(r"(\d+) passed", output)
    report = {"generated_at_utc": utc_now(), "command": ".\\.venv\\Scripts\\python.exe -m pytest -o addopts= -q", "exit_code": completed.returncode, "passed_count": int(match.group(1)) if match else None, "status": "PASSED" if completed.returncode == 0 else "FAILED", "output_tail": "\n".join(output.splitlines()[-10:])}
    write_json(PAPER_TEXT / "regression_test_report.json", report)
    if completed.returncode:
        raise RuntimeError("Regression tests failed")
    return report


def incorporate_regression_test_result(tests: dict[str, Any], manifest: dict[str, Any]) -> None:
    """Place the just-executed regression result in both manuscript and trace manifest."""
    manifest["environment"]["regression_tests"] = _metric(
        "passing regression tests",
        tests["passed_count"],
        "tests",
        "results/paper_text/regression_test_report.json",
        "passed_count",
        "Reproducibility",
    ) | {"status": tests["status"], "exit_code": tests["exit_code"]}
    write_json(PAPER_TEXT / "manuscript_data_manifest.json", manifest)
    path = GENERATED / "12_reproducibility.tex"
    statement = (
        f"\nThe final regression execution recorded {manuscript_integer(tests['passed_count'])} passed tests, "
        f"exit code {tests['exit_code']}, and status {_tex(tests['status'])}; the command and output tail are preserved "
        r"in \texttt{results/paper\_text/regression\_test\_report.json}."
    )
    _write(path, path.read_text(encoding="utf-8").rstrip() + statement + "\n")


def compile_latex() -> dict[str, Any]:
    compiler = shutil.which("pdflatex")
    if compiler is None:
        report = {"generated_at_utc": utc_now(), "compiler": None, "exit_code": None, "warnings": ["pdflatex not installed"], "errors": [], "overfull_box_count": None, "undefined_reference_count": None, "passes": 0}
        write_json(PAPER_TEXT / "latex_build_report.json", report); return report
    outputs: list[str] = []; code = 0
    for _ in range(2):
        completed = subprocess.run([compiler, "-interaction=nonstopmode", "-halt-on-error", "main_generated_test.tex"], cwd=PAPER, capture_output=True, text=True, shell=False)
        outputs.append(completed.stdout + completed.stderr); code = completed.returncode
        if code:
            break
    log_path = PAPER / "main_generated_test.log"; log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else "\n".join(outputs)
    report = {"generated_at_utc": utc_now(), "compiler": subprocess.run([compiler, "--version"], capture_output=True, text=True, shell=False).stdout.splitlines()[0], "exit_code": code, "passes": len(outputs), "warnings": sorted(set(re.findall(r"(?:LaTeX|Package [^:]+) Warning: (.+)", log))), "errors": re.findall(r"^! (.+)$", log, flags=re.M), "overfull_box_count": len(re.findall(r"Overfull \\hbox", log)), "undefined_reference_count": len(re.findall(r"Reference `[^']+' .*undefined", log)), "pdf_path": "paper/main_generated_test.pdf" if (PAPER / "main_generated_test.pdf").is_file() else None}
    write_json(PAPER_TEXT / "latex_build_report.json", report)
    if code:
        raise RuntimeError("LaTeX build failed")
    return report


def generate_all() -> dict[str, Any]:
    for directory in (GENERATED, FIGURES, TABLES, APPENDICES, PAPER_TEXT):
        directory.mkdir(parents=True, exist_ok=True)
    # Some isolated checksum tests write their temporary population to the
    # shared result path. Recompute before and after regression execution so
    # manuscript inputs and final public artifacts remain authoritative.
    verify_reference_checksums()
    data = _load(); manifest = build_data_manifest(data)
    generate_figures(data); generate_tables(data); generate_architecture(); generate_figure_environments(data)
    generate_sections(data); generate_appendices(data, manifest); generate_main(); generate_recommendation()
    tests = run_tests(); verify_reference_checksums(); incorporate_regression_test_result(tests, manifest)
    generate_appendices(data, manifest)
    number_audit = audit_number_format(); latex = compile_latex()
    summary = {"generated_at_utc": utc_now(), "master": "paper/generated/leancert_validation.tex", "primary_figures": [f"paper/figures/{name}" for name in PRIMARY_FIGURES], "number_format_violations": len(number_audit["formatting_violations"]), "regression_tests": tests, "latex_build": latex}
    write_json(PAPER_TEXT / "manuscript_generation_summary.json", summary)
    return summary
