from __future__ import annotations

import argparse
import csv
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from pydantic import ValidationError

from .datasets import (
    DEFAULT_MANIFEST, discover_local_artifacts, fetch_datasets,
    register_cfreds_batch, register_local_artifact,
)
from .artifact_processing import process_cfreds_images
from .benchmark import (
    BENCHMARK_ROOT, build_blinded_holdout, freeze_benchmark, verify_benchmark_lock,
)
from .external_cases import import_external_cases
from .evaluation_v2 import evaluate_holdout_v2, write_v2_tables
from .final_outputs import finalize_publication_outputs
from .formalization_audit import audit_formalization, audit_sub_obligations_v2
from .hierarchy_audit import audit_requirement_hierarchy
from .image_inspection import inspect_images
from .holdout_v2 import (
    DEFAULT_ROOT as HOLDOUT_V2_ROOT,
    build_holdout_v2, freeze_holdout_v2, load_holdout_v2, verify_holdout_v2_lock,
)
from .lean_generator import detect_lean, generate_lean
from .reference_hashes import verify_reference_checksums
from .metamorphic import run_metamorphic_and_differential
from .manuscript_readiness import run_final_scientific_audit
from .manuscript_latex import generate_all as generate_manuscript
from .report import (
    process_directory, process_scalability_directory, process_trace_file,
    write_experiment_results,
)
from .schema import ForensicTrace
from .scalability_v2 import run_scalability_experiments
from .trace_builder import build_scalability_traces, build_traces_from_manifest
from .utils import PROJECT_ROOT, read_json, safe_filename, write_json
from .validator import validate_trace
from .sub_obligation_benchmark import (
    ROOT as SUB_OBLIGATION_ROOT,
    audit_isolation as audit_sub_obligation_isolation,
    build_benchmark as build_sub_obligation_benchmark,
    freeze_benchmark as freeze_sub_obligation_benchmark,
    verify_lock as verify_sub_obligation_lock,
)
from .sub_obligation_evaluation import evaluate_sub_obligations

NO_ARTIFACTS_MESSAGE = (
    "No public forensic artifacts were available locally. Dataset fetch completed, but trace "
    "construction was skipped. Add valid artifact URLs to datasets/public_sources.yaml or manually "
    "place downloaded public forensic artifacts under datasets/raw/ and rerun "
    "build-traces-from-datasets."
)


def _path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def command_fetch(args: argparse.Namespace) -> int:
    records = fetch_datasets(allow_large_downloads=args.allow_large_downloads)
    successful = sum(item.get("download_status") in {"downloaded", "existing"} for item in records)
    print(f"Dataset manifest written to datasets/manifests/download_manifest.json ({successful} usable).")
    return 0


def command_build(args: argparse.Namespace) -> int:
    written = build_traces_from_manifest(force=args.force, variants=args.variants)
    if not written:
        # Existing traces are a successful no-op; no usable artifact is not.
        existing = list((PROJECT_ROOT / "traces").rglob("*.json"))
        if existing:
            print("No traces were overwritten. Use --force to rebuild existing generated traces.")
        else:
            print(NO_ARTIFACTS_MESSAGE)
        return 0
    print(f"Wrote {len(written)} public-data-derived traces.")
    return 0


def command_check_lean(args: argparse.Namespace) -> int:
    status = detect_lean()
    print(f"Lean available: {str(status['lean_available']).lower()}")
    print(f"Lean version: {status['lean_version'] or 'not available'}")
    print(f"Lake available: {str(status['lake_available']).lower()}")
    print(f"Lake version: {status['lake_version'] or 'not available'}")
    print("PATH entry hints: " + "; ".join(status["path_entry_hints"]))
    return 0


def command_install_lean_windows(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        print(
            "Automatic Lean installation is only supported on Windows. "
            "Install elan from https://github.com/leanprover/elan and verify lean --version."
        )
        return 0
    script = PROJECT_ROOT / "scripts" / "install_lean_windows.ps1"
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        print(f"PowerShell was not found. Run the installation script manually: {script}")
        return 1
    result = subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        cwd=PROJECT_ROOT, capture_output=False, text=True, shell=False,
    )
    return result.returncode


def command_register_local(args: argparse.Namespace) -> int:
    try:
        record = register_local_artifact(
            source_name=args.source_name,
            artifact_name=args.artifact_name,
            kind=args.kind,
            path=_path(args.path),
            source_url=args.source_url,
            usage_note=args.usage_note,
        )
    except FileNotFoundError as exc:
        print(str(exc))
        return 1
    print(f"Registered: {record['artifact_name']}")
    print(f"SHA-256: {record['sha256']}")
    print(f"Size bytes: {record['size_bytes']}")
    print("Status: local_registered")
    return 0


def command_discover_local(args: argparse.Namespace) -> int:
    paths = discover_local_artifacts([_path(root) for root in args.search_root])
    if args.source_name.casefold() == "nist cfreds":
        paths = [
            path for path in paths
            if re.search(r"(?:dfr-\d+-.+\.dd|l\d+_.+\.dd)\.(?:bz2|gz|zip|7z)$",
                         path.name, re.IGNORECASE)
        ]
    print(f"Discovered {len(paths)} completed supported artifacts for {args.source_name}:")
    for path in paths:
        rendered = str(path)
        encoding = sys.stdout.encoding or "utf-8"
        print(rendered.encode(encoding, errors="replace").decode(encoding))
    return 0


def command_register_cfreds(args: argparse.Namespace) -> int:
    try:
        records = register_cfreds_batch(
            dfr_fat=_path(args.dfr_fat),
            dfr_ntfs=_path(args.dfr_ntfs),
            l0_graphic=_path(args.l0_graphic),
            dfr_02_fat=_path(args.dfr_02_fat) if args.dfr_02_fat else None,
            l0_documents=_path(args.l0_documents) if args.l0_documents else None,
            l0_archive=_path(args.l0_archive) if args.l0_archive else None,
            copy=args.copy,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc))
        return 1
    for record in records:
        print(
            f"{record['artifact_name']}: {record['sha256']} "
            f"({record['size_bytes']} bytes) -> {record['local_path']}"
        )
    return 0


def command_build_scalability(args: argparse.Namespace) -> int:
    try:
        written = build_scalability_traces(
            args.sizes, traces_per_size=args.traces_per_size, seed=args.seed,
        )
    except ValueError as exc:
        print(str(exc))
        return 1
    if not written:
        print(NO_ARTIFACTS_MESSAGE)
        return 0
    print(f"Wrote {len(written)} scalability traces: {', '.join(map(str, args.sizes))} events.")
    return 0


def command_process_cfreds(args: argparse.Namespace) -> int:
    rows = process_cfreds_images(force=args.force)
    passed = sum(row["decompression_status"] == "PASSED" for row in rows)
    print(f"Processed {len(rows)} CFReDS distributions: {passed} decompressed successfully.")
    return 0 if all(row["decompression_status"] in {"PASSED", "NOT_RUN"} for row in rows) else 1


def command_inspect_images(args: argparse.Namespace) -> int:
    rows, summary = inspect_images(force=args.force)
    print(
        f"Inspected {len(rows)} images: {summary['inspection_passed_images']} passed, "
        f"{summary['inspection_partial_images']} partial, "
        f"{summary['inspection_not_run_images']} not run."
    )
    return 0


def command_verify_references(args: argparse.Namespace) -> int:
    _, summary = verify_reference_checksums()
    print(
        f"Official references: {summary['external_reference_available_count']} available, "
        f"{summary['external_reference_verified_count']} verified, "
        f"{summary['external_reference_unavailable_count']} unavailable."
    )
    return 1 if summary["external_reference_mismatch_count"] else 0


def command_freeze_benchmark(args: argparse.Namespace) -> int:
    if args.benchmark and _path(args.benchmark).resolve() == HOLDOUT_V2_ROOT.resolve():
        lock = freeze_holdout_v2(_path(args.benchmark))
        print(f"Benchmark v2 frozen: {lock['combined_benchmark_sha256']}")
        return 0
    if args.benchmark and _path(args.benchmark).resolve() == SUB_OBLIGATION_ROOT.resolve():
        lock = freeze_sub_obligation_benchmark(_path(args.benchmark))
        print(f"Sub-obligation benchmark frozen: {lock['benchmark_sha256']}")
        return 0
    lock = freeze_benchmark(seed=args.seed)
    print(f"Benchmark frozen: {lock['benchmark_sha256']}")
    return 0


def command_verify_benchmark(args: argparse.Namespace) -> int:
    if args.benchmark and _path(args.benchmark).resolve() == HOLDOUT_V2_ROOT.resolve():
        valid, errors = verify_holdout_v2_lock(_path(args.benchmark))
    elif args.benchmark and _path(args.benchmark).resolve() == SUB_OBLIGATION_ROOT.resolve():
        valid, errors = verify_sub_obligation_lock(_path(args.benchmark))
    else:
        valid, errors = verify_benchmark_lock()
    print(f"Benchmark lock valid: {str(valid).lower()}")
    for error in errors:
        print(error)
    return 0 if valid else 1


def command_build_holdout_v2(args: argparse.Namespace) -> int:
    manifest = build_holdout_v2(
        valid_trace_count=args.valid_traces,
        invalid_per_requirement=args.invalid_per_requirement,
        seed=args.seed,
    )
    print(
        f"Built holdout v2: {manifest['total_trace_count']} traces "
        f"({manifest['valid_trace_count']} valid, {manifest['invalid_trace_count']} invalid)."
    )
    return 0


def command_audit_formalization(args: argparse.Namespace) -> int:
    if args.output_version == "pre-fix":
        path = PROJECT_ROOT / "results" / "formalization_catalogue_pre_fix.json"
        if not path.is_file():
            print("Pre-fix inventory is missing; it must be captured before semantic edits.")
            return 1
        pre = read_json(path)
        print(f"Pre-fix catalogue inventory retained: {len(pre.get('sub_obligations', []))} children.")
        return 0
    _, summary = audit_formalization()
    if args.sub_obligation_level:
        _, child_summary = audit_sub_obligations_v2()
        print(
            "Explicit child mappings: "
            f"Python {child_summary['python_explicit_child_mappings']}/{child_summary['declared_sub_obligations']}, "
            f"Lean {child_summary['lean_explicit_child_mappings']}/{child_summary['declared_sub_obligations']}."
        )
    print(
        "Catalogue-relative formalization coverage: "
        f"{summary['catalogue_relative_formalization_rate']:.1%}"
    )
    return 0 if summary["audit_passed"] else 1


def command_build_sub_obligation_holdout(args: argparse.Namespace) -> int:
    manifest = build_sub_obligation_benchmark(
        invalid_per_child=args.invalid_per_sub_obligation,
        valid_traces=args.valid_traces, seed=args.seed,
    )
    print(
        f"Built controlled sub-obligation benchmark: {manifest['total_traces']} traces "
        f"({manifest['valid_traces']} valid, {manifest['invalid_traces']} invalid)."
    )
    return 0


def command_audit_mutation_isolation(args: argparse.Namespace) -> int:
    _, summary = audit_sub_obligation_isolation(_path(args.benchmark))
    print(
        f"Mutation cases: {summary['mutation_case_count']}; isolated/expected-coupled: "
        f"{summary['isolated_mutation_count']}; unexpected: {summary['unexpected_direct_failure_count']}."
    )
    return 0 if not summary["unexpected_direct_failure_count"] else 1


def command_audit_requirement_hierarchy(args: argparse.Namespace) -> int:
    rows, passed = audit_requirement_hierarchy()
    print(f"Requirement hierarchy: {sum(row['status'] == 'PASSED' for row in rows)}/{len(rows)} passed.")
    return 0 if passed else 1


def command_evaluate_sub_obligations(args: argparse.Namespace) -> int:
    if args.require_lean:
        status = detect_lean()
        if not status["lean_available"]:
            print("Lean is required for child-level agreement but was not found in PATH.")
            return 2
    try:
        summary, passed = evaluate_sub_obligations(
            _path(args.benchmark), require_lean=args.require_lean,
            run_reference_validation=args.run_reference_validation,
            run_python_lean_agreement=args.run_python_lean_agreement,
        )
    except RuntimeError as exc:
        print(str(exc)); return 2
    print(
        f"Controlled child traces: {summary['controlled_trace_count']}; "
        f"target detections: {summary['target_child_violations_detected']}/{summary['targeted_invalid_cases']}; "
        f"Python-Lean disagreements: {summary['disagreements']}; "
        f"reference disagreements: {summary['reference_child_disagreements']}."
    )
    return 0 if passed else 1


def command_final_scientific_audit(args: argparse.Namespace) -> int:
    summary = run_final_scientific_audit()
    coverage = summary["coverage"]
    print(
        f"Final scientific audit: Python {coverage['concrete_python_child_mappings']}/"
        f"{coverage['declared_sub_obligations']}, Lean {coverage['lean_explicit_child_mappings']}/"
        f"{coverage['declared_sub_obligations']}; hierarchy "
        f"{summary['hierarchy_rows'] if summary['hierarchy_passed'] else 0}/{summary['hierarchy_rows']}; "
        f"ROC applicable: {str(summary['roc']['roc_applicable']).lower()}."
    )
    return 0 if summary["hierarchy_passed"] and not coverage["uncovered_children"] else 1


def command_generate_manuscript(args: argparse.Namespace) -> int:
    summary = generate_manuscript()
    build = summary["latex_build"]
    tests = summary["regression_tests"]
    print(
        "Generated manuscript package: paper/generated/leancert_validation.tex; "
        f"figures={len(summary['primary_figures'])}; "
        f"number-format violations={summary['number_format_violations']}; "
        f"tests={tests['passed_count']} passed; LaTeX exit={build['exit_code']}."
    )
    return 0 if build["exit_code"] in {0, None} and tests["exit_code"] == 0 else 1


def command_import_external(args: argparse.Namespace) -> int:
    summary = import_external_cases(_path(args.directory))
    print(
        f"Independently labeled external cases: {summary['natural_external_case_count']} "
        f"({summary['natural_external_evaluation_status']})."
    )
    return 0


def command_validate(args: argparse.Namespace) -> int:
    path = _path(args.trace)
    record = process_trace_file(
        path, strict_artifacts=args.strict_artifacts, repeat_lean=args.repeat_lean,
    )
    report_path = PROJECT_ROOT / "reports" / safe_filename(f"{record['row']['trace_id']}_report.json")
    write_json(report_path, record["report"])
    row = record["row"]
    print(f"{row['trace_id']}: {row['predicted_status']}")
    if row["failed_requirements"]:
        print(f"Failed requirements: {row['failed_requirements']}")
    print(f"Report: {report_path.relative_to(PROJECT_ROOT)}")
    return 0 if row["predicted_status"] == "PASSED" else 1


def command_validate_dir(args: argparse.Namespace) -> int:
    records = process_directory(
        _path(args.trace_dir), strict_artifacts=args.strict_artifacts,
        repeat_lean=args.repeat_lean,
    )
    failed = sum(item["row"]["predicted_status"] == "FAILED" for item in records)
    print(f"Validated {len(records)} traces: {len(records) - failed} passed, {failed} failed.")
    return 0


def command_generate_lean(args: argparse.Namespace) -> int:
    path = _path(args.trace)
    try:
        trace = ForensicTrace.model_validate(read_json(path))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Cannot generate Lean for malformed trace: {exc}")
        return 1
    result = validate_trace(trace, strict_artifacts=args.strict_artifacts)
    primary, _ = generate_lean(trace, result)
    print(f"Generated {primary.relative_to(PROJECT_ROOT)}")
    return 0


def _evaluate(args: argparse.Namespace, experiment: bool) -> int:
    trace_dir = _path(args.trace_dir)
    lean_status = detect_lean()
    if getattr(args, "require_lean", False) and not (
        lean_status["lean_available"] and lean_status["lake_available"]
    ):
        print(
            "Lean and Lake are required but unavailable. Run "
            ".\\scripts\\install_lean_windows.ps1 and retry."
        )
        return 2
    if getattr(args, "fetch", False):
        fetch_datasets(allow_large_downloads=args.allow_large_downloads)
    if getattr(args, "build_traces", False):
        written = build_traces_from_manifest(force=args.force, variants=args.variants)
        if not written and not list(trace_dir.rglob("*.json")):
            print(NO_ARTIFACTS_MESSAGE)
            return 0
    if trace_dir.resolve() == HOLDOUT_V2_ROOT.resolve():
        try:
            records, v2_summary = evaluate_holdout_v2(
                root=trace_dir, repeat=args.repeat, repeat_lean=args.repeat_lean,
                strict_artifacts=args.strict_artifacts,
                require_lean=(
                    getattr(args, "require_lean", False)
                    or getattr(args, "run_python_lean_agreement", False)
                ),
            )
        except RuntimeError as exc:
            print(str(exc))
            return 2
        write_v2_tables(v2_summary)
        audit_formalization()
        if experiment:
            run_scalability_experiments()
            finalize_publication_outputs()
        metrics = v2_summary["metrics"]
        print(
            "LeanCert-Forensics holdout-v2 evaluation completed.\n"
            f"Total traces: {metrics['total_traces']}\n"
            f"TP={metrics['TP']} TN={metrics['TN']} FP={metrics['FP']} FN={metrics['FN']}\n"
            f"Accuracy: {metrics['accuracy']:.4f}\n"
            f"Differential disagreements: {v2_summary['differential']['disagreements']}\n"
            f"Python-Lean trace disagreements: {v2_summary['agreement']['trace_level_disagreements']}"
        )
        return 0
    label_mapping = None
    blinded_paths: list[Path] = []
    if getattr(args, "benchmark_track", None) == "holdout":
        if getattr(args, "verify_benchmark_lock", False):
            valid_lock, errors = verify_benchmark_lock()
            if not valid_lock:
                print("Benchmark lock verification failed: " + "; ".join(errors))
                return 2
        source_paths = sorted((PROJECT_ROOT / "traces" / "public_valid").glob("*.json"))
        blinded_paths, label_mapping = build_blinded_holdout(source_paths)
        trace_dir = blinded_paths[0].parent if blinded_paths else trace_dir
    records = process_directory(
        trace_dir, repeat=args.repeat, repeat_lean=args.repeat_lean,
        strict_artifacts=args.strict_artifacts, label_mapping=label_mapping,
    )
    if not records:
        print(f"No JSON trace files found under {trace_dir}.")
        return 0
    scalability_records = None
    if getattr(args, "benchmark_track", None) == "holdout":
        assert label_mapping is not None
        run_metamorphic_and_differential(
            blinded_paths, label_mapping, strict_artifacts=args.strict_artifacts,
        )
        import_external_cases(PROJECT_ROOT / "external_cases" / "incoming")
        scalability_root = PROJECT_ROOT / "traces" / "scalability"
        if scalability_root.is_dir():
            scalability_records = process_scalability_directory(
                scalability_root, repeat=args.repeat, repeat_lean=args.repeat_lean,
                strict_artifacts=args.strict_artifacts,
            )
    summary = write_experiment_results(
        records, trace_dir=trace_dir, repeat=args.repeat, repeat_lean=args.repeat_lean,
        strict_artifacts=args.strict_artifacts,
        trace_generation_variants=getattr(args, "variants", "standard"),
        paper_figures_only=getattr(args, "paper_figures_only", False),
        scalability_records=scalability_records,
    )
    if not experiment:
        write_json(PROJECT_ROOT / "reports" / "evaluation_summary.json", summary)
        with (PROJECT_ROOT / "reports" / "evaluation_summary.csv").open(
            "w", encoding="utf-8", newline=""
        ) as stream:
            writer = csv.DictWriter(stream, fieldnames=list(summary))
            writer.writeheader()
            writer.writerow(summary)
    if shutil.which("lean") is None:
        print(
            "Lean 4 was not found in PATH. Python validation and result generation completed. "
            "Lean proof checking was skipped."
        )
    print(
        f"LeanCert-Forensics Evaluation\n"
        f"Public sources used: {summary['public_sources_used']}\n"
        f"Public artifacts used: {summary['public_artifacts_used']}\n"
        f"Total traces: {summary['total_traces']}\n"
        f"TP={summary['TP']} TN={summary['TN']} FP={summary['FP']} FN={summary['FN']}\n"
        f"Accuracy: {summary['accuracy']:.4f}"
    )
    if experiment:
        print(
            "\nExperiment completed.\n\n"
            "Public dataset manifest: datasets/manifests/download_manifest.json\n"
            "Reports written to: reports/\n"
            "Aggregate results written to: results/\n"
            "Figures written to: results/figures/\n"
            "Paper tables written to: results/paper_tables/\n\n"
            "Scientific note:\n"
            "These results evaluate the implemented formalized requirements over public forensic "
            "artifacts and controlled public-data-derived trace perturbations. They do not prove "
            "legal admissibility or universal forensic correctness."
        )
    return 0


def command_evaluate(args: argparse.Namespace) -> int:
    return _evaluate(args, False)


def command_experiment(args: argparse.Namespace) -> int:
    return _evaluate(args, True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="leancert", description="LeanCert-Forensics prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch-datasets")
    fetch.add_argument("--allow-large-downloads", action="store_true")
    fetch.set_defaults(func=command_fetch)

    build = subparsers.add_parser("build-traces-from-datasets")
    build.add_argument("--force", action="store_true")
    build.add_argument("--variants", choices=["minimal", "standard", "full"], default="standard")
    build.set_defaults(func=command_build)

    check_lean = subparsers.add_parser("check-lean")
    check_lean.set_defaults(func=command_check_lean)

    install_lean = subparsers.add_parser("install-lean-windows")
    install_lean.set_defaults(func=command_install_lean_windows)

    register = subparsers.add_parser("register-local-artifact")
    register.add_argument("--source-name", required=True)
    register.add_argument("--artifact-name", required=True)
    register.add_argument(
        "--kind", required=True,
        choices=[
            "disk_image", "memory_dump", "network_capture", "log_file",
            "derived_artifact", "report", "digital_twin_state", "unknown_public_artifact",
        ],
    )
    register.add_argument("--path", required=True)
    register.add_argument("--source-url", default="")
    register.add_argument(
        "--usage-note",
        default="Locally registered public forensic artifact; review source terms.",
    )
    register.set_defaults(func=command_register_local)

    discover = subparsers.add_parser("discover-local-artifacts")
    discover.add_argument("--source-name", required=True)
    discover.add_argument("--search-root", action="append", required=True)
    discover.set_defaults(func=command_discover_local)

    register_batch = subparsers.add_parser("register-cfreds-batch")
    register_batch.add_argument("--dfr-fat", required=True)
    register_batch.add_argument("--dfr-ntfs", required=True)
    register_batch.add_argument("--l0-graphic", required=True)
    register_batch.add_argument("--dfr-02-fat")
    register_batch.add_argument("--l0-documents")
    register_batch.add_argument("--l0-archive")
    register_batch.add_argument("--copy", action="store_true")
    register_batch.set_defaults(func=command_register_cfreds)

    scalability = subparsers.add_parser("build-scalability-traces")
    scalability.add_argument("--sizes", nargs="+", type=int, required=True)
    scalability.add_argument("--traces-per-size", type=int, default=15)
    scalability.add_argument("--seed", type=int, default=20260726)
    scalability.set_defaults(func=command_build_scalability)

    processing = subparsers.add_parser("process-cfreds-images")
    processing.add_argument("--force", action="store_true")
    processing.set_defaults(func=command_process_cfreds)

    inspection = subparsers.add_parser("inspect-images")
    inspection.add_argument("--force", action="store_true")
    inspection.set_defaults(func=command_inspect_images)

    references = subparsers.add_parser("verify-reference-checksums")
    references.set_defaults(func=command_verify_references)

    freeze = subparsers.add_parser("freeze-benchmark")
    freeze.add_argument("--seed", type=int, default=20260726)
    freeze.add_argument("--benchmark")
    freeze.set_defaults(func=command_freeze_benchmark)

    verify_lock = subparsers.add_parser("verify-benchmark-lock")
    verify_lock.add_argument("--benchmark")
    verify_lock.set_defaults(func=command_verify_benchmark)

    holdout_v2 = subparsers.add_parser("build-holdout-v2")
    holdout_v2.add_argument("--valid-traces", type=int, default=30)
    holdout_v2.add_argument("--invalid-per-requirement", type=int, default=10)
    holdout_v2.add_argument("--seed", type=int, default=20260728)
    holdout_v2.set_defaults(func=command_build_holdout_v2)

    formalization = subparsers.add_parser("audit-formalization")
    formalization.add_argument(
        "--sub-obligation-level",
        action="store_true",
        help="Also emit the explicit 35-row sub-obligation coverage audit (always enabled).",
    )
    formalization.add_argument("--output-version", choices=["pre-fix", "final"], default="final")
    formalization.set_defaults(func=command_audit_formalization)

    child_build = subparsers.add_parser("build-sub-obligation-holdout")
    child_build.add_argument("--invalid-per-sub-obligation", type=int, default=3)
    child_build.add_argument("--valid-traces", type=int, default=35)
    child_build.add_argument("--seed", type=int, default=20260809)
    child_build.set_defaults(func=command_build_sub_obligation_holdout)

    mutation_audit = subparsers.add_parser("audit-mutation-isolation")
    mutation_audit.add_argument("benchmark")
    mutation_audit.set_defaults(func=command_audit_mutation_isolation)

    hierarchy = subparsers.add_parser("audit-requirement-hierarchy")
    hierarchy.set_defaults(func=command_audit_requirement_hierarchy)

    child_evaluation = subparsers.add_parser("evaluate-sub-obligations")
    child_evaluation.add_argument("benchmark")
    child_evaluation.add_argument("--blind-benchmark", action="store_true")
    child_evaluation.add_argument("--verify-benchmark-lock", action="store_true")
    child_evaluation.add_argument("--require-lean", action="store_true")
    child_evaluation.add_argument("--run-reference-validation", action="store_true")
    child_evaluation.add_argument("--run-python-lean-agreement", action="store_true")
    child_evaluation.set_defaults(func=command_evaluate_sub_obligations)

    readiness = subparsers.add_parser("final-scientific-audit")
    readiness.set_defaults(func=command_final_scientific_audit)

    manuscript = subparsers.add_parser("generate-manuscript")
    manuscript.set_defaults(func=command_generate_manuscript)

    external = subparsers.add_parser("import-external-cases")
    external.add_argument("directory")
    external.set_defaults(func=command_import_external)

    validate = subparsers.add_parser("validate")
    validate.add_argument("trace")
    validate.add_argument("--strict-artifacts", action="store_true")
    validate.add_argument("--repeat-lean", type=int, default=1)
    validate.set_defaults(func=command_validate)

    validate_dir = subparsers.add_parser("validate-dir")
    validate_dir.add_argument("trace_dir")
    validate_dir.add_argument("--strict-artifacts", action="store_true")
    validate_dir.add_argument("--repeat-lean", type=int, default=1)
    validate_dir.set_defaults(func=command_validate_dir)

    generate = subparsers.add_parser("generate-lean")
    generate.add_argument("trace")
    generate.add_argument("--strict-artifacts", action="store_true")
    generate.set_defaults(func=command_generate_lean)

    for name, function in (("evaluate", command_evaluate), ("run-experiment", command_experiment)):
        experiment_parser = subparsers.add_parser(name)
        experiment_parser.add_argument("trace_dir")
        experiment_parser.add_argument("--repeat", type=int, default=1)
        experiment_parser.add_argument("--repeat-lean", type=int, default=1)
        experiment_parser.add_argument("--strict-artifacts", action="store_true")
        if name == "run-experiment":
            experiment_parser.add_argument("--fetch", action="store_true")
            experiment_parser.add_argument("--build-traces", action="store_true")
            experiment_parser.add_argument("--allow-large-downloads", action="store_true")
            experiment_parser.add_argument("--force", action="store_true")
            experiment_parser.add_argument(
                "--variants", choices=["minimal", "standard", "full"], default="standard"
            )
            experiment_parser.add_argument("--require-lean", action="store_true")
            experiment_parser.add_argument("--paper-figures-only", action="store_true")
            experiment_parser.add_argument(
                "--benchmark-track", choices=["development", "holdout"],
            )
            experiment_parser.add_argument("--blind-benchmark", action="store_true")
            experiment_parser.add_argument("--verify-benchmark-lock", action="store_true")
            experiment_parser.add_argument("--run-differential-validation", action="store_true")
            experiment_parser.add_argument("--run-python-lean-agreement", action="store_true")
        experiment_parser.set_defaults(
            func=function, fetch=False, build_traces=False,
            allow_large_downloads=False, force=False, variants="standard",
            require_lean=False,
            paper_figures_only=False,
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(args, "repeat") and args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")
    if hasattr(args, "repeat_lean") and args.repeat_lean < 1:
        raise SystemExit("--repeat-lean must be at least 1")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
