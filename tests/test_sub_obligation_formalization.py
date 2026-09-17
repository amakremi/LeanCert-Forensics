from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

from leancert.hierarchy_audit import audit_requirement_hierarchy
from leancert.lean_generator import render_lean
from leancert.reference_sub_obligation_validator import CHILD_IDS as REFERENCE_IDS
from leancert.schema import ValidationTrace
from leancert.sub_obligation_benchmark import ROOT, freeze_benchmark, verify_lock
from leancert.sub_obligations import CHILD_IDS, LEAN_PREDICATES, PYTHON_PREDICATES, evaluate_children
from leancert.utils import read_json, write_json
from leancert.validator import validate_trace


CATALOGUE = Path("formalization/requirements_catalog.yaml")


def _catalogue_mappings():
    return yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))["sub_obligation_mappings"]


def _traces():
    labels = read_json(ROOT / "private" / "labels.json")["mapping"]
    by_id = {}
    for path in (ROOT / "blinded").glob("*.json"):
        trace = ValidationTrace.model_validate(read_json(path)); by_id[trace.trace_id] = trace
    return labels, by_id


def test_original_35_ids_are_preserved_without_duplicates():
    pre = read_json(Path("results/formalization_catalogue_pre_fix.json"))
    original = [row["sub_obligation_id"] for row in pre["sub_obligations"]]
    mapped = [row["id"] for row in _catalogue_mappings()]
    assert len(original) == len(set(original)) == 35
    assert mapped == original


def test_every_child_has_concrete_unique_python_and_lean_mapping():
    mappings = _catalogue_mappings()
    assert [row["id"] for row in mappings] == CHILD_IDS
    assert all(row["python_predicate"] == PYTHON_PREDICATES[row["id"]] for row in mappings)
    assert len({row["lean_predicate"] for row in mappings}) == 35
    assert all(row["lean_predicate"] == LEAN_PREDICATES[row["id"]] for row in mappings)
    assert not ({"IdentityComplete", "ReferentiallyValid", "ValidTrace"} & {row["lean_predicate"] for row in mappings})


def test_claimed_positive_and_negative_python_coverage_is_direct():
    labels, traces = _traces()
    valid = [trace_id for trace_id, meta in labels.items() if meta["expected_label"] == "valid"]
    assert valid
    assert all(all(evaluate_children(traces[trace_id]).values()) for trace_id in valid)
    for child in CHILD_IDS:
        targets = [trace_id for trace_id, meta in labels.items() if meta.get("target_sub_obligation") == child]
        assert len(targets) == 3
        assert all(evaluate_children(traces[trace_id])[child] is False for trace_id in targets)


def test_blinded_inputs_do_not_contain_private_targets_or_labels():
    forbidden = {"expected_label", "mutation_id", "sub_obligation_id", "target_sub_obligation", "target_requirement", "evaluation_metadata"}
    for path in (ROOT / "blinded").glob("*.json"):
        raw = read_json(path)
        assert not (forbidden & set(raw))


def test_mutation_and_validation_modules_are_directionally_separated():
    mutation_source = Path("leancert/sub_obligation_benchmark.py").read_text(encoding="utf-8")
    validator_source = Path("leancert/validator.py").read_text(encoding="utf-8")
    assert "from .validator" not in mutation_source
    assert "sub_obligation_benchmark" not in validator_source
    assert "expected_label" not in validator_source


def test_reference_oracle_does_not_call_production_predicates():
    source = Path("leancert/reference_sub_obligation_validator.py").read_text(encoding="utf-8")
    assert "from .validator" not in source
    assert "from .sub_obligations" not in source
    assert REFERENCE_IDS == CHILD_IDS
    assert "STRUCTURALLY_INDEPENDENT" in source and "LIMITED" in source


def test_generated_certificates_state_actual_child_polarity():
    labels, traces = _traces()
    valid_id = next(trace_id for trace_id, meta in labels.items() if meta["expected_label"] == "valid")
    invalid_id = next(trace_id for trace_id, meta in labels.items() if meta.get("target_sub_obligation"))
    valid = traces[valid_id]; invalid = traces[invalid_id]
    valid_source = render_lean(valid, validate_trace(valid, strict_artifacts=True))
    invalid_source = render_lean(invalid, validate_trace(invalid, strict_artifacts=True))
    assert "theorem trace_validity : LeanCert.ValidTrace traceData" in valid_source
    assert "theorem trace_not_valid : ¬ LeanCert.ValidTrace traceData" in invalid_source
    target = labels[invalid_id]["target_sub_obligation"]
    assert f"child_{target.casefold().replace('-', '_')}_invalid" in invalid_source


def test_hierarchy_audit_reports_all_nine_equivalences():
    rows, passed = audit_requirement_hierarchy()
    assert passed and len(rows) == 9
    assert all(row["relation_type"] == "EQUIVALENT" for row in rows)


def test_lock_detects_a_changed_blinded_trace(tmp_path: Path):
    root = Path("results/.pytest_child_lock")
    (root / "blinded").mkdir(parents=True, exist_ok=True)
    (root / "private").mkdir(parents=True, exist_ok=True)
    (root / "manifests").mkdir(parents=True, exist_ok=True)
    source = next((ROOT / "blinded").glob("*.json"))
    write_json(root / "blinded" / "case.json", read_json(source))
    write_json(root / "private" / "labels.json", {"mapping": {}})
    freeze_benchmark(root)
    assert verify_lock(root)[0]
    changed = read_json(root / "blinded" / "case.json"); changed["trace_id"] += "-changed"
    write_json(root / "blinded" / "case.json", changed)
    assert not verify_lock(root)[0]


def test_holdout_v2_lock_identity_is_unchanged():
    lock = read_json(Path("benchmark/holdout_v2/manifests/benchmark_lock_v2.json"))
    assert lock["combined_benchmark_sha256"] == "99433a2c11d550565d2daba701749f4b671dd34c5b481bb773b054731aa99532"
