from __future__ import annotations

import shutil

from leancert.lean_generator import check_lean_file, render_lean
from leancert.validator import validate_trace


def test_lean_generator_is_deterministic(valid_trace):
    result = validate_trace(valid_trace)
    assert render_lean(valid_trace, result) == render_lean(valid_trace, result)


def test_lean_generator_does_not_assert_failed_obligation(valid_trace):
    valid_trace.events[1].actor_id = "ANA-001"
    result = validate_trace(valid_trace)
    content = render_lean(valid_trace, result)
    assert "Validation failures detected" in content
    assert "example : False" not in content


def test_missing_lean_does_not_fail(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    result = check_lean_file(tmp_path / "unused.lean")
    assert result["lean_check_status"] == "NOT_RUN"
    assert result["lean_check_time_ms"] is None

