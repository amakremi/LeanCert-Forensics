from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from leancert.schema import ForensicTrace


def test_schema_accepts_valid_trace(valid_data):
    assert ForensicTrace.model_validate(valid_data).case_id.startswith("CASE-PUBLIC-")


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("actors", "role", "administrator"),
        ("events", "action", "delete"),
        ("evidence", "kind", "paper_document"),
    ],
)
def test_unsupported_enum_values_fail(valid_data, section, field, value):
    data = copy.deepcopy(valid_data)
    data[section][0][field] = value
    with pytest.raises(ValidationError):
        ForensicTrace.model_validate(data)


def test_extra_fields_are_rejected(valid_data):
    data = copy.deepcopy(valid_data)
    data["validation_shortcut"] = True
    with pytest.raises(ValidationError):
        ForensicTrace.model_validate(data)

