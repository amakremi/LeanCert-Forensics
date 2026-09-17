from __future__ import annotations

import copy
from pathlib import Path

import pytest

from leancert.schema import ForensicTrace
from leancert.trace_builder import baseline_trace
from leancert.utils import sha256_file


@pytest.fixture
def public_artifact(tmp_path: Path) -> Path:
    path = tmp_path / "public sample.bin"
    path.write_bytes(b"public-forensic-test-artifact\n")
    return path


@pytest.fixture
def valid_data(public_artifact: Path) -> dict:
    digest = sha256_file(public_artifact)
    return baseline_trace({
        "source_name": "Public Test Corpus",
        "artifact_name": "Tiny public test fixture",
        "artifact_kind": "log_file",
        "source_url": "https://example.invalid/public-fixture",
        "local_path": str(public_artifact),
        "sha256": digest,
        "size_bytes": public_artifact.stat().st_size,
        "retrieved_at_utc": "2025-01-01T00:00:00Z",
    })


@pytest.fixture
def valid_trace(valid_data: dict) -> ForensicTrace:
    return ForensicTrace.model_validate(copy.deepcopy(valid_data))

