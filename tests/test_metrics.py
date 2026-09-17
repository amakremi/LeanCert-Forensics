from __future__ import annotations

from leancert.metrics import compute_metrics


def test_metrics_known_confusion_matrix():
    rows = [
        {"is_expected_valid": False, "is_predicted_valid": False, "validation_time_ms": 1,
         "lean_check_time_ms": None, "dataset_source": "A", "artifact_name": "1", "artifact_sha256": "a"},
        {"is_expected_valid": True, "is_predicted_valid": True, "validation_time_ms": 2,
         "lean_check_time_ms": None, "dataset_source": "A", "artifact_name": "1", "artifact_sha256": "a"},
        {"is_expected_valid": True, "is_predicted_valid": False, "validation_time_ms": 3,
         "lean_check_time_ms": None, "dataset_source": "A", "artifact_name": "1", "artifact_sha256": "a"},
        {"is_expected_valid": False, "is_predicted_valid": True, "validation_time_ms": 4,
         "lean_check_time_ms": None, "dataset_source": "A", "artifact_name": "1", "artifact_sha256": "a"},
    ]
    metrics = compute_metrics(rows)
    assert (metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]) == (1, 1, 1, 1)
    assert metrics["accuracy"] == 0.5
    assert metrics["mean_lean_check_time_ms"] is None

