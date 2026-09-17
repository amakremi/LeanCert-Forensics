from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path
from typing import Any

from .utils import PROJECT_ROOT, utc_now, write_json

OUTPUT_PATH = PROJECT_ROOT / "results" / "environment_dependencies.json"


def capture_environment_dependencies(output_path: Path = OUTPUT_PATH) -> dict[str, Any]:
    record: dict[str, Any] = {
        "execution_timestamp_utc": utc_now(),
        "python_executable": sys.executable,
        "python_version": sys.version,
        "python_architecture": platform.architecture()[0],
        "pytsk3_available": False,
        "pytsk3_module_path": None,
        "pytsk3_version": None,
        "sleuthkit_embedded_version": None,
        "selected_image_inspection_backend": "none",
        "import_exception": None,
    }
    try:
        import pytsk3  # type: ignore

        record.update({
            "pytsk3_available": True,
            "pytsk3_module_path": str(Path(pytsk3.__file__).resolve()),
            "pytsk3_version": importlib.metadata.version("pytsk3"),
            "sleuthkit_embedded_version": getattr(
                pytsk3, "TSK_VERSION_STR", "unavailable"
            ),
            "selected_image_inspection_backend": "pytsk3",
        })
    except Exception as exc:
        record["import_exception"] = f"{type(exc).__name__}: {exc}"
    write_json(output_path, record)
    return record
