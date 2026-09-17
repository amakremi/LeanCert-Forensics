from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_filename(name: str, max_length: int = 180) -> str:
    """Return a useful filename valid on Windows, Linux, and macOS."""
    raw = Path(name).name or "artifact"
    raw = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", raw).rstrip(" .")
    if not raw:
        raw = "artifact"
    path = Path(raw)
    suffix = "".join(path.suffixes)
    stem = raw[: -len(suffix)] if suffix else raw
    if stem.upper() in WINDOWS_RESERVED:
        stem = f"_{stem}"
    room = max(1, max_length - len(suffix))
    stem = stem[:room].rstrip(" .") or "artifact"
    return f"{stem}{suffix}"[:max_length].rstrip(" .")


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._ ")
    return safe_filename(slug.lower() or "source", 100)


@lru_cache(maxsize=256)
def _sha256_cached(path_text: str, size: int, modified_ns: int, chunk_size: int) -> str:
    digest = hashlib.sha256()
    with Path(path_text).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    resolved = path.resolve()
    stat = resolved.stat()
    return _sha256_cached(str(resolved), stat.st_size, stat.st_mtime_ns, chunk_size)


def resolve_project_path(path: str | Path) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def relative_to_project(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
