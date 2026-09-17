from __future__ import annotations

from pathlib import Path

import leancert.datasets as dataset_module
from leancert.datasets import load_sources, register_unlisted_local_artifacts
from leancert.utils import safe_filename, slugify


def test_public_manifest_configures_two_sources():
    config = load_sources()
    names = {source["source_name"] for source in config["sources"]}
    assert {"Digital Corpora", "NIST CFReDS"} <= names


def test_safe_filename_handles_windows_rules():
    assert safe_filename("CON.txt").startswith("_CON")
    assert not any(character in safe_filename('bad<>:"/\\|?*.txt') for character in '<>:"/\\|?*')
    assert not safe_filename("trailing. ").endswith((".", " "))


def test_source_names_become_safe_folders():
    slug = slugify("NIST CFReDS: Corpus / 2025?")
    assert slug == "nist_cfreds_corpus_2025"


def test_long_filename_preserves_extension():
    name = safe_filename("x" * 300 + ".pcap", max_length=80)
    assert len(name) <= 80
    assert name.endswith(".pcap")


def test_manually_placed_real_artifact_is_registered(monkeypatch, tmp_path):
    monkeypatch.setattr(dataset_module, "PROJECT_ROOT", tmp_path)
    raw = tmp_path / "datasets" / "raw" / "nist_cfreds"
    raw.mkdir(parents=True)
    artifact = raw / "small.pcap"
    artifact.write_bytes(b"real manually downloaded bytes")
    config = tmp_path / "sources.yaml"
    config.write_text(
        "sources:\n"
        "  - source_name: NIST CFReDS\n"
        "    usage_note: public reference data\n"
        "    artifacts:\n"
        "      - artifact_name: manual\n"
        "        url: MANUAL_DOWNLOAD_REQUIRED\n"
        "        kind: network_capture\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    records = register_unlisted_local_artifacts(
        [], config_path=config, manifest_path=manifest
    )
    assert records[0]["download_status"] == "manual_local"
    assert records[0]["sha256"]
    assert manifest.is_file()
