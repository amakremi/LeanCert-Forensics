# Public forensic datasets

The manifest configures Digital Corpora, official Wireshark test captures, and
NIST CFReDS. Digital Corpora's small Lone Wolf scenario bill of materials and
three benign Wireshark samples (PCAP, text log, and compressed capture) are
downloaded automatically. Six completed NIST CFReDS bzip2 distributions are
registered locally for the publication evaluation: three deleted-file-recovery
images and three level-zero file-carving images.

Discover completed CFReDS archives (partial `.crdownload` files are excluded)
and register the six measured files:

```powershell
.\.venv\Scripts\python.exe -m leancert.cli discover-local-artifacts `
  --source-name "NIST CFReDS" `
  --search-root "$env:USERPROFILE\Downloads"

.\.venv\Scripts\python.exe -m leancert.cli register-cfreds-batch `
  --dfr-fat "$env:USERPROFILE\Downloads\dfr-01-fat.dd.bz2" `
  --dfr-ntfs "$env:USERPROFILE\Downloads\dfr-01-ntfs.dd.bz2" `
  --dfr-02-fat "$env:USERPROFILE\Downloads\dfr-02-fat.dd.bz2" `
  --l0-graphic "$env:USERPROFILE\Downloads\L0_Graphic.dd.bz2" `
  --l0-documents "$env:USERPROFILE\Downloads\L0_Documents.dd.bz2" `
  --l0-archive "$env:USERPROFILE\Downloads\L0_Archive.dd.bz2" `
  --copy
```

The batch command verifies existence, copies the selected files under
`datasets/raw/nist_cfreds/`, computes SHA-256 and size, records distribution and
content formats, preserves official source attribution, and writes
`download_status: local_registered`. It does not imply that LeanCert downloaded
the artifacts.

Downloads are third-party research data. Review each source's usage terms and
handle forensic images with appropriate care. The repository never fabricates a
successful download record.

Process the registered CFReDS distributions without modifying the originals:

```powershell
.\.venv\Scripts\python.exe -m leancert.cli process-cfreds-images
.\.venv\Scripts\python.exe -m leancert.cli inspect-images
.\.venv\Scripts\python.exe -m leancert.cli verify-reference-checksums
```

Decompressed images are written under
`datasets/derived/nist_cfreds/decompressed/`; compressed and decompressed hashes
and sizes are recorded separately in
`datasets/manifests/cfreds_processing_manifest.json`. Official reference
checksums are declared in `datasets/reference_checksums.yaml`. Empty
`expected_value` fields mean that no official checksum was located and produce
`UNAVAILABLE`, never a pass.
