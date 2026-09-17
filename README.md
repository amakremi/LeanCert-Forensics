# LeanCert-Forensics

LeanCert-Forensics is a research prototype for proof-carrying assurance of
digital-evidence process traces. It registers real public forensic artifacts by
hash, constructs explicit process traces, checks nine general forensic
requirements in Python, and emits deterministic Lean 4 certificates containing
only proof obligations that passed.

This is a validation instrument for a research paper, not a commercial forensic
platform. It favors reproducibility, transparent failures, and scientifically
limited claims over production features.

## Research contribution

The prototype demonstrates that a forensic evidence trace can be evaluated
against explicit obligations for:

1. identity completeness;
2. referential integrity and derived-artifact lineage;
3. public artifact integrity;
4. custody continuity;
5. chronological consistency;
6. hash continuity;
7. authorized handling;
8. lifecycle correctness; and
9. report traceability.

The validator derives outcomes from trace content and local artifact bytes. It
does not inspect filenames, trace IDs, source names, expected labels, scenarios,
or injected-violation metadata to decide validity. Tests deliberately reverse
labels and metadata to enforce this separation.

## Architecture

```text
public forensic source
        |
        v
Python streaming fetcher ---> attributed download manifest
        |                              |
        v                              v
artifact SHA-256 + size ------> canonical baseline trace
                                       |
                        +--------------+--------------+
                        |                             |
                        v                             v
                    valid trace           controlled perturbations
                        |                             |
                        +--------------+--------------+
                                       |
                                       v
                              Python requirements
                                       |
                  +--------------------+--------------------+
                  |                    |                    |
                  v                    v                    v
            JSON/CSV reports     Lean certificate     plots/tables
                                       |
                                       v
                            optional Lean type checking
```

The publication evaluation is split into four non-interchangeable tracks:

1. **Distribution integrity** checks local existence, readability, stored
   SHA-256/size consistency, distribution signatures, provenance, and the
   separately reported availability of official publisher checksums.
2. **Decompressed-image validation** streams CFReDS bzip2 distributions to
   preserved raw `.dd` derivatives, records a second hash/size pair, and attempts
   semantic inspection. Decompression alone is not content inspection.
3. **Locked process assurance** freezes physically separate declarative
   development/holdout mutations, blinds identifiers and filenames, and removes
   labels and mutation metadata before the validator process.
4. **Formalization and scalability audit** measures catalogue-relative mappings,
   positive/negative/benchmark coverage, and Python/Lean timings over 15
   structurally distinct traces at each declared size.

# Public Dataset Grounding

The benchmark uses publicly available forensic material from sources such as
NIST CFReDS, Digital Corpora, and official Wireshark test captures:

- Digital Corpora: a small Lone Wolf scenario bill-of-materials document is
  fetched automatically from the corpus host.
- Wireshark Sample Captures: three benign repository artifacts provide PCAP,
  text-log, and compressed-capture coverage.
- NIST CFReDS: six user-supplied archives are registered from the official
  archive distributions: DFR-01 FAT, DFR-01 NTFS, DFR-02 FAT, L0 Graphic,
  L0 Documents, and L0 Archive. The repository stores copied distributions,
  measured SHA-256 values, byte sizes, format metadata, and source URLs.

The system computes SHA-256 hashes and sizes from downloaded bytes. Valid traces
are constructed from those real public artifacts. Invalid traces are controlled
metadata perturbations of the public-data-derived baseline; they are not claimed
to be naturally occurring failures in the datasets.

Public datasets usually do not include complete chain-of-custody logs. The
prototype therefore creates deterministic logical process timestamps and
registration, preservation, handling, analysis, reporting, and archiving
events. These model validation events, not original forensic timestamps.

See [datasets/README.md](datasets/README.md) and
[datasets/public_sources.yaml](datasets/public_sources.yaml).

## Dataset links

These are the exact public sources the prototype registers artifacts from.
Automatically fetched sources (`python -m leancert.cli fetch-datasets`):

- Digital Corpora — Lone Wolf scenario bill of materials:
  https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/0%20%20README.pdf
- Wireshark Sample Captures (official repository test data):
  - HTTP sample capture:
    https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/http.pcap
  - SIP message log sample:
    https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/sipmsg.log
  - Community ID compressed capture sample:
    https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures/communityid.pcap.gz

Manual-selection source (no automated bulk download; select individual
archives yourself):

- NIST CFReDS project index: https://cfreds.nist.gov/
  - Data Leakage Case (DFR-01 FAT, DFR-01 NTFS, DFR-02 FAT) and Data Leakage
    Case L0 (Graphic, Documents, Archive) image sets are found from that
    index; download each `.dd.bz2` distribution to a local folder (for
    example `%USERPROFILE%\Downloads`).

Raw downloaded/derived bytes are **not** committed to this repository (see
`.gitignore`); only the small configuration that describes where to get them
is tracked, plus the measured SHA-256/size manifests produced once you fetch
them locally.

## Adding a new dataset artifact to the project

1. **Automatically downloadable source:** add an entry under `sources:` in
   [datasets/public_sources.yaml](datasets/public_sources.yaml) with
   `source_name`, `artifact_name`, `url`, `filename`, `kind`,
   `expected_format`, `max_size_mb`, and `enabled: true`. Then run:

   ```powershell
   python -m leancert.cli fetch-datasets
   ```

   This streams the file into `datasets/raw/<safe_source_name>/`, sanitizes
   the filename, enforces `max_size_mb`, and records the result in
   `datasets/manifests/download_manifest.json`.

2. **Manually obtained artifact (e.g. another NIST CFReDS image):** download
   it yourself from its official source, then register it without editing
   any code:

   ```powershell
   python -m leancert.cli register-local-artifact `
     --source-name "NIST CFReDS" `
     --artifact-name "<descriptive name>" `
     --kind "disk_image" `
     --path "C:\path\to\downloaded\artifact"
   ```

   or, for the six-artifact CFReDS batch used in the publication evaluation:

   ```powershell
   python -m leancert.cli discover-local-artifacts `
     --source-name "NIST CFReDS" --search-root "$env:USERPROFILE\Downloads"
   python -m leancert.cli register-cfreds-batch `
     --dfr-fat <path> --dfr-ntfs <path> --dfr-02-fat <path> `
     --l0-graphic <path> --l0-documents <path> --l0-archive <path> --copy
   ```

   Registration computes the real SHA-256 and size from the actual bytes and
   writes `download_status: local_registered`; it never fabricates a
   successful download. See
   [Manual NIST CFReDS registration](#manual-nist-cfreds-registration) below
   for the full command.

3. **Rebuild traces** so the new artifact is exercised by the validator:

   ```powershell
   python -m leancert.cli build-traces-from-datasets --force
   ```

Never mark an artifact as downloaded/registered unless it was legitimately
obtained from its public source; see
[datasets/README.md](datasets/README.md) for source-specific detail.

# Running on Windows 11

The primary supported environment is Windows 11, Python 3.11 or newer, and
PowerShell. WSL, Docker, and administrator privileges are not required.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m leancert.cli fetch-datasets
python -m leancert.cli build-traces-from-datasets
python -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5
pytest
```

The included setup and experiment scripts provide the same flow:

```powershell
.\scripts\setup_windows.ps1
.\scripts\run_experiment.ps1
```

If PowerShell blocks activation or scripts, either enable locally authored
scripts for the current user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

or run without activation:

```powershell
.\.venv\Scripts\python.exe -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5
```

## Lean 4 on Windows

Lean is optional for Python validation, reports, tables, and figures. Install it
with:

```powershell
winget install Lean.Lean
lean --version
lake --version
```

Alternatively install `elan` using its official Windows installer and let the
repository's `lean-toolchain` select the toolchain. If Lean is absent, the run
completes with `lean_check_status = NOT_RUN`; no timing values are invented.

Optional semantic disk-image inspection uses `pytsk3` when available, then
Sleuth Kit's `mmls` and `fsstat`. On Windows, install either backend using its
official distribution. If neither is installed, `inspect-images` reports
`NOT_RUN`; it never converts the metadata-only fallback into a successful
semantic inspection.

## Cross-platform installation

On Linux or macOS, create a Python 3.11+ virtual environment using the platform's
standard `python3 -m venv .venv`, activate it, install `requirements.txt`, and
run the same `python -m leancert.cli ...` commands. All application paths use
`pathlib.Path`, downloads use `requests`, subprocesses use argument arrays with
`shell=False`, and Matplotlib uses its headless `Agg` backend.

## Dataset acquisition

Fetch enabled small artifacts:

```powershell
python -m leancert.cli fetch-datasets
```

The fetcher streams each response, sanitizes Windows filenames, checks
`Content-Length` when available, enforces each entry's `max_size_mb`, continues
after failures, and writes:

```text
datasets/manifests/download_manifest.json
```

Permit configured large downloads explicitly:

```powershell
python -m leancert.cli fetch-datasets --allow-large-downloads
```

For manual acquisition, obtain an artifact from its public source, place it
under `datasets/raw/<safe_source_name>/`, and record its real path, SHA-256,
size, URL, and status in the manifest as described in `datasets/README.md`.
Never mark an unavailable artifact as downloaded.

Build deterministic baseline and controlled negative traces:

```powershell
python -m leancert.cli build-traces-from-datasets
python -m leancert.cli build-traces-from-datasets --force
```

Without `--force`, existing traces are preserved so user edits are not
overwritten.

## Command-line use

Validate one trace, generate its Lean certificate, optionally check it, and
write a per-trace report:

```powershell
python -m leancert.cli validate traces/public_valid/<trace>.json
python -m leancert.cli validate traces/public_valid/<trace>.json --strict-artifacts
```

Validate all JSON traces recursively:

```powershell
python -m leancert.cli validate-dir traces
```

Generate a certificate without invoking Lean:

```powershell
python -m leancert.cli generate-lean traces/public_valid/<trace>.json
```

Evaluate or run the complete experiment:

```powershell
python -m leancert.cli evaluate traces
python -m leancert.cli run-experiment traces
python -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5
python -m leancert.cli run-experiment traces --repeat 5 --repeat-lean 3
```

Run the publication workflow:

```powershell
python -m leancert.cli process-cfreds-images
python -m leancert.cli inspect-images
python -m leancert.cli verify-reference-checksums
python -m leancert.cli freeze-benchmark
python -m leancert.cli verify-benchmark-lock
python -m leancert.cli build-scalability-traces `
  --sizes 4 8 12 20 50 100 200 500 --traces-per-size 15 --seed 20260726
python -m leancert.cli audit-formalization
python -m leancert.cli run-experiment traces `
  --benchmark-track holdout --blind-benchmark --verify-benchmark-lock `
  --repeat 30 --repeat-lean 3 --strict-artifacts --require-lean `
  --paper-figures-only
```

The benchmark lock protects authored mutation files. Generated blinded traces
and their external label mapping are evaluation artifacts; the production
validator imports neither the transformer nor benchmark metadata.

`--repeat` averages measured Python validation time without duplicating reports.
`--repeat-lean` separately controls Lean repetitions. Use `--strict-artifacts`
when missing local artifacts must fail rather than produce warnings.

Run tests:

```powershell
pytest
```

The tests use tiny temporary fixtures for isolated dataset behavior and do not
perform large downloads.

## Interpretation boundaries

Catalogue-relative formalization coverage does not establish completeness with
respect to all forensic practice, law, standards, or operational environments.
The locked holdout benchmark reduces implementation coupling but does not make
controlled perturbations equivalent to naturally occurring failures. External
checksum verification is reported only where an official publisher reference
was available. Successful Lean checking establishes acceptance of emitted
propositions by the tested Lean kernel; invalid traces do not receive a
`ValidTrace` theorem.

## Validation behavior

The Python operational checker evaluates the following rules:

- **IdentityCompleteness**: required trace, evidence, actor, event, and claim
  identities are non-empty.
- **ReferentialIntegrity**: references resolve, IDs are unique, and derived
  artifacts name an existing parent.
- **PublicArtifactIntegrity**: existing artifact bytes match registered evidence
  and dataset-origin hashes and sizes. Missing bytes warn in normal mode and
  fail in strict mode.
- **CustodyContinuity**: each evidence item's holder sequence is independently
  continuous.
- **ChronologicalConsistency**: timestamps do not roll back and prerequisites
  precede reporting and derivation.
- **HashContinuity**: each evidence item's event hash chain is independently
  linked and unauthorized mutation is rejected.
- **AuthorizedHandling**: actions follow the declared role/action matrix.
- **LifecycleCorrectness**: acquisition, preservation, examination/analysis,
  reporting, and archiving order is enforced.
- **ReportTraceability**: claims resolve to evidence that passed all core
  requirements.

Malformed JSON and schema-invalid traces are never skipped. They appear in
per-trace and aggregate results as failed `SchemaValidation` entries.

## Example output

A content-valid trace produces:

```text
TRACE-PUBLIC-...-VALID: PASSED
Lean status: PASSED or NOT_RUN
```

A controlled hash-chain violation produces:

```text
TRACE-PUBLIC-...-HASH_DISCONTINUITY: FAILED
Failed requirements: HashContinuity;ReportTraceability
```

Multiple failures are expected when one defect invalidates evidence later used
by a report claim. Failure propagation is visible rather than hidden.

## Sample result

This repository tracks one representative figure and one representative table
from a full publication run, as a preview of the evaluation outputs
(the complete figure/table set is regenerated locally; see
[Result files](#result-files) below).

**Figure — confusion matrix** (invalid-trace violation detection, positive
class): [results/figures/confusion_matrix.png](results/figures/confusion_matrix.png)

**Table — holdout benchmark detection metrics**
([results/paper_tables/table_holdout_metrics.md](results/paper_tables/table_holdout_metrics.md)):

| Metric | Estimate | 95% interval | Method |
|---|---:|---|---|
| Accuracy | 1.0000 | [0.9697, 1.0000] | exact Clopper-Pearson |
| Precision | 1.0000 | [0.9598, 1.0000] | exact Clopper-Pearson |
| Recall | 1.0000 | [0.9598, 1.0000] | exact Clopper-Pearson |
| Specificity | 1.0000 | [0.8843, 1.0000] | exact Clopper-Pearson |
| F1 | 1.0000 | [1.0000, 1.0000] | stratified bootstrap; 10000 resamples; seed 20260728 |
| False Acceptance Rate | 0.0000 | [0.0000, 0.0402] | exact Clopper-Pearson |
| False Rejection Rate | 0.0000 | [0.0000, 0.1157] | exact Clopper-Pearson |

The F1 bootstrap interval degenerates at 1.0 when every stratified resample
remains perfectly classified; exact class-specific intervals therefore
provide a more informative characterization of finite-sample uncertainty.
Metrics are on the locked, blinded holdout benchmark (see
[Interpretation boundaries](#interpretation-boundaries)); they reflect
detection of controlled, declaratively specified perturbations and are not a
claim about natural forensic failure rates.

## Result files

The publication experiment produces the following primary outputs:

```text
reports/<trace_id>_report.json
results/evaluation_summary.json
results/evaluation_summary.csv
results/per_trace_results.csv
results/artifact_native_results.csv
results/scalability_results.csv
results/per_requirement_failures.csv
results/per_requirement_failures_direct.csv
results/per_requirement_failures_cascading.csv
results/confusion_matrix.csv
results/experiment_manifest.json
results/dataset_manifest_used.json
results/plot_warnings.json
results/figures/confusion_matrix.png
results/figures/artifact_native_validation.png
results/figures/direct_vs_cascading_failures.png
results/figures/proof_checking_time.png
results/figures/trace_size_vs_validation_time.png
results/paper_tables/table_dataset_sources.md
results/paper_tables/table_metrics.md
results/paper_tables/table_artifact_native_validation.md
results/paper_tables/table_lean_checking.md
results/paper_tables/table_scalability.md
```

The experiment manifest records the timestamp, Python/platform versions, trace
count, repetition settings, public sources/artifacts, Lean/Lake availability,
Lean version, and Git commit when available.

# Interpreting the Figures

- **Confusion matrix** shows invalid-trace violation detection as the positive
  class: TP, FN, FP, and TN are never rearranged or hidden.
- **Artifact-native validation** reports measured pass rates for existence,
  readability, hash, size, provenance, and distribution signatures.
- **Direct versus cascading failures** distinguishes injected primary defects
  from downstream report-traceability effects.
- **Trace size versus validation time** uses only dedicated valid scalability
  traces at 4, 8, 12, 20, 50, and 100 events.
- **Proof-checking time** reports median measured Lean time by event count.

# How to Interpret Results

A passed trace means that it satisfies the requirements modeled by this
prototype. A failed trace means at least one modeled requirement was violated.
A passed Lean check means that the generated formal definitions and emitted
successful obligations type-check or proof-check.

It does not mean that any external-world event definitely happened as recorded.
Invalid trace certificates list failed obligations in comments and prove only
successful obligations; the generator never invents a proof of a failed
requirement.

# Scientific Scope and Limitations

- The prototype validates formalized forensic process requirements.
- It does not prove that evidence content is factually true.
- It does not verify the correctness of Autopsy, Volatility, EnCase, or any
  external forensic tool.
- It does not prove legal admissibility in court.
- It checks explicitly modeled admissibility-readiness properties.
- The evaluation combines public artifacts with controlled process-violation
  perturbations.
- Invalid cases are rule-driven and validation is not scenario- or
  filename-driven.
- Lean 4 is a proof-checking backend for generated formal artifacts; Python
  performs operational validation and reporting.
- The Lean predicates intentionally represent a clear subset of the richer
  Python algorithms. They do not duplicate filesystem hashing or establish
  real-world facts.
- Correctness is limited by the completeness and correctness of the modeled
  requirements.
- The default automatically downloadable set remains small: scenario
  documentation and protocol test samples. A NIST CFReDS artifact currently
  requires manual selection. Larger disk and memory images provide broader
  empirical grounding but are excluded from the default run for safety and
  accessibility.

# Scientific Interpretation

Perfect results on controlled traces mean that this implementation detects the
modeled violations in this benchmark. They do not imply universal digital
forensic correctness. Scientific value comes from public-dataset grounding,
explicit obligations, deterministic transformations, reproducible execution,
honest dataset states, and transparent failure reports.

In citation-style terms, the prototype is an executable feasibility artifact
supporting the paper's claim that digital-evidence process assurance can be
decomposed into inspectable obligations and accompanied by machine-checkable
certificates. It supports that mechanics claim only; it is not evidence of
production readiness or guaranteed admissibility.

## Troubleshooting

- **PowerShell execution policy:** use the current-user `RemoteSigned` command
  above or call `.\.venv\Scripts\python.exe` directly.
- **Lean not found in PATH:** restart PowerShell after installation and verify
  `lean --version` and `lake --version`. Python outputs still complete.
- **Download skipped due to size:** inspect the manifest and opt into
  `--allow-large-downloads` only after checking storage and source terms.
- **Manual dataset download:** follow `datasets/README.md`; record real metadata
  and never fabricate a success status.
- **Long paths:** keep the repository near a short drive path and enable Windows
  long-path support if handling deeply nested corpora.
- **Antivirus hashing delay:** real forensic images may be scanned while Python
  hashes them. A slower measurement is retained rather than filtered out.

## Running the improved Windows experiment

```powershell
.\scripts\setup_windows.ps1
.\scripts\install_lean_windows.ps1
.\.venv\Scripts\python.exe -m leancert.cli check-lean
.\.venv\Scripts\python.exe -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5 --variants standard
pytest
```

The installer checks existing `lean` and `lake` commands before asking winget to
install `Lean.Lean`. Lean installation is optional unless `--require-lean` is
passed to `run-experiment`.

```powershell
.\.venv\Scripts\python.exe -m leancert.cli run-experiment traces --require-lean
```

Trace-generation modes are:

- `minimal`: one valid trace and three controlled invalid traces per artifact;
- `standard`: one valid trace, nine single-violation traces, and three paired
  multi-violation traces per artifact;
- `full`: the standard set plus one combined three-violation stress trace.

Kind-specific lifecycle templates create varied event counts: report/log
artifacts use four events, memory dumps five, network captures six, and disk
images eight.

## Six-artifact CFReDS publication evaluation

Only completed archives are eligible; `.crdownload` files are ignored. Discover
and register the six supplied official distributions:

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

.\.venv\Scripts\python.exe -m leancert.cli build-traces-from-datasets `
  --force --variants standard
.\.venv\Scripts\python.exe -m leancert.cli build-scalability-traces `
  --sizes 4 8 12 20 50 100
.\.venv\Scripts\python.exe -m leancert.cli run-experiment traces `
  --repeat 20 --strict-artifacts --require-lean --paper-figures-only
```

The evaluation has two separate tracks. Artifact-native validation operates
directly on unmodified registered bytes and checks existence, readability,
SHA-256 consistency, size consistency, provenance completeness, and container
signature consistency. Controlled process-assurance validation constructs
valid lifecycles around those evidence objects and applies general,
content-level perturbation rules.

The evaluation uses real public forensic artifacts from NIST CFReDS, Digital
Corpora, and Wireshark Sample Captures. Process-assurance failures are
controlled perturbations because these public datasets do not provide
independently labeled chain-of-custody, authorization, or lifecycle failures.
They are not claimed to be naturally occurring defects in CFReDS.

Perfect classification on the controlled benchmark demonstrates correct
enforcement of the modeled requirements over the evaluated traces. It does not
imply universal forensic correctness or legal admissibility.

Lean proof checking establishes that generated formal artifacts and emitted
proof obligations are accepted by the tested Lean kernel. It does not establish
factual truth of external evidence or correctness of external forensic tools.

## If Lean is unavailable

Python operational validation, reports, plots, tables, and deterministic Lean
artifact generation still run. Proof checking is recorded as `NOT_RUN`,
`results/lean_not_run_reason.txt` explains why, and no Lean timing is invented.
Install Lean and rerun before claiming that actual proof checking occurred.

## Manual NIST CFReDS registration

```powershell
.\.venv\Scripts\python.exe -m leancert.cli register-local-artifact `
  --source-name "NIST CFReDS" `
  --artifact-name "NIST manually downloaded artifact" `
  --kind "disk_image" `
  --path "D:\Datasets\NIST\artifact.zip"
```

The command validates the file, computes its actual SHA-256 and size, and
records `local_registered`. It does not claim that LeanCert downloaded it.

## ReportTraceability interpretation

ReportTraceability is intentionally downstream of other requirements. If
evidence fails custody, integrity, authorization, or lifecycle validation,
claims relying on that evidence are marked unsupported. These are reported as
cascading traceability failures rather than independent direct claim defects.

Direct failures are empty claim support, missing claim text, or references to
nonexistent evidence. The aggregate, direct, and cascading views are stored in
separate CSV files and compared in a dedicated plot and paper table.

## Dataset limitations

If only one artifact is available, the run validates framework mechanics, not
dataset diversity. A stronger evaluation requires multiple artifact types such
as disk images, memory dumps, PCAPs, and logs/reports. The default lightweight
set now includes four artifacts when all configured downloads succeed, but its
Wireshark files are small protocol test samples rather than complete incident
cases. NIST CFReDS commonly requires manual selection and registration.

## Publication wording

> The prototype generated public-data-derived forensic traces from available
> public artifacts and evaluated controlled perturbations representing modeled
> process violations. Lean artifacts were generated for each trace. When
> Lean/Lake were available, these artifacts were proof-checked; otherwise, the
> system reported Lean status as NOT_RUN and did not invent proof-checking
> results.
## Controlled sub-obligation conformance benchmark

All 35 sub-obligations in the declared LeanCert-Forensics catalogue were explicitly mapped to Python and Lean and exercised by the reported controlled validation. This is catalogue-relative coverage; it is not a claim of complete forensic-domain, legal, jurisdictional, or admissibility coverage.

The sub-obligation benchmark consists of controlled, declaratively specified perturbations of public-data-derived forensic traces. It validates enforcement of the declared obligation catalogue; it does not estimate the prevalence or detection accuracy of naturally occurring forensic process failures.

No independently labelled natural chain-of-custody failure corpus was available.
