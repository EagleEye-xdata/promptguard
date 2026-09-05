# Curated upstream parameter repository

This directory is generated from commit-pinned, license-reviewed upstream
sources. It deliberately does **not** vendor entire applications.

Generated artifacts:

- `attack_templates.jsonl`: reusable target-facing templates only.
- `technique_parameters.jsonl`: attack goals, descriptions, required
  capabilities, generation parameters, and safe-behavior checks.
- `evaluation_dataset.jsonl`: labeled examples held out from runtime matching.
- `curation_report.json`: counts, exclusions, duplicates, and provenance.

The curation excludes source code, dependencies, tests, binaries, images,
audio, generated reports, caches, documentation prose, empty records, likely
credentials, duplicates, and sources without an explicit license. Evaluation
examples never enter the runtime attack library, preventing benchmark leakage.

Rebuild from local pinned checkouts:

```powershell
python scripts/build_upstream_corpus.py --source-root C:\path\to\checkouts
```

The checkout folder must contain `promptfoo`, `giskard`, `promptmap`, and
`llm-sentinel-proxy` at the commits declared in `sources.yaml`.

Upstream copyright remains with the respective authors. See `sources.yaml`
for repository, revision, license, included path, and intended use.
