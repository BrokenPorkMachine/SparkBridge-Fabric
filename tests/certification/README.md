# Certification test/evidence workspace

SparkBridge v0.12.0-rc3 treats certification evidence as a release artifact rather than a textual assertion.

## Per-platform runner

Run:

```bash
python3 scripts/certification/generate_local_results.py
```

Retain:

- `certification-results.local.json`
- `certification-evidence/`

The result includes a deterministic `source_revision`. All platform bundles merged for one release decision must have exactly the same revision.

## Manual E2E/fault/drill evidence

Record a check and hash its log/artifact:

```bash
python3 scripts/certification/record_check.py \
  --results dgx-evidence.json \
  --check fault.ollama-restart \
  --status pass \
  --platform linux-aarch64 \
  --command "./fault-ollama-restart.sh" \
  --evidence ./logs/fault-ollama-restart.log
```

## Merge and blockers

```bash
python3 scripts/certification/merge_results.py certification-results.json \
  linux-x86_64.json dgx-aarch64.json macos-arm64.json windows-x86_64.json
python3 scripts/certification/release_blockers.py --results certification-results.json
```

A required SKIP, FAIL, missing result, missing evidence, or missing source revision blocks 1.0 promotion.
