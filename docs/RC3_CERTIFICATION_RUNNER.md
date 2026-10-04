# SparkBridge v0.12.0-rc3 Certification Runner

rc3 does not add product architecture. It makes 1.0 qualification repeatable and portable.

## Local run

```bash
./scripts/certify.sh --output-dir certification-run
```

This runs the local source/native collector, assembles its evidence, verifies referenced hashes/sizes, renders blockers and triage, and writes `certification-report.json`. Missing native tooling is reported as unresolved evidence, not converted into PASS.

## Merge platform evidence

Each platform must certify the exact same `source_revision`. Pass additional result files with repeated `--input` options. Mixed revisions fail closed.

```bash
./scripts/certify.sh --output-dir certification-run \
  --input linux-x86_64.json \
  --input macos-arm64.json \
  --input windows-x86_64.json \
  --input dgx-aarch64.json
```

## Portable bundle

`assemble_evidence_bundle.py` copies each referenced evidence file beneath the output directory and rewrites the result bundle to those portable paths. It emits `evidence-manifest.json` covering the assembled payload.

Re-verify after copying the directory to another machine:

```bash
python3 scripts/certification/verify_evidence_bundle.py \
  --results certification-run/bundle/certification-results.json \
  --root certification-run/bundle
```

## Triage

`triage.md` gives the next action for each unresolved release gate. It is advisory; `config/certification/profile-1.0-candidate.json` remains authoritative.

## Promotion behavior

```bash
./scripts/certify.sh --output-dir certification-run --require-ready
```

returns success only when no required check, release identity condition, or required metric is blocking promotion. rc3 itself is expected to remain not-ready until real DGX/macOS/Windows/Linux and E2E/fault evidence is supplied.
