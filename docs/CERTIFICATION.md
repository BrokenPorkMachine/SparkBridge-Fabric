# SparkBridge v0.12 — Certification & 1.0 Promotion Guide

## Principle

A source audit, successful build, or one successful demo is not a release certification. SparkBridge 1.0 requires evidence that the same release behaves correctly across its supported execution platforms and under expected failures.

## Authoritative profile

`config/certification/profile-1.0-candidate.json` is the machine-readable promotion contract.

Required native targets:

- `rust.linux-x86_64`
- `rust.linux-aarch64-dgx`
- `rust.macos-arm64`
- `rust.windows-x86_64`

Required system scenarios:

- `e2e.control-plane`
- `e2e.agent-repair`
- `fault.server-restart`
- `fault.executor-disconnect`
- `fault.ollama-restart`
- `drill.backup-restore`
- `drill.upgrade-rollback`
- `compat.protocol-1.9`
- `compat.protocol-1.10`
- `security.audit-chain`

A required `skip` blocks promotion exactly like a failure.

## rc2/rc3 evidence identity and provenance

A certification result is valid for promotion only when all participating runners certify the **same source revision**. When no Git metadata is present, SparkBridge computes a deterministic tree SHA-256 over the release source tree. `merge_results.py` refuses to merge different revisions.

Every required PASS must include evidence. Automated runners write logs beneath `certification-evidence/` and record each evidence file's SHA-256 and byte size in the result bundle. Manual E2E/fault/drill checks can be recorded with:

```bash
python3 scripts/certification/record_check.py \
  --results dgx-evidence.json \
  --check e2e.control-plane \
  --status pass \
  --platform linux-aarch64 \
  --command "./run-control-plane-e2e.sh" \
  --evidence ./logs/control-plane-e2e.log
```

After merging all platform bundles, render blockers before attempting promotion:

```bash
python3 scripts/certification/release_blockers.py \
  --results certification-results.json
```

`config/certification/evidence-bundle.schema.json` documents the evidence format. The merge result also contains SHA-256 provenance for each input bundle.


## rc3 one-command workflow

For one machine, collect, assemble, verify, evaluate, and render triage in one step:

```bash
./scripts/certify.sh --output-dir certification-run
```

To merge additional same-revision platform bundles:

```bash
./scripts/certify.sh \
  --output-dir certification-run \
  --input linux-x86_64.json \
  --input macos-arm64.json \
  --input windows-x86_64.json \
  --input dgx-aarch64.json
```

The runner creates:

- `bundle/certification-results.json`;
- `bundle/evidence-manifest.json`;
- copied/rewritten evidence under `bundle/evidence/`;
- `release-blockers.json` and `.md`;
- `triage.md`;
- `certification-report.json`.

Use `--require-ready` only in a final promotion pipeline; it exits non-zero while any required gate remains unresolved.

The evidence assembler refuses mixed source revisions and validates the SHA-256 and byte size of every evidence file it copies. `verify_evidence_bundle.py` can independently re-check a portable bundle after transfer.

## CI and DGX evidence lanes

The standard CI workflow runs Linux x86_64, macOS arm64 and Windows x86_64 certification generation and then merges those artifacts in `certification-aggregate`. The merge is source-revision checked and emits `release-blockers.ci.md`.

DGX Spark uses `.github/workflows/certification-dgx.yml` on a self-hosted runner labeled `dgx-spark`. That lane records the host environment, runs native source/Rust gates, and uploads its result bundle plus evidence files. Its result must still be merged with the other platform and manual drill bundles before 1.0 promotion.

## E2E control-plane scenario

Prove, using production-equivalent TLS/configuration:

1. enroll a fresh executor;
2. reconnect with mTLS;
3. report capabilities/workspace binding;
4. snapshot a repository and upload only missing CAS objects;
5. build repository intelligence;
6. create a candidate;
7. validate candidate on an executor sandbox;
8. observe durable action/task evidence;
9. dry-run promotion;
10. require explicit approval before live promotion.

## Agent repair scenario

Use a deliberately broken fixture repository. The agent must:

1. discover relevant source using repository intelligence;
2. propose an immutable candidate;
3. run build/test against candidate sandbox;
4. receive normalized diagnostics;
5. produce a repair candidate;
6. pass required validation targets;
7. stop at validated candidate without automatic promotion.

## Fault scenarios

The canonical fault plan is `scripts/certification/fault_plan.json`.

Evidence must show the expected invariant, not merely that the service restarted.

## Backup/restore

Use `scripts/certification/backup_restore_drill.sh` after building the CLI. A production drill should also restore a copy of real metadata/PKI into an isolated host and prove health/node/task/audit visibility.

## Upgrade/rollback

v0.12 keeps protocol 1.10/schema 9 specifically to make rollback qualification meaningful. Stage v0.12, preserve v0.11, upgrade binaries, verify, then prove the old binaries can be restored without database conversion.

## Result evaluation

```bash
sparkbridge certification evaluate \
  --profile config/certification/profile-1.0-candidate.json \
  --results certification-results.json
```

Only `release_ready: true` is eligible for 1.0 promotion.

## Merging platform evidence

Each native runner produces an independent result bundle from the exact same source revision. Merge them without allowing a later PASS to erase an earlier FAIL:

```bash
python3 scripts/certification/merge_results.py certification-results.json \
  linux-x86_64.json dgx-aarch64.json macos-arm64.json windows-x86_64.json
```

Then evaluate the merged bundle.

## Remote smoke and latency probes

For a deployed candidate:

```bash
python3 scripts/certification/remote_smoke.py \
  --integration https://dgx.example:7791 \
  --integration-token "$SPARKBRIDGE_INTEGRATION_TOKEN" \
  --gateway https://dgx.example:7790 \
  --gateway-token "$SPARKBRIDGE_GATEWAY_TOKEN" \
  --ca ./pki/ca.pem
```

Latency probes can be recorded with:

```bash
python3 scripts/certification/benchmark_http.py \
  https://127.0.0.1:7790/api/v1/inference/health \
  --token "$SPARKBRIDGE_GATEWAY_TOKEN" \
  --ca ./pki/ca.pem \
  --metric gateway_local_overhead_p95_ms
```
