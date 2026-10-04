# SparkBridge Fabric — v0.12.0-rc3 1.0 Candidate / Certification Runner Hardening

SparkBridge Fabric is a private distributed agentic software-engineering platform centered on an NVIDIA DGX Spark inference host with authenticated macOS, Windows, and Linux execution nodes.

**v0.12.0-rc3 adds no new product architecture.** It freezes Fabric Protocol **1.10** and SQLite schema **9** from v0.11 and concentrates on release qualification: machine-readable certification, native platform build evidence, E2E/fault drills, compatibility fixtures, backup/rollback qualification, installer hardening, threat-model review, and performance characterization.

```text
SparkBridge Fabric  0.12.0
Release class       1.0 Candidate (rc3)
Fabric Protocol     1.10 (frozen from v0.11)
SQLite schema       9    (frozen from v0.11)
Rust MSRV           1.85
```

## What v0.12 adds

- `sparkbridge-certification` release-gate crate;
- machine-readable 1.0 certification profile and result bundle;
- `sparkbridge certification evaluate` and `template` commands;
- Linux/macOS/Windows CI evidence artifacts;
- explicit DGX Spark / Linux aarch64 native-build requirement;
- protocol 1.8/1.9/1.10 compatibility fixture plus major-version rejection case;
- backup/restore and staged-update rollback drills;
- native Rust tests for backup/restore and Ed25519 update verification;
- fault-injection plan for server restart, executor disconnect, Ollama restart, CAS interruption, and promotion interruption;
- dedicated compatibility, threat-model, certification, and performance guides;
- hardened Linux service account bootstrap;
- Linux server/executor uninstallers and macOS executor uninstaller;
- frozen wire/database versions as the first explicit compatibility commitment.

## What rc2 tightens

rc2 hardens the *evidence*, not the product protocol:

- every certification bundle carries a deterministic `source_revision`;
- required PASS results must carry evidence;
- evidence files are represented by SHA-256 and size;
- platform bundles record runner/environment/command/timing metadata;
- merging different source revisions is rejected;
- conflicting values for the same performance metric are rejected instead of last-write-wins;
- merged bundles record the SHA-256 of every input bundle;
- `record_check.py` records manual E2E/fault/drill evidence;
- `release_blockers.py` renders the exact remaining 1.0 blockers.
- CI aggregates Linux/macOS/Windows bundles into a same-revision combined report;
- a dedicated self-hosted DGX Spark workflow emits aarch64 native evidence.

This is intentionally compatible with Protocol **1.10** and schema **9**.

## What rc3 tightens

rc3 turns the evidence pieces into a repeatable operator workflow:

- `./scripts/certify.sh` is the one-command local/merge/evaluate entry point;
- `assemble_evidence_bundle.py` copies and rewrites evidence into a portable bundle instead of leaving references tied to CI artifact directories;
- `verify_evidence_bundle.py` verifies every referenced evidence file by SHA-256 and byte size;
- `release_blockers.py` now mirrors release identity and metric-threshold blockers instead of checking only required check IDs;
- `triage_results.py` maps every remaining blocker to an actionable next step;
- CI aggregation emits a portable evidence directory plus blocker and triage reports;
- the DGX self-hosted workflow runs the same certification runner used by operators.

The runner still refuses to manufacture missing native/E2E/fault evidence: unresolved required gates remain blockers.

## Certification is intentionally stricter than source validation

`./scripts/validate.sh` proves source-level and structural invariants and, when Rust is installed, runs the workspace check/test/Clippy suite. Source formatting is governed by `scripts/rust_delimiter_scan.py` rather than `cargo fmt`, because the audit suite asserts security and correctness invariants against exact source text that rustfmt would rewrite (see `CONTRIBUTING.md`).

That is **not enough to declare 1.0**. The 1.0 certification profile additionally requires evidence from:

- Linux x86_64;
- NVIDIA DGX Spark / Linux aarch64;
- macOS arm64;
- Windows x86_64;
- control-plane E2E;
- agent repair E2E;
- server/executor/Ollama failure drills;
- backup/restore drill;
- staged update/rollback drill;
- protocol compatibility fixtures;
- tamper-evident audit verification.

Run:

```bash
./scripts/certify.sh --output-dir certification-run
cat certification-run/release-blockers.md
cat certification-run/triage.md
sparkbridge certification evaluate \
  --profile config/certification/profile-1.0-candidate.json \
  --results certification-results.local.json
```

A required `skip` is a release blocker, not a pass.

## Existing platform remains intact

v0.12 preserves all prior layers:

- Secure Fabric and mTLS node identity;
- private DGX/Ollama inference gateway;
- transactional SHA-256 CAS and immutable snapshots;
- candidate workspaces and transactional promotion;
- remote actions/execution domains;
- deterministic agent runtime;
- repository intelligence;
- policy, approvals, secrets and data boundaries;
- action cache and multi-platform validation;
- MCP / IDE / OpenAI / Ollama integration surfaces;
- backup/restore, staged signed updates, dashboard and service packaging.

The agent still **does not automatically promote a validated candidate into the live workspace**.

## Documentation

Start with:

- `docs/USER_MANUAL.md`
- `docs/INSTALLATION_GUIDE.md`
- `docs/CERTIFICATION.md`
- `docs/COMPATIBILITY.md`
- `docs/THREAT_MODEL.md`
- `docs/PERFORMANCE.md`
- `SECURITY.md`

## Validation

```bash
./scripts/validate.sh
```

See `VALIDATION.md` and `CERTIFICATION_STATUS.md` for the exact distinction between source gates and native release certification.
