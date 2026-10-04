# Changelog

## 0.12.0-rc3 — Certification Runner Hardening

- Preserved Fabric Protocol 1.10 and SQLite schema 9; rc3 remains wire/database compatible with v0.11, rc1 and rc2.
- Added `scripts/certify.sh` / `certify_revision.py` as a one-command same-revision certification workflow.
- Added portable evidence assembly that copies evidence, rewrites references, and emits an evidence manifest.
- Added independent evidence-file SHA-256/size verification.
- Expanded blocker evaluation to include release/protocol/schema/source identity and metric thresholds.
- Added actionable blocker triage with recommended follow-up commands/scenarios.
- CI aggregation now emits a portable verified evidence bundle rather than only a merged JSON file.
- DGX self-hosted certification now emits the same operator-style certification run directory.
- Added a certification-runner example and dedicated rc3 operator guide.
- Updated bundled User Manual and Installation Guide for the rc3 certification workflow.

## 0.12.0-rc2 — Certification Evidence Hardening

- Preserved Fabric Protocol 1.10 and SQLite schema 9; rc2 remains wire/database compatible with v0.11 and rc1.
- Added source-revision pinning to certification bundles so evidence from different source trees cannot be merged into one release decision.
- Required evidence for every required PASS in the 1.0 promotion profile.
- Added hashed evidence-file metadata, runner/command/timing fields, bundle IDs, and merge provenance.
- Hardened result merging to reject conflicting metrics and mixed source revisions while retaining FAIL over PASS/SKIP.
- Added `record_check.py` for manually recording E2E/fault/drill evidence with SHA-256 references.
- Added `release_blockers.py` for deterministic human-readable/JSON 1.0 blocker summaries.
- CI now uploads the generated certification evidence directory with each platform result.
- Added CI aggregation for Linux/macOS/Windows evidence and a dedicated self-hosted DGX Spark certification workflow.
- Backup/restore drill now checks Unix mode preservation and deliberate-corruption rejection.
- Clarified staged-update rollback script as a preflight; production signed-update/service-manager rollback remains a required external certification drill.
- Updated bundled User Manual, Installation Guide, Certification Guide, Maintenance Guide, status and validation evidence for rc2.

## 0.12.0 — 1.0 Candidate / Certification + Hardening

- Froze Fabric Protocol at 1.10 and SQLite schema at 9; no gratuitous wire/database bump.
- Added `sparkbridge-certification` with a machine-readable 1.0 release profile and evaluator.
- Added four-platform native Rust certification requirements including DGX Spark/Linux aarch64.
- Added protocol compatibility fixtures, fault-injection plan, backup/restore drill, and staged-update rollback drill.
- Added native Rust maintenance tests for backup/restore and Ed25519 update staging.
- CI now emits per-platform certification evidence artifacts.
- Added compatibility, certification, performance and threat-model guides.
- Hardened Linux installation to create its service account and added Linux/macOS uninstallers.
- Manuals updated and remain bundled.
- 1.0 promotion is blocked until every required certification gate is a real PASS; required SKIP is failure.

## 0.11.0 — External Integrations + Production Polish

- Advanced Fabric Protocol to 1.10 and SQLite schema marker to 9.
- Added `sparkbridge-integrations` and `sparkbridge-maintenance` crates.
- Added independent TLS integration listener on port 7791.
- Added independent integration bearer credential and PKI bootstrap generation.
- Added integration-principal identity with non-privileged default permissions.
- Added MCP stateless core tool surface with 2026-07-28 discovery plus legacy initialize compatibility.
- Added IDE/task REST API bound to the integration principal.
- Added OpenAI `/v1/models` and `/v1/chat/completions` compatibility.
- Added protected Ollama-compatible `/api/tags`, `/api/ps`, `/api/generate`, `/api/chat` routes.
- Added lightweight operator dashboard.
- Added integration-call audit events.
- Added digest-verified backup/restore CLI.
- Added Ed25519 signed update verification and staging.
- Added offline reachability-based CAS garbage-collection utility.
- Added Linux installer helpers, macOS LaunchDaemon packaging and Windows service installer/uninstaller.
- Updated User Manual and Installation Guide; manuals remain bundled by default.

## 0.10.0

Action Cache + Multi-Platform Validation. See `docs/CACHE_VALIDATION.md`.
