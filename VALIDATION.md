# SparkBridge Fabric v0.12.0-rc3 — Validation Report

## Release identity

- Source revision: `tree-sha256:b7ed5cbc8687932a36ea99884fb50d7a797ee81f0e205a9bb10eba3ae1913743`
- Fabric Protocol: **1.10** (frozen)
- SQLite schema: **9** (frozen)
- Rust workspace packages: **23**
- Native Rust compilation in this artifact environment: **PASS — cargo 1.94.1 / rustc on Apple Silicon arm64** (`cargo check --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, all exit 0)

## Source/invariant gates

| Layer | Result |
|---|---:|
| Secure Fabric | 28 / 28 |
| Inference Gateway | 37 / 37 |
| CAS + Snapshots | 31 / 31 |
| Candidate + Promotion | 41 / 41 |
| Remote Actions | 28 / 28 |
| Deterministic Agent Runtime | 46 / 46 |
| Repository Intelligence | 47 / 47 |
| Policy + Secrets | 58 / 58 |
| Action Cache + Validation | 68 / 68 |
| External Integrations + Production | 58 / 58 |
| Certification + Hardening rc3 | 78 / 78 |
| **Total invariants** | **520 / 520** |

Additional rc3 certification-tooling self-test: **PASS**.

## rc3 hardening tests

- one-command certification runner: PASS;
- source revision stable when certification output is generated: PASS;
- portable evidence assembly: PASS;
- evidence SHA-256/size verification: PASS;
- tampered evidence rejection: PASS;
- release identity blocker rendering: PASS;
- metric-threshold blocker rendering: PASS;
- actionable triage rendering: PASS;
- CI portable-bundle aggregation wiring: PASS;
- DGX one-command runner wiring: PASS.

## Certification result in this environment

The bundled certification run reports:

- PASS: 4;
- FAIL: 0;
- SKIP: 11;
- outstanding required blockers: 11;
- `release_ready: false`.

The native macOS arm64 build, test and strict-Clippy gate passed on Apple Silicon and is recorded as `rust.macos-arm64` with hashed evidence.

This is the correct outcome because this environment does not provide the Linux x86_64, DGX Spark/Linux aarch64, Windows x86_64, E2E, fault or drill evidence required by the 1.0 promotion profile.

## Artifact hygiene

- bundled User Manual: PASS;
- bundled Installation Guide: PASS;
- rc3 Certification Runner Guide: PASS;
- credential/private-key/token artifacts: none expected in release tree;
- generated Python/build caches excluded from source revision;
- generated certification-run output excluded from source revision.

Run `./scripts/validate.sh` on a Rust-equipped machine to add `cargo check`, workspace tests, and strict Clippy to these source gates. Source structure is gated by `scripts/rust_delimiter_scan.py` instead of `cargo fmt`: the audit suite asserts invariants against exact source text that rustfmt would rewrite, so running it would break roughly two dozen security and correctness assertions (see `CONTRIBUTING.md`).

## Packaging preflight

Archive construction is not performed by any tooling in this tree, so no archive-level claim is made here. The release inventory is `PROJECT_FILES.txt`; the file count below is the inventory size, not a verified archive.
