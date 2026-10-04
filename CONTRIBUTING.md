# Contributing — SparkBridge Fabric v0.12 1.0 Candidate

Before submitting changes:

```bash
./scripts/validate.sh
```

On a Rust-equipped machine this must include the source-structure scan, workspace check, tests and strict Clippy.

Formatting contract: this source tree intentionally uses a dense style, and `scripts/rust_delimiter_scan.py` is its structural gate. `cargo fmt` is not run as a gate because rustfmt rewrites that dense style, and the audit suite under `scripts/audit_*.py` asserts security and correctness invariants against exact source text — running rustfmt breaks roughly two dozen of those assertions. Keep new code in the surrounding dense style and let the delimiter scan and audit suite police it.

Before a 1.0 promotion, additionally collect the evidence required by `config/certification/profile-1.0-candidate.json`. A required `skip` blocks release.

Changes must preserve:

- separate admin/fabric/gateway/integration trust surfaces;
- integration principal binding and workspace ACLs;
- inference admission control;
- no external live-promotion shortcut;
- no plaintext secret logging;
- candidate/source/CAS integrity guarantees;
- backward-compatible protocol-major-1 negotiation;
- v0.12 protocol 1.10 and schema 9 freeze unless a documented compatibility decision changes them.

Maintenance changes must be fail-closed: backups are verified, restores do not overwrite by default, update signatures/digests are mandatory, and destructive CAS GC is opt-in.

Operator-visible changes require synchronized updates to both `docs/USER_MANUAL.md` and `docs/INSTALLATION_GUIDE.md`.
