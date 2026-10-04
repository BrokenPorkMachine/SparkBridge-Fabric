#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/validate_structure.py
python3 scripts/rust_delimiter_scan.py
python3 scripts/audit_secure.py
python3 scripts/audit_inference.py
python3 scripts/audit_snapshots.py
python3 scripts/audit_candidates.py
python3 scripts/audit_actions.py
python3 scripts/audit_agent.py
python3 scripts/audit_intelligence.py
python3 scripts/audit_policy.py
python3 scripts/audit_cache_validation.py
python3 scripts/audit_integrations.py
python3 scripts/audit_certification.py
python3 scripts/certification/selftest_rc3.py

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not installed; structural validation passed, Rust build checks skipped" >&2
  exit 0
fi

# Formatting contract: `scripts/rust_delimiter_scan.py` (run above) is the structural gate for
# this source tree. `cargo fmt` is deliberately NOT used as a gate because rustfmt would
# rewrite the dense single-line style that the audit suite asserts against as exact source
# text (e.g. `state.cas.put_bytes(None,&bytes)`); running it breaks ~24 security and
# correctness invariants across audit_secure/agent/intelligence/integrations.
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

echo "SparkBridge v0.12 Certification + Hardening source gates passed"
