#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    "Cargo.toml",
    "rust-toolchain.toml",
    "crates/sparkbridge-core/Cargo.toml",
    "crates/sparkbridge-config/Cargo.toml",
    "crates/sparkbridge-protocol/Cargo.toml",
    "crates/sparkbridge-cas/Cargo.toml",
    "crates/sparkbridge-snapshot/Cargo.toml",
    "crates/sparkbridge-candidate/Cargo.toml",
    "crates/sparkbridge-promotion/Cargo.toml",
    "crates/sparkbridge-index/Cargo.toml",
    "crates/sparkbridge-policy/Cargo.toml",
    "crates/sparkbridge-secrets/Cargo.toml",
    "crates/sparkbridge-audit/Cargo.toml",
    "crates/sparkbridge-integrations/Cargo.toml",
    "crates/sparkbridge-maintenance/Cargo.toml",
    "crates/sparkbridge-certification/Cargo.toml",
    "apps/sparkbridge-server/Cargo.toml",
    "apps/sparkbridge-executor/Cargo.toml",
    "apps/sparkbridge-cli/Cargo.toml",
    "docs/ARCHITECTURE.md",
    "docs/ITERATION_PLAN.md",
    "docs/REPOSITORY_INTELLIGENCE.md",
    "docs/POLICY_SECRETS.md",
    "docs/EXTERNAL_INTEGRATIONS.md",
    "docs/MAINTENANCE.md",
    "docs/CERTIFICATION.md",
    "docs/COMPATIBILITY.md",
    "docs/THREAT_MODEL.md",
    "docs/PERFORMANCE.md",
    "docs/USER_MANUAL.md",
    "docs/INSTALLATION_GUIDE.md",
]
missing = [p for p in required if not (root / p).exists()]
if missing:
    print("missing required files:", *missing, sep="\n  ", file=sys.stderr)
    raise SystemExit(1)

for path in root.rglob("*.toml"):
    with path.open("rb") as f:
        tomllib.load(f)

workspace = tomllib.loads((root / "Cargo.toml").read_text())
members = workspace["workspace"]["members"]
for member in members:
    if not (root / member / "Cargo.toml").exists():
        raise SystemExit(f"workspace member missing Cargo.toml: {member}")

print(f"structure OK: {len(members)} workspace packages")
