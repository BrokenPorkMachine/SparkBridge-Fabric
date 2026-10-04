# AGENTS.md — SparkBridge Fabric v0.12 1.0 Candidate

## Non-negotiable invariants

1. Ollama remains loopback-only.
2. `admin_bind` remains loopback-only.
3. External integrations use port 7791 and `integration-token`; do not expose admin APIs to IDEs.
4. Integration clients are bound to `integration_principal_id`; never trust a client-supplied principal for authority.
5. MCP/IDE repository reads must pass workspace ACL checks.
6. External integrations may not bypass approval, validation, secret or promotion policy.
7. The model never owns authoritative state.
8. Candidates remain immutable and live promotion remains explicit/transactional.
9. Executor private keys and secret values never pass through model context.
10. Cached results never weaken their declared trust level.
11. Signed updates are verified/staged only; no silent self-update.
12. CAS GC defaults to dry-run and must not run destructively against a live server.
13. Protocol 1.10 and schema 9 are frozen for v0.12 unless a real incompatibility requires a deliberate change.
14. A required certification `skip` is a release blocker, never a pass.
15. Certification evidence must come from the named real platform/hardware.
16. User Manual and Installation Guide ship updated in every release.

## Development rule

New client surfaces remain adapters around existing services. Do not create a certification shortcut around policy, a separate state model, or a direct client-to-Ollama bypass.

Changes that invalidate a certification result require that result to be regenerated.
