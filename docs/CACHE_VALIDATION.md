# Action Cache + Multi-Platform Validation — v0.10

## Purpose

v0.10 reduces repeated build/test work without turning stale or undeclared machine state into false validation evidence. It also allows a single immutable candidate to be validated on multiple operating systems while preserving the original executor's exclusive authority to promote into the live workspace.

## Cache trust levels

### Disabled
No cache key is generated. The action always runs.

### Best effort
The action must still be pure, candidate-bound and free of secret injections. Successful results may be recorded and used for scheduler affinity, but they are not treated as authoritative execution substitutes.

### Strong
A strong hit may skip execution. SparkBridge requires:

1. `side_effect = pure`;
2. immutable `candidate_id`;
3. no secret injections;
4. `network_policy = none`;
5. a valid toolchain fingerprint;
6. known fingerprint data for every required tool capability;
7. an execution domain that advertises `cache:strong`, meaning the domain claims closed/hermetic non-network inputs.

A failure to prove any item rejects strong caching rather than downgrading silently. Native `host` domains intentionally do not advertise `cache:strong` in v0.10 because network isolation alone does not close package caches, SDKs, home-directory files, or other host state.

## Cache key

The canonical SHA-256 cache key covers:

```text
workspace ID
candidate ID
execution domain
target platform
target architecture
argv
relative CWD
ordinary environment overrides
timeout/output bounds
network policy + declared hosts
required capabilities
cache trust
toolchain digest
```

Secret values are deliberately excluded because secret-dependent actions are not cacheable.

## Toolchain fingerprint

Each execution domain reports a digest built from:

```text
platform
architecture
domain
executor version
resolved command paths
reported command versions
selected toolchain/SDK environment
```

Current selected environment includes `SDKROOT`, `DEVELOPER_DIR`, `CC`, `CXX`, `RUSTUP_TOOLCHAIN`, `DOTNET_ROOT`, and `JAVA_HOME` when present.

## Cache result provenance

Successful cacheable results are serialized into DGX CAS. The SQLite cache row records the CAS digest, source action, trust level, candidate, workspace, toolchain digest, timestamps and hit count. Thus the cache result has immutable content-addressed evidence independent of the mutable cache index.

## Multi-platform validation

A validation run contains one or more targets. Each target declares at least:

```text
name
platform
optional architecture
domain
argv
required capabilities
network/cache policy
limits
```

The scheduler selects an online executor that:

- advertises the target domain;
- advertises the same logical workspace ID;
- matches requested platform/architecture;
- has every required capability.

The executor reconstructs the immutable candidate into a disposable sandbox from DGX CAS. It does not need ownership of the original source snapshot.

## Cross-node safety

Cross-node permission is intentionally asymmetric:

```text
candidate owner executor  -> may validate + may request promotion
other matching executor   -> may validate read-only
```

Promotion authorization still requires the original candidate node and workspace.

## Validation status

A run is:

- `running` while at least one target is still non-terminal;
- `awaiting_approval` when applicable;
- `failed` if any target fails, times out or is lost;
- `cancelled` if cancellation is terminal;
- `succeeded` only when every target succeeds.

## Agent fan-out

With `validation_fanout=true`, a task schedules its remaining validation actions in one durable group. The task records all action IDs, waits for every one to become terminal, concatenates evidence, collects diagnostic source paths, and either:

- marks validation complete when all succeed; or
- increments the repair cycle and gives the aggregate evidence back to the next model turn.

The task also materializes that validation cycle as the same durable `ValidationRunRecord` used by the operator validation API. This means successful agent fan-out can directly satisfy `required_validation_platforms`; a second manual matrix is not required.

## Promotion requirements

`WorkspacePolicyRecord.required_validation_platforms` may enforce platform coverage. For example:

```json
"required_validation_platforms": ["macos", "windows", "linux"]
```

A live promotion is denied unless at least one successful validation run for that candidate contains all listed platforms. This is additive to the existing explicit promotion approval requirement.

## Operator commands

```bash
sparkbridge cache list
sparkbridge validations create --spec config/validation.example.json
sparkbridge validations list
sparkbridge validations show <validation-id>
```

## Security rules

1. Never use a cache hit to bypass workspace policy.
2. Never cache secret-dependent actions.
3. Never strongly cache network-dependent actions.
4. Never strongly reuse an unknown toolchain.
5. Never allow a validation executor to gain promotion authority merely by sharing a workspace ID.
6. Never count `best_effort` as authoritative cached validation.
7. Never auto-promote after fan-out success.
