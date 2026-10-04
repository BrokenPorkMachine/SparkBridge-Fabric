# SparkBridge Threat Model — v0.12 Review

## Protected assets

- source repositories and candidate content;
- node/executor private keys and bearer bindings;
- CA/server keys;
- locally bound secrets;
- task/action history and audit evidence;
- model context and outputs;
- build/sign/publish authority;
- CAS and snapshot integrity.

## Primary trust boundaries

1. remote client → integration/inference listeners;
2. executor → mTLS fabric listener;
3. DGX control plane → localhost Ollama;
4. executor process → authorized workspace roots;
5. model proposal → deterministic policy/action/candidate validators;
6. secret reference → executor-local secret value;
7. candidate → explicit promotion transaction.

## Threats and controls

### Stolen external token

Integration and inference credentials are separate and independently rotatable. External integration authority is ACL-bound and cannot promote candidates or manage secrets/policies.

### Malicious/compromised model

The model is not authoritative state. Structured directives are schema/policy checked; live promotion is explicit and approval gated; secrets are referenced rather than supplied to model context.

### Compromised executor

mTLS/node credentials identify the node but do not make its host trustworthy. Node capability/workspace scope should be minimal. Audit evidence records assigned work. High-value signing/deployment credentials should remain isolated to dedicated executors.

### Workspace race

Stable snapshots, promotion locking, digest preconditions, second pre-commit snapshot and rollback protect against concurrent editor/agent changes.

### CAS corruption

Object identity is SHA-256 of uncompressed bytes. Writes are transactional and verified before publication.

### Replay/duplicate side effects

Leases and action side-effect classification allow automatic retry only for pure work. Side-effecting lease loss becomes `lost` rather than silently replayed.

### Secret leakage

Context scanning/redaction, executor-local injection and output redaction reduce accidental exposure. Secrets must never be committed into source/CAS intentionally.

### Audit tampering

Security-sensitive audit events are hash chained. Certification requires an audit-chain verification drill.

## Residual risks before 1.0

- host compromise defeats host-local controls;
- network sandbox support is platform/domain dependent;
- local coding models can still produce unsafe or incorrect patches;
- no clustered control plane/high availability;
- no hardware-backed key requirement;
- external security review/penetration testing remains recommended before multi-user Internet exposure.

## rc2 certification-evidence threats

The release-certification pipeline is itself part of the supply chain. rc2 explicitly defends against several evidence-layer failures:

- **mixed-source certification:** results from different source revisions are rejected during merge;
- **evidence-free PASS:** every required PASS must identify inline evidence or a hashed evidence file;
- **evidence substitution:** evidence-file metadata carries SHA-256 and byte size so the referenced artifact can be checked independently;
- **metric overwrite:** conflicting values for the same metric cause merge failure rather than last-writer-wins;
- **hidden failing contribution:** FAIL outranks PASS/SKIP when duplicate check IDs are merged;
- **opaque merge provenance:** merged bundles record the SHA-256 and source revision of each input bundle.

These controls do not make a forged runner trustworthy by themselves. Native certification runners and production drills still require an operator-controlled execution environment and retained logs/artifacts.


## Portable evidence substitution

rc3 adds a portable certification bundle specifically to reduce path-dependent CI evidence. Threats include substituting a log after collection, omitting an evidence file during transfer, or combining results from different revisions. The assembler verifies evidence hashes/sizes, rewrites paths under one bundle root, records input-bundle hashes, and rejects mixed source revisions. Final promotion should re-run `verify_evidence_bundle.py` on the transferred bundle.
