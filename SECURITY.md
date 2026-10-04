# SparkBridge Security Model — v0.12.0-rc3

SparkBridge v0.12.0-rc3 preserves every trust boundary from v0.2–v0.11 while hardening 1.0 certification evidence and release qualification.

## Trust surfaces

### Admin — `127.0.0.1:7787`

Loopback-only. Full operator/administrative API. Never expose this port remotely merely to support an IDE.

### Enrollment — `:7788`

Server-authenticated TLS plus one-time enrollment token. Executor private keys are generated locally.

### Executor fabric — `:7789`

mTLS plus per-node bearer identity. CAS, snapshots, capabilities, candidates and actions use this surface.

### Inference gateway — `:7790`

TLS plus `gateway-token`. Ollama remains on loopback.

### Integration listener — `:7791`

TLS plus an independent `integration-token`. MCP, IDE API, OpenAI/Ollama compatibility and dashboard data use this surface.

The integration credential is intentionally separate so it can be revoked or rotated without disturbing executor trust or ordinary inference clients.

## Integration principal

On startup the server ensures a service principal named by `integration_principal_id` exists. The default `integration-client` permissions are:

```text
Read
Snapshot
CandidateCreate
Execute
```

It intentionally lacks:

```text
Promote
Approve
UseSecret
ManagePolicy
```

Workspace ACLs still apply. External task creation rewrites `principal_id` to this service principal. External clients cannot submit `local-admin` and thereby impersonate it.

External task list/get/run is restricted to tasks owned by that principal. Action/validation lists are filtered the same way. Repository-intelligence MCP tools resolve the snapshot's workspace and require `Read` authorization before returning data.

## No integration promotion endpoint

v0.11 deliberately does not expose live candidate promotion on port 7791. Promotion continues through the executor fabric, remains owner-pinned, validation-gated where configured, and requires approval according to workspace policy.

## Model compatibility routes

OpenAI/Ollama compatibility routes still call the SparkBridge inference gateway object. They therefore retain:

- model allowlists;
- bounded concurrency;
- queue timeouts;
- persistent local provider pooling;
- model residency control;
- request cancellation/telemetry where applicable.

They do not open raw port 11434.

## Dashboard

The dashboard HTML itself contains no project state. It requests operational summary data only after the operator provides the integration bearer token. The page stores that value in browser `sessionStorage`, not persistent local storage.

Do not use the dashboard from an untrusted/shared browser profile.

## MCP

MCP is treated as another API adapter—not as an authority boundary. Tool calls operate through existing durable stores and policy checks. v0.11 emits audit records for MCP tool calls without storing tool arguments that might contain source snippets.

## Backup security

A full backup can contain:

```text
CA private key
server private key
bearer tokens
SQLite principal/node/action/task state
CAS source content
```

Therefore the backup destination is equivalent to the server trust root. Encrypt/protect it appropriately. The backup implementation refuses symlink inputs and records SHA-256/size for copied files.

For a strict point-in-time database/CAS copy, stop `sparkbridge-server` before creating the backup.

## Restore security

Restore verifies every backup file digest before copying. Existing targets are not overwritten unless `--overwrite` is explicit.

A restore is a privileged administrative operation and should be performed while SparkBridge services are stopped.

## Signed staged updates

The update verifier checks:

1. Ed25519 signature over the exact update-manifest bytes;
2. artifact SHA-256 against the signed manifest;
3. artifact byte size against the signed manifest.

Staging copies only after all checks pass. v0.11 does not auto-replace running binaries, which leaves final deployment under service/change control.

Keep the release signing private key offline or in dedicated signing infrastructure. Targets require only the Ed25519 public key.

## CAS GC

`cas_gc.py` derives reachability from durable database roots (snapshots, candidates, repository indexes, native intelligence, and promotion history) and recursively follows digest fields found in JSON CAS objects. It defaults to dry-run and an age grace period.

Deletion is refused unless `--confirm-server-stopped` is passed and `--min-age-seconds` is greater than zero, and the database is opened read-only so GC cannot write to a live server's state.

GC fails closed. An unreadable reachability table, an unparsable record, or a live object larger than the traversal limit aborts the run rather than shrinking the root set — an understated root set is what turns live state into deletable garbage.

Deletion should be performed only while the server is stopped. Maintain a verified backup before the first production GC run.

## Service-manager boundaries

Linux systemd, macOS launchd and Windows SCM package examples supervise SparkBridge processes. They are not a replacement for OS account/file ACL hardening.

Executor configurations and identity material must remain restricted to the account/service that runs the executor.

## Secrets

Existing v0.9 secret guarantees remain:

- model receives references, not secret values;
- executor resolves authorized secret refs locally;
- secret-dependent actions are not cacheable;
- output/context redaction remains active;
- integration principal has no `UseSecret` by default.

## Remaining v0.11 limitations

- a single bearer token represents the integration service rather than per-client OAuth identities;
- full MCP 2026 subscriptions/tasks extension is not implemented;
- no automatic binary installation after staging;
- no online SQLite backup snapshot API;
- no high-availability control plane;
- macOS/Windows host network isolation is still not claimed as enforceable;
- dashboard is status-only, not a privileged web administration surface.

## Cache and validation inheritance

The v0.10 cache trust model remains unchanged in v0.11. `strong` reuse is restricted to defensible closed-input/hermetic conditions; native host actions normally use `best_effort` or `disabled`. External integration clients cannot mark an unsafe result authoritative or bypass required multi-platform validation before promotion.

---

# v0.12 Certification / Hardening Security Amendments

v0.12 intentionally freezes Protocol 1.10 and schema 9. The release-certification layer is offline/local and does not introduce a new network listener or remote authority.

A certification result is evidence, not authorization. It cannot approve promotions, actions, secrets, policy changes, or releases by itself.

A required certification check reported as `skip` blocks 1.0 promotion. SparkBridge does not translate missing evidence into success.

The 1.0 candidate threat review is documented in `docs/THREAT_MODEL.md`. Native and fault-injection evidence must be generated on the actual target platform/hardware named by the check.

## v0.12.0-rc2 certification evidence hardening

Certification evidence is now source-revision pinned. A merged 1.0 result may not combine evidence produced from different source trees. Required PASS checks must carry evidence, and evidence files are represented by SHA-256 and size in the bundle. Merge provenance records the digest of every contributing bundle and rejects conflicting metric values instead of silently choosing one.

This protects release decisions from accidental evidence mixing and overwrite, but it does not replace runner trust: certification hosts, signing keys, and retained drill logs remain operator-controlled security assets.


## rc3 certification evidence transport

Certification evidence is part of the release supply chain. rc3 copies evidence into a portable bundle and verifies referenced SHA-256 digests and byte sizes before evaluation. The assembler rejects mixed source revisions. Treat any missing, rewritten, or hash-mismatched evidence as a certification failure; do not repair it by editing the result JSON.
