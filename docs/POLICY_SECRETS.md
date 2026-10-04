# Policy, Secrets & Data Boundaries — v0.9

## Purpose

v0.9 adds authorization and data-handling controls to the deterministic coding fabric. The central rule is that the model may request operations, but SparkBridge decides whether those operations are allowed, require approval, or are denied. Secret values remain at the executor and are never included in model context, control-plane action JSON, audit payloads, or capability reports.

## Principals

A principal is a durable identity used for policy decisions:

```json
{
  "principal_id": "coding-agent",
  "display_name": "Coding Agent",
  "kind": "agent",
  "enabled": true,
  "permissions": ["read", "snapshot", "candidate_create", "execute"],
  "created_unix_ms": 0
}
```

Permissions are:

- `read`
- `snapshot`
- `candidate_create`
- `execute`
- `promote`
- `approve`
- `use_secret`
- `manage_policy`

`local-admin` is seeded automatically and owns all permissions. Policy administration remains on the loopback admin surface.

## Workspace policy

A workspace policy binds authorization, classification, secret allowlists and approval requirements to the logical workspace ID:

```json
{
  "workspace_id": "reworkbench",
  "classification": "private",
  "allowed_principals": ["local-admin", "coding-agent"],
  "allowed_secret_refs": ["github-token"],
  "require_approval_for": ["promote", "use_secret"],
  "updated_unix_ms": 0
}
```

An empty `allowed_principals` list does **not** mean public access. It falls back to `local-admin` only.

An empty `allowed_secret_refs` means no secret references are permitted for that workspace.

`require_approval_for` lists permissions that resolve to `ask` rather than `allow`. Only action execution and live workspace promotion have an approval workflow, so listing `execute` or `promote` parks the operation until an approval is granted. Listing a permission with no approval workflow — `read`, `candidate_create`, `snapshot` — **denies** that operation rather than permitting it, because there is nothing that could later consume the approval.

## Decisions

Policy decisions are:

- `allow` — may proceed;
- `ask` — create/require an approval before execution;
- `deny` — reject the operation.

Side-effecting actions default toward `ask`. Secret-bearing actions always require explicit approval after permission/allowlist checks.

## Approvals

Actions requiring approval enter `awaiting_approval` and cannot be leased to an executor.

```bash
sparkbridge approvals list
sparkbridge approvals approve <approval-id> --principal local-admin --reason "Reviewed build publish step"
sparkbridge approvals deny <approval-id> --principal local-admin --reason "Not authorized"
```

Approvals expire according to `approval_ttl_seconds`.

A **live candidate promotion always requires explicit approval in v0.9**, even when the requesting principal otherwise possesses `promote`. This prevents an authenticated remote executor from self-asserting a privileged principal and mutating the live checkout without a loopback decision. Dry-run promotion remains non-mutating and may proceed when read permission permits it.

## Secret broker

Actions carry references, never values:

```json
{
  "reference": "github-token",
  "env_name": "GITHUB_TOKEN"
}
```

Executor configuration maps the opaque reference to the name of a local environment variable:

```toml
secret_env_bindings = { github-token = "SPARKBRIDGE_SECRET_GITHUB_TOKEN" }
```

Before starting the executor, the workstation owner supplies the value locally:

```bash
export SPARKBRIDGE_SECRET_GITHUB_TOKEN='...'
```

The DGX learns only that the executor can satisfy capability `secret:github-token`. It does not learn the local environment-variable name or value.

At spawn time the executor resolves the local value and injects it under the action-requested target environment name. Captured stdout/stderr is scrubbed for the exact injected values and then passed through the generic secret-pattern redactor before being sent to the DGX.

## Agent validation actions with secrets

A TaskSpec may reference a secret without containing its value:

```json
{
  "domain": "host",
  "argv": ["cargo", "test", "--workspace"],
  "network_policy": "unrestricted",
  "secret_injections": [
    {"reference": "github-token", "env_name": "GITHUB_TOKEN"}
  ],
  "declared_hosts": []
}
```

The task principal must have `use_secret`, the workspace must explicitly allow `github-token`, an eligible executor must advertise `secret:github-token`, and an operator must approve the resulting action.

## Context redaction

When `context_secret_scan_enabled = true`, source fragments are scanned before they enter a model ContextBundle. Recognized credential-shaped values are replaced with markers such as:

```text
[REDACTED:github_token]
```

The ContextBundle records only finding type and source line metadata. The system prompt explicitly forbids reconstructing or requesting secret values.

Candidate content emitted by a model is scanned as well. If it appears to contain a credential/private key/token/password, candidate creation is rejected and the finding becomes repair evidence.

The scanner is defense-in-depth, not a complete secret-classification oracle. Real secrets should still be excluded from source snapshots whenever possible.

## Data classifications

Projects/tasks use one of:

```text
public < private < confidential < restricted
```

The effective task classification is the stricter of TaskSpec and workspace policy.

Inference-provider boundaries are:

- `local_only`
- `private_remote`
- `public_cloud`

Current policy:

| Classification | local_only | private_remote | public_cloud |
|---|---:|---:|---:|
| public | yes | yes | yes |
| private | yes | yes | no |
| confidential | yes | no | no |
| restricted | yes | no | no |

The boundary is checked at task creation and before every model turn. Disabling or restricting a principal after a task starts also causes the task to pause before more context is sent to inference.

For a DGX-hosted local Ollama deployment, keep:

```toml
inference_data_boundary = "local_only"
```

## Network policy

v0.9 adds one enforceable restricted host-network mode:

### Linux `network=none`

When the executor has bubblewrap and:

```toml
action_allow_linux_network_none = true
```

it advertises `network:none`. Such actions are launched through a bubblewrap network namespace using `--unshare-net`.

macOS and Windows host executors do not claim equivalent enforcement yet.

`dependency_fetch` and `declared_hosts` are rejected on all v0.9 host domains because correct cross-platform enforcement is not implemented yet.

## Audit chain

Security-relevant events are stored in an append-only logical chain. Each event contains the previous event hash and a SHA-256 hash over a deterministic JSON envelope.

Inspect and verify:

```bash
sparkbridge audit list --limit 200
sparkbridge audit verify
```

The chain is tamper-evident, not an external immutable ledger. An administrator with filesystem/database authority can replace both database and software; signed checkpoints/external anchoring are future hardening work.

## Operational rules

1. Keep the admin API loopback-only.
2. Treat `local-admin` as a powerful local operator principal.
3. Give agents only the permissions they need.
4. Explicitly enumerate workspace principals and secret refs.
5. Put secret values only in executor-local protected environment/provider state.
6. Review every approval before deciding it.
7. Keep confidential/restricted code on `local_only` inference.
8. Run `sparkbridge audit verify` as part of operational checks.
9. Do not describe `declared_hosts`/dependency-fetch isolation as implemented in v0.9.
10. Promotion remains review-gated even when a candidate has passed validation.
