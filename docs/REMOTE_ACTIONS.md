# Remote Actions + Execution Domains — v0.6

## Purpose

v0.6 turns SparkBridge from a system that can infer, snapshot, propose and promote changes into one that can also ask the correct machine to compile/test those changes.

The design is intentionally not a remote shell.

## Action identity

Every action is a durable object containing:

- action ID;
- assigned node ID;
- logical workspace ID;
- execution domain;
- structured argv;
- relative working directory;
- explicitly permitted environment overrides;
- timeout;
- output limit;
- side-effect class;
- declared network intent;
- required capabilities.

No action carries a shell command string.

## Execution domains

The wire model supports named execution domains. v0.6 advertises only:

```text
host
```

on each macOS, Windows, or Linux executor.

This is deliberate. WSL, containers, simulators and other nested domains need their own correct workspace/path/toolchain semantics before SparkBridge should schedule work into them.

## Capability discovery

At fabric connect, an executor scans its PATH for a bounded list of development tools and reports:

- OS and architecture;
- domain ID;
- available commands;
- configured logical workspace IDs.

The DGX persists this report. Action creation succeeds only when an online node reports:

1. the requested domain;
2. the requested workspace ID;
3. every required tool capability.

The executable itself is automatically added as a required capability by the server.

## Workspace mapping

The action references `workspace_id`, never a remote path.

The executor resolves the ID through `workspace_bindings`, canonicalizes it, verifies it remains beneath `workspace_roots`, then resolves `relative_cwd` beneath that root.

Parent traversal and absolute CWDs are rejected.

## Command boundary

Two independent checks apply:

1. scheduler: command must be reported as a node capability;
2. executor: command name must be present in `action_allowed_commands`.

Executable paths are rejected. v0.6 therefore cannot be used to submit `/bin/sh`, `C:\...\tool.exe`, or an arbitrary repository binary unless a future policy explicitly introduces that capability.

## Leases

A queued action is leased atomically to its assigned node.

While the process is alive, the executor renews the lease. The renew response also carries `cancel_requested`.

If renewal fails, the executor cancels the local process rather than continuing work after losing coordination with the DGX.

### Expiry

Expired `pure` actions may safely return to `queued`.

Expired actions with any side-effect classification become `lost`:

```text
workspace_mutation
external_side_effect
privileged_side_effect
```

SparkBridge does not guess whether such an action is safe to repeat.

## Process supervision

### Unix

The action is placed in a new session/process group before exec. Timeout/cancel sends TERM, waits briefly, then KILLs the group and finally signals the root child.

### Windows

Timeout/cancel uses `taskkill /T /F` on the root PID and then the Tokio child kill fallback.

## Output

stdout and stderr are drained concurrently to avoid pipe deadlock. Only the configured prefix up to `max_output_bytes` per stream is retained; the rest is drained and marked truncated.

v0.6 returns retained logs inline in the durable action result. Moving large action logs/artifacts into CAS is a future optimization.

## Diagnostics

The executor normalizes common diagnostic forms into:

```text
severity
file
line
column
code
message
tool
```

Current parser families:

- GCC/Clang/Swift/Rust file diagnostics;
- MSVC/MSBuild file diagnostics;
- simple Rust/tool error/warning/note summaries.

Raw stdout/stderr are still retained within the configured limits.

## Durable completion outbox

Before reporting completion, the executor writes the completion request to an atomic local JSON outbox.

Only after the DGX acknowledges the terminal result does the executor delete that file.

After reconnect, the executor flushes pending completion records before continuing normal work.

This closes the v0.5 consistency gap where local work could complete while the network failed before the DGX learned the result.

## Network policy

The protocol records a requested network policy. In v0.12 one mode is genuinely enforceable: on a Linux executor with bubblewrap and `action_allow_linux_network_none = true`, a `network=none` action runs inside an unshared network namespace. macOS and Windows host executors do not claim equivalent enforcement and reject `network=none`.

`dependency_fetch` and `declared_hosts` are rejected on every host domain, because correct cross-platform enforcement is not implemented yet.

So `unrestricted` is accepted everywhere; `none` is accepted only on a Linux executor with the opt-in enabled and `bwrap` present; `dependency_fetch` and `declared_hosts` always fail before process execution. See `docs/POLICY_SECRETS.md` for the operator configuration.
