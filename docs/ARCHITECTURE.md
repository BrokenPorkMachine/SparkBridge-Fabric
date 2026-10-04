# SparkBridge Fabric Architecture — v0.12 1.0 Candidate

## System planes

```text
Clients / IDEs / MCP / OpenAI / Ollama clients
                     │
                     ▼
            Integration Plane :7791
                     │
          principal + policy boundary
                     │
                     ▼
┌───────────────────────────────────────────────┐
│              DGX Control Plane                │
│ tasks / events / policy / approvals           │
│ repository intelligence                       │
│ CAS / snapshots / candidates                  │
│ action cache / validation matrices            │
│ audit chain                                    │
└──────────────┬───────────────────┬────────────┘
               │                   │
         inference plane       executor fabric
           :7790                   :7789
               │                   │
       Ollama localhost      macOS/Windows/Linux
```

## Integration adapters are not new authorities

The integration architecture does not create a parallel state model for MCP or IDEs. Adapters call the same stores/services used by the local CLI:

```text
MCP ──────────────┐
IDE REST ─────────┤
OpenAI compat ────┼──► SparkBridge authoritative services
Ollama compat ────┤
CLI/admin ─────────┘
```

This prevents external integrations from developing different task/candidate/action semantics.

## Integration authentication

The integration listener uses the same server TLS certificate but a dedicated bearer token. That token maps to one configured service principal.

Task payload principals are overwritten server-side with `integration_principal_id`.

## MCP architecture

The v0.11 MCP adapter is stateless. It supports modern discovery and the core tool list/call flow, plus legacy initialize compatibility. SparkBridge's own durable `TaskRecord` and event stream remain the long-running task mechanism.

## Inference compatibility

The Ollama/OpenAI routes are adapters around `InferenceGateway`; they do not connect to Ollama independently. This keeps admission control and model policy centralized.

## Maintenance

`SparkBridge-maintenance` contains backup/restore and signed-update verification. CAS GC is an offline Python utility because it needs cross-object/database reachability traversal rather than online request handling.

## Service packaging

- Linux: systemd server/executor units and install helpers;
- macOS: executor LaunchDaemon + installer;
- Windows: executor SCM installer/uninstaller.

The DGX server remains a Linux deployment target.

## Release flow

```text
build + tests
     ↓
release archive
     ↓
update-manifest.json
     ↓
Ed25519 signature
     ↓
verify on target
     ↓
staging directory
     ↓
operator/service-manager rollout
```

Automatic replacement is deliberately outside the current release.


## Certification plane

Certification is intentionally outside the runtime authority path:

```text
source/runtime artifacts ──► certification evidence ──► release evaluator
                                                     │
                                                     └─► release_ready true/false
```

It has no network listener, cannot approve actions/promotions, and cannot alter live state. Its job is to prove that the existing planes satisfy the 1.0 release contract on real supported platforms.

Protocol 1.10 and schema 9 remain unchanged from v0.11 so upgrade/rollback qualification tests the actual compatibility promise instead of a moving target.
