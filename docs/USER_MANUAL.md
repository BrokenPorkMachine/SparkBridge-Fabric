# SparkBridge Fabric v0.12.0 — User Manual

**Release:** v0.12.0-rc3 — 1.0 Candidate — Certification Runner Hardening  
**Fabric Protocol:** 1.10  
**SQLite schema:** 9  
**Primary inference host:** NVIDIA DGX Spark / GB10  
**Executor platforms:** macOS, Windows, Linux

SparkBridge is a private distributed coding fabric. The DGX hosts the control plane, repository intelligence, immutable project state, deterministic agent runtime and Ollama inference. Enrolled executors provide native platform toolchains and authoritative local workspaces.

v0.12 preserves the production integration/maintenance surfaces and adds release certification without weakening earlier safety boundaries.

---

## 1. What SparkBridge can do

SparkBridge can:

- keep Ollama private on `127.0.0.1:11434`;
- expose authenticated model access through SparkBridge;
- enroll macOS, Windows and Linux executors;
- snapshot project state into transactional SHA-256 CAS;
- create immutable agent candidates without touching live source;
- run candidate builds/tests in disposable executor sandboxes;
- normalize diagnostics and feed repair evidence back into the model;
- maintain event-sourced coding tasks that survive restart;
- search symbols, references, lexical text and recent Git history by immutable snapshot;
- enforce workspace principals, approvals, data classifications and secret boundaries;
- fan a candidate out across multiple platforms for validation;
- reuse only defensible cached results;
- expose MCP/IDE/OpenAI/Ollama compatibility through a separately authenticated integration listener;
- create verified backups;
- verify/stage signed updates;
- perform offline CAS reachability maintenance.

SparkBridge still does **not** automatically promote model-generated code.

---

## 2. Mental model

```text
                            DGX SPARK
┌───────────────────────────────────────────────────────────────┐
│ SparkBridge control plane                                     │
│                                                               │
│  tasks / event log / policy / approvals                       │
│  snapshots / candidates / CAS / indexes / cache              │
│  validation scheduler                                         │
│  Ollama gateway ───────────► 127.0.0.1:11434                  │
│                                                               │
│  integration API / MCP / compatibility / dashboard            │
└──────────────────────────────┬────────────────────────────────┘
                               │ authenticated fabric
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         macOS node       Windows node      Linux node
           Xcode             MSBuild          GCC/Cargo
```

> The model proposes. SparkBridge owns state and evidence. Executors own platform reality. The user owns promotion authority.

---

## 3. Network surfaces

| Port | Surface | Authentication |
|---|---|---|
| `7787` | admin | loopback only |
| `7788` | enrollment | TLS + one-time token |
| `7789` | executor fabric | mTLS + node bearer |
| `7790` | inference | TLS + gateway token |
| `7791` | integrations | TLS + integration token |
| `11434` | Ollama | loopback only |

Do not expose `7787` or `11434` to the network.

---

## 4. Basic health checks

On the DGX:

```bash
sparkbridge health
sparkbridge protocol
sparkbridge doctor
sparkbridge nodes list
sparkbridge capabilities
```

The expected protocol for this release is:

```text
1.10
```

---

## 5. Executor workspaces

Executors map a stable logical workspace ID to a local path.

macOS:

```toml
workspace_bindings = { reworkbench = "/Users/me/src/REWorkbench" }
```

Windows:

```toml
workspace_bindings = { reworkbench = "D:/src/REWorkbench" }
```

Linux:

```toml
workspace_bindings = { reworkbench = "/home/me/src/REWorkbench" }
```

The DGX refers to `reworkbench`; it never needs the host-specific path.

---

## 6. Snapshot a project

From the executor that owns the workspace:

```bash
sparkbridge-executor \
  --config /etc/sparkbridge/executor.toml \
  --snapshot /path/to/project \
  --workspace-id reworkbench
```

Optionally collect native document symbols:

```bash
sparkbridge-executor \
  --config /etc/sparkbridge/executor.toml \
  --snapshot /path/to/project \
  --workspace-id reworkbench \
  --native-intelligence
```

Inspect on the DGX:

```bash
sparkbridge snapshots list
sparkbridge intelligence build <snapshot-id>
sparkbridge intelligence search <snapshot-id> "UsbController"
sparkbridge intelligence symbols <snapshot-id> "reset"
```

---

## 7. Run a deterministic coding task

Create a TaskSpec JSON using `config/task.example.json` as a starting point.

```bash
sparkbridge tasks create --spec task.json
sparkbridge tasks list
sparkbridge tasks run <task-id> --follow
```

Inspect durable evidence:

```bash
sparkbridge tasks show <task-id>
sparkbridge tasks events <task-id>
sparkbridge actions list
sparkbridge validations list
```

The agent loop can create/repair/validate a candidate, but completion does not alter the live workspace.

---

## 8. Cross-platform validation

Create a validation matrix:

```bash
sparkbridge validations create --spec config/validation.example.json
sparkbridge validations show <validation-id>
```

A workspace policy can require validation on named platforms before promotion.

---

## 9. Review and promote a candidate

Inspect candidates:

```bash
sparkbridge candidates list
sparkbridge candidates show <candidate-id>
```

Dry run from the owning executor:

```bash
sparkbridge-executor \
  --config /etc/sparkbridge/executor.toml \
  --promote <candidate-id> \
  --workspace /path/to/project \
  --workspace-id reworkbench \
  --dry-run
```

A real promotion remains approval-gated. List pending approvals on the DGX:

```bash
sparkbridge approvals list
sparkbridge approvals approve <approval-id> --principal local-admin
```

Then retry promotion with the approval identifier. `--promotion-approval` is required for a live promotion; without it the executor requests an approval and exits. Approvals expire after `approval_ttl_seconds`, so request a new one if the retry is rejected as expired.

```bash
sparkbridge-executor \
  --config /etc/sparkbridge/executor.toml \
  --promote <candidate-id> \
  --workspace /path/to/project \
  --workspace-id reworkbench \
  --promotion-approval <approval-id>
```

`--promotion-principal` selects the principal the approval is requested for; it must match the principal that approved it, and defaults to `local-admin`.

---

## 10. External integrations

### 10.1 Integration token

The integration listener uses a credential separate from the model gateway:

```bash
sudo cat /etc/sparkbridge/pki/integration-token
```

Rotate independently:

```bash
sudo sparkbridge integration-token rotate \
  --path /etc/sparkbridge/pki/integration-token \
  --force
sudo systemctl restart sparkbridge-server
```

### 10.2 Check integration status

From a machine with the CA certificate:

```bash
export SPARKBRIDGE_INTEGRATION_TOKEN="$(cat integration-token)"

sparkbridge integrations \
  --url https://dgx-spark.example.lan:7791 \
  --ca-cert ca.pem \
  status
```

### 10.3 Enable a workspace for external clients

The default external identity is `integration-client`. A workspace policy must allow that principal before MCP/IDE repository access or task creation succeeds.

Example policy fragment:

```json
{
  "workspace_id": "reworkbench",
  "allowed_principals": ["local-admin", "integration-client"]
}
```

Do not grant `Promote`, `Approve`, `UseSecret` or `ManagePolicy` to the integration principal unless you deliberately want that stronger trust boundary.

---

## 11. MCP

Point an MCP-capable client at:

```text
https://dgx-spark.example.lan:7791/mcp
```

Send:

```http
Authorization: Bearer <integration-token>
```

Available tools:

```text
sparkbridge.tasks.list
sparkbridge.tasks.get
sparkbridge.tasks.run
sparkbridge.intelligence.search
sparkbridge.intelligence.symbols
sparkbridge.actions.list
sparkbridge.validations.list
```

Repository-intelligence calls are checked against the integration principal's workspace `Read` permission.

v0.12 implements the stateless core methods documented in `docs/EXTERNAL_INTEGRATIONS.md`; it is not the full MCP subscriptions/tasks extension.

---

## 12. OpenAI-compatible clients

Configure the client base URL as:

```text
https://dgx-spark.example.lan:7791/v1
```

Use the integration token as the bearer/API key.

Supported endpoints:

```text
GET  /v1/models
POST /v1/chat/completions
```

Streaming chat uses SSE from the Ollama OpenAI-compatible provider path but remains subject to SparkBridge model allowlists and admission control.

---

## 13. Ollama-compatible clients

Configure the SparkBridge integration origin instead of raw port 11434:

```text
https://dgx-spark.example.lan:7791
```

Available routes:

```text
/api/tags
/api/ps
/api/generate
/api/chat
```

This preserves immediate streaming while keeping Ollama loopback-only.

---

## 14. Operator dashboard

Browse to:

```text
https://dgx-spark.example.lan:7791/dashboard
```

Enter the integration token when prompted. The dashboard currently shows only operational counts and inference queue state; use the CLI for administration and approvals.

---

## 15. Backup and restore

Stop the server for a strict point-in-time backup:

```bash
sudo systemctl stop sparkbridge-server
sudo sparkbridge backup create \
  --root / \
  --output /srv/backups/sparkbridge-$(date +%F) \
  --include etc/sparkbridge \
  --include var/lib/sparkbridge
sudo sparkbridge backup verify \
  --backup /srv/backups/sparkbridge-$(date +%F)
sudo systemctl start sparkbridge-server
```

Restore:

```bash
sudo sparkbridge backup restore \
  --backup /srv/backups/sparkbridge-2026-10-04 \
  --target /
```

The backup includes highly sensitive CA/security state. Protect it accordingly.

---

## 16. Signed updates

Verify before staging:

```bash
sparkbridge update verify \
  --manifest update-manifest.json \
  --signature update-manifest.sig \
  --public-key release-public-key \
  --artifact SparkBridge-Fabric-v0.12.0-rc3.zip
```

Stage:

```bash
sparkbridge update stage \
  --manifest update-manifest.json \
  --signature update-manifest.sig \
  --public-key release-public-key \
  --artifact SparkBridge-Fabric-v0.12.0-rc3.zip \
  --staging-dir /var/lib/sparkbridge/update-staging
```

v0.12 does not automatically install a staged update.

---

## 17. CAS maintenance

Dry run:

```bash
python3 scripts/cas_gc.py \
  --database /var/lib/sparkbridge/sparkbridge.db \
  --cas /var/lib/sparkbridge/cas
```

Deletion requires an explicit `--delete` together with `--confirm-server-stopped`, and a `--min-age-seconds` greater than zero. Stop the server before deleting:

```bash
sudo systemctl stop sparkbridge-server
python3 scripts/cas_gc.py \
  --database /var/lib/sparkbridge/sparkbridge.db \
  --cas /var/lib/sparkbridge/cas \
  --min-age-seconds 604800 \
  --delete \
  --confirm-server-stopped
sudo systemctl start sparkbridge-server
```

GC opens the database read-only and aborts rather than guessing when reachability cannot be determined (unreadable table, unparsable record, or a live object above `--max-traversable-bytes`).

---

## 18. Security operations

Verify audit integrity:

```bash
sparkbridge audit verify
```

Inspect principals and workspace policy:

```bash
sparkbridge policy principals list
sparkbridge policy workspaces list
```

Rotate node/gateway/integration credentials according to `SECURITY.md` and the Installation Guide.

---

## 19. Troubleshooting

### Integration API returns 401

Check:

- integration token, not gateway token;
- correct port `7791`;
- server restart after token rotation;
- CA trust and hostname SAN.

### MCP search returns 403

Add `integration-client` to the target workspace policy and ensure the principal remains enabled with `Read` permission.

### OpenAI client reaches server but model is denied

Check `inference_allowed_models` in server configuration.

### Executor cannot lease actions

Check:

```bash
sparkbridge nodes list
sparkbridge capabilities
sparkbridge actions list
```

Confirm the logical workspace and command capability are advertised.

### Backup verification fails

Do not restore it. Create a new backup and investigate storage or concurrent mutation.

---

## 20. Current limits

v0.12 intentionally does not provide:

- automatic promotion;
- MCP subscriptions or full MCP task extension;
- full OpenAI API coverage;
- web-based policy/approval editing;
- silent automatic service replacement during updates;
- clustered/high-availability control plane;
- online point-in-time database backup.

---

# v0.12 Certification Workflow

v0.12 adds a release-certification layer without changing your normal coding workflow.

## Generate local evidence

```bash
python3 scripts/certification/generate_local_results.py
```

This creates `certification-results.local.json`. If Cargo is available, the generator runs the native workspace tests for the current supported platform. Checks that cannot be proven on the current machine remain `skip`.

## Evaluate 1.0 readiness

```bash
sparkbridge certification evaluate \
  --profile config/certification/profile-1.0-candidate.json \
  --results certification-results.local.json
```

The command exits unsuccessfully if any required check is missing, failed, or skipped. This is intentional: SparkBridge never equates “not tested” with “passed.”

## Evidence from multiple machines

CI or operators should retain result bundles from Linux x86_64, DGX Spark/Linux aarch64, macOS arm64 and Windows x86_64. Merge only evidence produced by the actual named platform. The DGX requirement is specifically intended to catch GB10/CUDA/Ollama integration failures that a generic ARM runner cannot reveal.

## 1.0 promotion

Do not label a build SparkBridge 1.0 until the profile in `config/certification/profile-1.0-candidate.json` evaluates `release_ready: true` and the evidence has been reviewed.

## rc3 release-certification workflow

For operators qualifying the 1.0 candidate:

```bash
python3 scripts/certification/generate_local_results.py
python3 scripts/certification/release_blockers.py \
  --results certification-results.local.json
```

A required PASS without evidence is a blocker. Platform bundles from different `source_revision` values cannot be merged. For manually exercised scenarios, use `record_check.py` and attach the actual test/drill log with `--evidence`; SparkBridge records its SHA-256 and size in the certification bundle.


## rc3 certification runner

Operators preparing a 1.0 promotion should use the bundled one-command runner instead of manually merging JSON files:

```bash
./scripts/certify.sh --output-dir certification-run
```

Review `certification-run/release-blockers.md` and `certification-run/triage.md`. To combine evidence from other machines, repeat `--input <results.json>` for each same-revision bundle. A mixed-revision input is rejected. The assembled bundle is self-contained and evidence hashes can be re-verified after transfer.

Do not use `--require-ready` during ordinary development. It is intended for the final promotion gate and deliberately fails while any required platform, E2E, fault, drill, or audit-chain evidence is missing.
