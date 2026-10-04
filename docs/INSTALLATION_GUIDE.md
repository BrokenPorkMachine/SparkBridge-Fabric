# SparkBridge Fabric v0.12.0 — Installation & Deployment Guide

**Release:** v0.12.0-rc3 — 1.0 Candidate — Certification Runner Hardening  
**Fabric Protocol:** 1.10  
**SQLite schema:** 9

This guide installs the DGX Spark control plane and macOS, Windows and Linux executors, then enables the integration listener, MCP/API compatibility, service packaging, backup and staged updates, and the v0.12 certification workflow.

---

## 1. Topology

```text
DGX Spark
  Ollama                    127.0.0.1:11434
  SparkBridge admin         127.0.0.1:7787
  enrollment               :7788 TLS
  executor fabric          :7789 mTLS
  inference gateway        :7790 TLS + gateway token
  integrations             :7791 TLS + integration token

Executors
  macOS / Windows / Linux
  outbound enrollment/fabric connections
```

Only expose the network ports you actually use. Never publish `7787` or `11434`.

---

## 2. Prerequisites

DGX:

- Linux DGX Spark / GB10;
- working Ollama on loopback;
- Git;
- Rust 1.85+ compatible toolchain;
- systemd for the packaged service path;
- stable hostname/DNS or IP included in TLS SANs;
- persistent storage for CAS/database/models.

Executors:

- Rust toolchain;
- Git;
- native build tools required by projects;
- network access to DGX `7788` and `7789`.

Integration clients additionally need access to `7791` and a trusted copy of `ca.pem`.

---

## 3. Unpack and verify

Verify the archive **before** extracting it:

```bash
sha256sum -c SparkBridge-Fabric-v0.12.0-rc3.zip.sha256
unzip SparkBridge-Fabric-v0.12.0-rc3.zip
cd SparkBridge-Fabric-v0.12.0-rc3
```

On macOS, `shasum -a 256 SparkBridge-Fabric-v0.12.0-rc3.zip` is also available. On Windows use `Get-FileHash .\SparkBridge-Fabric-v0.12.0-rc3.zip -Algorithm SHA256` and compare it to the supplied checksum file.

---

## 4. Validate and build

```bash
./scripts/validate.sh
cargo build --release --workspace
```

Binaries:

```text
target/release/sparkbridge-server
target/release/sparkbridge-executor
target/release/sparkbridge
```

Do not deploy a production build if Cargo checks fail.

---

# Part I — DGX Spark server

## 5. Create account/directories

```bash
sudo useradd --system --home /var/lib/sparkbridge --shell /usr/sbin/nologin sparkbridge 2>/dev/null || true
sudo install -d -o sparkbridge -g sparkbridge -m 0750 /var/lib/sparkbridge
sudo install -d -o root -g sparkbridge -m 0750 /etc/sparkbridge
sudo install -d -o root -g sparkbridge -m 0750 /etc/sparkbridge/pki
```

---

## 6. Install binaries

You may use:

```bash
sudo packaging/linux/install-server.sh
```

or install manually:

```bash
sudo install -m 0755 target/release/sparkbridge-server /usr/local/bin/
sudo install -m 0755 target/release/sparkbridge /usr/local/bin/
```

---

## 7. Initialize PKI and service tokens

Use the real name clients will use:

```bash
sudo sparkbridge pki init \
  --dir /etc/sparkbridge/pki \
  --server-name dgx-spark.example.lan \
  --san dgx-spark.example.lan \
  --san 192.0.2.50
```

v0.12 creates:

```text
ca.pem
ca-key.pem
server.pem
server-key.pem
gateway-token
integration-token
```

Protect the key/token files. Copy only `ca.pem` to clients/executors.

The service unit runs as `User=sparkbridge`/`Group=sparkbridge`, but `pki init` is run as root and writes `0600` root-owned files. Make the server-readable material group-readable by `sparkbridge`, and keep the CA private key root-only:

```bash
sudo chgrp -R sparkbridge /etc/sparkbridge/pki
sudo chmod 0640 /etc/sparkbridge/pki/ca.pem /etc/sparkbridge/pki/server.pem /etc/sparkbridge/pki/server-key.pem
sudo chmod 0640 /etc/sparkbridge/pki/gateway-token /etc/sparkbridge/pki/integration-token
sudo chmod 0600 /etc/sparkbridge/pki/ca-key.pem
```

`packaging/linux/install-server.sh` creates `/etc/sparkbridge` and `/etc/sparkbridge/pki` setgid `root:sparkbridge` and installs `server.toml` as `root:sparkbridge 0640`, so files created there later already inherit the group. Run the commands above after `pki init` to set the modes.

When upgrading from an older installation that does not have an integration token:

```bash
sudo sparkbridge integration-token rotate \
  --path /etc/sparkbridge/pki/integration-token \
  --force
```

---

## 8. Configure server

```bash
sudo cp config/server.example.toml /etc/sparkbridge/server.toml
sudo chown root:sparkbridge /etc/sparkbridge/server.toml
sudo chmod 0640 /etc/sparkbridge/server.toml
```

The server reads this file as the `sparkbridge` service account, so it must be `root:sparkbridge 0640`; a `root:root 0640` file is unreadable by the unit and the server will fail to start.

Important settings:

```toml
admin_bind = "127.0.0.1:7787"
enrollment_bind = "0.0.0.0:7788"
fabric_bind = "0.0.0.0:7789"
public_fabric_url = "https://dgx-spark.example.lan:7789"

gateway_bind = "0.0.0.0:7790"
public_gateway_url = "https://dgx-spark.example.lan:7790"
gateway_token_path = "/etc/sparkbridge/pki/gateway-token"

integration_bind = "0.0.0.0:7791"
public_integration_url = "https://dgx-spark.example.lan:7791"
integration_token_path = "/etc/sparkbridge/pki/integration-token"
integration_principal_id = "integration-client"
dashboard_enabled = true

ollama_base_url = "http://127.0.0.1:11434"
```

The server refuses non-loopback Ollama configuration.

---

## 9. Firewall

Permit only trusted sources to:

```text
7788 enrollment
7789 executor fabric
7790 inference clients
7791 IDE/MCP/integration clients
```

Do not expose:

```text
7787 admin
11434 Ollama
```

---

## 10. Install/start systemd service

```bash
sudo cp packaging/systemd/sparkbridge-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sparkbridge-server
sudo systemctl status sparkbridge-server
```

Verify locally:

```bash
sparkbridge health
sparkbridge protocol
```

Expected protocol:

```text
1.10
```

---

# Part II — Executor enrollment

## 11. Copy the CA certificate

Copy `/etc/sparkbridge/pki/ca.pem` over a trusted channel to each executor.

Never copy `ca-key.pem` or `server-key.pem`.

---

## 12. Create enrollment token

On the DGX:

```bash
sparkbridge enrollment create --ttl-seconds 900 --label mac-mini
```

Put the token into the executor configuration or environment only long enough to enroll.

---

## 13. Configure executor

Edit `config/executor.example.toml` or install it at the platform path.

Key settings:

```toml
enrollment_url = "https://dgx-spark.example.lan:7788"
fabric_url = "https://dgx-spark.example.lan:7789"
ca_cert_path = "/path/to/ca.pem"
workspace_roots = ["/path/to/dev"]
workspace_bindings = { reworkbench = "/path/to/dev/REWorkbench" }
```

Keep `action_allowed_commands` narrow.

---

## 14. Native service installation

### Linux executor

```bash
sudo packaging/linux/install-executor.sh
```

### macOS executor

After editing the installed config:

```bash
sudo packaging/macos/install-executor.sh
```

This uses a LaunchDaemon under `/Library/LaunchDaemons`.

### Windows executor

From elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\packaging\windows\install-executor.ps1
```

The service is installed as `SparkBridgeExecutor`.

---

# Part III — External integrations

## 15. Copy CA + integration token

A trusted integration client needs:

```text
ca.pem
integration-token
```

Treat the integration token as a service credential.

---

## 16. Verify integration listener

```bash
export SPARKBRIDGE_INTEGRATION_TOKEN="$(cat integration-token)"

sparkbridge integrations \
  --url https://dgx-spark.example.lan:7791 \
  --ca-cert ca.pem \
  status
```

---

## 17. Authorize integration principal for a workspace

The server seeds `integration-client` with non-privileged permissions, but workspace ACLs remain deny-by-default when a restricted list is configured.

Add the principal only to workspaces external clients need:

```json
{
  "workspace_id": "reworkbench",
  "classification": "private",
  "allowed_principals": ["local-admin", "integration-client"],
  "allowed_secret_refs": [],
  "require_approval_for": ["promote"],
  "required_validation_platforms": [],
  "updated_unix_ms": 0
}
```

Apply:

```bash
sparkbridge policy workspaces set --file workspace-policy.json
```

---

## 18. MCP setup

Use:

```text
URL: https://dgx-spark.example.lan:7791/mcp
Authorization: Bearer <integration-token>
```

See `docs/EXTERNAL_INTEGRATIONS.md` for the implemented methods/tools and current limits.

---

## 19. OpenAI-compatible setup

Set client base URL to:

```text
https://dgx-spark.example.lan:7791/v1
```

Use the integration token as the API key/bearer token.

---

## 20. Ollama-compatible setup

Point clients to:

```text
https://dgx-spark.example.lan:7791
```

rather than raw `11434`.

---

## 21. Dashboard

Open:

```text
https://dgx-spark.example.lan:7791/dashboard
```

The UI asks for the integration token and stores it only in browser `sessionStorage`.

---

# Part IV — Production maintenance

## 22. Backup

For a consistent disaster-recovery set:

```bash
sudo systemctl stop sparkbridge-server
sudo sparkbridge backup create \
  --root / \
  --output /srv/backups/sparkbridge-$(date +%F) \
  --include etc/sparkbridge \
  --include var/lib/sparkbridge
sudo sparkbridge backup verify --backup /srv/backups/sparkbridge-$(date +%F)
sudo systemctl start sparkbridge-server
```

Protect backup storage because it can contain the CA private key and node credentials.

---

## 23. CAS GC

Dry-run first:

```bash
python3 scripts/cas_gc.py \
  --database /var/lib/sparkbridge/sparkbridge.db \
  --cas /var/lib/sparkbridge/cas \
  --min-age-seconds 604800
```

Stop the server before `--delete`, and pass both `--delete` and `--confirm-server-stopped` with a non-zero `--min-age-seconds`:

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

---

## 24. Signed staged updates

Generate a manifest:

```bash
python3 scripts/make_update_manifest.py \
  SparkBridge-Fabric-v0.12.0-rc3.zip \
  --version 0.12.0
```

Sign the manifest with your controlled Ed25519 release key, then verify/stage using:

```bash
sparkbridge update verify ...
sparkbridge update stage ... --staging-dir /var/lib/sparkbridge/update-staging
```

SparkBridge does not replace a running executable automatically in v0.12.

---

## 25. Upgrade from v0.11

1. Back up v0.11.
2. Build/validate v0.12.
3. Generate `integration-token` if absent.
4. Add integration settings to `server.toml`.
5. Stop server.
6. Replace binaries.
7. Start server; the schema marker must read 9.
8. Verify `sparkbridge health`, `audit verify`, executor reconnects and integration status.
9. Keep the previous binaries/config backup until validation is complete.

For the full signed-artifact rehearsal, including rollback, see "Upgrade rehearsal" in the certification appendix below. Because v0.12 keeps Protocol 1.10 and schema 9 unchanged, rollback does not require a database downgrade.

---

## 26. Final deployment checks

```bash
sparkbridge health
sparkbridge protocol
sparkbridge nodes list
sparkbridge capabilities
sparkbridge audit verify
sparkbridge integrations --url https://dgx-spark.example.lan:7791 --ca-cert ca.pem status
```

Then exercise one snapshot, one candidate validation, and one non-destructive integration task before enabling wider client access.

---

# v0.12 Pre-Production Certification

After installation, perform certification on the real machines that will form the fabric.

## On every supported platform

```bash
./scripts/validate.sh
python3 scripts/certification/generate_local_results.py
```

Windows CI should invoke the Python generator directly and run Cargo commands from PowerShell or GitHub Actions as supplied by `.github/workflows/ci.yml`.

## On DGX Spark

In addition to native Rust validation:

1. Start the production-equivalent Ollama Spark service.
2. Start SparkBridge with the same TLS, policy, storage and model-residency configuration planned for production.
3. Execute the control-plane and agent-repair E2E scenarios in `docs/CERTIFICATION.md`.
4. Run the Ollama restart fault drill.
5. Record inference and gateway measurements described in `docs/PERFORMANCE.md`.
6. Mark `rust.linux-aarch64-dgx` PASS only when the exact release source builds/tests on the DGX Spark itself.

## Upgrade rehearsal

Before upgrading a production installation from v0.11 to v0.12:

1. create and verify a SparkBridge backup;
2. stage the signed v0.12 artifact;
3. stop services;
4. preserve the v0.11 binaries;
5. install v0.12 binaries without changing schema or protocol configuration;
6. start services and run health/protocol checks;
7. if qualification fails, stop services and restore the prior binaries;
8. verify the unchanged schema 9 database and existing credentials are readable by the prior version.

Because v0.12 intentionally keeps Protocol 1.10 and schema 9, rollback does not require a database downgrade.

## rc3 certification evidence collection

On every supported certification host, run from an identical unpacked rc3 source tree:

```bash
python3 scripts/certification/generate_local_results.py
```

Keep both `certification-results.local.json` and the `certification-evidence/` directory. Do not edit `source_revision`; the merge tool will reject results produced from a different source tree.

After collecting Linux x86_64, DGX Spark/Linux aarch64, macOS arm64 and Windows x86_64 results:

```bash
python3 scripts/certification/merge_results.py certification-results.json \
  linux-x86_64.json dgx-aarch64.json macos-arm64.json windows-x86_64.json
python3 scripts/certification/release_blockers.py --results certification-results.json
```

Record manual E2E/fault/drill checks using `scripts/certification/record_check.py`, attaching the corresponding log files as hashed evidence.


## Certification runner setup

No additional daemon is required for rc3. Python 3 is sufficient for evidence assembly/verification; native Rust certification additionally requires the repository's pinned Rust toolchain.

After unpacking the same rc3 source tree on each certification host:

```bash
./scripts/certify.sh --output-dir certification-run
```

Archive the resulting `certification-results.local.json`, `certification-evidence/`, or the complete `certification-run/` directory. Never edit a result file to make a source revision match another host; rerun the host on the exact same source tree instead.

CI aggregation and the DGX self-hosted workflow use the same portable evidence format.
