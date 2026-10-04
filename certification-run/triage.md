# SparkBridge Certification Triage

Source revision: `tree-sha256:b7ed5cbc8687932a36ea99884fb50d7a797ee81f0e205a9bb10eba3ae1913743`

Outstanding items: **11**

## `rust.linux-x86_64`

Status: **skip**

Next action: Run .github/workflows/ci.yml on ubuntu-latest for this exact revision.

## `rust.linux-aarch64-dgx`

Status: **skip**

Next action: Run .github/workflows/certification-dgx.yml on the self-hosted DGX Spark runner.

## `rust.windows-x86_64`

Status: **skip**

Next action: Run CI/native certification on Windows x86_64.

## `e2e.control-plane`

Status: **skip**

Next action: Run the production-equivalent control-plane E2E scenario in docs/CERTIFICATION.md.

## `e2e.agent-repair`

Status: **skip**

Next action: Run the broken-fixture agent repair scenario and attach task/action evidence.

## `fault.server-restart`

Status: **skip**

Next action: Execute the server restart scenario from scripts/certification/fault_plan.json.

## `fault.executor-disconnect`

Status: **skip**

Next action: Execute the executor disconnect scenario from scripts/certification/fault_plan.json.

## `fault.ollama-restart`

Status: **skip**

Next action: Execute the Ollama restart scenario from scripts/certification/fault_plan.json.

## `drill.backup-restore`

Status: **skip**

Next action: Run backup_restore_drill.sh plus an isolated restore of production-equivalent metadata/PKI.

## `drill.upgrade-rollback`

Status: **skip**

Next action: Perform the signed staged v0.11→v0.12 upgrade and service-manager rollback drill.

## `security.audit-chain`

Status: **skip**

Next action: Run an audit append/verify/tamper-detection runtime drill and attach logs.

