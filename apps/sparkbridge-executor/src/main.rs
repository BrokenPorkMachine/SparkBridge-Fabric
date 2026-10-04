mod identity;

use anyhow::{Context, Result, bail};
use clap::Parser;
use identity::{IdentityStore, LoadedIdentity, NodeIdentity, combined_identity_pem, new_key_and_csr};
use reqwest::{Certificate, Client, Identity, StatusCode};
use sparkbridge_config::{ExecutorConfig, load_file};
use sparkbridge_core::{FabricFeature, Platform};
use sparkbridge_cas::{Cas, Digest};
use sparkbridge_candidate::{CandidateManifest, CandidateOperation};
use sparkbridge_promotion::{WorkspacePromotionLock, apply_transaction, plan_promotion, recover_incomplete_transactions};
use sparkbridge_execution::{discover_execution_domains, execute_action};
use sparkbridge_secrets::resolve_secret_injections;
use sparkbridge_index::{NativeCollectionOptions, NativeIntelligenceRecord, NativeIntelligenceReport, collect_native_symbols, discover_native_adapters_with_commands, indexed_files_from_snapshot};
use sparkbridge_snapshot::{EntryKind, SnapshotOptions, WorkspaceSnapshot, snapshot_workspace};
use sparkbridge_protocol::{
    CertificateRotationRequest, CertificateRotationResponse, HeartbeatRequest, NodeConnectRequest,
    NodeConnectResponse, NodeEnrollmentRequest, NodeEnrollmentResponse, ProtocolVersion,
    MissingObjectsRequest, MissingObjectsResponse, SnapshotRegistrationRequest, SnapshotRecord,
    CandidateRecord, PromotionOutcome, PromotionRecord, PromotionReportRequest,
    ActionCompletionRequest, ActionCompletionResponse, ActionExecutionResult, ActionLeaseRequest, ActionLeaseResponse,
    ActionLeaseRenewRequest, ActionLeaseRenewResponse, ActionStartRequest, CapabilityReport,
    PolicyDecision, PromotionAuthorizationRequest, PromotionAuthorizationResponse,
};
use std::{fs, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "sparkbridge-executor", version, about = "SparkBridge Secure Fabric executor")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    enrollment_url: Option<String>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, env = "SPARKBRIDGE_ENROLLMENT_TOKEN")]
    enrollment_token: Option<String>,
    /// Rotate to a fresh local private key/certificate, then exit.
    #[arg(long)]
    rotate_certificate: bool,
    /// Snapshot and incrementally upload an authorized workspace, then exit.
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// Stable logical workspace identifier used with --snapshot or --promote.
    #[arg(long)]
    workspace_id: Option<String>,
    /// After --snapshot, query available native language servers and upload a snapshot-bound symbol overlay.
    #[arg(long, requires = "snapshot")]
    native_intelligence: bool,
    /// Promote a DGX candidate into an authorized live workspace, then exit.
    #[arg(long, conflicts_with = "snapshot")]
    promote: Option<String>,
    /// Live workspace targeted by --promote.
    #[arg(long, requires = "promote")]
    workspace: Option<PathBuf>,
    /// Plan and report promotion without changing files.
    #[arg(long, requires = "promote")]
    dry_run: bool,
    /// Principal on whose authority promotion is requested.
    #[arg(long, requires = "promote", default_value = "local-admin")]
    promotion_principal: String,
    /// Previously approved promotion approval ID. Live promotion always requires one in v0.12.
    #[arg(long, requires = "promote")]
    promotion_approval: Option<String>,
}

const FEATURES: &[FabricFeature] = &[
    FabricFeature::Heartbeat,
    FabricFeature::CapabilityReporting,
    FabricFeature::FeatureNegotiation,
    FabricFeature::CertificateRotation,
    FabricFeature::ContentAddressedStorage,
    FabricFeature::WorkspaceSnapshots,
    FabricFeature::SnapshotTransfer,
    FabricFeature::CandidateWorkspaces,
    FabricFeature::TransactionalPromotion,
    FabricFeature::ThreeWayMerge,
    FabricFeature::RemoteActions,
    FabricFeature::ExecutionDomains,
    FabricFeature::ActionLeases,
    FabricFeature::ActionCancellation,
    FabricFeature::StructuredDiagnostics,
    FabricFeature::ResultOutbox,
    FabricFeature::DeterministicAgentRuntime,
    FabricFeature::TaskEventLog,
    FabricFeature::CandidateValidationSandbox,
    FabricFeature::RepositoryIntelligence,
    FabricFeature::TreeSitterIndex,
    FabricFeature::NativeLanguageAdapters,
    FabricFeature::PolicyEngine,
    FabricFeature::ApprovalWorkflow,
    FabricFeature::SecretBroker,
    FabricFeature::DataBoundaries,
    FabricFeature::TamperEvidentAudit,
    FabricFeature::NetworkSandbox,
    FabricFeature::ActionCache,
    FabricFeature::ToolchainFingerprints,
    FabricFeature::MultiPlatformValidation,
    FabricFeature::BuildAffinity,
];

#[derive(Debug, Error)]
enum FabricConnectionError {
    #[error("retryable fabric connection error: {0}")]
    Retry(anyhow::Error),
    #[error("fatal fabric connection error: {0}")]
    Fatal(anyhow::Error),
}

impl FabricConnectionError {
    fn retry(error: impl Into<anyhow::Error>) -> Self {
        Self::Retry(error.into())
    }

    fn fatal(error: impl Into<anyhow::Error>) -> Self {
        Self::Fatal(error.into())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = match args.config {
        Some(path) => load_file::<ExecutorConfig>(&path)
            .with_context(|| format!("loading {}", path.display()))?,
        None => ExecutorConfig::default(),
    };
    if let Some(url) = args.enrollment_url {
        config.enrollment_url = url.trim_end_matches('/').to_owned();
    }
    if let Some(name) = args.name {
        config.name = Some(name);
    }
    if args.enrollment_token.is_some() {
        config.enrollment_token = args.enrollment_token;
    }
    config.validate().context("validating executor configuration")?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_filter)),
        )
        .init();

    cleanup_action_sandboxes(&config.action_sandbox_path)?;

    let node_name = config.name.clone().unwrap_or_else(default_node_name);
    let store = IdentityStore::new(config.identity_dir.clone());
    if !store.exists() {
        enroll(&config, &store, &node_name).await?;
    }

    if args.rotate_certificate {
        rotate_certificate(&store, &node_name).await?;
        info!("certificate rotation completed");
        return Ok(());
    }
    if let Some(workspace) = args.snapshot {
        let workspace_id = args.workspace_id.as_deref().unwrap_or("default");
        let record = snapshot_and_upload(&config, &store, &workspace, workspace_id).await?;
        if args.native_intelligence {
            let native = collect_and_upload_native_intelligence(&config,&store,&workspace,workspace_id,&record).await?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"snapshot":record,"native_intelligence":native}))?);
        } else {
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        return Ok(());
    }
    if let Some(candidate_id) = args.promote {
        let workspace = args.workspace.as_ref().context("--workspace is required with --promote")?;
        let workspace_id = args.workspace_id.as_deref().unwrap_or("default");
        let record = promote_candidate(&config, &store, workspace, workspace_id, &candidate_id, args.dry_run, &args.promotion_principal, args.promotion_approval.as_deref()).await?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }

    run_connected(&config, &store).await
}

async fn enroll(config: &ExecutorConfig, store: &IdentityStore, node_name: &str) -> Result<()> {
    let token = config
        .enrollment_token
        .as_deref()
        .context("executor is not enrolled; provide enrollment_token or SPARKBRIDGE_ENROLLMENT_TOKEN")?;
    let ca_pem = fs::read(&config.ca_cert_path)
        .with_context(|| format!("reading pinned CA {}", config.ca_cert_path.display()))?;
    let client = server_authenticated_client(&ca_pem)?;
    let (private_key_pem, csr_pem) = new_key_and_csr(node_name)?;
    let request = NodeEnrollmentRequest {
        token: token.to_owned(),
        name: node_name.to_owned(),
        platform: Platform::current(),
        architecture: std::env::consts::ARCH.into(),
        requested_features: FEATURES.to_vec(),
        protocol: ProtocolVersion::CURRENT,
        csr_pem,
    };
    let url = format!("{}/api/v1/enroll", config.enrollment_url.trim_end_matches('/'));
    let response = client.post(&url).json(&request).send().await
        .with_context(|| format!("enrolling at {url}"))?;
    if !response.status().is_success() {
        bail!("enrollment failed: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    let enrolled: NodeEnrollmentResponse = response.json().await.context("decoding enrollment response")?;
    let metadata = NodeIdentity {
        node_id: enrolled.node_id,
        node_secret: enrolled.node_secret,
        fabric_url: config.fabric_url.clone().unwrap_or(enrolled.fabric_url),
        accepted_features: enrolled.accepted_features,
        generation: String::new(),
    };
    store.commit_generation(
        metadata,
        &enrolled.certificate_pem,
        &private_key_pem,
        std::str::from_utf8(&ca_pem).context("pinned CA is not UTF-8 PEM")?,
    )?;
    info!(node_id = %enrolled.node_id, "executor enrolled with durable identity");
    Ok(())
}

async fn rotate_certificate(store: &IdentityStore, node_name: &str) -> Result<()> {
    let loaded = store.load()?;
    let client = fabric_client(&loaded)?;
    let (new_private_key, csr_pem) = new_key_and_csr(node_name)?;
    let url = format!(
        "{}/api/v1/nodes/{}/rotate-certificate",
        loaded.metadata.fabric_url.trim_end_matches('/'),
        loaded.metadata.node_id
    );
    let response = client
        .post(url)
        .bearer_auth(&loaded.metadata.node_secret)
        .json(&CertificateRotationRequest {
            protocol: ProtocolVersion::CURRENT,
            csr_pem,
        })
        .send()
        .await
        .context("requesting certificate rotation")?;
    if !response.status().is_success() {
        bail!("certificate rotation failed: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    let rotated: CertificateRotationResponse = response.json().await?;
    let metadata = NodeIdentity {
        node_id: loaded.metadata.node_id,
        node_secret: rotated.node_secret,
        fabric_url: loaded.metadata.fabric_url,
        accepted_features: loaded.metadata.accepted_features,
        generation: String::new(),
    };
    store.commit_generation(
        metadata,
        &rotated.certificate_pem,
        &new_private_key,
        std::str::from_utf8(&loaded.ca_certificate_pem).context("CA certificate is not UTF-8 PEM")?,
    )?;
    Ok(())
}

async fn run_connected(config: &ExecutorConfig, store: &IdentityStore) -> Result<()> {
    let mut backoff = config.reconnect_initial_seconds;
    let max_backoff = config.reconnect_max_seconds;

    loop {
        let loaded = store.load()?;
        let client = fabric_client(&loaded)?;
        match connect_once(&client, &loaded).await {
            Ok(()) => {
                backoff = config.reconnect_initial_seconds;
                match connected_loop(&client, &loaded, config).await {
                    Ok(()) => return Ok(()),
                    Err(FabricConnectionError::Fatal(error)) => return Err(error),
                    Err(FabricConnectionError::Retry(error)) => {
                        warn!(%error, "fabric connection interrupted")
                    }
                }
            }
            Err(FabricConnectionError::Fatal(error)) => return Err(error),
            Err(FabricConnectionError::Retry(error)) => {
                warn!(%error, "unable to connect to SparkBridge fabric")
            }
        }
        warn!(seconds = backoff, "reconnecting after backoff");
        tokio::select! {
            _ = time::sleep(Duration::from_secs(backoff)) => {},
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
        backoff = backoff.saturating_mul(2).min(max_backoff);
    }
}

async fn connect_once(client: &Client, loaded: &LoadedIdentity) -> Result<(), FabricConnectionError> {
    let url = format!(
        "{}/api/v1/nodes/{}/connect",
        loaded.metadata.fabric_url.trim_end_matches('/'),
        loaded.metadata.node_id
    );
    let response = client
        .post(url)
        .bearer_auth(&loaded.metadata.node_secret)
        .json(&NodeConnectRequest {
            protocol: ProtocolVersion::CURRENT,
            requested_features: FEATURES.to_vec(),
        })
        .send()
        .await
        .map_err(|error| FabricConnectionError::retry(anyhow::Error::new(error)))?;
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
        return Err(FabricConnectionError::fatal(anyhow::anyhow!(
            "node credential rejected or node revoked; administrator action is required"
        )));
    }
    if response.status() == StatusCode::UPGRADE_REQUIRED {
        return Err(FabricConnectionError::fatal(anyhow::anyhow!(
            "protocol major is incompatible with the server"
        )));
    }
    if !response.status().is_success() {
        return Err(FabricConnectionError::retry(anyhow::anyhow!(
            "connect rejected with {}", response.status()
        )));
    }
    let negotiated: NodeConnectResponse = response
        .json()
        .await
        .map_err(|error| FabricConnectionError::retry(anyhow::Error::new(error)))?;
    info!(
        node_id = %loaded.metadata.node_id,
        protocol_major = negotiated.protocol.major,
        protocol_minor = negotiated.protocol.minor,
        features = ?negotiated.accepted_features,
        "connected to Secure Fabric"
    );
    Ok(())
}

async fn connected_loop(client: &Client, loaded: &LoadedIdentity, config: &ExecutorConfig) -> Result<(), FabricConnectionError> {
    report_execution_capabilities(client, loaded, config).await?;
    if let Err(error) = flush_action_outbox(client, loaded, &config.action_outbox_path).await {
        warn!(%error, "unable to flush action completion outbox after reconnect");
    }

    let mut heartbeat = time::interval(Duration::from_secs(config.heartbeat_seconds));
    let mut action_poll = time::interval(Duration::from_secs(config.action_poll_seconds));
    heartbeat.tick().await;
    action_poll.tick().await;
    let action_running = Arc::new(AtomicBool::new(false));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let url = format!("{}/api/v1/nodes/{}/heartbeat", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id);
                let response = client.put(url)
                    .bearer_auth(&loaded.metadata.node_secret)
                    .json(&HeartbeatRequest { protocol: ProtocolVersion::CURRENT })
                    .send().await
                    .map_err(|error| FabricConnectionError::retry(anyhow::Error::new(error)))?;
                if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
                    return Err(FabricConnectionError::fatal(anyhow::anyhow!("node has been revoked or its credential is no longer valid; administrator action is required")));
                }
                if !response.status().is_success() {
                    return Err(FabricConnectionError::retry(anyhow::anyhow!("heartbeat rejected with {}", response.status())));
                }
                if let Err(error) = flush_action_outbox(client, loaded, &config.action_outbox_path).await {
                    warn!(%error, "action outbox flush deferred");
                }
            }
            _ = action_poll.tick(), if !action_running.load(Ordering::Acquire) => {
                match lease_next_action(client, loaded).await {
                    Ok(Some(lease)) => {
                        action_running.store(true, Ordering::Release);
                        let running = Arc::clone(&action_running);
                        let client = client.clone();
                        let loaded = loaded.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            if let Err(error) = run_leased_action(&client, &loaded, &config, lease).await {
                                warn!(%error, "leased action failed before durable completion report");
                            }
                            running.store(false, Ordering::Release);
                        });
                    }
                    Ok(None) => {}
                    Err(error) => warn!(%error, "action lease poll failed"),
                }
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

async fn report_execution_capabilities(client: &Client, loaded: &LoadedIdentity, config: &ExecutorConfig) -> Result<(), FabricConnectionError> {
    let valid_workspaces: Vec<String> = config.workspace_bindings.iter().filter_map(|(workspace_id, path)| {
        let canonical = path.canonicalize().ok()?;
        authorize_workspace(config, &canonical).ok()?;
        Some(workspace_id.clone())
    }).collect();
    let mut domains = discover_execution_domains(valid_workspaces, &config.action_allowed_commands, config.action_allow_linux_network_none);
    let adapters = discover_native_adapters_with_commands(&config.intelligence_lsp_commands);
    let adapter_json = serde_json::to_string(&adapters).unwrap_or_else(|_| "[]".into());
    for domain in &mut domains {
        domain.metadata.insert("repository_intelligence_adapters".into(), adapter_json.clone());
        for reference in config.secret_env_bindings.keys() {
            domain.capabilities.push(format!("secret:{reference}"));
        }
        domain.capabilities.sort();
        domain.capabilities.dedup();
    }
    let report = CapabilityReport {
        node_id: loaded.metadata.node_id,
        protocol: ProtocolVersion::CURRENT,
        domains,
        reported_unix_ms: unix_ms(),
    };
    let url = format!("{}/api/v1/nodes/{}/capabilities", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id);
    let response = client.put(url).bearer_auth(&loaded.metadata.node_secret).json(&report).send().await
        .map_err(|error| FabricConnectionError::retry(anyhow::Error::new(error)))?;
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN {
        return Err(FabricConnectionError::fatal(anyhow::anyhow!("capability report credential rejected")));
    }
    if !response.status().is_success() {
        return Err(FabricConnectionError::retry(anyhow::anyhow!("capability report rejected with {}", response.status())));
    }
    info!(domains = report.domains.len(), workspaces = config.workspace_bindings.len(), "reported execution domains and capabilities");
    Ok(())
}

async fn lease_next_action(client: &Client, loaded: &LoadedIdentity) -> Result<Option<sparkbridge_protocol::ActionLease>> {
    let url = format!("{}/api/v1/nodes/{}/actions/lease", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id);
    let response = client.post(url).bearer_auth(&loaded.metadata.node_secret)
        .json(&ActionLeaseRequest { protocol: ProtocolVersion::CURRENT }).send().await?;
    if !response.status().is_success() {
        bail!("action lease failed: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    Ok(response.json::<ActionLeaseResponse>().await?.lease)
}

async fn run_leased_action(
    client: &Client,
    loaded: &LoadedIdentity,
    config: &ExecutorConfig,
    lease: sparkbridge_protocol::ActionLease,
) -> Result<()> {
    let action_id = lease.action.action_id.clone();
    let start_url = format!("{}/api/v1/nodes/{}/actions/{}/start", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, action_id);
    let response = client.post(start_url).bearer_auth(&loaded.metadata.node_secret)
        .json(&ActionStartRequest { lease_id: lease.lease_id.clone(), started_unix_ms: unix_ms() }).send().await?;
    if !response.status().is_success() {
        bail!("action start rejected: {} {}", response.status(), response.text().await.unwrap_or_default());
    }

    let prepared = match prepare_action_workspace(client, loaded, config, &lease.action).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let request = ActionCompletionRequest {
                lease_id: lease.lease_id,
                completed_unix_ms: unix_ms(),
                result: ActionExecutionResult {
                    exit_code: None, duration_ms: 0, timed_out: false, cancelled: false,
                    stdout: String::new(), stderr: format!("executor action preflight failed: {error:#}"),
                    stdout_truncated: false, stderr_truncated: false, diagnostics: Vec::new(),
                },
            };
            persist_outbox_entry(&config.action_outbox_path, &action_id, &request)?;
            if report_action_completion(client, loaded, &action_id, &request).await.is_ok() {
                remove_outbox_entry(&config.action_outbox_path, &action_id)?;
            }
            return Ok(());
        }
    };
    let workspace = prepared.path.clone();

    let cancellation = CancellationToken::new();
    let stop_renewal = CancellationToken::new();
    let renew_task = {
        let client = client.clone();
        let loaded = loaded.clone();
        let action_id = action_id.clone();
        let lease_id = lease.lease_id.clone();
        let cancellation = cancellation.clone();
        let stop = stop_renewal.clone();
        let seconds = config.action_lease_renew_seconds;
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(seconds));
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = ticker.tick() => {
                        let url = format!("{}/api/v1/nodes/{}/actions/{}/renew", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, action_id);
                        match client.post(url).bearer_auth(&loaded.metadata.node_secret)
                            .json(&ActionLeaseRenewRequest { lease_id: lease_id.clone() }).send().await {
                            Ok(response) if response.status().is_success() => {
                                match response.json::<ActionLeaseRenewResponse>().await {
                                    Ok(control) if control.cancel_requested => { cancellation.cancel(); return; }
                                    Ok(_) => {}
                                    Err(_) => { cancellation.cancel(); return; }
                                }
                            }
                            _ => { cancellation.cancel(); return; }
                        }
                    }
                }
            }
        })
    };

    let secret_env = match resolve_secret_injections(&lease.action.spec.secret_injections, &config.secret_env_bindings) {
        Ok(values) => values,
        Err(error) => {
            stop_renewal.cancel();
            let _ = renew_task.await;
            let result = ActionExecutionResult {
                exit_code: None, duration_ms: 0, timed_out: false, cancelled: false,
                stdout: String::new(), stderr: format!("executor secret preflight failed: {error:#}"),
                stdout_truncated: false, stderr_truncated: false, diagnostics: Vec::new(),
            };
            let request = ActionCompletionRequest { lease_id: lease.lease_id, completed_unix_ms: unix_ms(), result };
            persist_outbox_entry(&config.action_outbox_path, &action_id, &request)?;
            if report_action_completion(client, loaded, &action_id, &request).await.is_ok() {
                remove_outbox_entry(&config.action_outbox_path, &action_id)?;
            }
            if prepared.disposable { let _ = fs::remove_dir_all(&prepared.path); }
            return Ok(());
        }
    };
    let result = match execute_action(&lease.action.spec, &workspace, &config.action_allowed_env, &config.action_allowed_commands, &secret_env, config.action_allow_linux_network_none, cancellation).await {
        Ok(result) => result,
        Err(error) => ActionExecutionResult {
            exit_code: None,
            duration_ms: 0,
            timed_out: false,
            cancelled: false,
            stdout: String::new(),
            stderr: format!("executor rejected or failed action before completion: {error:#}"),
            stdout_truncated: false,
            stderr_truncated: false,
            diagnostics: Vec::new(),
        },
    };
    stop_renewal.cancel();
    let _ = renew_task.await;
    if prepared.disposable {
        if let Err(error) = fs::remove_dir_all(&prepared.path) {
            warn!(%error, path = %prepared.path.display(), "failed to remove candidate validation sandbox");
        }
    }
    let request = ActionCompletionRequest { lease_id: lease.lease_id, completed_unix_ms: unix_ms(), result };
    persist_outbox_entry(&config.action_outbox_path, &action_id, &request)?;
    if let Err(error) = report_action_completion(client, loaded, &action_id, &request).await {
        warn!(%error, action_id, "action completion retained in durable outbox");
        return Ok(());
    }
    remove_outbox_entry(&config.action_outbox_path, &action_id)?;
    Ok(())
}


struct PreparedActionWorkspace { path: PathBuf, disposable: bool }

async fn prepare_action_workspace(
    client: &Client,
    loaded: &LoadedIdentity,
    config: &ExecutorConfig,
    action: &sparkbridge_protocol::ActionRecord,
) -> Result<PreparedActionWorkspace> {
    if action.spec.candidate_id.is_none() {
        let workspace = config.workspace_bindings.get(&action.spec.workspace_id)
            .with_context(|| format!("workspace_id {:?} has no executor binding", action.spec.workspace_id))?
            .canonicalize().with_context(|| format!("canonicalizing action workspace {}", action.spec.workspace_id))?;
        authorize_workspace(config, &workspace)?;
        return Ok(PreparedActionWorkspace { path: workspace, disposable: false });
    }

    let candidate_id = action.spec.candidate_id.as_deref().context("candidate action is missing candidate_id")?;
    let candidate_url = format!("{}/api/v1/nodes/{}/candidates/{}", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, candidate_id);
    let response = client.get(candidate_url).bearer_auth(&loaded.metadata.node_secret).send().await?;
    if !response.status().is_success() {
        bail!("candidate lookup failed for validation sandbox: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    let record: CandidateRecord = response.json().await?;
    if record.workspace_id != action.spec.workspace_id { bail!("candidate workspace does not match action workspace"); }
    // Read-only validation may reconstruct a candidate captured on another executor
    // as long as this executor advertises the same logical workspace. Promotion
    // remains pinned to the original owner and is checked separately.

    let cas = Cas::open(&config.local_cas_path)?;
    let candidate_bytes = fetch_cas_object(client, loaded, &cas, &Digest(record.manifest_digest.clone()), config.snapshot_max_file_bytes.max(16 * 1024 * 1024)).await?;
    let candidate: CandidateManifest = serde_json::from_slice(&candidate_bytes).context("decoding candidate validation manifest")?;
    let base_digest = Digest(record.base_manifest_digest.clone());
    let base_bytes = fetch_cas_object(client, loaded, &cas, &base_digest, config.snapshot_max_file_bytes.max(16 * 1024 * 1024)).await?;
    let base: WorkspaceSnapshot = serde_json::from_slice(&base_bytes).context("decoding candidate base snapshot")?;
    for entry in &base.entries {
        if let Some(digest) = &entry.digest {
            let _ = fetch_cas_object(client, loaded, &cas, digest, config.snapshot_max_file_bytes).await?;
        }
    }
    for digest in candidate_required_digests(&candidate) {
        let _ = fetch_cas_object(client, loaded, &cas, &digest, config.snapshot_max_file_bytes).await?;
    }

    fs::create_dir_all(&config.action_sandbox_path)?;
    let sandbox = config.action_sandbox_path.join(&action.action_id);
    if sandbox.exists() { fs::remove_dir_all(&sandbox)?; }
    fs::create_dir_all(&sandbox)?;
    if let Err(error) = materialize_candidate_sandbox(&sandbox, &base, &candidate, &cas, config.snapshot_max_file_bytes) {
        let _ = fs::remove_dir_all(&sandbox);
        return Err(error);
    }
    Ok(PreparedActionWorkspace { path: sandbox, disposable: true })
}

fn materialize_candidate_sandbox(root: &Path, base: &WorkspaceSnapshot, candidate: &CandidateManifest, cas: &Cas, max_file_bytes: u64) -> Result<()> {
    for entry in base.entries.iter().filter(|entry| entry.kind == EntryKind::Directory) {
        fs::create_dir_all(root.join(&entry.path))?;
    }
    for entry in base.entries.iter().filter(|entry| entry.kind == EntryKind::File) {
        let digest = entry.digest.as_ref().context("base file has no digest")?;
        let path = root.join(&entry.path);
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(&path, cas.get_bytes(digest, max_file_bytes)?)?;
        set_executable(&path, entry.executable)?;
    }
    for entry in base.entries.iter().filter(|entry| entry.kind == EntryKind::Symlink) {
        materialize_safe_symlink(root, &entry.path, entry.symlink_target.as_deref().context("symlink has no target")?)?;
    }
    for op in &candidate.operations {
        match op {
            CandidateOperation::CreateFile { path, content_digest, executable, .. } |
            CandidateOperation::ModifyFile { path, content_digest, executable, .. } => {
                let destination = root.join(path);
                if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
                fs::write(&destination, cas.get_bytes(content_digest, max_file_bytes)?)?;
                set_executable(&destination, *executable)?;
            }
            CandidateOperation::DeleteFile { path, .. } => {
                let destination = root.join(path);
                if destination.exists() { fs::remove_file(destination)?; }
            }
            CandidateOperation::RenameFile { from_path, to_path, executable, .. } => {
                let source = root.join(from_path); let destination = root.join(to_path);
                if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
                fs::rename(source, &destination)?; set_executable(&destination, *executable)?;
            }
            CandidateOperation::SetExecutable { path, executable, .. } => set_executable(&root.join(path), *executable)?,
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    let mode = permissions.mode();
    permissions.set_mode(if executable { mode | 0o111 } else { mode & !0o111 });
    fs::set_permissions(path, permissions)?;
    Ok(())
}
#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn materialize_safe_symlink(root: &Path, logical_path: &str, target: &str) -> Result<()> {
    let target_path = Path::new(target);
    if target_path.is_absolute() { bail!("candidate sandbox refuses absolute symlink target {target:?}"); }
    let link = root.join(logical_path);
    let parent = link.parent().context("symlink path has no parent")?;
    let mut depth: i64 = Path::new(logical_path).parent().unwrap_or_else(|| Path::new(""))
        .components().filter(|component| matches!(component, std::path::Component::Normal(_))).count() as i64;
    for component in target_path.components() {
        match component {
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {},
            std::path::Component::ParentDir => { depth -= 1; if depth < 0 { bail!("candidate sandbox symlink escapes workspace"); } },
            _ => bail!("unsupported symlink target in candidate sandbox"),
        }
    }
    fs::create_dir_all(parent)?;
    std::os::unix::fs::symlink(target_path, &link)?;
    Ok(())
}

#[cfg(windows)]
fn materialize_safe_symlink(_root: &Path, _logical_path: &str, _target: &str) -> Result<()> {
    bail!("candidate sandbox containing symlinks is not supported on Windows")
}

#[cfg(not(any(unix, windows)))]
fn materialize_safe_symlink(_root: &Path, _logical_path: &str, _target: &str) -> Result<()> {
    bail!("candidate sandbox symlinks are unsupported on this platform")
}

fn cleanup_action_sandboxes(path: &Path) -> Result<()> {
    if !path.exists() { fs::create_dir_all(path)?; return Ok(()); }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let candidate = entry.path();
        if candidate.is_dir() { fs::remove_dir_all(candidate)?; }
        else if candidate.is_file() { fs::remove_file(candidate)?; }
    }
    Ok(())
}

fn outbox_file(path: &Path, action_id: &str) -> PathBuf { path.join(format!("{action_id}.json")) }

fn persist_outbox_entry(path: &Path, action_id: &str, request: &ActionCompletionRequest) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating action outbox {}", path.display()))?;
    let destination = outbox_file(path, action_id);
    let temp = path.join(format!(".{action_id}.tmp"));
    fs::write(&temp, serde_json::to_vec_pretty(request)?)?;
    fs::rename(&temp, &destination)?;
    Ok(())
}

fn remove_outbox_entry(path: &Path, action_id: &str) -> Result<()> {
    let file = outbox_file(path, action_id);
    if file.exists() { fs::remove_file(file)?; }
    Ok(())
}

async fn report_action_completion(client: &Client, loaded: &LoadedIdentity, action_id: &str, request: &ActionCompletionRequest) -> Result<ActionCompletionResponse> {
    let url = format!("{}/api/v1/nodes/{}/actions/{}/complete", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, action_id);
    let response = client.post(url).bearer_auth(&loaded.metadata.node_secret).json(request).send().await?;
    if !response.status().is_success() {
        bail!("action completion report failed: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    response.json().await.context("decoding action completion acknowledgment")
}

async fn flush_action_outbox(client: &Client, loaded: &LoadedIdentity, path: &Path) -> Result<()> {
    if !path.is_dir() { return Ok(()); }
    let mut entries: Vec<PathBuf> = fs::read_dir(path)?.filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_file() && path.extension().and_then(|v| v.to_str()) == Some("json")).collect();
    entries.sort();
    for file in entries {
        let action_id = file.file_stem().and_then(|v| v.to_str()).context("invalid outbox filename")?.to_owned();
        let request: ActionCompletionRequest = serde_json::from_slice(&fs::read(&file)?)?;
        let url = format!("{}/api/v1/nodes/{}/actions/{}/complete", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, action_id);
        let response = client.post(url).bearer_auth(&loaded.metadata.node_secret).json(&request).send().await?;
        if response.status().is_success() {
            fs::remove_file(file)?;
            continue;
        }
        if response.status() == StatusCode::CONFLICT || response.status() == StatusCode::NOT_FOUND {
            let rejected = path.join("rejected");
            fs::create_dir_all(&rejected)?;
            let destination = rejected.join(file.file_name().context("outbox entry has no filename")?);
            warn!(action_id, status = %response.status(), "server rejected stale action completion; preserving it in rejected outbox");
            fs::rename(file, destination)?;
            continue;
        }
        bail!("action outbox flush failed for {action_id}: {} {}", response.status(), response.text().await.unwrap_or_default());
    }
    Ok(())
}


async fn snapshot_and_upload(config: &ExecutorConfig, store: &IdentityStore, requested: &Path, workspace_id: &str) -> Result<SnapshotRecord> {
    let workspace = requested.canonicalize().with_context(|| format!("canonicalizing workspace {}", requested.display()))?;
    authorize_workspace(config, &workspace)?;
    let loaded = store.load()?;
    let client = fabric_client(&loaded)?;
    let cas = Cas::open(&config.local_cas_path)?;
    let options = SnapshotOptions { max_retries: config.snapshot_max_retries, max_file_bytes: config.snapshot_max_file_bytes, ..SnapshotOptions::default() };
    let snapshot = snapshot_workspace(&workspace, &cas, &options)?;
    let manifest_digest = snapshot.manifest_digest.clone().context("snapshot has no manifest digest")?;
    let mut digests: Vec<Digest> = snapshot.entries.iter().filter_map(|e| e.digest.clone()).collect();
    digests.push(manifest_digest.clone());
    digests.sort_by(|a,b| a.0.cmp(&b.0)); digests.dedup_by(|a,b| a.0 == b.0);

    let missing_url = format!("{}/api/v1/nodes/{}/cas/missing", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id);
    let response = client.post(missing_url).bearer_auth(&loaded.metadata.node_secret)
        .json(&MissingObjectsRequest { digests: digests.iter().map(|d| d.0.clone()).collect() }).send().await?;
    if !response.status().is_success() { bail!("CAS missing query failed: {} {}", response.status(), response.text().await.unwrap_or_default()); }
    let missing: MissingObjectsResponse = response.json().await?;
    for raw in &missing.missing {
        let digest = Digest(raw.clone());
        let bytes = cas.get_bytes(&digest, config.snapshot_max_file_bytes.max(16 * 1024 * 1024))?;
        let url = format!("{}/api/v1/nodes/{}/cas/{}", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, raw);
        let compressed = if bytes.len() >= 4096 { zstd::stream::encode_all(&bytes[..], 3).ok().filter(|v| v.len() + 64 < bytes.len()) } else { None };
        let mut request = client.put(url).bearer_auth(&loaded.metadata.node_secret).header(reqwest::header::CONTENT_TYPE,"application/octet-stream");
        request = if let Some(payload) = compressed { request.header(reqwest::header::CONTENT_ENCODING, "zstd").body(payload) } else { request.body(bytes) };
        let response = request.send().await?;
        if !response.status().is_success() { bail!("CAS upload failed for {raw}: {} {}", response.status(), response.text().await.unwrap_or_default()); }
    }
    let mut head = load_workspace_head(&workspace)?;
    if head.manifest_digest.as_deref() != Some(manifest_digest.0.as_str()) {
        head.generation = head.generation.saturating_add(1);
        head.manifest_digest = Some(manifest_digest.0.clone());
    }
    let request = SnapshotRegistrationRequest {
        workspace_id: workspace_id.to_owned(), node_id: loaded.metadata.node_id, manifest_digest: manifest_digest.0.clone(),
        root_name: snapshot.root_name, entry_count: snapshot.entries.len() as u64, source_generation: head.generation,
        git_head: snapshot.git.and_then(|g| g.head), created_unix_ms: unix_ms(),
    };
    let url = format!("{}/api/v1/nodes/{}/snapshots", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id);
    let response = client.post(url).bearer_auth(&loaded.metadata.node_secret).json(&request).send().await?;
    if !response.status().is_success() { bail!("snapshot registration failed: {} {}", response.status(), response.text().await.unwrap_or_default()); }
    let record: SnapshotRecord = response.json().await.context("decoding snapshot registration response")?;
    save_workspace_head(&workspace, &head)?;
    Ok(record)
}


async fn collect_and_upload_native_intelligence(
    config:&ExecutorConfig, store:&IdentityStore, requested:&Path, workspace_id:&str, snapshot_record:&SnapshotRecord,
)->Result<NativeIntelligenceRecord>{
    let workspace=requested.canonicalize().with_context(||format!("canonicalizing workspace {}",requested.display()))?; authorize_workspace(config,&workspace)?;
    let loaded=store.load()?; let client=fabric_client(&loaded)?; let cas=Cas::open(&config.local_cas_path)?;
    let manifest=Digest(snapshot_record.manifest_digest.clone()); let bytes=cas.get_bytes(&manifest,config.snapshot_max_file_bytes.max(16*1024*1024))?;
    let snapshot:WorkspaceSnapshot=serde_json::from_slice(&bytes).context("decoding local snapshot for native intelligence")?;
    let files=indexed_files_from_snapshot(&snapshot);
    let options=NativeCollectionOptions{max_files:config.intelligence_native_max_files,max_file_bytes:config.intelligence_native_file_max_bytes,request_timeout:Duration::from_secs(30),commands:config.intelligence_lsp_commands.clone()};
    let (adapters,symbols,truncated)=collect_native_symbols(&workspace,&files,&options).await?;
    let report=NativeIntelligenceReport{format_version:1,snapshot_id:snapshot_record.snapshot_id.clone(),workspace_id:workspace_id.to_owned(),adapters,symbols,created_unix_ms:unix_ms(),truncated};
    let url=format!("{}/api/v1/nodes/{}/snapshots/{}/native-intelligence",loaded.metadata.fabric_url.trim_end_matches('/'),loaded.metadata.node_id,snapshot_record.snapshot_id);
    let response=client.put(url).bearer_auth(&loaded.metadata.node_secret).json(&report).send().await?;
    if !response.status().is_success(){bail!("native intelligence upload failed: {} {}",response.status(),response.text().await.unwrap_or_default());}
    response.json().await.context("decoding native intelligence registration")
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct WorkspaceHead { generation: u64, manifest_digest: Option<String> }

// Promotion is a single-call-site operation whose arguments mirror the promotion policy it
// enforces; a wrapper struct would restate the policy rather than clarify it.
#[allow(clippy::too_many_arguments)]
async fn promote_candidate(
    config: &ExecutorConfig,
    store: &IdentityStore,
    requested: &Path,
    workspace_id: &str,
    candidate_id: &str,
    dry_run: bool,
    principal_id: &str,
    approval_id: Option<&str>,
) -> Result<PromotionRecord> {
    let workspace = requested.canonicalize().with_context(|| format!("canonicalizing workspace {}", requested.display()))?;
    authorize_workspace(config, &workspace)?;
    let loaded = store.load()?;
    let client = fabric_client(&loaded)?;
    let cas = Cas::open(&config.local_cas_path)?;
    let candidate_url = format!("{}/api/v1/nodes/{}/candidates/{}", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, candidate_id);
    let response = client.get(candidate_url).bearer_auth(&loaded.metadata.node_secret).send().await?;
    if !response.status().is_success() { bail!("candidate lookup failed: {} {}", response.status(), response.text().await.unwrap_or_default()); }
    let record: CandidateRecord = response.json().await?;
    if record.workspace_id != workspace_id { bail!("candidate targets workspace_id {}, but promotion requested {}", record.workspace_id, workspace_id); }
    let authorization_url = format!("{}/api/v1/nodes/{}/candidates/{}/promotion-authorization", loaded.metadata.fabric_url.trim_end_matches('/'), loaded.metadata.node_id, candidate_id);
    let authorization_response = client.post(authorization_url).bearer_auth(&loaded.metadata.node_secret).json(&PromotionAuthorizationRequest {
        principal_id: principal_id.to_owned(), workspace_id: workspace_id.to_owned(), dry_run,
        approval_id: approval_id.map(str::to_owned),
    }).send().await?;
    if !authorization_response.status().is_success() {
        bail!("promotion authorization failed: {} {}", authorization_response.status(), authorization_response.text().await.unwrap_or_default());
    }
    let authorization: PromotionAuthorizationResponse = authorization_response.json().await?;
    if authorization.decision == PolicyDecision::Ask {
        bail!("promotion requires approval {}; approve it with the operator CLI, then retry with --promotion-approval <id>", authorization.approval_id.as_deref().unwrap_or("<missing>"));
    }
    if authorization.decision != PolicyDecision::Allow { bail!("promotion was not authorized: {}", authorization.reason); }

    let candidate_bytes = fetch_cas_object(&client, &loaded, &cas, &Digest(record.manifest_digest.clone()), config.snapshot_max_file_bytes.max(16 * 1024 * 1024)).await?;
    let candidate: CandidateManifest = serde_json::from_slice(&candidate_bytes).context("decoding candidate manifest")?;
    let base_digest = Digest(record.base_manifest_digest.clone());
    let base_bytes = fetch_cas_object(&client, &loaded, &cas, &base_digest, config.snapshot_max_file_bytes.max(16 * 1024 * 1024)).await?;
    let base: sparkbridge_snapshot::WorkspaceSnapshot = serde_json::from_slice(&base_bytes).context("decoding base snapshot")?;

    for digest in candidate_required_digests(&candidate) {
        let _ = fetch_cas_object(&client, &loaded, &cas, &digest, config.snapshot_max_file_bytes).await?;
    }

    let promotion_lock = WorkspacePromotionLock::acquire(&workspace)?;
    // A dry-run must not mutate the live workspace. Crash recovery rolls back abandoned
    // live promotions (it overwrites real files) and the head bump advances the
    // authoritative generation, so both are skipped when only inspecting the plan. The
    // promotion lock is still taken: it is transient and is what makes the observed plan
    // trustworthy against a concurrent live promotion.
    if !dry_run { recover_incomplete_transactions(&workspace, &cas)?; }
    let options = SnapshotOptions { max_retries: config.snapshot_max_retries, max_file_bytes: config.snapshot_max_file_bytes, ..SnapshotOptions::default() };
    let current = snapshot_workspace(&workspace, &cas, &options)?;
    let before_digest = current.manifest_digest.as_ref().context("live snapshot has no manifest digest")?.0.clone();
    let mut head = load_workspace_head(&workspace)?;
    if head.manifest_digest.as_deref() != Some(before_digest.as_str()) {
        head.generation = head.generation.saturating_add(1);
        head.manifest_digest = Some(before_digest.clone());
        if !dry_run { save_workspace_head(&workspace, &head)?; }
    }
    let generation_before = head.generation;
    let plan = plan_promotion(&base, &current, &candidate, &cas, config.snapshot_max_file_bytes as usize)?;
    let conflict_strings: Vec<String> = plan.conflicts.iter().map(|c| format!("{}: {}", c.path, c.reason)).collect();

    if !plan.conflicts.is_empty() || dry_run {
        let outcome = if dry_run { PromotionOutcome::DryRun } else { PromotionOutcome::Conflict };
        return report_promotion(&client, &loaded, PromotionReportRequest {
            candidate_id: candidate_id.to_owned(), workspace_id: workspace_id.to_owned(), node_id: loaded.metadata.node_id,
            outcome, base_manifest_digest: record.base_manifest_digest, observed_before_manifest_digest: before_digest,
            result_manifest_digest: None, generation_before, generation_after: generation_before,
            merged_files: plan.merged_files as u64, conflicts: conflict_strings, created_unix_ms: unix_ms(),
        }).await;
    }

    // Re-snapshot after planning to detect user edits that landed during merge preparation.
    let precommit = snapshot_workspace(&workspace, &cas, &options)?;
    let precommit_digest = precommit.manifest_digest.as_ref().context("precommit snapshot has no manifest digest")?.0.clone();
    if precommit_digest != before_digest {
        return report_promotion(&client, &loaded, PromotionReportRequest {
            candidate_id: candidate_id.to_owned(), workspace_id: workspace_id.to_owned(), node_id: loaded.metadata.node_id,
            outcome: PromotionOutcome::Conflict, base_manifest_digest: record.base_manifest_digest,
            observed_before_manifest_digest: before_digest, result_manifest_digest: None, generation_before, generation_after: generation_before,
            merged_files: plan.merged_files as u64, conflicts: vec!["WORKSPACE_CHANGED: live workspace changed while promotion was being prepared".into()], created_unix_ms: unix_ms(),
        }).await;
    }
    if let Err(error) = apply_transaction(&workspace, &plan, &cas, &promotion_lock) {
        return report_promotion(&client, &loaded, PromotionReportRequest {
            candidate_id: candidate_id.to_owned(), workspace_id: workspace_id.to_owned(), node_id: loaded.metadata.node_id,
            outcome: PromotionOutcome::Failed, base_manifest_digest: record.base_manifest_digest,
            observed_before_manifest_digest: before_digest, result_manifest_digest: None, generation_before, generation_after: generation_before,
            merged_files: plan.merged_files as u64, conflicts: vec![format!("promotion transaction failed: {error:#}")], created_unix_ms: unix_ms(),
        }).await;
    }
    let result_snapshot = snapshot_and_upload(config, store, &workspace, workspace_id).await?;
    let generation_after = result_snapshot.source_generation;
    report_promotion(&client, &loaded, PromotionReportRequest {
        candidate_id: candidate_id.to_owned(), workspace_id: workspace_id.to_owned(), node_id: loaded.metadata.node_id,
        outcome: PromotionOutcome::Applied, base_manifest_digest: record.base_manifest_digest,
        observed_before_manifest_digest: before_digest, result_manifest_digest: Some(result_snapshot.manifest_digest),
        generation_before, generation_after, merged_files: plan.merged_files as u64, conflicts: Vec::new(), created_unix_ms: unix_ms(),
    }).await
}

async fn fetch_cas_object(client:&Client, loaded:&LoadedIdentity, cas:&Cas, digest:&Digest, limit:u64)->Result<Vec<u8>> {
    if cas.contains(digest) { return cas.get_bytes(digest, limit); }
    let url=format!("{}/api/v1/nodes/{}/cas/{}",loaded.metadata.fabric_url.trim_end_matches('/'),loaded.metadata.node_id,digest.0);
    let response=client.get(url).bearer_auth(&loaded.metadata.node_secret).send().await?;
    if !response.status().is_success(){bail!("CAS download failed for {}: {} {}",digest.0,response.status(),response.text().await.unwrap_or_default());}
    let bytes=response.bytes().await?.to_vec(); if bytes.len() as u64>limit{bail!("downloaded CAS object exceeds local limit");} cas.put_bytes(Some(digest),&bytes)?; Ok(bytes)
}

fn candidate_required_digests(candidate:&CandidateManifest)->Vec<Digest>{
    let mut out=Vec::new(); for op in &candidate.operations { match op { CandidateOperation::CreateFile{content_digest,..}=>out.push(content_digest.clone()), CandidateOperation::ModifyFile{expected_base_digest,content_digest,..}=>{out.push(expected_base_digest.clone());out.push(content_digest.clone());}, CandidateOperation::DeleteFile{expected_base_digest,..}|CandidateOperation::RenameFile{expected_base_digest,..}|CandidateOperation::SetExecutable{expected_base_digest,..}=>out.push(expected_base_digest.clone()) } } out.sort_by(|a,b|a.0.cmp(&b.0));out.dedup_by(|a,b|a.0==b.0);out
}

async fn report_promotion(client:&Client,loaded:&LoadedIdentity,request:PromotionReportRequest)->Result<PromotionRecord>{
    let url=format!("{}/api/v1/nodes/{}/promotions",loaded.metadata.fabric_url.trim_end_matches('/'),loaded.metadata.node_id);
    let response=client.post(url).bearer_auth(&loaded.metadata.node_secret).json(&request).send().await?;
    if !response.status().is_success(){bail!("promotion report failed: {} {}",response.status(),response.text().await.unwrap_or_default());}
    response.json().await.context("decoding promotion record")
}

fn workspace_head_path(workspace:&Path)->PathBuf{workspace.join(".sparkbridge/workspace-head.json")}
fn load_workspace_head(workspace:&Path)->Result<WorkspaceHead>{let p=workspace_head_path(workspace);if !p.is_file(){return Ok(WorkspaceHead::default());}Ok(serde_json::from_slice(&fs::read(p)?)?)}
fn save_workspace_head(workspace:&Path,head:&WorkspaceHead)->Result<()> {let p=workspace_head_path(workspace);if let Some(parent)=p.parent(){fs::create_dir_all(parent)?;}let tmp=p.with_extension("json.tmp");fs::write(&tmp,serde_json::to_vec_pretty(head)?)?;fs::rename(tmp,p)?;Ok(())}

fn authorize_workspace(config: &ExecutorConfig, workspace: &Path) -> Result<()> {
    for root in &config.workspace_roots {
        let root = root.canonicalize().with_context(|| format!("canonicalizing configured workspace root {}", root.display()))?;
        if workspace.starts_with(&root) { return Ok(()); }
    }
    bail!("workspace {} is outside configured workspace_roots", workspace.display())
}

fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64
}

fn server_authenticated_client(ca_pem: &[u8]) -> Result<Client> {
    let ca = Certificate::from_pem(ca_pem).context("parsing pinned SparkBridge CA")?;
    Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .https_only(true)
        .build()
        .context("building enrollment HTTPS client")
}

fn fabric_client(loaded: &LoadedIdentity) -> Result<Client> {
    let ca = Certificate::from_pem(&loaded.ca_certificate_pem).context("parsing CA certificate")?;
    let identity = Identity::from_pem(&combined_identity_pem(loaded)).context("parsing node TLS identity")?;
    Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .https_only(true)
        .build()
        .context("building mTLS fabric client")
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH))
}
