mod agent_runtime;
mod inference;
mod integrations;
mod repository;
mod pki;
mod store;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use inference::InferenceGateway;
use sparkbridge_integrations::IntegrationAuth;
use pki::CertificateAuthority;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig, server::WebPkiClientVerifier};
use sparkbridge_config::{ServerConfig, load_file};
use sparkbridge_core::{FabricFeature, NodeId, SPARKBRIDGE_VERSION};
use sparkbridge_cas::{Cas, Digest};
use sparkbridge_index::{NativeIntelligenceRecord, NativeIntelligenceReport, RepositoryIndexRecord};
use sparkbridge_task::{TaskCreateRequest, TaskEvent, TaskEventKind, TaskRecord, TaskRunRequest, TaskRunResponse, TaskStatus};
use sparkbridge_candidate::{CandidateManifest, CandidateOperation, validate_candidate};
use sparkbridge_protocol::{
    ActionCacheRecord, CacheTrust, ValidationMatrixCreateRequest, ValidationRunRecord, ValidationRunStatus, ValidationTargetRecord,
    CertificateRotationRequest, CertificateRotationResponse, EnrollmentCreateRequest,
    EnrollmentTokenResponse, HealthResponse, HeartbeatRequest, NodeConnectRequest,
    NodeConnectResponse, NodeEnrollmentRequest, NodeEnrollmentResponse, NodeRecord, NodeStatus,
    ProtocolVersion, ResidencyRequest, RevokeNodeRequest, VersionResponse, negotiate_features,
    MissingObjectsRequest, MissingObjectsResponse, CasObjectInfo, SnapshotRegistrationRequest, SnapshotRecord,
    CandidateCreateOperationInput, CandidateCreateRequest, CandidateRecord, PromotionAuthorizationRequest, PromotionAuthorizationResponse, PromotionRecord, PromotionReportRequest,
    ActionCancelResponse, ActionCompletionRequest, ActionCompletionResponse, ActionCreateRequest, ActionExecutionResult, ActionLeaseRequest,
    ActionLeaseResponse, ActionLeaseRenewRequest, ActionLeaseRenewResponse, ActionRecord, ActionStatus, ActionStartRequest,
    CapabilityReport, ApprovalDecisionRequest, ApprovalRecord, AuditRecord, AuditVerifyResponse,
    DataClassification, InferenceDataBoundary, Permission, PolicyDecision, PrincipalRecord,
    PrincipalUpsertRequest, PrincipalKind, WorkspacePolicyRecord, WorkspacePolicyUpsertRequest,
};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use store::Store;
use sparkbridge_policy::{authorize_workspace as policy_authorize_workspace, classification_allows_boundary, effective_classification, evaluate_action};
use sparkbridge_cache::{action_cache_key, decode_cached_result, encode_cached_result, validate_cache_request};
use sparkbridge_validation::{derive_run_status, hydrate_targets};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sparkbridge-server", version, about = "SparkBridge Fabric secure control plane")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    ca: CertificateAuthority,
    config: Arc<ServerConfig>,
    inference: InferenceGateway,
    integration_auth: IntegrationAuth,
    cas: Arc<Cas>,
    task_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

type ApiError = (StatusCode, String);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = match args.config {
        Some(path) => load_file::<ServerConfig>(&path)
            .with_context(|| format!("loading {}", path.display()))?,
        None => ServerConfig::default(),
    };
    config.validate().context("validating server configuration")?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_filter)),
        )
        .init();

    let admin_addr: SocketAddr = config.admin_bind.parse().context("parsing admin bind")?;
    if !admin_addr.ip().is_loopback() {
        bail!("admin_bind must remain loopback-only; got {admin_addr}");
    }
    let enrollment_addr: SocketAddr = config.enrollment_bind.parse().context("parsing enrollment bind")?;
    let fabric_addr: SocketAddr = config.fabric_bind.parse().context("parsing fabric bind")?;
    let gateway_addr: SocketAddr = config.gateway_bind.parse().context("parsing inference gateway bind")?;
    let integration_addr: SocketAddr = config.integration_bind.parse().context("parsing integration bind")?;

    let store = Arc::new(Store::open(&config.database_path)?);
    if store.get_principal(&config.integration_principal_id).is_err() {
        let integration_principal = PrincipalRecord {
            principal_id: config.integration_principal_id.clone(),
            display_name: "External Integration Client".into(),
            kind: PrincipalKind::Service,
            enabled: true,
            permissions: vec![Permission::Read, Permission::Snapshot, Permission::CandidateCreate, Permission::Execute],
            created_unix_ms: unix_ms(),
        };
        store.upsert_principal(&integration_principal).context("seeding integration principal")?;
    }
    let integration_token = fs::read_to_string(&config.integration_token_path)
        .with_context(|| format!("reading integration token {}", config.integration_token_path.display()))?;
    let integration_auth = IntegrationAuth::new(&integration_token).map_err(anyhow::Error::msg)?;
    let ca = CertificateAuthority::load(&config.ca_cert_path, &config.ca_key_path)?;
    let inference = InferenceGateway::new(&config).context("initializing DGX inference gateway")?;
    let cas = Arc::new(Cas::open(&config.cas_path).context("opening content-addressed store")?);
    let state = AppState {
        store,
        ca,
        config: Arc::new(config.clone()),
        inference,
        integration_auth,
        cas,
        task_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    let recovered_tasks = state.store.recover_tasks(unix_ms()).context("recovering durable agent tasks")?;
    if recovered_tasks > 0 { info!(recovered_tasks, "recovered durable agent tasks after restart"); }

    let admin_app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/api/v1/admin/enrollments", post(admin_create_enrollment))
        .route("/api/v1/admin/nodes", get(admin_list_nodes))
        .route("/api/v1/admin/snapshots", get(admin_list_snapshots))
        .route("/api/v1/admin/indexes", get(admin_list_indexes))
        .route("/api/v1/admin/indexes/{snapshot_id}", get(admin_get_index).post(admin_build_index))
        .route("/api/v1/admin/indexes/{snapshot_id}/search", get(admin_search_index))
        .route("/api/v1/admin/indexes/{snapshot_id}/symbols", get(admin_search_symbols))
        .route("/api/v1/admin/indexes/{snapshot_id}/references", get(admin_search_references))
        .route("/api/v1/admin/indexes/{snapshot_id}/history", get(admin_git_history))
        .route("/api/v1/admin/candidates", get(admin_list_candidates).post(admin_create_candidate))
        .route("/api/v1/admin/candidates/{candidate_id}", get(admin_get_candidate))
        .route("/api/v1/admin/promotions", get(admin_list_promotions))
        .route("/api/v1/admin/capabilities", get(admin_list_capabilities))
        .route("/api/v1/admin/actions", get(admin_list_actions).post(admin_create_action))
        .route("/api/v1/admin/actions/{action_id}", get(admin_get_action).delete(admin_cancel_action))
        .route("/api/v1/admin/cache", get(admin_list_cache))
        .route("/api/v1/admin/validations", get(admin_list_validations).post(admin_create_validation))
        .route("/api/v1/admin/validations/{validation_id}", get(admin_get_validation))
        .route("/api/v1/admin/tasks", get(admin_list_tasks).post(admin_create_task))
        .route("/api/v1/admin/tasks/{task_id}", get(admin_get_task).delete(admin_cancel_task))
        .route("/api/v1/admin/tasks/{task_id}/events", get(admin_task_events))
        .route("/api/v1/admin/tasks/{task_id}/run", post(admin_run_task))
        .route("/api/v1/admin/tasks/{task_id}/pause", post(admin_pause_task))
        .route("/api/v1/admin/tasks/{task_id}/resume", post(admin_resume_task))
        .route("/api/v1/admin/principals", get(admin_list_principals).post(admin_upsert_principal))
        .route("/api/v1/admin/workspace-policies", get(admin_list_workspace_policies).post(admin_upsert_workspace_policy))
        .route("/api/v1/admin/approvals", get(admin_list_approvals))
        .route("/api/v1/admin/approvals/{approval_id}/approve", post(admin_approve))
        .route("/api/v1/admin/approvals/{approval_id}/deny", post(admin_deny))
        .route("/api/v1/admin/audit", get(admin_list_audit))
        .route("/api/v1/admin/audit/verify", get(admin_verify_audit))
        .route("/api/v1/admin/nodes/{id}/revoke", post(admin_revoke_node))
        .layer(DefaultBodyLimit::max(config.cas_max_object_bytes.saturating_mul(4).max(1024 * 1024)))
        .with_state(state.clone());

    let enrollment_app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/api/v1/enroll", post(enroll_node))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state.clone());

    let fabric_app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/api/v1/nodes/{id}/connect", post(connect_node))
        .route("/api/v1/nodes/{id}/heartbeat", put(heartbeat))
        .route("/api/v1/nodes/{id}/rotate-certificate", post(rotate_certificate))
        .route("/api/v1/nodes/{id}/cas/missing", post(cas_missing))
        .route("/api/v1/nodes/{id}/cas/{digest}", get(cas_get).put(cas_put))
        .route("/api/v1/nodes/{id}/snapshots", post(register_snapshot).get(list_snapshots))
        .route("/api/v1/nodes/{id}/snapshots/{snapshot_id}/native-intelligence", put(register_native_intelligence))
        .route("/api/v1/nodes/{id}/candidates/{candidate_id}", get(get_candidate_for_node))
        .route("/api/v1/nodes/{id}/candidates/{candidate_id}/promotion-authorization", post(authorize_promotion))
        .route("/api/v1/nodes/{id}/promotions", post(register_promotion))
        .route("/api/v1/nodes/{id}/capabilities", put(report_capabilities))
        .route("/api/v1/nodes/{id}/actions/lease", post(lease_action))
        .route("/api/v1/nodes/{id}/actions/{action_id}/renew", post(renew_action_lease))
        .route("/api/v1/nodes/{id}/actions/{action_id}/start", post(start_action))
        .route("/api/v1/nodes/{id}/actions/{action_id}/complete", post(complete_action))
        .layer(DefaultBodyLimit::max(config.cas_max_object_bytes.max(64 * 1024)))
        .with_state(state.clone());

    let gateway_app = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/api/v1/inference/health", get(inference_health))
        .route("/api/v1/inference/models", get(inference_models))
        .route("/api/v1/inference/running", get(inference_running))
        .route("/api/v1/inference/metrics", get(inference_metrics))
        .route("/api/v1/inference/generate", post(inference_generate))
        .route("/api/v1/inference/chat", post(inference_chat))
        .route("/api/v1/inference/residency", post(inference_residency))
        .route("/api/v1/inference/requests/{request_id}", delete(inference_cancel))
        .layer(DefaultBodyLimit::max(config.inference_max_request_bytes))
        .with_state(state.clone());

    let integration_app = integrations::router()
        .layer(DefaultBodyLimit::max(config.inference_max_request_bytes.max(1024 * 1024)))
        .with_state(state);

    let enrollment_tls = RustlsConfig::from_pem_file(&config.server_cert_path, &config.server_key_path)
        .await
        .context("loading enrollment TLS certificate")?;
    let fabric_tls = build_mtls_config(&config)?;
    let gateway_tls = RustlsConfig::from_pem_file(&config.server_cert_path, &config.server_key_path)
        .await
        .context("loading inference gateway TLS certificate")?;
    let integration_tls = RustlsConfig::from_pem_file(&config.server_cert_path, &config.server_key_path)
        .await
        .context("loading integration TLS certificate")?;

    let admin_listener = TcpListener::bind(admin_addr)
        .await
        .with_context(|| format!("binding admin API {admin_addr}"))?;

    info!(%admin_addr, %enrollment_addr, %fabric_addr, %gateway_addr, %integration_addr, version = SPARKBRIDGE_VERSION, "SparkBridge Fabric starting");

    let admin_task = tokio::spawn(async move {
        axum::serve(admin_listener, admin_app).await.context("admin server failed")
    });
    let enrollment_task = tokio::spawn(async move {
        axum_server::bind_rustls(enrollment_addr, enrollment_tls)
            .serve(enrollment_app.into_make_service())
            .await
            .context("enrollment server failed")
    });
    let fabric_task = tokio::spawn(async move {
        axum_server::bind_rustls(fabric_addr, fabric_tls)
            .serve(fabric_app.into_make_service())
            .await
            .context("fabric server failed")
    });
    let gateway_task = tokio::spawn(async move {
        axum_server::bind_rustls(gateway_addr, gateway_tls)
            .serve(gateway_app.into_make_service())
            .await
            .context("inference gateway server failed")
    });
    let integration_task = tokio::spawn(async move {
        axum_server::bind_rustls(integration_addr, integration_tls)
            .serve(integration_app.into_make_service())
            .await
            .context("integration server failed")
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("shutdown requested"),
        result = admin_task => warn!(?result, "admin server stopped"),
        result = enrollment_task => warn!(?result, "enrollment server stopped"),
        result = fabric_task => warn!(?result, "fabric server stopped"),
        result = gateway_task => warn!(?result, "inference gateway stopped"),
        result = integration_task => warn!(?result, "integration server stopped"),
    }

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: SPARKBRIDGE_VERSION.into(),
        protocol: ProtocolVersion::CURRENT,
    })
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: SPARKBRIDGE_VERSION.into(),
        protocol: ProtocolVersion::CURRENT,
    })
}

async fn admin_create_enrollment(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentCreateRequest>,
) -> Result<(StatusCode, Json<EnrollmentTokenResponse>), ApiError> {
    let ttl = request.ttl_seconds.clamp(30, 86_400);
    state
        .store
        .create_enrollment_token(ttl, request.label, unix_ms())
        .map(|token| (StatusCode::CREATED, Json(token)))
        .map_err(internal_error)
}

async fn admin_list_nodes(State(state): State<AppState>) -> Result<Json<Vec<NodeRecord>>, ApiError> {
    state
        .store
        .list_nodes(
            unix_ms(),
            state.config.heartbeat_stale_seconds,
            state.config.heartbeat_offline_seconds,
        )
        .map(Json)
        .map_err(internal_error)
}

async fn admin_list_snapshots(State(state): State<AppState>) -> Result<Json<Vec<SnapshotRecord>>, ApiError> {
    state.store.list_snapshots().map(Json).map_err(internal_error)
}

#[derive(Debug, serde::Deserialize)]
struct IntelligenceQuery { q: Option<String>, limit: Option<usize> }

async fn admin_list_indexes(State(state): State<AppState>) -> Result<Json<Vec<RepositoryIndexRecord>>, ApiError> {
    state.store.list_repository_indexes().map(Json).map_err(internal_error)
}

async fn admin_get_index(State(state): State<AppState>, Path(snapshot_id): Path<String>) -> Result<Json<RepositoryIndexRecord>, ApiError> {
    state.store.get_repository_index(&snapshot_id).map(Json).map_err(|e| (StatusCode::NOT_FOUND,e.to_string()))
}

async fn admin_build_index(State(state): State<AppState>, Path(snapshot_id): Path<String>) -> Result<Json<RepositoryIndexRecord>, ApiError> {
    repository::build_index(&state,&snapshot_id).map(Json)
}

async fn admin_search_index(State(state): State<AppState>, Path(snapshot_id): Path<String>, Query(query): Query<IntelligenceQuery>) -> Result<Json<Vec<sparkbridge_index::SearchHit>>, ApiError> {
    let q=query.q.unwrap_or_default(); let limit=query.limit.unwrap_or(state.config.intelligence_search_limit);
    repository::search(&state,&snapshot_id,&q,limit).map(Json)
}

async fn admin_search_symbols(State(state): State<AppState>, Path(snapshot_id): Path<String>, Query(query): Query<IntelligenceQuery>) -> Result<Json<Vec<sparkbridge_index::SymbolHit>>, ApiError> {
    let q=query.q.unwrap_or_default(); let limit=query.limit.unwrap_or(state.config.intelligence_search_limit);
    repository::symbols(&state,&snapshot_id,&q,limit).map(Json)
}

async fn admin_search_references(State(state): State<AppState>, Path(snapshot_id): Path<String>, Query(query): Query<IntelligenceQuery>) -> Result<Json<Vec<sparkbridge_index::ReferenceRecord>>, ApiError> {
    let q=query.q.unwrap_or_default(); let limit=query.limit.unwrap_or(state.config.intelligence_search_limit);
    repository::references(&state,&snapshot_id,&q,limit).map(Json)
}

async fn admin_git_history(State(state): State<AppState>, Path(snapshot_id): Path<String>) -> Result<Json<Vec<sparkbridge_snapshot::GitCommitSummary>>, ApiError> {
    repository::history(&state,&snapshot_id).map(Json)
}


async fn admin_list_candidates(State(state): State<AppState>) -> Result<Json<Vec<CandidateRecord>>, ApiError> {
    state.store.list_candidates().map(Json).map_err(internal_error)
}

async fn admin_get_candidate(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
) -> Result<Json<CandidateRecord>, ApiError> {
    state.store.get_candidate(&candidate_id).map(Json).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))
}

async fn admin_list_promotions(State(state): State<AppState>) -> Result<Json<Vec<PromotionRecord>>, ApiError> {
    state.store.list_promotions().map(Json).map_err(internal_error)
}

async fn admin_create_candidate(
    State(state): State<AppState>,
    Json(request): Json<CandidateCreateRequest>,
) -> Result<(StatusCode, Json<CandidateRecord>), ApiError> {
    let record = create_candidate_internal(&state, request, "local-admin")?;
    state.store.append_audit(
        "candidate.created", Some("local-admin".into()), Some(format!("candidate:{}", record.candidate_id)),
        serde_json::json!({"workspace_id":record.workspace_id,"base_snapshot_id":record.base_snapshot_id,"operation_count":record.operation_count}), unix_ms(),
    ).map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(record)))
}

pub(crate) fn create_candidate_internal(state: &AppState, request: CandidateCreateRequest, principal_id: &str) -> Result<CandidateRecord, ApiError> {
    if request.operations.is_empty() || request.operations.len() > 10_000 {
        return Err((StatusCode::BAD_REQUEST, "candidate must contain between 1 and 10000 operations".into()));
    }
    let base_record = state.store.get_snapshot(&request.base_snapshot_id)
        .map_err(|error| (StatusCode::NOT_FOUND, format!("base snapshot not found: {error}")))?;
    // Re-authorize on every creation, not only when the task was created: the agent loop
    // calls this each turn, so a principal that lost CandidateCreate (or was disabled /
    // removed from allowed_principals) must stop minting authoritative candidates. This
    // mirrors the per-request Execute re-check in create_action_internal.
    let principal = state.store.get_principal(principal_id)
        .map_err(|error| (StatusCode::FORBIDDEN, format!("candidate principal unavailable: {error}")))?;
    let policy = workspace_policy_for(state, &base_record.workspace_id)?;
    if policy_authorize_workspace(&principal, &policy, Permission::CandidateCreate) == PolicyDecision::Deny {
        return Err((StatusCode::FORBIDDEN, "principal is not authorized to create candidates in this workspace".into()));
    }
    let base_digest = Digest(base_record.manifest_digest.clone());
    let base_bytes = state.cas.get_bytes(&base_digest, state.config.cas_max_object_bytes as u64)
        .map_err(|error| (StatusCode::CONFLICT, format!("base snapshot manifest unavailable: {error}")))?;
    let base: sparkbridge_snapshot::WorkspaceSnapshot = serde_json::from_slice(&base_bytes)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("stored base snapshot is invalid: {error}")))?;
    let base_files: std::collections::BTreeMap<&str, &sparkbridge_snapshot::SnapshotEntry> =
        base.entries.iter().map(|entry| (entry.path.as_str(), entry)).collect();
    let mut operations = Vec::with_capacity(request.operations.len());
    for operation in request.operations {
        let translated = match operation {
            CandidateCreateOperationInput::CreateFile { path, content_base64, executable } => {
                let bytes = BASE64.decode(content_base64).map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid base64 for {path}: {error}")))?;
                if bytes.len() > state.config.cas_max_object_bytes { return Err((StatusCode::PAYLOAD_TOO_LARGE, format!("candidate content for {path} exceeds CAS limit"))); }
                let info = state.cas.put_bytes(None, &bytes).map_err(internal_error)?;
                CandidateOperation::CreateFile { path, content_digest: info.digest, size_bytes: info.size_bytes, executable }
            }
            CandidateCreateOperationInput::ModifyFile { path, content_base64, executable } => {
                let entry = base_files.get(path.as_str()).ok_or_else(|| (StatusCode::BAD_REQUEST, format!("modify path is absent from base snapshot: {path}")))?;
                let expected = entry.digest.clone().ok_or_else(|| (StatusCode::BAD_REQUEST, format!("modify path is not a regular file in base snapshot: {path}")))?;
                let bytes = BASE64.decode(content_base64).map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid base64 for {path}: {error}")))?;
                if bytes.len() > state.config.cas_max_object_bytes { return Err((StatusCode::PAYLOAD_TOO_LARGE, format!("candidate content for {path} exceeds CAS limit"))); }
                let info = state.cas.put_bytes(None, &bytes).map_err(internal_error)?;
                CandidateOperation::ModifyFile { path, expected_base_digest: expected, content_digest: info.digest, size_bytes: info.size_bytes, executable }
            }
            CandidateCreateOperationInput::DeleteFile { path } => {
                let entry = base_files.get(path.as_str()).ok_or_else(|| (StatusCode::BAD_REQUEST, format!("delete path is absent from base snapshot: {path}")))?;
                let expected = entry.digest.clone().ok_or_else(|| (StatusCode::BAD_REQUEST, format!("delete path is not a regular file in base snapshot: {path}")))?;
                CandidateOperation::DeleteFile { path, expected_base_digest: expected }
            }
            CandidateCreateOperationInput::RenameFile { from_path, to_path, executable } => {
                let entry = base_files.get(from_path.as_str()).ok_or_else(|| (StatusCode::BAD_REQUEST, format!("rename source is absent from base snapshot: {from_path}")))?;
                let expected = entry.digest.clone().ok_or_else(|| (StatusCode::BAD_REQUEST, format!("rename source is not a regular file in base snapshot: {from_path}")))?;
                CandidateOperation::RenameFile { from_path, to_path, expected_base_digest: expected, executable }
            }
            CandidateCreateOperationInput::SetExecutable { path, executable } => {
                let entry = base_files.get(path.as_str()).ok_or_else(|| (StatusCode::BAD_REQUEST, format!("mode path is absent from base snapshot: {path}")))?;
                let expected = entry.digest.clone().ok_or_else(|| (StatusCode::BAD_REQUEST, format!("mode path is not a regular file in base snapshot: {path}")))?;
                CandidateOperation::SetExecutable { path, expected_base_digest: expected, executable }
            }
        };
        operations.push(translated);
    }
    let candidate_id = Uuid::new_v4().to_string();
    let candidate = CandidateManifest {
        format_version: 1,
        candidate_id: candidate_id.clone(),
        base_snapshot_id: base_record.snapshot_id.clone(),
        base_manifest_digest: base_digest.clone(),
        description: request.description.clone(),
        operations,
        created_unix_ms: unix_ms(),
        manifest_digest: None,
    };
    validate_candidate(&base, &candidate, &state.cas).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let candidate = candidate.store(&state.cas).map_err(internal_error)?;
    let manifest_digest = candidate.manifest_digest.as_ref().expect("stored candidate has digest").0.clone();
    let record = CandidateRecord {
        candidate_id,
        base_snapshot_id: base_record.snapshot_id,
        base_manifest_digest: base_record.manifest_digest,
        manifest_digest,
        node_id: base_record.node_id,
        workspace_id: base_record.workspace_id,
        operation_count: candidate.operations.len() as u64,
        description: request.description,
        created_unix_ms: candidate.created_unix_ms,
    };
    state.store.register_candidate(&record).map_err(internal_error)?;
    Ok(record)
}


async fn admin_list_capabilities(State(state): State<AppState>) -> Result<Json<Vec<CapabilityReport>>, ApiError> {
    state.store.list_capability_reports().map(Json).map_err(internal_error)
}

async fn admin_list_actions(State(state): State<AppState>) -> Result<Json<Vec<ActionRecord>>, ApiError> {
    state.store.list_actions().map(Json).map_err(internal_error)
}

async fn admin_get_action(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
) -> Result<Json<ActionRecord>, ApiError> {
    state.store.get_action(&action_id).map(Json).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))
}

async fn admin_cancel_action(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
) -> Result<Json<ActionCancelResponse>, ApiError> {
    let record = state.store.cancel_action(&action_id, unix_ms()).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    Ok(Json(ActionCancelResponse { action_id: record.action_id, cancel_requested: record.cancel_requested, status: record.status }))
}

async fn admin_create_action(
    State(state): State<AppState>,
    Json(request): Json<ActionCreateRequest>,
) -> Result<(StatusCode, Json<ActionRecord>), ApiError> {
    create_action_internal(&state, request).map(|record| (StatusCode::CREATED, Json(record)))
}

pub(crate) fn create_action_internal(state: &AppState, mut request: ActionCreateRequest) -> Result<ActionRecord, ApiError> {
    if request.spec.argv.is_empty() || request.spec.argv[0].trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "action argv must contain an executable".into()));
    }
    if request.spec.principal_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "action principal_id is required".into()));
    }
    if request.spec.workspace_id.trim().is_empty() || request.spec.domain.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "workspace_id and domain are required".into()));
    }
    if let Some(candidate_id) = &request.spec.candidate_id {
        let candidate = state.store.get_candidate(candidate_id).map_err(|error| (StatusCode::NOT_FOUND, format!("candidate not found: {error}")))?;
        if candidate.workspace_id != request.spec.workspace_id {
            return Err((StatusCode::BAD_REQUEST, "candidate workspace does not match action workspace".into()));
        }
    }
    let executable = request.spec.argv[0].clone();
    if std::path::Path::new(&executable).components().count() != 1 {
        return Err((StatusCode::BAD_REQUEST, "action executable must be a command name, not a path".into()));
    }
    if !request.spec.required_capabilities.iter().any(|capability| capability == &executable) {
        request.spec.required_capabilities.push(executable);
    }
    match request.spec.network_policy {
        sparkbridge_protocol::ActionNetworkPolicy::Unrestricted => {}
        sparkbridge_protocol::ActionNetworkPolicy::None => {
            if !request.spec.required_capabilities.iter().any(|capability| capability == "network:none") {
                request.spec.required_capabilities.push("network:none".into());
            }
        }
        sparkbridge_protocol::ActionNetworkPolicy::DependencyFetch | sparkbridge_protocol::ActionNetworkPolicy::DeclaredHosts => {
            return Err((StatusCode::BAD_REQUEST, "dependency_fetch and declared_hosts network policies are not yet enforceable in v0.12".into()));
        }
    }
    let mut secret_refs = Vec::new();
    let mut secret_targets = std::collections::HashSet::new();
    for injection in &request.spec.secret_injections {
        if injection.reference.trim().is_empty() || injection.env_name.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "secret injections require non-empty reference and env_name".into()));
        }
        if !secret_targets.insert(injection.env_name.clone()) {
            return Err((StatusCode::BAD_REQUEST, format!("duplicate secret target environment variable {}", injection.env_name)));
        }
        secret_refs.push(injection.reference.clone());
        let capability = format!("secret:{}", injection.reference);
        if !request.spec.required_capabilities.iter().any(|existing| existing == &capability) {
            request.spec.required_capabilities.push(capability);
        }
    }
    secret_refs.sort();
    secret_refs.dedup();

    let max_timeout_ms = state.config.action_max_timeout_seconds.saturating_mul(1000);
    request.spec.timeout_ms = request.spec.timeout_ms.clamp(1_000, max_timeout_ms);
    request.spec.max_output_bytes = request.spec.max_output_bytes.clamp(1_024, state.config.action_max_output_bytes);

    let principal = state.store.get_principal(&request.spec.principal_id)
        .map_err(|error| (StatusCode::FORBIDDEN, format!("action principal unavailable: {error}")))?;
    let workspace_policy = workspace_policy_for(state, &request.spec.workspace_id)?;
    let (decision, reason) = evaluate_action(&principal, &workspace_policy, request.spec.side_effect, request.spec.network_policy, &secret_refs);
    if decision == PolicyDecision::Deny {
        state.store.append_audit(
            "action.denied", Some(principal.principal_id.clone()), Some(format!("workspace:{}", request.spec.workspace_id)),
            serde_json::json!({"reason":reason,"argv0":request.spec.argv[0],"secret_refs":secret_refs,"network_policy":request.spec.network_policy,"side_effect":request.spec.side_effect}), unix_ms(),
        ).map_err(internal_error)?;
        return Err((StatusCode::FORBIDDEN, reason));
    }

    let nodes = state.store.list_nodes(unix_ms(), state.config.heartbeat_stale_seconds, state.config.heartbeat_offline_seconds).map_err(internal_error)?;
    let online: std::collections::HashSet<NodeId> = nodes.into_iter().filter(|n| n.status == NodeStatus::Online).map(|n| n.id).collect();
    if request.spec.cache_trust != CacheTrust::Disabled {
        validate_cache_request(&request.spec).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
        if request.spec.cache_trust == CacheTrust::Strong
            && !request.spec.required_capabilities.iter().any(|capability| capability == "cache:strong")
        {
            request.spec.required_capabilities.push("cache:strong".into());
        }
    }
    let reports = state.store.list_capability_reports().map_err(internal_error)?;
    let mut choices: Vec<_> = reports.iter().filter_map(|report| {
        if !online.contains(&report.node_id) || !request.target_node_id.is_none_or(|id| id == report.node_id) { return None; }
        let domain = matching_domain(report, &request.spec)?;
        Some((report, domain))
    }).collect();
    if choices.is_empty() {
        return Err((StatusCode::CONFLICT, "no online executor satisfies the action workspace/domain/platform/architecture/capability requirements".into()));
    }

    // Build affinity: prefer an executor/toolchain that already has this exact cache key.
    let mut selected_index = 0usize;
    let mut selected_key: Option<String> = None;
    let mut selected_cache: Option<ActionCacheRecord> = None;
    if request.spec.cache_trust != CacheTrust::Disabled {
        for (index, (_report, domain)) in choices.iter().enumerate() {
            let Some(toolchain) = domain.toolchain.as_ref() else { continue; };
            let key = action_cache_key(&request.spec, toolchain).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
            let hit = state.store.get_action_cache(&key).map_err(internal_error)?;
            if hit.is_some() { selected_index = index; selected_key = Some(key); selected_cache = hit; break; }
            if selected_key.is_none() { selected_index = index; selected_key = Some(key); }
        }
    }
    let (chosen_report, chosen_domain) = choices.swap_remove(selected_index);
    let chosen = chosen_report.node_id;
    let toolchain_digest = chosen_domain.toolchain.as_ref().map(|f| f.digest.clone());
    if request.spec.cache_trust != CacheTrust::Disabled && selected_key.is_none() {
        let toolchain = chosen_domain.toolchain.as_ref().ok_or_else(|| (StatusCode::CONFLICT, "selected executor did not report a toolchain fingerprint required for caching".into()))?;
        selected_key = Some(action_cache_key(&request.spec, toolchain).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?);
        selected_cache = state.store.get_action_cache(selected_key.as_deref().unwrap()).map_err(internal_error)?;
    }
    let status = if decision == PolicyDecision::Ask { ActionStatus::AwaitingApproval } else { ActionStatus::Queued };
    let cached_result = if decision == PolicyDecision::Allow && request.spec.cache_trust == CacheTrust::Strong {
        if let Some(hit) = selected_cache.as_ref().filter(|hit| hit.trust == CacheTrust::Strong) {
            match load_cached_result(state, hit) {
                Ok(result) => {
                    let _ = state.store.touch_action_cache(&hit.cache_key, unix_ms()).map_err(internal_error)?;
                    Some(result)
                }
                Err(error) => {
                    warn!(cache_key = %hit.cache_key, %error, "strong cache metadata exists but immutable CAS result is unavailable; executing action instead");
                    None
                }
            }
        } else { None }
    } else { None };
    let cache_source_action_id = selected_cache.as_ref().map(|hit| hit.source_action_id.clone());
    let record = state.store.create_action(
        chosen, request.spec, unix_ms(), status, decision, Some(reason.clone()), state.config.approval_ttl_seconds,
        selected_key, toolchain_digest, cache_source_action_id, cached_result,
    ).map_err(internal_error)?;
    state.store.append_audit(
        "action.policy_decision", Some(record.spec.principal_id.clone()), Some(format!("action:{}", record.action_id)),
        serde_json::json!({"decision":record.policy_decision,"approval_id":record.approval_id,"reason":reason,"workspace_id":record.spec.workspace_id,"secret_refs":secret_refs,"network_policy":record.spec.network_policy,"side_effect":record.spec.side_effect,"cache_trust":record.spec.cache_trust}), unix_ms(),
    ).map_err(internal_error)?;
    if record.cache_hit {
        state.store.append_audit("action.cache_hit",Some(record.spec.principal_id.clone()),Some(format!("action:{}",record.action_id)),serde_json::json!({"cache_key":record.cache_key,"source_action_id":record.cache_source_action_id,"toolchain_digest":record.toolchain_digest}),unix_ms()).map_err(internal_error)?;
    }
    Ok(record)
}

fn load_cached_result(state: &AppState, record: &ActionCacheRecord) -> Result<ActionExecutionResult> {
    let bytes = state.cas.get_bytes(&Digest(record.result_digest.clone()), state.config.cas_max_object_bytes as u64)
        .with_context(|| format!("loading cached action result {}", record.result_digest))?;
    decode_cached_result(&bytes, &record.cache_key, &record.toolchain_digest)
        .with_context(|| format!("verifying cached action result {}", record.result_digest))
}

fn matching_domain<'a>(report: &'a CapabilityReport, spec: &sparkbridge_protocol::ActionSpec) -> Option<&'a sparkbridge_protocol::ExecutionDomainDescriptor> {
    report.domains.iter().find(|domain| {
        domain.id == spec.domain
            && spec.required_platform.as_deref().is_none_or(|platform| domain.platform.eq_ignore_ascii_case(platform))
            && spec.required_architecture.as_deref().is_none_or(|arch| domain.architecture.eq_ignore_ascii_case(arch))
            && domain.workspace_ids.iter().any(|id| id == &spec.workspace_id)
            && spec.required_capabilities.iter().all(|required| domain.capabilities.iter().any(|available| available == required))
    })
}


async fn admin_list_cache(State(state): State<AppState>) -> Result<Json<Vec<ActionCacheRecord>>, ApiError> {
    state.store.list_action_cache().map(Json).map_err(internal_error)
}

async fn admin_create_validation(
    State(state): State<AppState>, Json(request): Json<ValidationMatrixCreateRequest>,
) -> Result<(StatusCode, Json<ValidationRunRecord>), ApiError> {
    if request.workspace_id.trim().is_empty() || request.candidate_id.trim().is_empty() || request.targets.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "workspace_id, candidate_id and at least one validation target are required".into()));
    }
    if request.targets.len() > state.config.validation_max_targets { return Err((StatusCode::BAD_REQUEST, format!("validation matrix exceeds configured target limit {}",state.config.validation_max_targets))); }
    let candidate = state.store.get_candidate(&request.candidate_id).map_err(|e| (StatusCode::NOT_FOUND,e.to_string()))?;
    if candidate.workspace_id != request.workspace_id { return Err((StatusCode::BAD_REQUEST, "candidate workspace does not match validation workspace".into())); }
    let mut created: Vec<ActionRecord> = Vec::new();
    for target in &request.targets {
        if target.name.trim().is_empty() || target.platform.trim().is_empty() || target.argv.is_empty() {
            for action in &created { let _ = state.store.cancel_action(&action.action_id, unix_ms()); }
            return Err((StatusCode::BAD_REQUEST, "each validation target requires name, platform and argv".into()));
        }
        let spec = sparkbridge_protocol::ActionSpec {
            principal_id: request.principal_id.clone(), workspace_id: request.workspace_id.clone(), candidate_id: Some(request.candidate_id.clone()), origin_task_id: None,
            domain: target.domain.clone(), required_platform: Some(target.platform.clone()), required_architecture: target.architecture.clone(),
            argv: target.argv.clone(), relative_cwd: target.relative_cwd.clone(), env: std::collections::BTreeMap::new(),
            secret_injections: target.secret_injections.clone(), declared_hosts: target.declared_hosts.clone(), timeout_ms: target.timeout_ms,
            max_output_bytes: target.max_output_bytes, side_effect: sparkbridge_protocol::ActionSideEffect::Pure, network_policy: target.network_policy,
            cache_trust: target.cache_trust, required_capabilities: target.required_capabilities.clone(),
        };
        match create_action_internal(&state, ActionCreateRequest { target_node_id: None, spec }) {
            Ok(action) => created.push(action),
            Err(error) => {
                for action in &created { let _ = state.store.cancel_action(&action.action_id, unix_ms()); }
                return Err(error);
            }
        }
    }
    let now=unix_ms();
    let targets = request.targets.iter().zip(created.iter()).map(|(spec, action)| ValidationTargetRecord {
        name: spec.name.clone(), platform: spec.platform.clone(), architecture: spec.architecture.clone(), node_id: action.assigned_node_id,
        action_id: action.action_id.clone(), status: action.status, cache_hit: action.cache_hit,
    }).collect::<Vec<_>>();
    let status=derive_run_status(&targets);
    let completed_unix_ms=matches!(status,ValidationRunStatus::Succeeded|ValidationRunStatus::Failed|ValidationRunStatus::Cancelled).then_some(now);
    let record=ValidationRunRecord{validation_id:Uuid::new_v4().to_string(),principal_id:request.principal_id,workspace_id:request.workspace_id,candidate_id:request.candidate_id,status,targets,created_unix_ms:now,completed_unix_ms};
    state.store.save_validation_run(&record).map_err(internal_error)?;
    state.store.append_audit("validation.created",Some(record.principal_id.clone()),Some(format!("validation:{}",record.validation_id)),serde_json::json!({"candidate_id":record.candidate_id,"targets":record.targets}),now).map_err(internal_error)?;
    Ok((StatusCode::CREATED,Json(record)))
}

fn hydrate_validation(state:&AppState, mut record:ValidationRunRecord)->Result<ValidationRunRecord,ApiError>{
    let actions=state.store.list_actions().map_err(internal_error)?;
    record.targets=hydrate_targets(&record.targets,&actions);
    record.status=derive_run_status(&record.targets);
    if record.completed_unix_ms.is_none() && matches!(record.status,ValidationRunStatus::Succeeded|ValidationRunStatus::Failed|ValidationRunStatus::Cancelled){ record.completed_unix_ms=Some(unix_ms()); }
    state.store.save_validation_run(&record).map_err(internal_error)?;
    Ok(record)
}

async fn admin_get_validation(State(state):State<AppState>,Path(validation_id):Path<String>)->Result<Json<ValidationRunRecord>,ApiError>{
    let record=state.store.get_validation_run(&validation_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    hydrate_validation(&state,record).map(Json)
}

async fn admin_list_validations(State(state):State<AppState>)->Result<Json<Vec<ValidationRunRecord>>,ApiError>{
    let records=state.store.list_validation_runs().map_err(internal_error)?;
    let mut out=Vec::new(); for record in records { out.push(hydrate_validation(&state,record)?); } Ok(Json(out))
}

async fn admin_list_tasks(State(state): State<AppState>) -> Result<Json<Vec<TaskRecord>>, ApiError> {
    state.store.list_tasks().map(Json).map_err(internal_error)
}

async fn admin_get_task(State(state): State<AppState>, Path(task_id): Path<String>) -> Result<Json<TaskRecord>, ApiError> {
    state.store.get_task(&task_id).map(Json).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))
}

async fn admin_task_events(State(state): State<AppState>, Path(task_id): Path<String>) -> Result<Json<Vec<TaskEvent>>, ApiError> {
    state.store.list_task_events(&task_id).map(Json).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))
}

async fn admin_create_task(State(state): State<AppState>, Json(mut request): Json<TaskCreateRequest>) -> Result<(StatusCode, Json<TaskRecord>), ApiError> {
    request.spec.validate().map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let base = state.store.get_snapshot(&request.spec.base_snapshot_id).map_err(|error| (StatusCode::NOT_FOUND, format!("base snapshot not found: {error}")))?;
    if base.workspace_id != request.spec.workspace_id { return Err((StatusCode::BAD_REQUEST, "task workspace_id does not match base snapshot".into())); }
    let principal = state.store.get_principal(&request.spec.principal_id)
        .map_err(|error| (StatusCode::FORBIDDEN, format!("task principal unavailable: {error}")))?;
    let policy = workspace_policy_for(&state, &request.spec.workspace_id)?;
    // Require Allow, not merely "not Deny": `require_approval_for` yields Ask, and there is
    // no approval workflow for task creation, so treating Ask as permitted would silently
    // ignore a configured approval requirement.
    if policy_authorize_workspace(&principal, &policy, Permission::CandidateCreate) != PolicyDecision::Allow {
        return Err((StatusCode::FORBIDDEN, "principal is not authorized to create candidates in this workspace, or this workspace requires approval for candidate creation".into()));
    }
    request.spec.data_classification = effective_classification(request.spec.data_classification, policy.classification);
    let boundary = parse_inference_boundary(&state.config.inference_data_boundary);
    if !classification_allows_boundary(request.spec.data_classification, boundary) {
        return Err((StatusCode::FORBIDDEN, format!("{:?} task data may not be sent to {:?} inference provider", request.spec.data_classification, boundary)));
    }
    let now = unix_ms();
    let record = TaskRecord::new(Uuid::new_v4().to_string(), request.spec, now);
    let record = state.store.create_task(&record, now).map_err(internal_error)?;
    state.store.append_audit(
        "task.created", Some(record.spec.principal_id.clone()), Some(format!("task:{}", record.task_id)),
        serde_json::json!({"workspace_id":record.spec.workspace_id,"classification":record.spec.data_classification,"base_snapshot_id":record.spec.base_snapshot_id}), now,
    ).map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn admin_run_task(State(state): State<AppState>, Path(task_id): Path<String>, Json(request): Json<TaskRunRequest>) -> Result<Json<TaskRunResponse>, ApiError> {
    let task_lock = {
        let mut locks = state.task_locks.lock().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "task lock registry poisoned".into()))?;
        locks.entry(task_id.clone()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    };
    let _guard = task_lock.lock().await;
    agent_runtime::run_task(&state, &task_id, request.max_steps).await.map(Json)
}

async fn admin_pause_task(State(state): State<AppState>, Path(task_id): Path<String>) -> Result<Json<TaskRecord>, ApiError> {
    let mut task = state.store.get_task(&task_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if task.status.terminal() { return Ok(Json(task)); }
    task.status = TaskStatus::Paused; task.updated_unix_ms = unix_ms();
    state.store.save_task_event(&task, TaskEventKind::TaskPaused, serde_json::json!({"reason":"operator pause"}), task.updated_unix_ms).map_err(internal_error)?;
    Ok(Json(task))
}

async fn admin_resume_task(State(state): State<AppState>, Path(task_id): Path<String>) -> Result<Json<TaskRecord>, ApiError> {
    let mut task = state.store.get_task(&task_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if task.status == TaskStatus::Paused { task.status = TaskStatus::Running; task.last_error = None; task.updated_unix_ms = unix_ms(); state.store.save_task_event(&task, TaskEventKind::TaskResumed, serde_json::json!({}), task.updated_unix_ms).map_err(internal_error)?; }
    Ok(Json(task))
}

async fn admin_cancel_task(State(state): State<AppState>, Path(task_id): Path<String>) -> Result<Json<TaskRecord>, ApiError> {
    let mut task = state.store.get_task(&task_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if let Some(action_id) = &task.pending_action_id { let _ = state.store.cancel_action(action_id, unix_ms()); }
    for action_id in &task.pending_action_ids { let _ = state.store.cancel_action(action_id, unix_ms()); }
    if !task.status.terminal() { task.status = TaskStatus::Cancelled; task.completed_unix_ms = Some(unix_ms()); task.updated_unix_ms = task.completed_unix_ms.unwrap_or_else(unix_ms); state.store.save_task_event(&task, TaskEventKind::TaskCancelled, serde_json::json!({}), task.updated_unix_ms).map_err(internal_error)?; }
    Ok(Json(task))
}


#[derive(Debug, serde::Deserialize)]
struct AuditQuery { limit: Option<usize> }

async fn admin_list_principals(State(state): State<AppState>) -> Result<Json<Vec<PrincipalRecord>>, ApiError> {
    state.store.list_principals().map(Json).map_err(internal_error)
}

async fn admin_upsert_principal(
    State(state): State<AppState>,
    Json(request): Json<PrincipalUpsertRequest>,
) -> Result<(StatusCode, Json<PrincipalRecord>), ApiError> {
    if request.principal.principal_id.trim().is_empty() || request.principal.display_name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "principal_id and display_name are required".into()));
    }
    let actor = state.store.get_principal("local-admin").map_err(internal_error)?;
    if !actor.permissions.contains(&Permission::ManagePolicy) {
        return Err((StatusCode::FORBIDDEN, "local administrator lacks manage_policy permission".into()));
    }
    let record = state.store.upsert_principal(&request.principal).map_err(internal_error)?;
    state.store.append_audit(
        "principal.upsert", Some("local-admin".into()), Some(format!("principal:{}", record.principal_id)),
        serde_json::json!({"kind":record.kind,"enabled":record.enabled,"permissions":record.permissions}), unix_ms(),
    ).map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn admin_list_workspace_policies(State(state): State<AppState>) -> Result<Json<Vec<WorkspacePolicyRecord>>, ApiError> {
    state.store.list_workspace_policies().map(Json).map_err(internal_error)
}

async fn admin_upsert_workspace_policy(
    State(state): State<AppState>,
    Json(request): Json<WorkspacePolicyUpsertRequest>,
) -> Result<(StatusCode, Json<WorkspacePolicyRecord>), ApiError> {
    if request.policy.workspace_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "workspace_id is required".into()));
    }
    let actor = state.store.get_principal("local-admin").map_err(internal_error)?;
    if !actor.permissions.contains(&Permission::ManagePolicy) {
        return Err((StatusCode::FORBIDDEN, "local administrator lacks manage_policy permission".into()));
    }
    let mut policy = request.policy;
    policy.updated_unix_ms = unix_ms();
    let record = state.store.upsert_workspace_policy(&policy).map_err(internal_error)?;
    state.store.append_audit(
        "workspace_policy.upsert", Some("local-admin".into()), Some(format!("workspace:{}", record.workspace_id)),
        serde_json::json!({"classification":record.classification,"allowed_principals":record.allowed_principals,"allowed_secret_refs":record.allowed_secret_refs,"require_approval_for":record.require_approval_for}), unix_ms(),
    ).map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn admin_list_approvals(State(state): State<AppState>) -> Result<Json<Vec<ApprovalRecord>>, ApiError> {
    state.store.list_approvals(unix_ms()).map(Json).map_err(internal_error)
}

async fn admin_approve(
    State(state): State<AppState>, Path(approval_id): Path<String>, Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<ApprovalRecord>, ApiError> {
    decide_approval(&state, &approval_id, request, true).map(Json)
}

async fn admin_deny(
    State(state): State<AppState>, Path(approval_id): Path<String>, Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<ApprovalRecord>, ApiError> {
    decide_approval(&state, &approval_id, request, false).map(Json)
}

fn decide_approval(state: &AppState, approval_id: &str, request: ApprovalDecisionRequest, approve: bool) -> Result<ApprovalRecord, ApiError> {
    let principal = state.store.get_principal(&request.principal_id)
        .map_err(|error| (StatusCode::FORBIDDEN, format!("approval principal unavailable: {error}")))?;
    if !principal.enabled || !principal.permissions.contains(&Permission::Approve) {
        return Err((StatusCode::FORBIDDEN, "principal is not authorized to approve operations".into()));
    }
    let record = state.store.decide_approval(approval_id, approve, principal.principal_id.clone(), unix_ms())
        .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
    state.store.append_audit(
        if approve { "approval.approved" } else { "approval.denied" },
        Some(principal.principal_id), Some(format!("approval:{}", record.approval_id)),
        serde_json::json!({"workspace_id":record.workspace_id,"operation":record.operation,"action_id":record.action_id,"reason":request.reason}), unix_ms(),
    ).map_err(internal_error)?;
    Ok(record)
}

async fn admin_list_audit(
    State(state): State<AppState>, Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    state.store.list_audit(query.limit.unwrap_or(500)).map(Json).map_err(internal_error)
}

async fn admin_verify_audit(State(state): State<AppState>) -> Result<Json<AuditVerifyResponse>, ApiError> {
    state.store.verify_audit().map(Json).map_err(internal_error)
}

fn parse_classification(value: &str) -> DataClassification {
    match value {
        "public" => DataClassification::Public,
        "confidential" => DataClassification::Confidential,
        "restricted" => DataClassification::Restricted,
        _ => DataClassification::Private,
    }
}

fn parse_inference_boundary(value: &str) -> InferenceDataBoundary {
    match value {
        "private_remote" => InferenceDataBoundary::PrivateRemote,
        "public_cloud" => InferenceDataBoundary::PublicCloud,
        _ => InferenceDataBoundary::LocalOnly,
    }
}

pub(crate) fn workspace_policy_for(state: &AppState, workspace_id: &str) -> Result<WorkspacePolicyRecord, ApiError> {
    if let Some(policy) = state.store.get_workspace_policy(workspace_id).map_err(internal_error)? {
        return Ok(policy);
    }
    Ok(WorkspacePolicyRecord {
        workspace_id: workspace_id.to_owned(),
        classification: state.config.workspace_classifications.get(workspace_id).map(|value| parse_classification(value)).unwrap_or(DataClassification::Private),
        allowed_principals: Vec::new(),
        allowed_secret_refs: Vec::new(),
        require_approval_for: Vec::new(),
        required_validation_platforms: Vec::new(),
        updated_unix_ms: 0,
    })
}

async fn admin_revoke_node(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    Json(request): Json<RevokeNodeRequest>,
) -> Result<Json<NodeRecord>, ApiError> {
    let reason = request.reason.clone();
    let record = state.store.revoke_node(id, request.reason, unix_ms())
        .map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    state.store.append_audit(
        "node.revoked", Some("local-admin".into()), Some(format!("node:{id}")), serde_json::json!({"reason":reason}), unix_ms(),
    ).map_err(internal_error)?;
    Ok(Json(record))
}

async fn enroll_node(
    State(state): State<AppState>,
    Json(request): Json<NodeEnrollmentRequest>,
) -> Result<(StatusCode, Json<NodeEnrollmentResponse>), ApiError> {
    if !request.protocol.compatible_with(ProtocolVersion::CURRENT) {
        return Err((StatusCode::UPGRADE_REQUIRED, "incompatible protocol major".into()));
    }
    if request.name.is_empty() || request.name.len() > 128 || request.architecture.len() > 64 {
        return Err((StatusCode::BAD_REQUEST, "invalid node metadata".into()));
    }
    if request.requested_features.len() > 64 || request.csr_pem.len() > 16 * 1024 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "enrollment request is too large".into()));
    }
    state
        .store
        .validate_enrollment_token(&request.token, unix_ms())
        .map_err(|error| (StatusCode::UNAUTHORIZED, error.to_string()))?;

    let node_id = NodeId::new();
    let issued = state
        .ca
        .sign_node_csr(&request.csr_pem, node_id, &request.name)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let accepted_features = negotiate_features(
        &request.requested_features,
        &supported_fabric_features(),
    );
    let negotiated_protocol = ProtocolVersion {
        major: ProtocolVersion::CURRENT.major,
        minor: request.protocol.minor.min(ProtocolVersion::CURRENT.minor),
    };
    let node_secret = random_secret();
    let record = NodeRecord {
        id: node_id,
        name: request.name,
        platform: request.platform,
        architecture: request.architecture,
        status: NodeStatus::Online,
        last_seen_unix_ms: unix_ms(),
        protocol: negotiated_protocol,
        features: accepted_features.clone(),
        certificate_fingerprint_sha256: issued.fingerprint_sha256,
        certificate_not_after_unix_ms: issued.not_after_unix_ms,
        revoked_unix_ms: None,
    };

    state
        .store
        .enroll_node(&request.token, &record, &node_secret, unix_ms())
        .map_err(|error| (StatusCode::UNAUTHORIZED, error.to_string()))?;

    info!(node_id = %node_id, node_name = %record.name, "executor enrolled");
    Ok((
        StatusCode::CREATED,
        Json(NodeEnrollmentResponse {
            node_id,
            node_secret,
            certificate_pem: issued.certificate_pem,
            ca_certificate_pem: state.ca.certificate_pem().to_owned(),
            fabric_url: state.config.public_fabric_url.clone(),
            protocol: negotiated_protocol,
            accepted_features,
        }),
    ))
}

async fn connect_node(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<NodeConnectRequest>,
) -> Result<Json<NodeConnectResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    if !request.protocol.compatible_with(ProtocolVersion::CURRENT) {
        return Err((StatusCode::UPGRADE_REQUIRED, "incompatible protocol major".into()));
    }
    let accepted_features = negotiate_features(
        &request.requested_features,
        &supported_fabric_features(),
    );
    let protocol = ProtocolVersion {
        major: ProtocolVersion::CURRENT.major,
        minor: request.protocol.minor.min(ProtocolVersion::CURRENT.minor),
    };
    state
        .store
        .update_connection(id, protocol, accepted_features.clone(), unix_ms())
        .map_err(internal_error)?;
    Ok(Json(NodeConnectResponse {
        protocol,
        accepted_features,
        certificate_rotation_supported: true,
    }))
}

async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<NodeRecord>, ApiError> {
    authenticate(&state, id, &headers)?;
    if !request.protocol.compatible_with(ProtocolVersion::CURRENT) {
        return Err((StatusCode::UPGRADE_REQUIRED, "incompatible protocol major".into()));
    }
    state.store.heartbeat(id, unix_ms()).map(Json).map_err(internal_error)
}

async fn rotate_certificate(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<CertificateRotationRequest>,
) -> Result<Json<CertificateRotationResponse>, ApiError> {
    let presented_secret = bearer_token(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer credential".into()))?;
    let record = state
        .store
        .authenticate_node(id, presented_secret)
        .map_err(|error| (StatusCode::UNAUTHORIZED, error.to_string()))?;
    if !request.protocol.compatible_with(ProtocolVersion::CURRENT) {
        return Err((StatusCode::UPGRADE_REQUIRED, "incompatible protocol major".into()));
    }
    let issued = state
        .ca
        .sign_node_csr(&request.csr_pem, id, &record.name)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let new_secret = random_secret();
    state
        .store
        .rotate_credentials(
            id,
            issued.fingerprint_sha256,
            issued.not_after_unix_ms,
            &new_secret,
            presented_secret,
            unix_ms(),
        )
        .map_err(internal_error)?;
    Ok(Json(CertificateRotationResponse {
        certificate_pem: issued.certificate_pem,
        node_secret: new_secret,
    }))
}


async fn cas_missing(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<MissingObjectsRequest>,
) -> Result<Json<MissingObjectsResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    if request.digests.len() > 50_000 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "too many digests".into()));
    }
    let mut missing = Vec::new();
    for raw in request.digests {
        let digest = Digest(raw.clone());
        digest.hex().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        if !state.cas.contains(&digest) { missing.push(raw); }
    }
    Ok(Json(MissingObjectsResponse { missing }))
}

async fn cas_put(
    State(state): State<AppState>,
    Path((id, raw_digest)): Path<(NodeId, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<CasObjectInfo>), ApiError> {
    authenticate(&state, id, &headers)?;
    let encoded_zstd = headers.get(axum::http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("zstd"));
    let decoded = if encoded_zstd {
        zstd::stream::decode_all(&body[..]).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid zstd CAS payload: {e}")))?
    } else { body.to_vec() };
    if decoded.len() > state.config.cas_max_object_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "CAS object exceeds configured limit after decoding".into()));
    }
    let expected = Digest(raw_digest);
    expected.hex().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let info = state.cas.put_bytes(Some(&expected), &decoded).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(CasObjectInfo { digest: info.digest.0, size_bytes: info.size_bytes, present: true })))
}

async fn cas_get(
    State(state): State<AppState>,
    Path((id, raw_digest)): Path<(NodeId, String)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Bytes), ApiError> {
    authenticate(&state, id, &headers)?;
    let digest = Digest(raw_digest);
    digest.hex().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let bytes = state.cas.get_bytes(&digest, state.config.cas_max_object_bytes as u64)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(axum::http::header::CONTENT_TYPE, "application/octet-stream".parse().expect("static header"));
    Ok((response_headers, Bytes::from(bytes)))
}

async fn register_snapshot(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<SnapshotRegistrationRequest>,
) -> Result<(StatusCode, Json<SnapshotRecord>), ApiError> {
    authenticate(&state, id, &headers)?;
    if request.node_id != id { return Err((StatusCode::BAD_REQUEST, "node_id does not match authenticated node".into())); }
    let manifest = Digest(request.manifest_digest.clone());
    manifest.hex().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if !state.cas.contains(&manifest) { return Err((StatusCode::CONFLICT, "snapshot manifest is not present in CAS".into())); }
    let manifest_bytes = state.cas.get_bytes(&manifest, state.config.cas_max_object_bytes as u64)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    let snapshot: sparkbridge_snapshot::WorkspaceSnapshot = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid snapshot manifest: {e}")))?;
    if snapshot.entries.len() as u64 != request.entry_count || snapshot.root_name != request.root_name {
        return Err((StatusCode::BAD_REQUEST, "snapshot registration metadata does not match manifest".into()));
    }
    for entry in &snapshot.entries {
        if let Some(digest) = &entry.digest {
            if !state.cas.contains(digest) {
                return Err((StatusCode::CONFLICT, format!("snapshot references missing CAS object {}", digest.0)));
            }
        }
    }
    state.store.register_snapshot(request).map(|record| (StatusCode::CREATED, Json(record))).map_err(internal_error)
}

async fn list_snapshots(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
) -> Result<Json<Vec<SnapshotRecord>>, ApiError> {
    authenticate(&state, id, &headers)?;
    state.store.list_snapshots_for_node(id).map(Json).map_err(internal_error)
}

async fn register_native_intelligence(
    State(state): State<AppState>,
    Path((id, snapshot_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
    Json(report): Json<NativeIntelligenceReport>,
) -> Result<(StatusCode, Json<NativeIntelligenceRecord>), ApiError> {
    authenticate(&state,id,&headers)?;
    repository::register_native_report(&state,id,&snapshot_id,report).map(|record|(StatusCode::CREATED,Json(record)))
}


async fn get_candidate_for_node(
    State(state): State<AppState>,
    Path((id, candidate_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
) -> Result<Json<CandidateRecord>, ApiError> {
    authenticate(&state, id, &headers)?;
    let record = state.store.get_candidate(&candidate_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if record.node_id != id {
        let reports=state.store.list_capability_reports().map_err(internal_error)?;
        let owns_workspace=reports.iter().find(|report|report.node_id==id).is_some_and(|report|report.domains.iter().any(|domain|domain.workspace_ids.iter().any(|workspace|workspace==&record.workspace_id)));
        if !owns_workspace { return Err((StatusCode::FORBIDDEN, "candidate validation requires this executor to advertise the same logical workspace".into())); }
    }
    Ok(Json(record))
}


async fn authorize_promotion(
    State(state): State<AppState>,
    Path((id, candidate_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
    Json(request): Json<PromotionAuthorizationRequest>,
) -> Result<Json<PromotionAuthorizationResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    let candidate = state.store.get_candidate(&candidate_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if candidate.node_id != id || candidate.workspace_id != request.workspace_id {
        return Err((StatusCode::FORBIDDEN, "candidate does not belong to this node/workspace".into()));
    }
    let principal = state.store.get_principal(&request.principal_id)
        .map_err(|error| (StatusCode::FORBIDDEN, format!("promotion principal unavailable: {error}")))?;
    let policy = workspace_policy_for(&state, &request.workspace_id)?;
    if !request.dry_run && !policy.required_validation_platforms.is_empty() {
        let runs=state.store.list_validation_runs().map_err(internal_error)?;
        let mut satisfied=false;
        for run in runs.into_iter().filter(|run|run.candidate_id==candidate_id) {
            let hydrated=hydrate_validation(&state,run)?;
            if hydrated.status!=ValidationRunStatus::Succeeded { continue; }
            let platforms:std::collections::HashSet<String>=hydrated.targets.iter().map(|target|target.platform.to_lowercase()).collect();
            if policy.required_validation_platforms.iter().all(|required|platforms.contains(&required.to_lowercase())) { satisfied=true; break; }
        }
        if !satisfied {
            return Err((StatusCode::CONFLICT,format!("promotion requires successful validation on: {}",policy.required_validation_platforms.join(", "))));
        }
    }
    let permission = if request.dry_run { Permission::Read } else { Permission::Promote };
    let decision = policy_authorize_workspace(&principal, &policy, permission);
    let reason = if request.dry_run { "promotion dry-run authorization" } else { "live workspace promotion authorization" };
    if decision == PolicyDecision::Deny {
        state.store.append_audit(
            "promotion.denied", Some(request.principal_id), Some(format!("candidate:{candidate_id}")),
            serde_json::json!({"workspace_id":request.workspace_id,"dry_run":request.dry_run}), unix_ms(),
        ).map_err(internal_error)?;
        return Err((StatusCode::FORBIDDEN, "principal is not authorized to promote this workspace".into()));
    }

    // Live workspace mutation always requires an explicit approval created and
    // decided on the loopback administrative surface.  This is intentionally
    // stronger than the workspace ACL itself: an authenticated executor cannot
    // self-assert a privileged principal and use that assertion to bypass human
    // approval of a live mutation.  Dry-runs remain non-mutating and may proceed
    // directly when Read is allowed.
    if !request.dry_run {
        let expected_operation = format!("promotion:{candidate_id}");
        let now_ms = unix_ms();
        if let Some(approval_id) = &request.approval_id {
            let approval = state.store.get_approval(approval_id)
                .map_err(|error| (StatusCode::FORBIDDEN, format!("approval unavailable: {error}")))?;
            // An approval is a time-boxed human decision, not a standing grant. Without the
            // expiry check one loopback approval would authorize replaying this promotion
            // indefinitely, long after the operator's intent lapsed or the granting
            // principal was revoked.
            let expired = approval.expires_unix_ms <= now_ms;
            if expired {
                state.store.append_audit(
                    "promotion.approval_expired", Some(request.principal_id.clone()), Some(format!("candidate:{candidate_id}")),
                    serde_json::json!({"approval_id":approval_id,"workspace_id":request.workspace_id,"expires_unix_ms":approval.expires_unix_ms}), now_ms,
                ).map_err(internal_error)?;
            }
            if expired
                || approval.status != sparkbridge_protocol::ApprovalStatus::Approved
                || approval.workspace_id != request.workspace_id
                || approval.principal_id != request.principal_id
                || approval.operation != expected_operation
            {
                return Err((StatusCode::FORBIDDEN, if expired { "approval has expired; request a new one".into() } else { "approval does not authorize this promotion".into() }));
            }
        } else {
            let approval = state.store.create_approval(
                request.principal_id.clone(),
                request.workspace_id.clone(),
                expected_operation,
                None,
                reason.into(),
                now_ms,
                state.config.approval_ttl_seconds,
            ).map_err(internal_error)?;
            state.store.append_audit(
                "promotion.approval_requested",
                Some(request.principal_id),
                Some(format!("candidate:{candidate_id}")),
                serde_json::json!({
                    "approval_id": approval.approval_id,
                    "workspace_id": request.workspace_id,
                    "node_id": id.to_string(),
                }),
                now_ms,
            ).map_err(internal_error)?;
            return Ok(Json(PromotionAuthorizationResponse {
                decision: PolicyDecision::Ask,
                approval_id: Some(approval.approval_id),
                reason: "live promotion requires explicit loopback approval".into(),
            }));
        }
    }

    state.store.append_audit(
        "promotion.authorized", Some(request.principal_id), Some(format!("candidate:{candidate_id}")),
        serde_json::json!({"workspace_id":request.workspace_id,"dry_run":request.dry_run,"approval_id":request.approval_id}), unix_ms(),
    ).map_err(internal_error)?;
    Ok(Json(PromotionAuthorizationResponse { decision: PolicyDecision::Allow, approval_id: request.approval_id, reason: reason.into() }))
}

async fn register_promotion(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<PromotionReportRequest>,
) -> Result<(StatusCode, Json<PromotionRecord>), ApiError> {
    authenticate(&state, id, &headers)?;
    if request.node_id != id { return Err((StatusCode::BAD_REQUEST, "node_id does not match authenticated node".into())); }
    let candidate = state.store.get_candidate(&request.candidate_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if candidate.node_id != id || candidate.workspace_id != request.workspace_id {
        return Err((StatusCode::FORBIDDEN, "promotion does not match candidate node/workspace".into()));
    }
    if candidate.base_manifest_digest != request.base_manifest_digest {
        return Err((StatusCode::BAD_REQUEST, "promotion base manifest does not match candidate".into()));
    }
    if let Some(result) = &request.result_manifest_digest {
        let digest = Digest(result.clone());
        digest.hex().map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
        if !state.cas.contains(&digest) { return Err((StatusCode::CONFLICT, "reported result manifest is not present in server CAS".into())); }
    }
    let record = state.store.register_promotion(request).map_err(internal_error)?;
    state.store.append_audit(
        "promotion.reported", None, Some(format!("promotion:{}", record.promotion_id)),
        serde_json::json!({"candidate_id":record.candidate_id,"workspace_id":record.workspace_id,"outcome":record.outcome,"node_id":record.node_id}), unix_ms(),
    ).map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(record)))
}


async fn report_capabilities(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(report): Json<CapabilityReport>,
) -> Result<StatusCode, ApiError> {
    authenticate(&state, id, &headers)?;
    if report.node_id != id { return Err((StatusCode::BAD_REQUEST, "capability report node_id does not match authenticated node".into())); }
    state.store.upsert_capabilities(&report).map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn lease_action(
    State(state): State<AppState>,
    Path(id): Path<NodeId>,
    headers: HeaderMap,
    Json(request): Json<ActionLeaseRequest>,
) -> Result<Json<ActionLeaseResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    if !ProtocolVersion::CURRENT.compatible_with(request.protocol) {
        return Err((StatusCode::UPGRADE_REQUIRED, "protocol major mismatch".into()));
    }
    let lease_ms = state.config.action_lease_seconds.saturating_mul(1000);
    let lease = state.store.lease_next_action(id, unix_ms(), lease_ms).map_err(internal_error)?;
    Ok(Json(ActionLeaseResponse { lease }))
}

async fn renew_action_lease(
    State(state): State<AppState>,
    Path((id, action_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
    Json(request): Json<ActionLeaseRenewRequest>,
) -> Result<Json<ActionLeaseRenewResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    let action = state.store.get_action(&action_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if action.assigned_node_id != id { return Err((StatusCode::FORBIDDEN, "action is assigned to another node".into())); }
    let (lease_expires_unix_ms, cancel_requested) = state.store.renew_action_lease(
        &action_id, &request.lease_id, unix_ms(), state.config.action_lease_seconds.saturating_mul(1000)
    ).map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
    Ok(Json(ActionLeaseRenewResponse { lease_expires_unix_ms, cancel_requested }))
}

async fn start_action(
    State(state): State<AppState>,
    Path((id, action_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
    Json(request): Json<ActionStartRequest>,
) -> Result<Json<ActionRecord>, ApiError> {
    authenticate(&state, id, &headers)?;
    let action = state.store.get_action(&action_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if action.assigned_node_id != id { return Err((StatusCode::FORBIDDEN, "action is assigned to another node".into())); }
    let record = state.store.start_action(&action_id, &request.lease_id, request.started_unix_ms)
        .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
    state.store.append_audit(
        "action.started", Some(record.spec.principal_id.clone()), Some(format!("action:{}", record.action_id)),
        serde_json::json!({"workspace_id":record.spec.workspace_id,"node_id":record.assigned_node_id,"secret_refs":record.spec.secret_injections.iter().map(|s| s.reference.clone()).collect::<Vec<_>>()}), request.started_unix_ms,
    ).map_err(internal_error)?;
    Ok(Json(record))
}

async fn complete_action(
    State(state): State<AppState>,
    Path((id, action_id)): Path<(NodeId, String)>,
    headers: HeaderMap,
    Json(request): Json<ActionCompletionRequest>,
) -> Result<Json<ActionCompletionResponse>, ApiError> {
    authenticate(&state, id, &headers)?;
    let action = state.store.get_action(&action_id).map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))?;
    if action.assigned_node_id != id { return Err((StatusCode::FORBIDDEN, "action is assigned to another node".into())); }
    let record = state.store.complete_action(&action_id, request).map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
    if record.status == ActionStatus::Succeeded && record.spec.cache_trust != CacheTrust::Disabled {
        if let (Some(cache_key), Some(toolchain_digest), Some(result)) = (record.cache_key.clone(), record.toolchain_digest.clone(), record.result.clone()) {
            let result_bytes=encode_cached_result(&cache_key,&record.action_id,&toolchain_digest,&result).map_err(internal_error)?;
            let result_object=state.cas.put_bytes(None,&result_bytes).map_err(internal_error)?;
            let cache_record=ActionCacheRecord{cache_key,source_action_id:record.action_id.clone(),workspace_id:record.spec.workspace_id.clone(),candidate_id:record.spec.candidate_id.clone(),toolchain_digest,trust:record.spec.cache_trust,result_digest:result_object.digest.0,result,created_unix_ms:record.completed_unix_ms.unwrap_or_else(unix_ms),last_used_unix_ms:record.completed_unix_ms.unwrap_or_else(unix_ms),hit_count:0};
            let stored=state.store.put_action_cache(cache_record).map_err(internal_error)?;
            state.store.prune_action_cache(state.config.action_cache_max_entries).map_err(internal_error)?;
            state.store.append_audit("action.cache_store",Some(record.spec.principal_id.clone()),Some(format!("action:{}",record.action_id)),serde_json::json!({"cache_key":stored.cache_key,"trust":stored.trust,"result_digest":stored.result_digest,"toolchain_digest":stored.toolchain_digest}),record.completed_unix_ms.unwrap_or_else(unix_ms)).map_err(internal_error)?;
        }
    }
    state.store.append_audit(
        "action.completed", Some(record.spec.principal_id.clone()), Some(format!("action:{}", record.action_id)),
        serde_json::json!({"status":record.status,"exit_code":record.result.as_ref().and_then(|r| r.exit_code),"duration_ms":record.result.as_ref().map(|r| r.duration_ms)}), record.completed_unix_ms.unwrap_or_else(unix_ms),
    ).map_err(internal_error)?;
    Ok(Json(ActionCompletionResponse { accepted: true }))
}

async fn inference_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<sparkbridge_protocol::InferenceProviderHealth>, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.health().await.map(Json)
}

async fn inference_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.models().await.map(Json)
}

async fn inference_running(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.running().await.map(Json)
}

async fn inference_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<sparkbridge_protocol::InferenceMetricsSnapshot>, ApiError> {
    state.inference.authorize(&headers)?;
    Ok(Json(state.inference.metrics()))
}

async fn inference_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.stream_generate(body).await
}

async fn inference_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.stream_chat(body).await
}

async fn inference_residency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResidencyRequest>,
) -> Result<Json<sparkbridge_protocol::ResidencyResponse>, ApiError> {
    state.inference.authorize(&headers)?;
    state.inference.residency(request).await.map(Json)
}

async fn inference_cancel(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<sparkbridge_protocol::CancellationResponse>, ApiError> {
    state.inference.authorize(&headers)?;
    Ok(Json(state.inference.cancel(&request_id)))
}

fn authenticate(state: &AppState, id: NodeId, headers: &HeaderMap) -> Result<NodeRecord, ApiError> {
    let secret = bearer_token(headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer credential".into()))?;
    state
        .store
        .authenticate_node(id, secret)
        .map_err(|error| (StatusCode::UNAUTHORIZED, error.to_string()))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn supported_fabric_features() -> Vec<FabricFeature> {
    FabricFeature::ITERATION_2_SERVER.into_iter().chain(FabricFeature::ITERATION_3_GATEWAY).chain(FabricFeature::ITERATION_4_WORKSPACES).chain(FabricFeature::ITERATION_5_CANDIDATES).chain(FabricFeature::ITERATION_6_ACTIONS).chain(FabricFeature::ITERATION_7_AGENT).chain(FabricFeature::ITERATION_8_INTELLIGENCE).chain(FabricFeature::ITERATION_9_POLICY).chain(FabricFeature::ITERATION_10_CACHE_VALIDATION).chain(FabricFeature::ITERATION_11_INTEGRATIONS).chain(FabricFeature::ITERATION_12_CERTIFICATION).collect()
}

fn random_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn internal_error(error: anyhow::Error) -> ApiError {
    warn!(%error, "request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into())
}

fn build_mtls_config(config: &ServerConfig) -> Result<RustlsConfig> {
    let mut roots = RootCertStore::empty();
    let mut ca_reader = BufReader::new(File::open(&config.ca_cert_path)?);
    for certificate in rustls_pemfile::certs(&mut ca_reader) {
        roots.add(certificate.context("reading CA certificate")?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building client-certificate verifier")?;

    let mut cert_reader = BufReader::new(File::open(&config.server_cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading server certificate chain")?;
    let mut key_reader = BufReader::new(File::open(&config.server_key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("reading server private key")?
        .context("server private key file contained no private key")?;

    let mut rustls = RustlsServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .context("building mTLS server configuration")?;
    rustls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(rustls)))
}
