use serde::{Deserialize, Serialize};
use sparkbridge_core::{FabricFeature, NodeId, Platform};
use std::collections::HashSet;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };

    pub fn compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }

    pub fn negotiated_minor(self, other: Self) -> Option<u16> {
        self.compatible_with(other).then_some(self.minor.min(other.minor))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentCreateRequest {
    pub ttl_seconds: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenResponse {
    pub token: String,
    pub expires_unix_ms: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEnrollmentRequest {
    pub token: String,
    pub name: String,
    pub platform: Platform,
    pub architecture: String,
    pub requested_features: Vec<FabricFeature>,
    pub protocol: ProtocolVersion,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEnrollmentResponse {
    pub node_id: NodeId,
    pub node_secret: String,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub fabric_url: String,
    pub protocol: ProtocolVersion,
    pub accepted_features: Vec<FabricFeature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnectRequest {
    pub protocol: ProtocolVersion,
    pub requested_features: Vec<FabricFeature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnectResponse {
    pub protocol: ProtocolVersion,
    pub accepted_features: Vec<FabricFeature>,
    pub certificate_rotation_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRotationRequest {
    pub protocol: ProtocolVersion,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRotationResponse {
    pub certificate_pem: String,
    pub node_secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Stale,
    Offline,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: NodeId,
    pub name: String,
    pub platform: Platform,
    pub architecture: String,
    pub status: NodeStatus,
    pub last_seen_unix_ms: u64,
    pub protocol: ProtocolVersion,
    pub features: Vec<FabricFeature>,
    pub certificate_fingerprint_sha256: String,
    pub certificate_not_after_unix_ms: u64,
    pub revoked_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeNodeRequest {
    pub reason: Option<String>,
}

pub fn negotiate_features(
    requested: &[FabricFeature],
    supported: &[FabricFeature],
) -> Vec<FabricFeature> {
    let supported: HashSet<_> = supported.iter().copied().collect();
    requested
        .iter()
        .copied()
        .filter(|feature| supported.contains(feature))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_major_controls_compatibility() {
        assert!(ProtocolVersion::CURRENT.compatible_with(ProtocolVersion { major: 1, minor: 99 }));
        assert!(!ProtocolVersion::CURRENT.compatible_with(ProtocolVersion { major: 2, minor: 0 }));
    }

    #[test]
    fn protocol_minor_negotiates_down_without_major_break() {
        assert_eq!(ProtocolVersion::CURRENT.negotiated_minor(ProtocolVersion { major: 1, minor: 9 }), Some(9));
        assert_eq!(ProtocolVersion::CURRENT.negotiated_minor(ProtocolVersion { major: 1, minor: 10 }), Some(10));
        assert_eq!(ProtocolVersion::CURRENT.negotiated_minor(ProtocolVersion { major: 1, minor: 99 }), Some(10));
        assert_eq!(ProtocolVersion::CURRENT.negotiated_minor(ProtocolVersion { major: 2, minor: 0 }), None);
    }

    #[test]
    fn feature_negotiation_is_intersection() {
        let accepted = negotiate_features(
            &[FabricFeature::Heartbeat, FabricFeature::CertificateRotation],
            &[FabricFeature::Heartbeat],
        );
        assert_eq!(accepted, vec![FabricFeature::Heartbeat]);
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceProviderHealth {
    pub status: String,
    pub provider: String,
    pub provider_version: Option<String>,
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceMetricsSnapshot {
    pub active_requests: u64,
    pub queued_requests: u64,
    pub total_requests: u64,
    pub completed_requests: u64,
    pub cancelled_requests: u64,
    pub failed_requests: u64,
    pub last_request: Option<InferenceTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceTrace {
    pub request_id: String,
    pub kind: String,
    pub model: String,
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub wall_duration_ms: u64,
    pub queue_duration_ms: u64,
    pub provider_connect_duration_ms: u64,
    pub first_chunk_ms: Option<u64>,
    pub total_duration_ns: Option<u64>,
    pub load_duration_ns: Option<u64>,
    pub prompt_eval_count: Option<u64>,
    pub prompt_eval_cached_count: Option<u64>,
    pub prompt_eval_duration_ns: Option<u64>,
    pub eval_count: Option<u64>,
    pub eval_duration_ns: Option<u64>,
    pub prompt_tokens_per_second: Option<f64>,
    pub generation_tokens_per_second: Option<f64>,
    pub cancelled: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidencyAction {
    Load,
    Unload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidencyRequest {
    pub model: String,
    pub action: ResidencyAction,
    pub keep_alive: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidencyResponse {
    pub model: String,
    pub action: ResidencyAction,
    pub provider_response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationResponse {
    pub request_id: String,
    pub cancelled: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasObjectInfo {
    pub digest: String,
    pub size_bytes: u64,
    pub present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingObjectsRequest {
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingObjectsResponse {
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRegistrationRequest {
    pub workspace_id: String,
    pub node_id: NodeId,
    pub manifest_digest: String,
    pub root_name: String,
    pub entry_count: u64,
    pub source_generation: u64,
    pub git_head: Option<String>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub snapshot_id: String,
    pub workspace_id: String,
    pub node_id: NodeId,
    pub manifest_digest: String,
    pub root_name: String,
    pub entry_count: u64,
    pub source_generation: u64,
    pub git_head: Option<String>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCreateResponse {
    pub snapshot: SnapshotRecord,
    pub uploaded_objects: u64,
    pub reused_objects: u64,
    pub uploaded_bytes: u64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CandidateCreateOperationInput {
    CreateFile { path: String, content_base64: String, executable: bool },
    ModifyFile { path: String, content_base64: String, executable: bool },
    DeleteFile { path: String },
    RenameFile { from_path: String, to_path: String, executable: bool },
    SetExecutable { path: String, executable: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateCreateRequest { pub base_snapshot_id: String, pub description: Option<String>, pub operations: Vec<CandidateCreateOperationInput> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateRecord {
    pub candidate_id: String,
    pub base_snapshot_id: String,
    pub base_manifest_digest: String,
    pub manifest_digest: String,
    pub node_id: NodeId,
    pub workspace_id: String,
    pub operation_count: u64,
    pub description: Option<String>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionOutcome { Applied, Conflict, DryRun, Failed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionReportRequest {
    pub candidate_id: String,
    pub workspace_id: String,
    pub node_id: NodeId,
    pub outcome: PromotionOutcome,
    pub base_manifest_digest: String,
    pub observed_before_manifest_digest: String,
    pub result_manifest_digest: Option<String>,
    pub generation_before: u64,
    pub generation_after: u64,
    pub merged_files: u64,
    pub conflicts: Vec<String>,
    pub created_unix_ms: u64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionAuthorizationRequest {
    #[serde(default = "default_local_admin_principal")]
    pub principal_id: String,
    pub workspace_id: String,
    pub dry_run: bool,
    #[serde(default)]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionAuthorizationResponse {
    pub decision: PolicyDecision,
    pub approval_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRecord {
    pub promotion_id: String,
    pub candidate_id: String,
    pub workspace_id: String,
    pub node_id: NodeId,
    pub outcome: PromotionOutcome,
    pub base_manifest_digest: String,
    pub observed_before_manifest_digest: String,
    pub result_manifest_digest: Option<String>,
    pub generation_before: u64,
    pub generation_after: u64,
    pub merged_files: u64,
    pub conflicts: Vec<String>,
    pub created_unix_ms: u64,
}



// ---- Iteration 9: Policy + Secrets + Data Boundaries ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DataClassification {
    Public,
    #[default]
    Private,
    Confidential,
    Restricted,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum InferenceDataBoundary {
    #[default]
    LocalOnly,
    PrivateRemote,
    PublicCloud,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Snapshot,
    CandidateCreate,
    Execute,
    Promote,
    Approve,
    UseSecret,
    ManagePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Agent,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalRecord {
    pub principal_id: String,
    pub display_name: String,
    pub kind: PrincipalKind,
    pub enabled: bool,
    pub permissions: Vec<Permission>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePolicyRecord {
    pub workspace_id: String,
    #[serde(default)]
    pub classification: DataClassification,
    #[serde(default)]
    pub allowed_principals: Vec<String>,
    #[serde(default)]
    pub allowed_secret_refs: Vec<String>,
    #[serde(default)]
    pub require_approval_for: Vec<Permission>,
    #[serde(default)]
    pub required_validation_platforms: Vec<String>,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PolicyDecision {
    #[default]
    Allow,
    Ask,
    Deny,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub operation: String,
    pub action_id: Option<String>,
    pub reason: String,
    pub status: ApprovalStatus,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub decided_unix_ms: Option<u64>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    #[serde(default = "default_local_admin_principal")]
    pub principal_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalUpsertRequest {
    pub principal: PrincipalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePolicyUpsertRequest {
    pub policy: WorkspacePolicyRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjection {
    pub reference: String,
    pub env_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub event_id: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub kind: String,
    pub principal_id: Option<String>,
    pub resource: Option<String>,
    pub created_unix_ms: u64,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerifyResponse {
    pub valid: bool,
    pub records_checked: u64,
    pub first_invalid_sequence: Option<u64>,
}

fn default_local_admin_principal() -> String { "local-admin".into() }

// ---- Iteration 6: Remote Actions + Execution Domains ----

use sparkbridge_diagnostics::Diagnostic;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDomainKind {
    Host,
    Wsl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum CacheTrust {
    Strong,
    BestEffort,
    #[default]
    Disabled,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolchainFingerprint {
    pub platform: String,
    pub architecture: String,
    pub domain: String,
    pub executor_version: String,
    #[serde(default)]
    pub command_versions: BTreeMap<String, String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDomainDescriptor {
    pub id: String,
    pub kind: ExecutionDomainKind,
    pub display_name: String,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<String>,
    pub workspace_ids: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub toolchain: Option<ToolchainFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub node_id: NodeId,
    pub protocol: ProtocolVersion,
    pub domains: Vec<ExecutionDomainDescriptor>,
    pub reported_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSideEffect {
    Pure,
    WorkspaceMutation,
    ExternalSideEffect,
    PrivilegedSideEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionNetworkPolicy {
    None,
    DependencyFetch,
    DeclaredHosts,
    Unrestricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    AwaitingApproval,
    Queued,
    Leased,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Lost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    #[serde(default = "default_local_admin_principal")]
    pub principal_id: String,
    pub workspace_id: String,
    #[serde(default)]
    pub candidate_id: Option<String>,
    #[serde(default)]
    pub origin_task_id: Option<String>,
    pub domain: String,
    #[serde(default)]
    pub required_platform: Option<String>,
    #[serde(default)]
    pub required_architecture: Option<String>,
    pub argv: Vec<String>,
    pub relative_cwd: String,
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_injections: Vec<SecretInjection>,
    #[serde(default)]
    pub declared_hosts: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub side_effect: ActionSideEffect,
    pub network_policy: ActionNetworkPolicy,
    #[serde(default)]
    pub cache_trust: CacheTrust,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCreateRequest {
    pub target_node_id: Option<NodeId>,
    pub spec: ActionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action_id: String,
    pub assigned_node_id: NodeId,
    pub spec: ActionSpec,
    pub status: ActionStatus,
    #[serde(default)]
    pub policy_decision: PolicyDecision,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub cache_key: Option<String>,
    #[serde(default)]
    pub toolchain_digest: Option<String>,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(default)]
    pub cache_source_action_id: Option<String>,
    pub cancel_requested: bool,
    pub lease_id: Option<String>,
    pub lease_expires_unix_ms: Option<u64>,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub completed_unix_ms: Option<u64>,
    pub result: Option<ActionExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionExecutionResult {
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLeaseRequest {
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLease {
    pub action: ActionRecord,
    pub lease_id: String,
    pub lease_expires_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLeaseResponse {
    pub lease: Option<ActionLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLeaseRenewRequest {
    pub lease_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLeaseRenewResponse {
    pub lease_expires_unix_ms: u64,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStartRequest {
    pub lease_id: String,
    pub started_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCompletionRequest {
    pub lease_id: String,
    pub completed_unix_ms: u64,
    pub result: ActionExecutionResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCompletionResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCancelResponse {
    pub action_id: String,
    pub cancel_requested: bool,
    pub status: ActionStatus,
}

// ---- Iteration 10: Action Cache + Multi-Platform Validation ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCacheRecord {
    pub cache_key: String,
    pub source_action_id: String,
    pub workspace_id: String,
    pub candidate_id: Option<String>,
    pub toolchain_digest: String,
    pub trust: CacheTrust,
    pub result_digest: String,
    pub result: ActionExecutionResult,
    pub created_unix_ms: u64,
    pub last_used_unix_ms: u64,
    pub hit_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationRunStatus {
    Running,
    AwaitingApproval,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationTargetSpec {
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default = "default_host_domain")]
    pub domain: String,
    pub argv: Vec<String>,
    #[serde(default = "default_relative_cwd")]
    pub relative_cwd: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default = "default_validation_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_validation_output_bytes")]
    pub max_output_bytes: u64,
    #[serde(default = "default_validation_network")]
    pub network_policy: ActionNetworkPolicy,
    #[serde(default)]
    pub cache_trust: CacheTrust,
    #[serde(default)]
    pub secret_injections: Vec<SecretInjection>,
    #[serde(default)]
    pub declared_hosts: Vec<String>,
}

fn default_host_domain() -> String { "host".into() }
fn default_relative_cwd() -> String { ".".into() }
fn default_validation_timeout_ms() -> u64 { 15 * 60 * 1000 }
fn default_validation_output_bytes() -> u64 { 1024 * 1024 }
fn default_validation_network() -> ActionNetworkPolicy { ActionNetworkPolicy::Unrestricted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMatrixCreateRequest {
    #[serde(default = "default_local_admin_principal")]
    pub principal_id: String,
    pub workspace_id: String,
    pub candidate_id: String,
    pub targets: Vec<ValidationTargetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationTargetRecord {
    pub name: String,
    pub platform: String,
    pub architecture: Option<String>,
    pub node_id: NodeId,
    pub action_id: String,
    pub status: ActionStatus,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRunRecord {
    pub validation_id: String,
    pub principal_id: String,
    pub workspace_id: String,
    pub candidate_id: String,
    pub status: ValidationRunStatus,
    pub targets: Vec<ValidationTargetRecord>,
    pub created_unix_ms: u64,
    pub completed_unix_ms: Option<u64>,
}
