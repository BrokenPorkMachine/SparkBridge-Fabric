use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

pub const SPARKBRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Windows,
    Linux,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for NodeId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricFeature {
    Heartbeat,
    CapabilityReporting,
    FeatureNegotiation,
    CertificateRotation,
    InferenceGateway,
    InferenceStreaming,
    ModelResidency,
    ContentAddressedStorage,
    WorkspaceSnapshots,
    SnapshotTransfer,
    CandidateWorkspaces,
    TransactionalPromotion,
    ThreeWayMerge,
    RemoteActions,
    ExecutionDomains,
    ActionLeases,
    ActionCancellation,
    StructuredDiagnostics,
    ResultOutbox,
    DeterministicAgentRuntime,
    TaskEventLog,
    CandidateValidationSandbox,
    RepositoryIntelligence,
    TreeSitterIndex,
    NativeLanguageAdapters,
    PolicyEngine,
    ApprovalWorkflow,
    SecretBroker,
    DataBoundaries,
    TamperEvidentAudit,
    NetworkSandbox,
    ActionCache,
    ToolchainFingerprints,
    MultiPlatformValidation,
    BuildAffinity,
    McpIntegration,
    IdeApi,
    OpenAiCompatibility,
    OperatorDashboard,
    BackupRestore,
    SignedUpdates,
    ReleaseCertification,
    ProtocolCompatibility,
}

impl FabricFeature {
    pub const ITERATION_2_SERVER: [Self; 4] = [
        Self::Heartbeat,
        Self::CapabilityReporting,
        Self::FeatureNegotiation,
        Self::CertificateRotation,
    ];

    pub const ITERATION_3_GATEWAY: [Self; 3] = [
        Self::InferenceGateway,
        Self::InferenceStreaming,
        Self::ModelResidency,
    ];

    pub const ITERATION_4_WORKSPACES: [Self; 3] = [
        Self::ContentAddressedStorage,
        Self::WorkspaceSnapshots,
        Self::SnapshotTransfer,
    ];

    pub const ITERATION_5_CANDIDATES: [Self; 3] = [
        Self::CandidateWorkspaces,
        Self::TransactionalPromotion,
        Self::ThreeWayMerge,
    ];

    pub const ITERATION_6_ACTIONS: [Self; 6] = [
        Self::RemoteActions,
        Self::ExecutionDomains,
        Self::ActionLeases,
        Self::ActionCancellation,
        Self::StructuredDiagnostics,
        Self::ResultOutbox,
    ];
    pub const ITERATION_7_AGENT: [Self; 3] = [
        Self::DeterministicAgentRuntime,
        Self::TaskEventLog,
        Self::CandidateValidationSandbox,
    ];
    pub const ITERATION_8_INTELLIGENCE: [Self; 3] = [
        Self::RepositoryIntelligence,
        Self::TreeSitterIndex,
        Self::NativeLanguageAdapters,
    ];
    pub const ITERATION_9_POLICY: [Self; 6] = [
        Self::PolicyEngine,
        Self::ApprovalWorkflow,
        Self::SecretBroker,
        Self::DataBoundaries,
        Self::TamperEvidentAudit,
        Self::NetworkSandbox,
    ];
    pub const ITERATION_10_CACHE_VALIDATION: [Self; 4] = [
        Self::ActionCache,
        Self::ToolchainFingerprints,
        Self::MultiPlatformValidation,
        Self::BuildAffinity,
    ];
    pub const ITERATION_11_INTEGRATIONS: [Self; 6] = [
        Self::McpIntegration,
        Self::IdeApi,
        Self::OpenAiCompatibility,
        Self::OperatorDashboard,
        Self::BackupRestore,
        Self::SignedUpdates,
    ];
    pub const ITERATION_12_CERTIFICATION: [Self; 2] = [
        Self::ReleaseCertification,
        Self::ProtocolCompatibility,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_round_trip() {
        let id = NodeId::new();
        let parsed: NodeId = id.to_string().parse().expect("parse node id");
        assert_eq!(id, parsed);
    }
}
