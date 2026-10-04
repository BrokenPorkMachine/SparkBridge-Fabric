mod pki;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use reqwest::{Certificate, Client};
use sparkbridge_core::NodeId;
use sparkbridge_index::{ReferenceRecord, RepositoryIndexRecord, SearchHit, SymbolHit};
use sparkbridge_snapshot::GitCommitSummary;
use sparkbridge_task::{TaskCreateRequest, TaskEvent, TaskRecord, TaskRunRequest, TaskRunResponse, TaskSpec, TaskStatus};
use sparkbridge_protocol::{
    EnrollmentCreateRequest, EnrollmentTokenResponse, HealthResponse, NodeRecord, ProtocolVersion,
    ResidencyAction, ResidencyRequest, RevokeNodeRequest, SnapshotRecord,
    CandidateCreateOperationInput, CandidateCreateRequest, CandidateRecord, PromotionRecord,
    ActionCacheRecord, ActionCreateRequest, ActionNetworkPolicy, ActionRecord, ActionSideEffect, ActionSpec, CacheTrust, CapabilityReport,
    ValidationMatrixCreateRequest, ValidationRunRecord,
    ApprovalDecisionRequest, ApprovalRecord, AuditRecord, AuditVerifyResponse, PrincipalRecord,
    PrincipalUpsertRequest, SecretInjection, WorkspacePolicyRecord, WorkspacePolicyUpsertRequest,
};
use std::{collections::BTreeMap, fs, io::Write, path::{Path, PathBuf}, time::Duration};

#[derive(Debug, Parser)]
#[command(name = "sparkbridge", version, about = "SparkBridge Fabric operator CLI")]
struct Args {
    #[arg(long, global = true, default_value = "http://127.0.0.1:7787")]
    admin_server: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Doctor,
    Health,
    Protocol,
    Pki {
        #[command(subcommand)]
        command: PkiCommand,
    },
    GatewayToken {
        #[command(subcommand)]
        command: GatewayTokenCommand,
    },
    IntegrationToken {
        #[command(subcommand)]
        command: IntegrationTokenCommand,
    },
    Integrations {
        #[arg(long, default_value = "https://127.0.0.1:7791")]
        url: String,
        #[arg(long, default_value = "./pki/ca.pem")]
        ca_cert: PathBuf,
        #[arg(long, env = "SPARKBRIDGE_INTEGRATION_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[command(subcommand)]
        command: IntegrationsCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },
    Certification {
        #[command(subcommand)]
        command: CertificationCommand,
    },
    Enrollment {
        #[command(subcommand)]
        command: EnrollmentCommand,
    },
    Nodes {
        #[command(subcommand)]
        command: NodesCommand,
    },
    Snapshots {
        #[command(subcommand)]
        command: SnapshotsCommand,
    },
    Intelligence {
        #[command(subcommand)]
        command: IntelligenceCommand,
    },
    Candidates {
        #[command(subcommand)]
        command: CandidatesCommand,
    },
    Promotions {
        #[command(subcommand)]
        command: PromotionsCommand,
    },
    Capabilities,
    Actions {
        #[command(subcommand)]
        command: ActionsCommand,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    Validations {
        #[command(subcommand)]
        command: ValidationsCommand,
    },
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Approvals {
        #[command(subcommand)]
        command: ApprovalsCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Inference {
        #[arg(long, default_value = "https://127.0.0.1:7790")]
        gateway_url: String,
        #[arg(long, default_value = "./pki/ca.pem")]
        ca_cert: PathBuf,
        #[arg(long, env = "SPARKBRIDGE_GATEWAY_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[command(subcommand)]
        command: InferenceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PkiCommand {
    Init {
        #[arg(long, default_value = "./pki")]
        dir: PathBuf,
        #[arg(long, default_value = "localhost")]
        server_name: String,
        #[arg(long = "san")]
        sans: Vec<String>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GatewayTokenCommand {
    Rotate {
        #[arg(long, default_value = "./pki/gateway-token")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IntegrationTokenCommand {
    Rotate {
        #[arg(long, default_value = "./pki/integration-token")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IntegrationsCommand {
    Status,
    Dashboard,
    Tasks,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    Create {
        #[arg(long, default_value = ".")] root: PathBuf,
        #[arg(long)] output: PathBuf,
        #[arg(long = "include")] include: Vec<PathBuf>,
    },
    Verify { #[arg(long)] backup: PathBuf },
    Restore { #[arg(long)] backup: PathBuf, #[arg(long)] target: PathBuf, #[arg(long)] overwrite: bool },
}

#[derive(Debug, Subcommand)]
enum UpdateCommand {
    Verify { #[arg(long)] manifest: PathBuf, #[arg(long)] signature: PathBuf, #[arg(long)] public_key: PathBuf, #[arg(long)] artifact: PathBuf },
    Stage { #[arg(long)] manifest: PathBuf, #[arg(long)] signature: PathBuf, #[arg(long)] public_key: PathBuf, #[arg(long)] artifact: PathBuf, #[arg(long)] staging_dir: PathBuf },
}

#[derive(Debug, Subcommand)]
enum CertificationCommand {
    Evaluate { #[arg(long)] profile: PathBuf, #[arg(long)] results: PathBuf },
    Template { #[arg(long)] output: PathBuf },
}

#[derive(Debug, Subcommand)]
enum EnrollmentCommand {
    Create {
        #[arg(long, default_value_t = 900)]
        ttl_seconds: u64,
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum NodesCommand {
    List,
    Revoke {
        id: NodeId,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SnapshotsCommand { List }

#[derive(Debug, Subcommand)]
enum IntelligenceCommand {
    List,
    Build { snapshot_id: String },
    Search { snapshot_id: String, query: String, #[arg(long, default_value_t = 50)] limit: usize },
    Symbols { snapshot_id: String, query: String, #[arg(long, default_value_t = 50)] limit: usize },
    References { snapshot_id: String, symbol: String, #[arg(long, default_value_t = 100)] limit: usize },
    History { snapshot_id: String },
}

#[derive(Debug, Subcommand)]
enum CandidatesCommand {
    List,
    Show { candidate_id: String },
    Create {
        #[arg(long)]
        base_snapshot: String,
        #[arg(long)]
        patch: PathBuf,
        #[arg(long)]
        description: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PromotionsCommand { List }


#[derive(Debug, Clone, Copy, ValueEnum)]
enum SideEffectArg { Pure, WorkspaceMutation, ExternalSideEffect, PrivilegedSideEffect }
impl From<SideEffectArg> for ActionSideEffect {
    fn from(value: SideEffectArg) -> Self { match value {
        SideEffectArg::Pure => Self::Pure,
        SideEffectArg::WorkspaceMutation => Self::WorkspaceMutation,
        SideEffectArg::ExternalSideEffect => Self::ExternalSideEffect,
        SideEffectArg::PrivilegedSideEffect => Self::PrivilegedSideEffect,
    }}
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkPolicyArg { None, DependencyFetch, DeclaredHosts, Unrestricted }
impl From<NetworkPolicyArg> for ActionNetworkPolicy {
    fn from(value: NetworkPolicyArg) -> Self { match value {
        NetworkPolicyArg::None => Self::None,
        NetworkPolicyArg::DependencyFetch => Self::DependencyFetch,
        NetworkPolicyArg::DeclaredHosts => Self::DeclaredHosts,
        NetworkPolicyArg::Unrestricted => Self::Unrestricted,
    }}
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CacheTrustArg { Strong, BestEffort, Disabled }
impl From<CacheTrustArg> for CacheTrust {
    fn from(value: CacheTrustArg) -> Self { match value {
        CacheTrustArg::Strong => Self::Strong,
        CacheTrustArg::BestEffort => Self::BestEffort,
        CacheTrustArg::Disabled => Self::Disabled,
    }}
}

// `Create` carries the full action-spec surface and is destructured immediately in its
// match arm, so the enum is never held in a collection and boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum ActionsCommand {
    List,
    Show { action_id: String },
    Cancel { action_id: String },
    Create {
        #[arg(long, default_value = "local-admin")]
        principal: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        candidate: Option<String>,
        #[arg(long, default_value = "host")]
        domain: String,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        architecture: Option<String>,
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(long)]
        node: Option<NodeId>,
        #[arg(long = "require")]
        required_capabilities: Vec<String>,
        #[arg(long, default_value_t = 600)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, value_enum, default_value = "pure")]
        side_effect: SideEffectArg,
        #[arg(long, value_enum, default_value = "unrestricted")]
        network: NetworkPolicyArg,
        #[arg(long, value_enum, default_value = "disabled")]
        cache: CacheTrustArg,
        /// Secret reference mapping REF=TARGET_ENV. Values are resolved only on the executor.
        #[arg(long = "secret")]
        secrets: Vec<String>,
        #[arg(long = "host")]
        declared_hosts: Vec<String>,
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CacheCommand { List }

#[derive(Debug, Subcommand)]
enum ValidationsCommand {
    List,
    Show { validation_id: String },
    Create { #[arg(long)] spec: PathBuf },
}

#[derive(Debug, Subcommand)]
enum TasksCommand {
    List,
    Show { task_id: String },
    Events { task_id: String },
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    Run {
        task_id: String,
        #[arg(long, default_value_t = 4)]
        steps: u32,
        #[arg(long)]
        follow: bool,
        #[arg(long, default_value_t = 2)]
        poll_seconds: u64,
    },
    Pause { task_id: String },
    Resume { task_id: String },
    Cancel { task_id: String },
}


#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Principals {
        #[command(subcommand)]
        command: PrincipalsCommand,
    },
    Workspaces {
        #[command(subcommand)]
        command: WorkspacePoliciesCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PrincipalsCommand {
    List,
    Set { #[arg(long)] file: PathBuf },
}

#[derive(Debug, Subcommand)]
enum WorkspacePoliciesCommand {
    List,
    Set { #[arg(long)] file: PathBuf },
}

#[derive(Debug, Subcommand)]
enum ApprovalsCommand {
    List,
    Approve { approval_id: String, #[arg(long, default_value = "local-admin")] principal: String, #[arg(long)] reason: Option<String> },
    Deny { approval_id: String, #[arg(long, default_value = "local-admin")] principal: String, #[arg(long)] reason: Option<String> },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    List { #[arg(long, default_value_t = 500)] limit: usize },
    Verify,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum PatchFileOperation {
    CreateFile { path: String, content_file: PathBuf, #[serde(default)] executable: bool },
    ModifyFile { path: String, content_file: PathBuf, #[serde(default)] executable: bool },
    DeleteFile { path: String },
    RenameFile { from_path: String, to_path: String, #[serde(default)] executable: bool },
    SetExecutable { path: String, executable: bool },
}

#[derive(Debug, Subcommand)]
enum InferenceCommand {
    Health,
    Models,
    Running,
    Metrics,
    Cancel {
        request_id: String,
    },
    Load {
        model: String,
        #[arg(long)]
        keep_alive: Option<String>,
    },
    Unload {
        model: String,
    },
    Generate {
        model: String,
        prompt: String,
        #[arg(long)]
        raw: bool,
    },
    Chat {
        model: String,
        prompt: String,
        #[arg(long)]
        raw: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let admin_client = Client::builder().build().context("building admin HTTP client")?;
    let admin = args.admin_server.trim_end_matches('/');

    match args.command {
        Command::Doctor => {
            println!("platform: {}", std::env::consts::OS);
            println!("architecture: {}", std::env::consts::ARCH);
            match get_health(&admin_client, admin).await {
                Ok(health) => println!("admin API: {} (SparkBridge {})", health.status, health.version),
                Err(error) => println!("admin API: unreachable ({error})"),
            }
        }
        Command::Health => {
            println!("{}", serde_json::to_string_pretty(&get_health(&admin_client, admin).await?)?);
        }
        Command::Protocol => {
            println!("{}.{}", ProtocolVersion::CURRENT.major, ProtocolVersion::CURRENT.minor);
        }
        Command::Pki { command } => match command {
            PkiCommand::Init { dir, server_name, sans, force } => {
                pki::initialize(&dir, &server_name, &sans, force)?;
            }
        },
        Command::GatewayToken { command } => match command {
            GatewayTokenCommand::Rotate { path, force } => {
                pki::rotate_gateway_token(&path, force)?;
            }
        },
        Command::IntegrationToken { command } => match command {
            IntegrationTokenCommand::Rotate { path, force } => {
                pki::rotate_gateway_token(&path, force)?;
            }
        },
        Command::Integrations { url, ca_cert, token, token_file, command } => {
            let token = resolve_integration_token(token, token_file)?;
            let client = gateway_client(&ca_cert)?;
            let base = url.trim_end_matches('/');
            match command {
                IntegrationsCommand::Status => print_integration_json(&client, base, &token, "/api/v1/integrations/summary").await?,
                IntegrationsCommand::Tasks => print_integration_json(&client, base, &token, "/api/v1/integrations/tasks").await?,
                IntegrationsCommand::Dashboard => println!("{base}/dashboard"),
            }
        },
        Command::Backup { command } => match command {
            BackupCommand::Create { root, output, include } => {
                let include = if include.is_empty() { vec![PathBuf::from("state"), PathBuf::from("pki"), PathBuf::from("config")] } else { include };
                let manifest = sparkbridge_maintenance::create_backup(&root, &output, &include, unix_ms_cli())?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
            BackupCommand::Verify { backup } => println!("{}", serde_json::to_string_pretty(&sparkbridge_maintenance::verify_backup(&backup)?)?),
            BackupCommand::Restore { backup, target, overwrite } => println!("{}", serde_json::to_string_pretty(&sparkbridge_maintenance::restore_backup(&backup, &target, overwrite)?)?),
        },
        Command::Update { command } => match command {
            UpdateCommand::Verify { manifest, signature, public_key, artifact } => println!("{}", serde_json::to_string_pretty(&sparkbridge_maintenance::verify_signed_update(&manifest, &signature, &public_key, &artifact)?)?),
            UpdateCommand::Stage { manifest, signature, public_key, artifact, staging_dir } => { let path=sparkbridge_maintenance::stage_verified_update(&manifest,&signature,&public_key,&artifact,&staging_dir)?; println!("staged: {}", path.display()); }
        },
        Command::Certification { command } => match command {
            CertificationCommand::Evaluate { profile, results } => {
                let profile: sparkbridge_certification::CertificationProfile = serde_json::from_slice(&fs::read(&profile).with_context(|| format!("reading {}", profile.display()))?)?;
                let results: sparkbridge_certification::CertificationBundle = serde_json::from_slice(&fs::read(&results).with_context(|| format!("reading {}", results.display()))?)?;
                let report = sparkbridge_certification::evaluate(&profile, &results)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.release_ready { bail!("release certification requirements are not satisfied"); }
            }
            CertificationCommand::Template { output } => {
                let profile = sparkbridge_certification::candidate_profile();
                if let Some(parent)=output.parent(){ if !parent.as_os_str().is_empty(){ fs::create_dir_all(parent)?; } }
                fs::write(&output, serde_json::to_vec_pretty(&profile)?)?;
                println!("wrote {}", output.display());
            }
        },
        Command::Enrollment { command } => match command {
            EnrollmentCommand::Create { ttl_seconds, label } => {
                let response = admin_client
                    .post(format!("{admin}/api/v1/admin/enrollments"))
                    .json(&EnrollmentCreateRequest { ttl_seconds, label })
                    .send().await?;
                if !response.status().is_success() {
                    bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default());
                }
                let token: EnrollmentTokenResponse = response.json().await?;
                println!("token: {}", token.token);
                println!("expires_unix_ms: {}", token.expires_unix_ms);
                if let Some(label) = token.label { println!("label: {label}"); }
            }
        },
        Command::Nodes { command } => match command {
            NodesCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/nodes")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                let nodes: Vec<NodeRecord> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&nodes)?);
            }
            NodesCommand::Revoke { id, reason } => {
                let response = admin_client
                    .post(format!("{admin}/api/v1/admin/nodes/{id}/revoke"))
                    .json(&RevokeNodeRequest { reason })
                    .send().await?;
                if !response.status().is_success() {
                    bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default());
                }
                let node: NodeRecord = response.json().await?;
                println!("revoked node {} ({})", node.id, node.name);
            }
        },
        Command::Snapshots { command } => match command {
            SnapshotsCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/snapshots")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                let snapshots: Vec<SnapshotRecord> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&snapshots)?);
            }
        },
        Command::Intelligence { command } => match command {
            IntelligenceCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/indexes")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<RepositoryIndexRecord>>().await?)?);
            }
            IntelligenceCommand::Build { snapshot_id } => {
                let response = admin_client.post(format!("{admin}/api/v1/admin/indexes/{snapshot_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<RepositoryIndexRecord>().await?)?);
            }
            IntelligenceCommand::Search { snapshot_id, query, limit } => {
                let params = vec![("q".to_string(), query), ("limit".to_string(), limit.to_string())];
                let response = admin_client.get(format!("{admin}/api/v1/admin/indexes/{snapshot_id}/search")).query(&params).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<SearchHit>>().await?)?);
            }
            IntelligenceCommand::Symbols { snapshot_id, query, limit } => {
                let params = vec![("q".to_string(), query), ("limit".to_string(), limit.to_string())];
                let response = admin_client.get(format!("{admin}/api/v1/admin/indexes/{snapshot_id}/symbols")).query(&params).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<SymbolHit>>().await?)?);
            }
            IntelligenceCommand::References { snapshot_id, symbol, limit } => {
                let params = vec![("q".to_string(), symbol), ("limit".to_string(), limit.to_string())];
                let response = admin_client.get(format!("{admin}/api/v1/admin/indexes/{snapshot_id}/references")).query(&params).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<ReferenceRecord>>().await?)?);
            }
            IntelligenceCommand::History { snapshot_id } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/indexes/{snapshot_id}/history")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<GitCommitSummary>>().await?)?);
            }
        },
        Command::Candidates { command } => match command {
            CandidatesCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/candidates")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                let records: Vec<CandidateRecord> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&records)?);
            }
            CandidatesCommand::Show { candidate_id } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/candidates/{candidate_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                let record: CandidateRecord = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
            CandidatesCommand::Create { base_snapshot, patch, description } => {
                let raw = fs::read(&patch).with_context(|| format!("reading patch specification {}", patch.display()))?;
                let operations: Vec<PatchFileOperation> = serde_json::from_slice(&raw).context("decoding patch specification JSON")?;
                let operations = encode_patch_operations(operations)?;
                let request = CandidateCreateRequest { base_snapshot_id: base_snapshot, description, operations };
                let response = admin_client.post(format!("{admin}/api/v1/admin/candidates")).json(&request).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                let record: CandidateRecord = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
        },
        Command::Promotions { command } => match command {
            PromotionsCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/promotions")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                let records: Vec<PromotionRecord> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&records)?);
            }
        },

        Command::Capabilities => {
            let response = admin_client.get(format!("{admin}/api/v1/admin/capabilities")).send().await?;
            if !response.status().is_success() { bail!("server returned {}", response.status()); }
            let reports: Vec<CapabilityReport> = response.json().await?;
            println!("{}", serde_json::to_string_pretty(&reports)?);
        }
        Command::Actions { command } => match command {
            ActionsCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/actions")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                let actions: Vec<ActionRecord> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&actions)?);
            }
            ActionsCommand::Show { action_id } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/actions/{action_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<ActionRecord>().await?)?);
            }
            ActionsCommand::Cancel { action_id } => {
                let response = admin_client.delete(format!("{admin}/api/v1/admin/actions/{action_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                let value: serde_json::Value = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            ActionsCommand::Create { principal, workspace, candidate, domain, platform, architecture, cwd, node, required_capabilities, timeout_seconds, max_output_bytes, side_effect, network, cache, secrets, declared_hosts, argv } => {
                let request = ActionCreateRequest {
                    target_node_id: node,
                    spec: ActionSpec {
                        principal_id: principal,
                        workspace_id: workspace,
                        candidate_id: candidate,
                        origin_task_id: None,
                        domain,
                        required_platform: platform,
                        required_architecture: architecture,
                        argv,
                        relative_cwd: cwd,
                        env: BTreeMap::new(),
                        secret_injections: parse_secret_injections(secrets)?,
                        declared_hosts,
                        timeout_ms: timeout_seconds.saturating_mul(1000),
                        max_output_bytes,
                        side_effect: side_effect.into(),
                        network_policy: network.into(),
                        cache_trust: cache.into(),
                        required_capabilities,
                    },
                };
                let response = admin_client.post(format!("{admin}/api/v1/admin/actions")).json(&request).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                let record: ActionRecord = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
        },
        Command::Cache { command } => match command {
            CacheCommand::List => {
                let response=admin_client.get(format!("{admin}/api/v1/admin/cache")).send().await?;
                if !response.status().is_success(){bail!("server returned {}: {}",response.status(),response.text().await.unwrap_or_default());}
                println!("{}",serde_json::to_string_pretty(&response.json::<Vec<ActionCacheRecord>>().await?)?);
            }
        },
        Command::Validations { command } => match command {
            ValidationsCommand::List => {
                let response=admin_client.get(format!("{admin}/api/v1/admin/validations")).send().await?;
                if !response.status().is_success(){bail!("server returned {}: {}",response.status(),response.text().await.unwrap_or_default());}
                println!("{}",serde_json::to_string_pretty(&response.json::<Vec<ValidationRunRecord>>().await?)?);
            }
            ValidationsCommand::Show { validation_id } => {
                let response=admin_client.get(format!("{admin}/api/v1/admin/validations/{validation_id}")).send().await?;
                if !response.status().is_success(){bail!("server returned {}: {}",response.status(),response.text().await.unwrap_or_default());}
                println!("{}",serde_json::to_string_pretty(&response.json::<ValidationRunRecord>().await?)?);
            }
            ValidationsCommand::Create { spec } => {
                let request:ValidationMatrixCreateRequest=serde_json::from_slice(&fs::read(&spec).with_context(||format!("reading validation spec {}",spec.display()))?).context("decoding validation matrix JSON")?;
                let response=admin_client.post(format!("{admin}/api/v1/admin/validations")).json(&request).send().await?;
                if !response.status().is_success(){bail!("server returned {}: {}",response.status(),response.text().await.unwrap_or_default());}
                println!("{}",serde_json::to_string_pretty(&response.json::<ValidationRunRecord>().await?)?);
            }
        },
        Command::Tasks { command } => match command {
            TasksCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/tasks")).send().await?;
                if !response.status().is_success() { bail!("server returned {}", response.status()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<TaskRecord>>().await?)?);
            }
            TasksCommand::Show { task_id } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/tasks/{task_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<TaskRecord>().await?)?);
            }
            TasksCommand::Events { task_id } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/tasks/{task_id}/events")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<TaskEvent>>().await?)?);
            }
            TasksCommand::Create { spec } => {
                let raw = fs::read(&spec).with_context(|| format!("reading task spec {}", spec.display()))?;
                let spec: TaskSpec = serde_json::from_slice(&raw).context("decoding TaskSpec JSON")?;
                spec.validate().map_err(anyhow::Error::msg)?;
                let response = admin_client.post(format!("{admin}/api/v1/admin/tasks")).json(&TaskCreateRequest { spec }).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<TaskRecord>().await?)?);
            }
            TasksCommand::Run { task_id, steps, follow, poll_seconds } => {
                loop {
                    let response = admin_client.post(format!("{admin}/api/v1/admin/tasks/{task_id}/run")).json(&TaskRunRequest { max_steps: steps }).send().await?;
                    if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                    let run: TaskRunResponse = response.json().await?;
                    println!("{}", serde_json::to_string_pretty(&run)?);
                    if !follow || run.task.status.terminal() || run.task.status == TaskStatus::Paused { break; }
                    tokio::time::sleep(Duration::from_secs(poll_seconds.max(1))).await;
                }
            }
            TasksCommand::Pause { task_id } => {
                let response = admin_client.post(format!("{admin}/api/v1/admin/tasks/{task_id}/pause")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<TaskRecord>().await?)?);
            }
            TasksCommand::Resume { task_id } => {
                let response = admin_client.post(format!("{admin}/api/v1/admin/tasks/{task_id}/resume")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<TaskRecord>().await?)?);
            }
            TasksCommand::Cancel { task_id } => {
                let response = admin_client.delete(format!("{admin}/api/v1/admin/tasks/{task_id}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<TaskRecord>().await?)?);
            }
        },
        Command::Policy { command } => match command {
            PolicyCommand::Principals { command } => match command {
                PrincipalsCommand::List => {
                    let response = admin_client.get(format!("{admin}/api/v1/admin/principals")).send().await?;
                    if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                    println!("{}", serde_json::to_string_pretty(&response.json::<Vec<PrincipalRecord>>().await?)?);
                }
                PrincipalsCommand::Set { file } => {
                    let principal: PrincipalRecord = serde_json::from_slice(&fs::read(&file).with_context(|| format!("reading {}", file.display()))?)
                        .context("decoding principal JSON")?;
                    let response = admin_client.post(format!("{admin}/api/v1/admin/principals")).json(&PrincipalUpsertRequest { principal }).send().await?;
                    if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                    println!("{}", serde_json::to_string_pretty(&response.json::<PrincipalRecord>().await?)?);
                }
            },
            PolicyCommand::Workspaces { command } => match command {
                WorkspacePoliciesCommand::List => {
                    let response = admin_client.get(format!("{admin}/api/v1/admin/workspace-policies")).send().await?;
                    if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                    println!("{}", serde_json::to_string_pretty(&response.json::<Vec<WorkspacePolicyRecord>>().await?)?);
                }
                WorkspacePoliciesCommand::Set { file } => {
                    let policy: WorkspacePolicyRecord = serde_json::from_slice(&fs::read(&file).with_context(|| format!("reading {}", file.display()))?)
                        .context("decoding workspace policy JSON")?;
                    let response = admin_client.post(format!("{admin}/api/v1/admin/workspace-policies")).json(&WorkspacePolicyUpsertRequest { policy }).send().await?;
                    if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                    println!("{}", serde_json::to_string_pretty(&response.json::<WorkspacePolicyRecord>().await?)?);
                }
            },
        },
        Command::Approvals { command } => match command {
            ApprovalsCommand::List => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/approvals")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<ApprovalRecord>>().await?)?);
            }
            ApprovalsCommand::Approve { approval_id, principal, reason } => {
                let response = admin_client.post(format!("{admin}/api/v1/admin/approvals/{approval_id}/approve"))
                    .json(&ApprovalDecisionRequest { principal_id: principal, reason }).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<ApprovalRecord>().await?)?);
            }
            ApprovalsCommand::Deny { approval_id, principal, reason } => {
                let response = admin_client.post(format!("{admin}/api/v1/admin/approvals/{approval_id}/deny"))
                    .json(&ApprovalDecisionRequest { principal_id: principal, reason }).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<ApprovalRecord>().await?)?);
            }
        },
        Command::Audit { command } => match command {
            AuditCommand::List { limit } => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/audit?limit={limit}")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<Vec<AuditRecord>>().await?)?);
            }
            AuditCommand::Verify => {
                let response = admin_client.get(format!("{admin}/api/v1/admin/audit/verify")).send().await?;
                if !response.status().is_success() { bail!("server returned {}: {}", response.status(), response.text().await.unwrap_or_default()); }
                println!("{}", serde_json::to_string_pretty(&response.json::<AuditVerifyResponse>().await?)?);
            }
        },
        Command::Inference { gateway_url, ca_cert, token, token_file, command } => {
            let token = resolve_gateway_token(token, token_file)?;
            let client = gateway_client(&ca_cert)?;
            let gateway = gateway_url.trim_end_matches('/');
            run_inference_command(&client, gateway, &token, command).await?;
        }
    }
    Ok(())
}


fn parse_secret_injections(values: Vec<String>) -> Result<Vec<SecretInjection>> {
    values.into_iter().map(|value| {
        let (reference, env_name) = value.split_once('=').ok_or_else(|| anyhow::anyhow!("--secret must be REF=TARGET_ENV"))?;
        if reference.trim().is_empty() || env_name.trim().is_empty() { bail!("--secret must contain non-empty REF and TARGET_ENV"); }
        Ok(SecretInjection { reference: reference.to_owned(), env_name: env_name.to_owned() })
    }).collect()
}

fn encode_patch_operations(operations: Vec<PatchFileOperation>) -> Result<Vec<CandidateCreateOperationInput>> {
    operations.into_iter().map(|operation| Ok(match operation {
        PatchFileOperation::CreateFile { path, content_file, executable } => {
            let bytes = fs::read(&content_file).with_context(|| format!("reading candidate content {}", content_file.display()))?;
            CandidateCreateOperationInput::CreateFile { path, content_base64: BASE64.encode(bytes), executable }
        }
        PatchFileOperation::ModifyFile { path, content_file, executable } => {
            let bytes = fs::read(&content_file).with_context(|| format!("reading candidate content {}", content_file.display()))?;
            CandidateCreateOperationInput::ModifyFile { path, content_base64: BASE64.encode(bytes), executable }
        }
        PatchFileOperation::DeleteFile { path } => CandidateCreateOperationInput::DeleteFile { path },
        PatchFileOperation::RenameFile { from_path, to_path, executable } => CandidateCreateOperationInput::RenameFile { from_path, to_path, executable },
        PatchFileOperation::SetExecutable { path, executable } => CandidateCreateOperationInput::SetExecutable { path, executable },
    })).collect()
}

async fn get_health(client: &Client, admin: &str) -> Result<HealthResponse> {
    let response = client.get(format!("{admin}/health")).send().await.context("requesting health")?;
    if !response.status().is_success() { bail!("server returned {}", response.status()); }
    response.json().await.context("decoding health response")
}

fn resolve_integration_token(token: Option<String>, token_file: Option<PathBuf>) -> Result<String> {
    if let Some(token)=token { return Ok(token); }
    if let Some(path)=token_file { return Ok(fs::read_to_string(&path).with_context(||format!("reading {}",path.display()))?.trim().to_owned()); }
    bail!("provide --token, --token-file, or SPARKBRIDGE_INTEGRATION_TOKEN")
}

async fn print_integration_json(client:&Client, base:&str, token:&str, path:&str)->Result<()> {
    let response=client.get(format!("{base}{path}")).bearer_auth(token).send().await?;
    if !response.status().is_success(){bail!("integration server returned {}: {}",response.status(),response.text().await.unwrap_or_default());}
    let value:serde_json::Value=response.json().await?; println!("{}",serde_json::to_string_pretty(&value)?); Ok(())
}

fn unix_ms_cli()->u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }

fn resolve_gateway_token(token: Option<String>, token_file: Option<PathBuf>) -> Result<String> {
    if let Some(token) = token {
        return Ok(token);
    }
    if let Some(path) = token_file {
        return Ok(fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?
            .trim()
            .to_owned());
    }
    bail!("provide --token, --token-file, or SPARKBRIDGE_GATEWAY_TOKEN")
}

fn gateway_client(ca_cert: &Path) -> Result<Client> {
    let ca = fs::read(ca_cert).with_context(|| format!("reading {}", ca_cert.display()))?;
    let certificate = Certificate::from_pem(&ca).context("parsing SparkBridge CA")?;
    Client::builder()
        .add_root_certificate(certificate)
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(300))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .context("building inference gateway client")
}

async fn run_inference_command(
    client: &Client,
    gateway: &str,
    token: &str,
    command: InferenceCommand,
) -> Result<()> {
    match command {
        InferenceCommand::Health => print_gateway_json(client, gateway, token, "/api/v1/inference/health").await?,
        InferenceCommand::Models => print_gateway_json(client, gateway, token, "/api/v1/inference/models").await?,
        InferenceCommand::Running => print_gateway_json(client, gateway, token, "/api/v1/inference/running").await?,
        InferenceCommand::Metrics => print_gateway_json(client, gateway, token, "/api/v1/inference/metrics").await?,
        InferenceCommand::Cancel { request_id } => {
            let response = client
                .delete(format!("{gateway}/api/v1/inference/requests/{request_id}"))
                .bearer_auth(token)
                .send()
                .await?;
            if !response.status().is_success() {
                bail!("gateway returned {}: {}", response.status(), response.text().await.unwrap_or_default());
            }
            let value: serde_json::Value = response.json().await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        InferenceCommand::Load { model, keep_alive } => {
            let keep_alive = keep_alive.map(serde_json::Value::String);
            let request = ResidencyRequest { model, action: ResidencyAction::Load, keep_alive };
            post_and_print(client, gateway, token, "/api/v1/inference/residency", &request).await?;
        }
        InferenceCommand::Unload { model } => {
            let request = ResidencyRequest { model, action: ResidencyAction::Unload, keep_alive: None };
            post_and_print(client, gateway, token, "/api/v1/inference/residency", &request).await?;
        }
        InferenceCommand::Generate { model, prompt, raw } => {
            let body = serde_json::json!({"model": model, "prompt": prompt});
            stream_inference(client, gateway, token, "/api/v1/inference/generate", &body, raw, false).await?;
        }
        InferenceCommand::Chat { model, prompt, raw } => {
            let body = serde_json::json!({"model": model, "messages": [{"role":"user", "content": prompt}]});
            stream_inference(client, gateway, token, "/api/v1/inference/chat", &body, raw, true).await?;
        }
    }
    Ok(())
}

async fn print_gateway_json(client: &Client, gateway: &str, token: &str, path: &str) -> Result<()> {
    let response = client.get(format!("{gateway}{path}")).bearer_auth(token).send().await?;
    if !response.status().is_success() {
        bail!("gateway returned {}: {}", response.status(), response.text().await.unwrap_or_default());
    }
    let value: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn post_and_print<T: serde::Serialize>(
    client: &Client,
    gateway: &str,
    token: &str,
    path: &str,
    body: &T,
) -> Result<()> {
    let response = client.post(format!("{gateway}{path}")).bearer_auth(token).json(body).send().await?;
    if !response.status().is_success() {
        bail!("gateway returned {}: {}", response.status(), response.text().await.unwrap_or_default());
    }
    let value: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn stream_inference(
    client: &Client,
    gateway: &str,
    token: &str,
    path: &str,
    body: &serde_json::Value,
    raw: bool,
    chat: bool,
) -> Result<()> {
    let response = client.post(format!("{gateway}{path}")).bearer_auth(token).json(body).send().await?;
    if !response.status().is_success() {
        bail!("gateway returned {}: {}", response.status(), response.text().await.unwrap_or_default());
    }
    if let Some(id) = response.headers().get("x-sparkbridge-request-id").and_then(|v| v.to_str().ok()) {
        eprintln!("request_id: {id}");
    }

    let mut source = response.bytes_stream();
    let mut buffer = Vec::<u8>::new();
    while let Some(chunk) = source.next().await {
        let chunk = chunk?;
        if raw {
            std::io::stdout().write_all(&chunk)?;
            std::io::stdout().flush()?;
            continue;
        }
        buffer.extend_from_slice(&chunk);
        while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = buffer.drain(..=index).collect();
            print_inference_line(&line, chat)?;
        }
    }
    if !raw && !buffer.is_empty() {
        print_inference_line(&buffer, chat)?;
    }
    if !raw {
        println!();
    }
    Ok(())
}

fn print_inference_line(line: &[u8], chat: bool) -> Result<()> {
    let value: serde_json::Value = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let text = if chat {
        value.get("message").and_then(|message| message.get("content")).and_then(serde_json::Value::as_str)
    } else {
        value.get("response").and_then(serde_json::Value::as_str)
    };
    if let Some(text) = text {
        print!("{text}");
        std::io::stdout().flush()?;
    }
    Ok(())
}
