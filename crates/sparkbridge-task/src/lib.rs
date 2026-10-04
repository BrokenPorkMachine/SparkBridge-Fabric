use serde::{Deserialize, Serialize};
use sparkbridge_protocol::{ActionStatus, ActionNetworkPolicy, CacheTrust, DataClassification, SecretInjection};
use sparkbridge_secrets::SecretFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskBudgets {
    pub max_wall_time_ms: u64,
    pub max_model_calls: u32,
    pub max_actions: u32,
    pub max_candidates: u32,
    pub max_repair_cycles: u32,
}

impl Default for TaskBudgets {
    fn default() -> Self {
        Self {
            max_wall_time_ms: 60 * 60 * 1000,
            max_model_calls: 32,
            max_actions: 32,
            max_candidates: 12,
            max_repair_cycles: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationActionTemplate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    pub domain: String,
    pub argv: Vec<String>,
    #[serde(default = "default_dot")]
    pub relative_cwd: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default = "default_action_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: u64,
    #[serde(default = "default_network")]
    pub network_policy: ActionNetworkPolicy,
    #[serde(default)]
    pub cache_trust: CacheTrust,
    #[serde(default)]
    pub secret_injections: Vec<SecretInjection>,
    #[serde(default)]
    pub declared_hosts: Vec<String>,
}

fn default_dot() -> String { ".".into() }
fn default_action_timeout_ms() -> u64 { 15 * 60 * 1000 }
fn default_output_limit() -> u64 { 1024 * 1024 }
fn default_network() -> ActionNetworkPolicy { ActionNetworkPolicy::Unrestricted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    #[serde(default = "default_local_admin")]
    pub principal_id: String,
    #[serde(default)]
    pub data_classification: DataClassification,
    pub objective: String,
    pub workspace_id: String,
    pub base_snapshot_id: String,
    pub model: String,
    #[serde(default)]
    pub context_paths: Vec<String>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub validation_actions: Vec<ValidationActionTemplate>,
    #[serde(default)]
    pub validation_fanout: bool,
    #[serde(default)]
    pub budgets: TaskBudgets,
    #[serde(default = "default_true")]
    pub require_candidate: bool,
    #[serde(default = "default_true")]
    pub require_validation: bool,
}

fn default_true() -> bool { true }
fn default_local_admin() -> String { "local-admin".into() }

impl TaskSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.principal_id.trim().is_empty() { return Err("task principal_id may not be empty".into()); }
        if self.objective.trim().is_empty() { return Err("task objective may not be empty".into()); }
        if self.workspace_id.trim().is_empty() { return Err("workspace_id may not be empty".into()); }
        if self.base_snapshot_id.trim().is_empty() { return Err("base_snapshot_id may not be empty".into()); }
        if self.model.trim().is_empty() { return Err("model may not be empty".into()); }
        if self.budgets.max_wall_time_ms == 0 || self.budgets.max_model_calls == 0 {
            return Err("task wall/model budgets must be greater than zero".into());
        }
        if self.budgets.max_actions == 0 || self.budgets.max_candidates == 0 || self.budgets.max_repair_cycles == 0 {
            return Err("task action/candidate/repair budgets must be greater than zero".into());
        }
        for action in &self.validation_actions {
            if action.argv.is_empty() || action.argv[0].trim().is_empty() {
                return Err("validation action argv must contain an executable".into());
            }
            if action.domain.trim().is_empty() { return Err("validation action domain may not be empty".into()); }
            if action.platform.as_deref().is_some_and(|v| v.trim().is_empty()) { return Err("validation action platform may not be empty when set".into()); }
            if action.architecture.as_deref().is_some_and(|v| v.trim().is_empty()) { return Err("validation action architecture may not be empty when set".into()); }
            for secret in &action.secret_injections {
                if secret.reference.trim().is_empty() || secret.env_name.trim().is_empty() {
                    return Err("validation secret references and target env names may not be empty".into());
                }
            }
            if action.cache_trust != CacheTrust::Disabled && !action.secret_injections.is_empty() {
                return Err("cached validation actions may not depend on secret injections".into());
            }
            if action.cache_trust == CacheTrust::Strong && action.network_policy != ActionNetworkPolicy::None {
                return Err("strong validation cache requires network_policy=none".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Created,
    Running,
    WaitingForAction,
    Paused,
    Completed,
    Failed,
    Cancelled,
    BudgetExceeded,
}

impl TaskStatus {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled | Self::BudgetExceeded)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskCounters {
    pub model_calls: u32,
    pub actions: u32,
    pub candidates: u32,
    pub repair_cycles: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: String,
    pub spec: TaskSpec,
    pub status: TaskStatus,
    pub counters: TaskCounters,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub completed_unix_ms: Option<u64>,
    pub current_candidate_id: Option<String>,
    pub pending_action_id: Option<String>,
    #[serde(default)]
    pub pending_action_ids: Vec<String>,
    #[serde(default)]
    pub validation_action_ids: Vec<String>,
    pub validation_index: usize,
    pub last_action_status: Option<ActionStatus>,
    pub last_evidence: Option<String>,
    #[serde(default)]
    pub evidence_paths: Vec<String>,
    pub last_context_digest: Option<String>,
    pub summary: Option<String>,
    pub last_error: Option<String>,
}

impl TaskRecord {
    pub fn new(task_id: String, spec: TaskSpec, now_ms: u64) -> Self {
        Self {
            task_id,
            spec,
            status: TaskStatus::Created,
            counters: TaskCounters::default(),
            created_unix_ms: now_ms,
            updated_unix_ms: now_ms,
            started_unix_ms: None,
            completed_unix_ms: None,
            current_candidate_id: None,
            pending_action_id: None,
            pending_action_ids: Vec::new(),
            validation_action_ids: Vec::new(),
            validation_index: 0,
            last_action_status: None,
            last_evidence: None,
            evidence_paths: Vec::new(),
            last_context_digest: None,
            summary: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCreateRequest { pub spec: TaskSpec }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunRequest {
    #[serde(default = "default_run_steps")]
    pub max_steps: u32,
}
fn default_run_steps() -> u32 { 4 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunResponse {
    pub task: TaskRecord,
    pub steps_performed: u32,
    pub waiting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEvent {
    pub event_id: String,
    pub task_id: String,
    pub sequence: u64,
    pub kind: TaskEventKind,
    pub created_unix_ms: u64,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskEventKind {
    TaskCreated,
    TaskStarted,
    ContextCompiled,
    ModelRequested,
    ModelResponded,
    CandidateCreated,
    CandidateRejected,
    ActionScheduled,
    ActionObserved,
    TaskPaused,
    TaskResumed,
    TaskCompleted,
    TaskFailed,
    TaskCancelled,
    BudgetExceeded,
    Recovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSourceFile {
    pub path: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBundle {
    pub format_version: u32,
    pub task_id: String,
    pub objective: String,
    pub acceptance_criteria: Vec<String>,
    pub base_snapshot_id: String,
    pub current_candidate_id: Option<String>,
    pub source_files: Vec<ContextSourceFile>,
    pub candidate_summary: Option<serde_json::Value>,
    pub last_evidence: Option<String>,
    pub counters: TaskCounters,
    #[serde(default)]
    pub intelligence: Option<serde_json::Value>,
    #[serde(default)]
    pub secret_findings: Vec<SecretFinding>,
    #[serde(default)]
    pub effective_classification: DataClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentFileOperation {
    CreateFile { path: String, content: String, #[serde(default)] executable: bool },
    ModifyFile { path: String, content: String, #[serde(default)] executable: bool },
    DeleteFile { path: String },
    RenameFile { from_path: String, to_path: String, #[serde(default)] executable: bool },
    SetExecutable { path: String, executable: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "directive", rename_all = "snake_case")]
pub enum AgentDirective {
    Candidate { description: Option<String>, operations: Vec<AgentFileOperation> },
    RunValidation,
    Complete { summary: String },
    Pause { reason: String },
    Fail { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_objective() {
        let mut spec = TaskSpec {
            principal_id: "local-admin".into(), data_classification: DataClassification::Private, objective: "x".into(), workspace_id: "w".into(), base_snapshot_id: "s".into(), model: "m".into(),
            context_paths: vec![], acceptance_criteria: vec![], validation_actions: vec![], validation_fanout: false, budgets: TaskBudgets::default(), require_candidate: true, require_validation: true,
        };
        assert!(spec.validate().is_ok());
        spec.objective.clear();
        assert!(spec.validate().is_err());
    }
}
