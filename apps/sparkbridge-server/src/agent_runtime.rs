use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};
use sparkbridge_agent::{budget_violation, parse_directive, system_prompt, user_prompt};
use sparkbridge_cas::Digest;
use sparkbridge_candidate::{CandidateManifest, CandidateOperation};
use sparkbridge_protocol::{
    ActionCreateRequest, ActionSideEffect, ActionSpec, ActionStatus, CandidateCreateOperationInput,
    CandidateCreateRequest, InferenceDataBoundary, Permission, PolicyDecision, ValidationRunRecord,
    ValidationRunStatus, ValidationTargetRecord,
};
use sparkbridge_snapshot::{EntryKind, WorkspaceSnapshot};
use sparkbridge_task::{
    AgentDirective, AgentFileOperation, ContextBundle, ContextSourceFile, TaskEventKind, TaskRecord,
    TaskRunResponse, TaskStatus,
};
use std::collections::BTreeMap;
use sparkbridge_policy::{authorize_workspace as policy_authorize_workspace, classification_allows_boundary, effective_classification};
use sparkbridge_secrets::{SecretFinding, scan_and_redact};
use sparkbridge_validation::derive_run_status;

use crate::{ApiError, AppState, create_action_internal, create_candidate_internal, unix_ms};

pub async fn run_task(state: &AppState, task_id: &str, requested_steps: u32) -> Result<TaskRunResponse, ApiError> {
    let max_steps = requested_steps.clamp(1, state.config.agent_max_run_steps);
    let mut task = state.store.get_task(task_id).map_err(not_found)?;
    let mut steps = 0u32;

    while steps < max_steps {
        if task.status.terminal() || task.status == TaskStatus::Paused { break; }
        let now = unix_ms();

        if task.status == TaskStatus::Created {
            task.status = TaskStatus::Running;
            task.started_unix_ms = Some(now);
            task.updated_unix_ms = now;
            state.store.save_task_event(&task, TaskEventKind::TaskStarted, json!({}), now).map_err(crate::internal_error)?;
            steps += 1;
            continue;
        }

        if task.status == TaskStatus::WaitingForAction {
            if !task.pending_action_ids.is_empty() {
                let mut actions=Vec::new();
                for action_id in &task.pending_action_ids { actions.push(state.store.get_action(action_id).map_err(crate::internal_error)?); }
                if actions.iter().any(|action| !matches!(action.status, ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Cancelled | ActionStatus::TimedOut | ActionStatus::Lost)) { break; }
                let all_succeeded=actions.iter().all(|action|action.status==ActionStatus::Succeeded);
                task.last_action_status=if all_succeeded{Some(ActionStatus::Succeeded)}else{actions.iter().find(|a|a.status!=ActionStatus::Succeeded).map(|a|a.status)};
                let mut evidence=String::new(); let mut paths=Vec::new();
                for action in &actions {
                    evidence.push_str(&format_action_evidence(action)); evidence.push_str("\n---\n");
                    if let Some(result)=&action.result { paths.extend(result.diagnostics.iter().filter_map(|d|d.file.clone())); }
                }
                paths.sort(); paths.dedup(); task.evidence_paths=paths; task.last_evidence=Some(evidence);
                let observed_ids=task.pending_action_ids.clone();
                if let Some(candidate_id)=task.current_candidate_id.clone() { persist_task_validation_run(state,&task,&candidate_id)?; }
                task.pending_action_ids.clear(); task.pending_action_id=None;
                if all_succeeded { task.validation_index=task.spec.validation_actions.len(); } else { task.counters.repair_cycles=task.counters.repair_cycles.saturating_add(1); task.validation_index=0; }
                task.status=TaskStatus::Running; task.updated_unix_ms=now;
                state.store.save_task_event(&task,TaskEventKind::ActionObserved,json!({"action_ids":observed_ids,"fanout":true,"all_succeeded":all_succeeded}),now).map_err(crate::internal_error)?;
                steps+=1; continue;
            }
            let Some(action_id) = task.pending_action_id.clone() else {
                task.status = TaskStatus::Running;
                task.updated_unix_ms = now;
                state.store.save_task_event(&task, TaskEventKind::Recovered, json!({"reason":"waiting task had no pending action"}), now).map_err(crate::internal_error)?;
                steps += 1;
                continue;
            };
            let action = state.store.get_action(&action_id).map_err(crate::internal_error)?;
            if !matches!(action.status, ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Cancelled | ActionStatus::TimedOut | ActionStatus::Lost) {
                break;
            }
            task.pending_action_id = None;
            task.last_action_status = Some(action.status);
            task.last_evidence = Some(format_action_evidence(&action));
            task.evidence_paths = action.result.as_ref().map(|result| {
                let mut paths: Vec<String> = result.diagnostics.iter().filter_map(|d| d.file.clone()).collect();
                paths.sort(); paths.dedup(); paths
            }).unwrap_or_default();
            if action.status == ActionStatus::Succeeded {
                task.validation_index = task.validation_index.saturating_add(1);
                task.status = TaskStatus::Running;
            } else {
                task.counters.repair_cycles = task.counters.repair_cycles.saturating_add(1);
                task.validation_index = 0;
                task.status = TaskStatus::Running;
            }
            if (action.status != ActionStatus::Succeeded || task.validation_index >= task.spec.validation_actions.len())
                && task.current_candidate_id.is_some()
            {
                let candidate_id = task.current_candidate_id.clone().expect("checked candidate");
                persist_task_validation_run(state, &task, &candidate_id)?;
            }
            task.updated_unix_ms = now;
            state.store.save_task_event(
                &task, TaskEventKind::ActionObserved,
                json!({"action_id": action_id, "status": action.status, "result": action.result}), now,
            ).map_err(crate::internal_error)?;
            steps += 1;

            if action.status == ActionStatus::Succeeded
                && task.current_candidate_id.is_some()
                && task.validation_index < task.spec.validation_actions.len()
            {
                schedule_validation_dispatch(state, &mut task).await?;
                steps += 1;
                break;
            }
            continue;
        }

        if let Some(reason) = budget_violation(&task, now) {
            task.status = TaskStatus::BudgetExceeded;
            task.last_error = Some(reason.clone());
            task.completed_unix_ms = Some(now);
            task.updated_unix_ms = now;
            state.store.save_task_event(&task, TaskEventKind::BudgetExceeded, json!({"reason":reason}), now).map_err(crate::internal_error)?;
            steps += 1;
            break;
        }

        let policy = crate::workspace_policy_for(state, &task.spec.workspace_id)?;
        let principal = state.store.get_principal(&task.spec.principal_id)
            .map_err(|error| (StatusCode::FORBIDDEN, format!("task principal unavailable: {error}")))?;
        if policy_authorize_workspace(&principal, &policy, Permission::Read) == PolicyDecision::Deny {
            task.status = TaskStatus::Paused;
            task.last_error = Some("task principal no longer has read access to this workspace".into());
            task.updated_unix_ms = now;
            state.store.save_task_event(&task, TaskEventKind::TaskPaused, json!({"reason":task.last_error,"principal_id":task.spec.principal_id}), now).map_err(crate::internal_error)?;
            break;
        }
        let effective = effective_classification(task.spec.data_classification, policy.classification);
        let boundary = match state.config.inference_data_boundary.as_str() {
            "private_remote" => InferenceDataBoundary::PrivateRemote,
            "public_cloud" => InferenceDataBoundary::PublicCloud,
            _ => InferenceDataBoundary::LocalOnly,
        };
        if !classification_allows_boundary(effective, boundary) {
            task.status = TaskStatus::Paused;
            task.last_error = Some(format!("data-boundary policy blocks {:?} task context from {:?} inference provider", effective, boundary));
            task.updated_unix_ms = now;
            state.store.save_task_event(&task, TaskEventKind::TaskPaused, json!({"reason":task.last_error,"classification":effective,"provider_boundary":boundary}), now).map_err(crate::internal_error)?;
            break;
        }
        let bundle = compile_context(state, &task)?;
        let context_bytes = serde_json::to_vec(&bundle).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let context_info = state.cas.put_bytes(None, &context_bytes).map_err(crate::internal_error)?;
        task.last_context_digest = Some(context_info.digest.0.clone());
        task.updated_unix_ms = now;
        state.store.save_task_event(&task, TaskEventKind::ContextCompiled, json!({"digest":context_info.digest.0,"secret_findings":bundle.secret_findings.len(),"classification":bundle.effective_classification}), now).map_err(crate::internal_error)?;

        task.counters.model_calls = task.counters.model_calls.saturating_add(1);
        task.updated_unix_ms = unix_ms();
        state.store.save_task_event(&task, TaskEventKind::ModelRequested, json!({"model":task.spec.model,"context_digest":task.last_context_digest}), task.updated_unix_ms).map_err(crate::internal_error)?;

        let prompt = user_prompt(&bundle).map_err(crate::internal_error)?;
        let response = match state.inference.agent_chat_json(&task.spec.model, system_prompt(), &prompt).await {
            Ok(value) => value,
            Err((_status, message)) => {
                task.status = TaskStatus::Paused;
                task.last_error = Some(format!("inference temporarily unavailable: {message}"));
                task.updated_unix_ms = unix_ms();
                state.store.save_task_event(&task, TaskEventKind::TaskPaused, json!({"reason":task.last_error}), task.updated_unix_ms).map_err(crate::internal_error)?;
                break;
            }
        };
        let content = response.get("message").and_then(|v| v.get("content")).and_then(Value::as_str)
            .ok_or_else(|| (StatusCode::BAD_GATEWAY, "Ollama agent response did not contain message.content".into()))?;
        let directive = match parse_directive(content) {
            Ok(directive) => directive,
            Err(error) => {
                task.status = TaskStatus::Paused;
                task.last_error = Some(format!("invalid model directive: {error:#}"));
                task.updated_unix_ms = unix_ms();
                state.store.save_task_event(&task, TaskEventKind::TaskPaused, json!({"reason":task.last_error}), task.updated_unix_ms).map_err(crate::internal_error)?;
                break;
            }
        };
        task.updated_unix_ms = unix_ms();
        state.store.save_task_event(&task, TaskEventKind::ModelResponded, serde_json::to_value(&directive).unwrap_or_else(|_| json!({})), task.updated_unix_ms).map_err(crate::internal_error)?;
        steps += 1;

        match directive {
            AgentDirective::Candidate { description, operations } => {
                if task.counters.candidates >= task.spec.budgets.max_candidates {
                    continue;
                }
                if state.config.context_secret_scan_enabled {
                    let mut secret_hits = Vec::new();
                    for operation in &operations {
                        let content = match operation {
                            AgentFileOperation::CreateFile { content, .. } | AgentFileOperation::ModifyFile { content, .. } => Some(content.as_str()),
                            _ => None,
                        };
                        if let Some(content) = content {
                            secret_hits.extend(scan_and_redact(content).findings);
                        }
                    }
                    if !secret_hits.is_empty() {
                        task.counters.repair_cycles = task.counters.repair_cycles.saturating_add(1);
                        task.last_evidence = Some(format!("candidate rejected: secret scanner detected {} sensitive-looking value(s); use secret references instead of writing credentials into source", secret_hits.len()));
                        task.updated_unix_ms = unix_ms();
                        state.store.save_task_event(&task, TaskEventKind::CandidateRejected, json!({"reason":"secret_scanner","findings":secret_hits}), task.updated_unix_ms).map_err(crate::internal_error)?;
                        continue;
                    }
                }
                let request = CandidateCreateRequest {
                    base_snapshot_id: task.spec.base_snapshot_id.clone(),
                    description,
                    operations: translate_agent_operations(operations),
                };
                let candidate = match create_candidate_internal(state, request, &task.spec.principal_id) {
                    Ok(candidate) => candidate,
                    Err((_status, message)) => {
                        task.counters.repair_cycles = task.counters.repair_cycles.saturating_add(1);
                        task.last_evidence = Some(format!("candidate rejected by deterministic validator: {message}"));
                        task.updated_unix_ms = unix_ms();
                        state.store.save_task_event(&task, TaskEventKind::CandidateRejected, json!({"reason":message}), task.updated_unix_ms).map_err(crate::internal_error)?;
                        continue;
                    }
                };
                task.current_candidate_id = Some(candidate.candidate_id.clone());
                task.counters.candidates = task.counters.candidates.saturating_add(1);
                task.validation_index = 0;
                task.validation_action_ids.clear();
                task.pending_action_id = None;
                task.pending_action_ids.clear();
                task.last_action_status = None;
                task.status = TaskStatus::Running;
                task.updated_unix_ms = unix_ms();
                state.store.save_task_event(&task, TaskEventKind::CandidateCreated, serde_json::to_value(&candidate).unwrap_or_else(|_| json!({})), task.updated_unix_ms).map_err(crate::internal_error)?;
                if !task.spec.validation_actions.is_empty() {
                    schedule_validation_dispatch(state, &mut task).await?;
                    steps += 1;
                    break;
                }
            }
            AgentDirective::RunValidation => {
                if task.current_candidate_id.is_none() {
                    task.last_evidence = Some("model requested validation before creating a candidate".into());
                    continue;
                }
                if task.validation_index >= task.spec.validation_actions.len() {
                    task.last_evidence = Some("all configured validation actions have already passed; complete the task or create a new candidate".into());
                    continue;
                }
                schedule_validation_dispatch(state, &mut task).await?;
                steps += 1;
                break;
            }
            AgentDirective::Complete { summary } => {
                if task.spec.require_candidate && task.current_candidate_id.is_none() {
                    task.last_evidence = Some("completion rejected: task requires a candidate".into());
                    continue;
                }
                if task.spec.require_validation && !task.spec.validation_actions.is_empty()
                    && task.validation_index < task.spec.validation_actions.len()
                {
                    task.last_evidence = Some("completion rejected: required validation has not fully passed".into());
                    continue;
                }
                task.status = TaskStatus::Completed;
                task.summary = Some(summary.clone());
                task.completed_unix_ms = Some(unix_ms());
                task.updated_unix_ms = task.completed_unix_ms.unwrap_or(now);
                state.store.save_task_event(&task, TaskEventKind::TaskCompleted, json!({"summary":summary,"candidate_id":task.current_candidate_id}), task.updated_unix_ms).map_err(crate::internal_error)?;
                break;
            }
            AgentDirective::Pause { reason } => {
                task.status = TaskStatus::Paused;
                task.last_error = Some(reason.clone());
                task.updated_unix_ms = unix_ms();
                state.store.save_task_event(&task, TaskEventKind::TaskPaused, json!({"reason":reason}), task.updated_unix_ms).map_err(crate::internal_error)?;
                break;
            }
            AgentDirective::Fail { reason } => {
                task.status = TaskStatus::Failed;
                task.last_error = Some(reason.clone());
                task.completed_unix_ms = Some(unix_ms());
                task.updated_unix_ms = task.completed_unix_ms.unwrap_or(now);
                state.store.save_task_event(&task, TaskEventKind::TaskFailed, json!({"reason":reason}), task.updated_unix_ms).map_err(crate::internal_error)?;
                break;
            }
        }
    }

    let waiting = task.status == TaskStatus::WaitingForAction;
    Ok(TaskRunResponse { task, steps_performed: steps, waiting })
}

fn persist_task_validation_run(state: &AppState, task: &TaskRecord, candidate_id: &str) -> Result<(), ApiError> {
    if task.validation_action_ids.is_empty() { return Ok(()); }
    let mut targets = Vec::new();
    for (index, action_id) in task.validation_action_ids.iter().enumerate() {
        let action = state.store.get_action(action_id).map_err(crate::internal_error)?;
        let template = task.spec.validation_actions.get(index);
        let name = template.and_then(|value| value.name.clone()).unwrap_or_else(|| format!("validation-{}", index + 1));
        let platform = template.and_then(|value| value.platform.clone())
            .or_else(|| action.spec.required_platform.clone()).unwrap_or_else(|| "unspecified".into());
        let architecture = template.and_then(|value| value.architecture.clone()).or_else(|| action.spec.required_architecture.clone());
        targets.push(ValidationTargetRecord { name, platform, architecture, node_id: action.assigned_node_id, action_id: action.action_id.clone(), status: action.status, cache_hit: action.cache_hit });
    }
    let status = derive_run_status(&targets);
    let now = unix_ms();
    let completed_unix_ms = matches!(status, ValidationRunStatus::Succeeded | ValidationRunStatus::Failed | ValidationRunStatus::Cancelled).then_some(now);
    let record = ValidationRunRecord {
        validation_id: format!("task:{}:candidate:{}", task.task_id, candidate_id),
        principal_id: task.spec.principal_id.clone(),
        workspace_id: task.spec.workspace_id.clone(),
        candidate_id: candidate_id.to_owned(),
        status, targets, created_unix_ms: task.created_unix_ms, completed_unix_ms,
    };
    state.store.save_validation_run(&record).map_err(crate::internal_error)?;
    Ok(())
}

async fn schedule_validation_dispatch(state:&AppState,task:&mut TaskRecord)->Result<(),ApiError>{
    if task.spec.validation_fanout { schedule_validation_fanout(state,task).await } else { schedule_validation(state,task).await }
}

async fn schedule_validation_fanout(state:&AppState,task:&mut TaskRecord)->Result<(),ApiError>{
    let remaining=task.spec.validation_actions.len().saturating_sub(task.validation_index);
    if remaining==0 { return Ok(()); }
    if task.counters.actions.saturating_add(remaining as u32)>task.spec.budgets.max_actions {
        let now=unix_ms(); task.status=TaskStatus::BudgetExceeded; task.last_error=Some("action budget exceeded before validation fan-out".into()); task.completed_unix_ms=Some(now); task.updated_unix_ms=now;
        state.store.save_task_event(task,TaskEventKind::BudgetExceeded,json!({"reason":task.last_error}),now).map_err(crate::internal_error)?; return Ok(());
    }
    let candidate_id=task.current_candidate_id.clone().ok_or_else(||(StatusCode::CONFLICT,"task has no candidate to validate".into()))?;
    let mut created=Vec::new();
    for (index,template) in task.spec.validation_actions.iter().enumerate().skip(task.validation_index) {
        let spec=ActionSpec{principal_id:task.spec.principal_id.clone(),workspace_id:task.spec.workspace_id.clone(),candidate_id:Some(candidate_id.clone()),origin_task_id:Some(task.task_id.clone()),domain:template.domain.clone(),required_platform:template.platform.clone(),required_architecture:template.architecture.clone(),argv:template.argv.clone(),relative_cwd:template.relative_cwd.clone(),env:BTreeMap::new(),secret_injections:template.secret_injections.clone(),declared_hosts:template.declared_hosts.clone(),timeout_ms:template.timeout_ms,max_output_bytes:template.max_output_bytes,side_effect:ActionSideEffect::Pure,network_policy:template.network_policy,cache_trust:template.cache_trust,required_capabilities:template.required_capabilities.clone()};
        match create_action_internal(state,ActionCreateRequest{target_node_id:None,spec}){
            Ok(action)=>created.push((index,action)),
            Err((_status,message))=>{ for (_,action) in &created { let _=state.store.cancel_action(&action.action_id,unix_ms()); } let now=unix_ms(); task.status=TaskStatus::Paused; task.last_error=Some(format!("validation fan-out scheduling paused: {message}")); task.updated_unix_ms=now; state.store.save_task_event(task,TaskEventKind::TaskPaused,json!({"reason":task.last_error}),now).map_err(crate::internal_error)?; return Ok(()); }
        }
    }
    task.pending_action_ids=created.iter().map(|(_,a)|a.action_id.clone()).collect();
    for action_id in &task.pending_action_ids {
        if !task.validation_action_ids.contains(action_id) { task.validation_action_ids.push(action_id.clone()); }
    }
    task.pending_action_id=None; task.status=TaskStatus::WaitingForAction; task.counters.actions=task.counters.actions.saturating_add(created.len() as u32); task.updated_unix_ms=unix_ms();
    state.store.save_task_event(task,TaskEventKind::ActionScheduled,json!({"action_ids":task.pending_action_ids,"candidate_id":candidate_id,"fanout":true}),task.updated_unix_ms).map_err(crate::internal_error)?; Ok(())
}

async fn schedule_validation(state: &AppState, task: &mut TaskRecord) -> Result<(), ApiError> {
    if task.counters.actions >= task.spec.budgets.max_actions {
        let now = unix_ms();
        task.status = TaskStatus::BudgetExceeded;
        task.last_error = Some("action budget exceeded before validation scheduling".into());
        task.completed_unix_ms = Some(now);
        task.updated_unix_ms = now;
        state.store.save_task_event(task, TaskEventKind::BudgetExceeded, json!({"reason":task.last_error}), now).map_err(crate::internal_error)?;
        return Ok(());
    }
    let template = task.spec.validation_actions.get(task.validation_index)
        .ok_or_else(|| (StatusCode::CONFLICT, "no validation action remains".into()))?;
    let candidate_id = task.current_candidate_id.clone().ok_or_else(|| (StatusCode::CONFLICT, "task has no candidate to validate".into()))?;
    let spec = ActionSpec {
        principal_id: task.spec.principal_id.clone(), workspace_id: task.spec.workspace_id.clone(), candidate_id: Some(candidate_id.clone()), origin_task_id: Some(task.task_id.clone()), domain: template.domain.clone(),
        required_platform: template.platform.clone(), required_architecture: template.architecture.clone(),
        argv: template.argv.clone(), relative_cwd: template.relative_cwd.clone(), env: BTreeMap::new(),
        secret_injections: template.secret_injections.clone(), declared_hosts: template.declared_hosts.clone(),
        timeout_ms: template.timeout_ms, max_output_bytes: template.max_output_bytes, side_effect: ActionSideEffect::Pure,
        network_policy: template.network_policy, cache_trust: template.cache_trust, required_capabilities: template.required_capabilities.clone(),
    };
    let action = match create_action_internal(state, ActionCreateRequest { target_node_id: None, spec }) {
        Ok(action) => action,
        Err((_status, message)) => {
            let now = unix_ms();
            task.status = TaskStatus::Paused;
            task.last_error = Some(format!("validation scheduling paused: {message}"));
            task.updated_unix_ms = now;
            state.store.save_task_event(task, TaskEventKind::TaskPaused, json!({"reason":task.last_error}), now).map_err(crate::internal_error)?;
            return Ok(());
        }
    };
    task.pending_action_id = Some(action.action_id.clone());
    if !task.validation_action_ids.iter().any(|id| id == &action.action_id) { task.validation_action_ids.push(action.action_id.clone()); }
    task.status = TaskStatus::WaitingForAction;
    task.counters.actions = task.counters.actions.saturating_add(1);
    task.updated_unix_ms = unix_ms();
    state.store.save_task_event(task, TaskEventKind::ActionScheduled, json!({"action_id":action.action_id,"candidate_id":candidate_id,"validation_index":task.validation_index}), task.updated_unix_ms).map_err(crate::internal_error)?;
    Ok(())
}

fn compile_context(state: &AppState, task: &TaskRecord) -> Result<ContextBundle, ApiError> {
    let snapshot_record = state.store.get_snapshot(&task.spec.base_snapshot_id).map_err(not_found)?;
    let manifest_bytes = state.cas.get_bytes(&Digest(snapshot_record.manifest_digest.clone()), state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?;
    let snapshot: WorkspaceSnapshot = serde_json::from_slice(&manifest_bytes).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let entry_map: BTreeMap<&str, _> = snapshot.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut overlay: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut candidate_summary = None;
    let mut candidate_paths = Vec::new();
    if let Some(candidate_id) = &task.current_candidate_id {
        let record = state.store.get_candidate(candidate_id).map_err(crate::internal_error)?;
        let bytes = state.cas.get_bytes(&Digest(record.manifest_digest), state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?;
        let candidate: CandidateManifest = serde_json::from_slice(&bytes).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        candidate_summary = serde_json::to_value(&candidate).ok();
        for operation in candidate.operations {
            match operation {
                CandidateOperation::CreateFile { path, content_digest, .. } | CandidateOperation::ModifyFile { path, content_digest, .. } => {
                    candidate_paths.push(path.clone());
                    overlay.insert(path, Some(state.cas.get_bytes(&content_digest, state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?));
                }
                CandidateOperation::DeleteFile { path, .. } => { candidate_paths.push(path.clone()); overlay.insert(path, None); }
                CandidateOperation::RenameFile { from_path, to_path, expected_base_digest, .. } => {
                    candidate_paths.push(from_path.clone()); candidate_paths.push(to_path.clone());
                    overlay.insert(from_path, None);
                    overlay.insert(to_path, Some(state.cas.get_bytes(&expected_base_digest, state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?));
                }
                CandidateOperation::SetExecutable { path, .. } => { candidate_paths.push(path); }
            }
        }
    }

    let intelligence_query = format!(
        "{}\n{}\n{}",
        task.spec.objective,
        task.spec.acceptance_criteria.join("\n"),
        task.last_evidence.as_deref().unwrap_or("").chars().take(16_000).collect::<String>(),
    );
    let (ranked_paths, intelligence) = crate::repository::context_intelligence(state, &task.spec.base_snapshot_id, &intelligence_query)?;

    let mut source_files = Vec::new();
    let mut secret_findings: Vec<SecretFinding> = Vec::new();
    let mut used = 0usize;
    let mut requested_paths = Vec::new();
    for path in task.spec.context_paths.iter().chain(candidate_paths.iter()).chain(task.evidence_paths.iter()).chain(ranked_paths.iter()) {
        if !requested_paths.iter().any(|existing| existing == path) { requested_paths.push(path.clone()); }
    }
    for path in &requested_paths {
        if used >= state.config.agent_context_max_bytes { break; }
        let bytes = match overlay.get(path) {
            Some(Some(bytes)) => bytes.clone(),
            Some(None) => { source_files.push(ContextSourceFile { path:path.clone(), content:"<deleted in current candidate>".into(), truncated:false }); continue; }
            None => {
                let Some(entry) = entry_map.get(path.as_str()) else {
                    source_files.push(ContextSourceFile { path:path.clone(), content:"<path absent from base snapshot>".into(), truncated:false });
                    continue;
                };
                if entry.kind != EntryKind::File { continue; }
                let Some(digest) = &entry.digest else { continue; };
                state.cas.get_bytes(digest, state.config.cas_max_object_bytes as u64).map_err(crate::internal_error)?
            }
        };
        let remaining = state.config.agent_context_max_bytes.saturating_sub(used);
        let limit = remaining.min(state.config.agent_context_file_max_bytes);
        let take = bytes.len().min(limit);
        let mut content = String::from_utf8_lossy(&bytes[..take]).into_owned();
        if state.config.context_secret_scan_enabled {
            let result = scan_and_redact(&content);
            for mut finding in result.findings {
                finding.kind = format!("{}:{}", path, finding.kind);
                secret_findings.push(finding);
            }
            content = result.redacted;
        }
        source_files.push(ContextSourceFile { path:path.clone(), content, truncated: take < bytes.len() });
        used = used.saturating_add(take);
    }

    Ok(ContextBundle {
        format_version: 2, task_id: task.task_id.clone(), objective: task.spec.objective.clone(),
        acceptance_criteria: task.spec.acceptance_criteria.clone(), base_snapshot_id: task.spec.base_snapshot_id.clone(),
        current_candidate_id: task.current_candidate_id.clone(), source_files, candidate_summary,
        last_evidence: task.last_evidence.clone(), counters: task.counters.clone(), intelligence: Some(intelligence),
        secret_findings,
        effective_classification: effective_classification(task.spec.data_classification, crate::workspace_policy_for(state, &task.spec.workspace_id)?.classification),
    })
}

fn translate_agent_operations(operations: Vec<AgentFileOperation>) -> Vec<CandidateCreateOperationInput> {
    operations.into_iter().map(|operation| match operation {
        AgentFileOperation::CreateFile { path, content, executable } => CandidateCreateOperationInput::CreateFile { path, content_base64: BASE64.encode(content.as_bytes()), executable },
        AgentFileOperation::ModifyFile { path, content, executable } => CandidateCreateOperationInput::ModifyFile { path, content_base64: BASE64.encode(content.as_bytes()), executable },
        AgentFileOperation::DeleteFile { path } => CandidateCreateOperationInput::DeleteFile { path },
        AgentFileOperation::RenameFile { from_path, to_path, executable } => CandidateCreateOperationInput::RenameFile { from_path, to_path, executable },
        AgentFileOperation::SetExecutable { path, executable } => CandidateCreateOperationInput::SetExecutable { path, executable },
    }).collect()
}

fn format_action_evidence(action: &sparkbridge_protocol::ActionRecord) -> String {
    let Some(result) = &action.result else { return format!("action {} ended {:?} without a result payload", action.action_id, action.status); };
    let mut evidence = format!("action {} status={:?} exit={:?} duration_ms={} cache_hit={} toolchain={}\n", action.action_id, action.status, result.exit_code, result.duration_ms, action.cache_hit, action.toolchain_digest.as_deref().unwrap_or("unknown"));
    if !result.diagnostics.is_empty() {
        evidence.push_str("diagnostics:\n");
        for diagnostic in result.diagnostics.iter().take(64) { evidence.push_str(&format!("- {:?} {}:{}:{} {}\n", diagnostic.severity, diagnostic.file.as_deref().unwrap_or("?"), diagnostic.line.unwrap_or(0), diagnostic.column.unwrap_or(0), diagnostic.message)); }
    }
    if !result.stderr.is_empty() { evidence.push_str("stderr:\n"); evidence.push_str(&result.stderr.chars().take(16_000).collect::<String>()); }
    if result.stderr.is_empty() && !result.stdout.is_empty() { evidence.push_str("stdout:\n"); evidence.push_str(&result.stdout.chars().take(16_000).collect::<String>()); }
    evidence
}

fn not_found(error: anyhow::Error) -> ApiError { (StatusCode::NOT_FOUND, error.to_string()) }
