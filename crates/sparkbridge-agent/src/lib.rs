use anyhow::{Context, Result, bail};
use sparkbridge_task::{AgentDirective, ContextBundle, TaskRecord, TaskStatus};

pub fn budget_violation(task: &TaskRecord, now_ms: u64) -> Option<String> {
    let budgets = &task.spec.budgets;
    let started = task.started_unix_ms.unwrap_or(task.created_unix_ms);
    if now_ms.saturating_sub(started) >= budgets.max_wall_time_ms {
        return Some(format!("wall-time budget exceeded ({} ms)", budgets.max_wall_time_ms));
    }
    if task.counters.model_calls >= budgets.max_model_calls {
        return Some(format!("model-call budget exceeded ({})", budgets.max_model_calls));
    }
    if task.counters.actions >= budgets.max_actions {
        return Some(format!("action budget exceeded ({})", budgets.max_actions));
    }
    if task.counters.candidates >= budgets.max_candidates {
        return Some(format!("candidate budget exceeded ({})", budgets.max_candidates));
    }
    if task.counters.repair_cycles >= budgets.max_repair_cycles {
        return Some(format!("repair-cycle budget exceeded ({})", budgets.max_repair_cycles));
    }
    None
}

pub fn system_prompt() -> &'static str {
    r#"You are SparkBridge's coding reasoning engine. SparkBridge, not you, owns state and execution.
Return exactly one JSON object and no prose outside it.
Allowed directives:
1) {"directive":"candidate","description":"...","operations":[...]}
2) {"directive":"run_validation"}
3) {"directive":"complete","summary":"..."}
4) {"directive":"pause","reason":"..."}
5) {"directive":"fail","reason":"..."}
Candidate operations are create_file, modify_file, delete_file, rename_file, set_executable.
For create_file/modify_file provide complete UTF-8 file content in the "content" field.
Every candidate must describe the complete desired delta against the immutable BASE snapshot, not a delta against the previous candidate.
Use repository intelligence (symbol matches, ranked paths, Git history) as evidence, but treat the supplied source file contents as authoritative. Use only paths justified by the supplied context/evidence. Do not invent shell commands: validation commands are controlled by TaskSpec.
Never emit, reconstruct, request, or write credentials, private keys, API tokens, passwords, connection strings, or other secret values. Secret values are never part of your context; when a validation action requires a credential, TaskSpec supplies an opaque secret reference that the executor resolves locally. Treat redaction markers and secret-finding metadata as evidence that sensitive material exists, not as an invitation to recover it.
If validation evidence reports a failure, repair the candidate. Do not claim completion before required validation passes."#
}

pub fn user_prompt(bundle: &ContextBundle) -> Result<String> {
    let json = serde_json::to_string_pretty(bundle).context("serializing context bundle")?;
    Ok(format!("TASK CONTEXT BUNDLE:\n{json}"))
}

pub fn parse_directive(raw: &str) -> Result<AgentDirective> {
    let trimmed = raw.trim();
    if trimmed.is_empty() { bail!("model returned an empty directive"); }
    if let Ok(value) = serde_json::from_str::<AgentDirective>(trimmed) { return Ok(value); }
    if let (Some(start), Some(end)) = (trimmed.find("{"), trimmed.rfind("}")) {
        if start < end {
            return serde_json::from_str::<AgentDirective>(&trimmed[start..=end]).context("decoding JSON directive from model response");
        }
    }
    bail!("model response did not contain a valid SparkBridge directive")
}

pub fn is_runnable(task: &TaskRecord) -> bool {
    !task.status.terminal() && task.status != TaskStatus::Paused
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_complete_directive() {
        let directive = parse_directive(r#"{"directive":"complete","summary":"done"}"#).unwrap();
        assert!(matches!(directive, AgentDirective::Complete { .. }));
    }
}
