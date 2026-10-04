use sparkbridge_protocol::{ActionRecord, ActionStatus, ValidationRunStatus, ValidationTargetRecord};
use std::collections::BTreeMap;

pub fn derive_run_status(targets: &[ValidationTargetRecord]) -> ValidationRunStatus {
    if targets.iter().any(|t| matches!(t.status, ActionStatus::Failed | ActionStatus::TimedOut | ActionStatus::Lost)) {
        return ValidationRunStatus::Failed;
    }
    if targets.iter().any(|t| t.status == ActionStatus::AwaitingApproval) {
        return ValidationRunStatus::AwaitingApproval;
    }
    if targets.iter().any(|t| t.status == ActionStatus::Cancelled) {
        return ValidationRunStatus::Cancelled;
    }
    if !targets.is_empty() && targets.iter().all(|t| t.status == ActionStatus::Succeeded) {
        return ValidationRunStatus::Succeeded;
    }
    ValidationRunStatus::Running
}

pub fn hydrate_targets(targets: &[ValidationTargetRecord], actions: &[ActionRecord]) -> Vec<ValidationTargetRecord> {
    let by_id: BTreeMap<&str, &ActionRecord> = actions.iter().map(|a| (a.action_id.as_str(), a)).collect();
    targets.iter().map(|target| {
        let mut out = target.clone();
        if let Some(action) = by_id.get(target.action_id.as_str()) {
            out.status = action.status;
            out.cache_hit = action.cache_hit;
        }
        out
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparkbridge_core::NodeId;
    fn t(status: ActionStatus) -> ValidationTargetRecord { ValidationTargetRecord { name:"x".into(), platform:"linux".into(), architecture:None, node_id:NodeId::new(), action_id:"a".into(), status, cache_hit:false } }
    #[test] fn succeeds_only_when_all_succeed() { assert_eq!(derive_run_status(&[t(ActionStatus::Succeeded)]), ValidationRunStatus::Succeeded); }
}
