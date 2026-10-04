use sparkbridge_protocol::{
    ActionNetworkPolicy, ActionSideEffect, DataClassification, InferenceDataBoundary, Permission,
    PolicyDecision, PrincipalRecord, WorkspacePolicyRecord,
};

pub fn classification_allows_boundary(
    classification: DataClassification,
    boundary: InferenceDataBoundary,
) -> bool {
    match classification {
        DataClassification::Public => true,
        DataClassification::Private => matches!(boundary, InferenceDataBoundary::LocalOnly | InferenceDataBoundary::PrivateRemote),
        DataClassification::Confidential | DataClassification::Restricted => matches!(boundary, InferenceDataBoundary::LocalOnly),
    }
}

pub fn effective_classification(a: DataClassification, b: DataClassification) -> DataClassification {
    a.max(b)
}

pub fn principal_has(principal: &PrincipalRecord, permission: Permission) -> bool {
    principal.enabled && principal.permissions.contains(&permission)
}

pub fn authorize_workspace(
    principal: &PrincipalRecord,
    policy: &WorkspacePolicyRecord,
    permission: Permission,
) -> PolicyDecision {
    if !principal.enabled || !principal_has(principal, permission) {
        return PolicyDecision::Deny;
    }
    if policy.allowed_principals.is_empty() {
        if principal.principal_id != "local-admin" { return PolicyDecision::Deny; }
    } else if !policy.allowed_principals.iter().any(|id| id == &principal.principal_id) {
        return PolicyDecision::Deny;
    }
    if policy.require_approval_for.contains(&permission) {
        return PolicyDecision::Ask;
    }
    PolicyDecision::Allow
}

pub fn evaluate_action(
    principal: &PrincipalRecord,
    policy: &WorkspacePolicyRecord,
    side_effect: ActionSideEffect,
    network_policy: ActionNetworkPolicy,
    secret_refs: &[String],
) -> (PolicyDecision, String) {
    let execute = authorize_workspace(principal, policy, Permission::Execute);
    if execute == PolicyDecision::Deny {
        return (PolicyDecision::Deny, "principal is not authorized to execute in this workspace".into());
    }

    if !secret_refs.is_empty() {
        if !principal_has(principal, Permission::UseSecret) {
            return (PolicyDecision::Deny, "principal is not authorized to use secrets".into());
        }
        if policy.allowed_secret_refs.is_empty()
            || secret_refs.iter().any(|reference| !policy.allowed_secret_refs.iter().any(|allowed| allowed == reference))
        {
            return (PolicyDecision::Deny, "one or more requested secret references are not explicitly allowed for this workspace".into());
        }
        return (PolicyDecision::Ask, "action requests one or more secret injections".into());
    }

    if network_policy == ActionNetworkPolicy::Unrestricted && policy.classification >= DataClassification::Confidential {
        return (PolicyDecision::Ask, "confidential/restricted workspace action requests unrestricted network access".into());
    }

    match side_effect {
        ActionSideEffect::Pure => {
            if execute == PolicyDecision::Ask {
                (PolicyDecision::Ask, "workspace policy requires approval for execution".into())
            } else {
                (PolicyDecision::Allow, "pure action allowed by workspace policy".into())
            }
        }
        ActionSideEffect::WorkspaceMutation => (PolicyDecision::Ask, "workspace mutation requires explicit approval".into()),
        ActionSideEffect::ExternalSideEffect => (PolicyDecision::Ask, "external side effect requires explicit approval".into()),
        ActionSideEffect::PrivilegedSideEffect => (PolicyDecision::Ask, "privileged side effect requires explicit approval".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparkbridge_protocol::PrincipalKind;

    fn admin() -> PrincipalRecord {
        PrincipalRecord {
            principal_id: "local-admin".into(),
            display_name: "Local Administrator".into(),
            kind: PrincipalKind::Human,
            enabled: true,
            permissions: vec![Permission::Execute, Permission::UseSecret],
            created_unix_ms: 1,
        }
    }

    fn policy() -> WorkspacePolicyRecord {
        WorkspacePolicyRecord {
            workspace_id: "repo".into(),
            classification: DataClassification::Private,
            allowed_principals: vec!["local-admin".into()],
            allowed_secret_refs: vec!["github-token".into()],
            require_approval_for: vec![],
            required_validation_platforms: vec![],
            updated_unix_ms: 1,
        }
    }

    #[test]
    fn local_only_accepts_restricted_data() {
        assert!(classification_allows_boundary(DataClassification::Restricted, InferenceDataBoundary::LocalOnly));
        assert!(!classification_allows_boundary(DataClassification::Restricted, InferenceDataBoundary::PublicCloud));
    }

    #[test]
    fn secret_use_requires_approval() {
        let (decision, _) = evaluate_action(&admin(), &policy(), ActionSideEffect::Pure, ActionNetworkPolicy::None, &["github-token".into()]);
        assert_eq!(decision, PolicyDecision::Ask);
    }

    // Call sites without an approval workflow must require `Allow`, not merely "not Deny".
    // These tests pin the distinction so `require_approval_for` cannot silently no-op.
    #[test]
    fn require_approval_for_yields_ask_rather_than_allow() {
        let reader = PrincipalRecord {
            permissions: vec![Permission::Read, Permission::CandidateCreate],
            ..admin()
        };
        let gated = WorkspacePolicyRecord { require_approval_for: vec![Permission::Read], ..policy() };
        assert_eq!(authorize_workspace(&reader, &gated, Permission::Read), PolicyDecision::Ask);
        // Other permissions are unaffected.
        assert_eq!(authorize_workspace(&reader, &gated, Permission::CandidateCreate), PolicyDecision::Allow);

        let gated_create = WorkspacePolicyRecord { require_approval_for: vec![Permission::CandidateCreate], ..policy() };
        assert_eq!(authorize_workspace(&reader, &gated_create, Permission::CandidateCreate), PolicyDecision::Ask);

        // A disabled principal or a missing permission is still a hard Deny.
        let disabled = PrincipalRecord { enabled: false, ..reader.clone() };
        assert_eq!(authorize_workspace(&disabled, &gated, Permission::Read), PolicyDecision::Deny);
        let no_read = PrincipalRecord { permissions: vec![Permission::Execute], ..reader };
        assert_eq!(authorize_workspace(&no_read, &gated, Permission::Read), PolicyDecision::Deny);
    }
}
