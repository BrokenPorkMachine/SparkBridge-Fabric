use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sparkbridge_protocol::{
    ActionExecutionResult, ActionSideEffect, ActionSpec, ActionNetworkPolicy, CacheTrust,
    ToolchainFingerprint,
};

/// Strong cache reuse is deliberately narrow. It may satisfy validation only when
/// inputs are immutable/closed enough for SparkBridge to defend the result.
pub fn validate_cache_request(spec: &ActionSpec) -> Result<()> {
    match spec.cache_trust {
        CacheTrust::Disabled => Ok(()),
        CacheTrust::BestEffort | CacheTrust::Strong => {
            if spec.side_effect != ActionSideEffect::Pure { bail!("only pure actions may be cached"); }
            if spec.candidate_id.is_none() { bail!("cached actions require an immutable candidate input"); }
            if !spec.secret_injections.is_empty() { bail!("cached actions do not permit secret-dependent inputs whose values are outside the cache key"); }
            if spec.cache_trust == CacheTrust::Strong && spec.network_policy != ActionNetworkPolicy::None {
                bail!("strong cache requires network=none so undeclared remote state cannot affect the result");
            }
            Ok(())
        }
    }
}

pub fn action_cache_key(spec: &ActionSpec, toolchain: &ToolchainFingerprint) -> Result<String> {
    validate_cache_request(spec)?;
    if spec.cache_trust == CacheTrust::Disabled { bail!("cache is disabled for this action"); }
    if spec.cache_trust == CacheTrust::Strong {
        if toolchain.digest.trim().is_empty() || toolchain.digest == "unavailable" { bail!("strong cache requires a valid toolchain fingerprint"); }
        for capability in spec.required_capabilities.iter().filter(|capability| !capability.contains(':')) {
            let Some(version) = toolchain.command_versions.get(capability) else { bail!("strong cache requires a fingerprinted tool capability: {capability}"); };
            if version.ends_with("|unknown") { bail!("strong cache refuses unknown tool version for {capability}"); }
        }
    }
    #[derive(Serialize)]
    struct Key<'a> {
        workspace_id: &'a str,
        candidate_id: &'a Option<String>,
        domain: &'a str,
        required_platform: &'a Option<String>,
        required_architecture: &'a Option<String>,
        argv: &'a [String],
        relative_cwd: &'a str,
        env: &'a std::collections::BTreeMap<String, String>,
        timeout_ms: u64,
        max_output_bytes: u64,
        declared_hosts: &'a [String],
        network_policy: ActionNetworkPolicy,
        required_capabilities: &'a [String],
        cache_trust: CacheTrust,
        toolchain_digest: &'a str,
    }
    let value = Key {
        workspace_id: &spec.workspace_id,
        candidate_id: &spec.candidate_id,
        domain: &spec.domain,
        required_platform: &spec.required_platform,
        required_architecture: &spec.required_architecture,
        argv: &spec.argv,
        relative_cwd: &spec.relative_cwd,
        env: &spec.env,
        timeout_ms: spec.timeout_ms,
        max_output_bytes: spec.max_output_bytes,
        declared_hosts: &spec.declared_hosts,
        network_policy: spec.network_policy,
        required_capabilities: &spec.required_capabilities,
        cache_trust: spec.cache_trust,
        toolchain_digest: &toolchain.digest,
    };
    canonical_hash(&value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedActionResultObject {
    pub format_version: u32,
    pub cache_key: String,
    pub source_action_id: String,
    pub toolchain_digest: String,
    pub result: ActionExecutionResult,
}

pub fn encode_cached_result(
    cache_key: &str,
    source_action_id: &str,
    toolchain_digest: &str,
    result: &ActionExecutionResult,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&CachedActionResultObject {
        format_version: 1,
        cache_key: cache_key.to_owned(),
        source_action_id: source_action_id.to_owned(),
        toolchain_digest: toolchain_digest.to_owned(),
        result: result.clone(),
    })?)
}

pub fn decode_cached_result(
    bytes: &[u8],
    expected_cache_key: &str,
    expected_toolchain_digest: &str,
) -> Result<ActionExecutionResult> {
    let object: CachedActionResultObject = serde_json::from_slice(bytes)?;
    if object.format_version != 1 { bail!("unsupported cached action result format {}", object.format_version); }
    if object.cache_key != expected_cache_key { bail!("cached action result cache-key mismatch"); }
    if object.toolchain_digest != expected_toolchain_digest { bail!("cached action result toolchain mismatch"); }
    Ok(object.result)
}

pub fn result_digest(result: &ActionExecutionResult) -> Result<String> {
    canonical_hash(result)
}

pub fn fingerprint_digest(fingerprint: &ToolchainFingerprint) -> Result<String> {
    #[derive(Serialize)]
    struct FingerprintKey<'a> {
        platform: &'a str,
        architecture: &'a str,
        domain: &'a str,
        executor_version: &'a str,
        command_versions: &'a std::collections::BTreeMap<String, String>,
        environment: &'a std::collections::BTreeMap<String, String>,
    }
    canonical_hash(&FingerprintKey {
        platform: &fingerprint.platform,
        architecture: &fingerprint.architecture,
        domain: &fingerprint.domain,
        executor_version: &fingerprint.executor_version,
        command_versions: &fingerprint.command_versions,
        environment: &fingerprint.environment,
    })
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    let canonical = canonical_json(&value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(v) => v.to_string(),
        serde_json::Value::Number(v) => v.to_string(),
        serde_json::Value::String(v) => serde_json::to_string(v).expect("serializable string"),
        serde_json::Value::Array(values) => format!("[{}]", values.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            format!("{{{}}}", entries.into_iter().map(|(k,v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json(v))).collect::<Vec<_>>().join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparkbridge_protocol::{ActionNetworkPolicy, ActionSideEffect, CacheTrust, ActionSpec};
    use std::collections::BTreeMap;

    fn strong_spec() -> ActionSpec {
        ActionSpec {
            principal_id: "local-admin".into(), workspace_id: "w".into(), candidate_id: Some("c".into()), origin_task_id: None,
            domain: "host".into(), required_platform: None, required_architecture: None, argv: vec!["cargo".into(), "test".into()], relative_cwd: ".".into(), env: BTreeMap::new(),
            secret_injections: vec![], declared_hosts: vec![], timeout_ms: 1000, max_output_bytes: 1024,
            side_effect: ActionSideEffect::Pure, network_policy: ActionNetworkPolicy::None, cache_trust: CacheTrust::Strong,
            required_capabilities: vec!["cargo".into()],
        }
    }

    #[test]
    fn strong_requires_closed_inputs() {
        let mut spec = strong_spec();
        assert!(validate_cache_request(&spec).is_ok());
        spec.network_policy = ActionNetworkPolicy::Unrestricted;
        assert!(validate_cache_request(&spec).is_err());
    }

    #[test]
    fn cached_result_envelope_binds_key_and_toolchain() {
        let result = ActionExecutionResult {
            exit_code: Some(0), duration_ms: 1, timed_out: false, cancelled: false,
            stdout: "ok".into(), stderr: String::new(), stdout_truncated: false, stderr_truncated: false, diagnostics: Vec::new(),
        };
        let bytes = encode_cached_result("key", "action", "toolchain", &result).expect("encode");
        let decoded = decode_cached_result(&bytes, "key", "toolchain").expect("decode");
        assert_eq!(decoded.exit_code, Some(0));
        assert!(decode_cached_result(&bytes, "other", "toolchain").is_err());
        assert!(decode_cached_result(&bytes, "key", "other").is_err());
    }
}
