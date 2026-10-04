use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sparkbridge_protocol::SecretInjection;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub kind: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionResult {
    pub redacted: String,
    pub findings: Vec<SecretFinding>,
}

pub fn scan_and_redact(input: &str) -> RedactionResult {
    let patterns: [(&str, &str); 7] = [
        ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("github_token", r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("generic_api_key", r#"(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-./+=]{12,}"#),
        ("bearer_token", r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*"),
        ("password_assignment", r#"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['"]?[^\s'"]{8,}"#),
        ("connection_string_secret", r"(?i)(password|pwd)=[^;\s]{4,}"),
    ];
    let mut redacted = input.to_owned();
    let mut findings = Vec::new();
    for (kind, raw) in patterns {
        let Ok(regex) = Regex::new(raw) else { continue; };
        let snapshot = redacted.clone();
        for found in regex.find_iter(&snapshot) {
            let line = snapshot[..found.start()].bytes().filter(|byte| *byte == b'\n').count() + 1;
            findings.push(SecretFinding { kind: kind.into(), line });
        }
        redacted = regex.replace_all(&redacted, format!("[REDACTED:{kind}]")).into_owned();
    }
    findings.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.kind.cmp(&b.kind)));
    findings.dedup_by(|a, b| a.line == b.line && a.kind == b.kind);
    RedactionResult { redacted, findings }
}

pub fn resolve_secret_injections(
    injections: &[SecretInjection],
    local_env_bindings: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut target_names = BTreeSet::new();
    for injection in injections {
        if injection.reference.trim().is_empty() || injection.env_name.trim().is_empty() {
            bail!("secret injection requires non-empty reference and env_name");
        }
        if !target_names.insert(injection.env_name.clone()) {
            bail!("duplicate secret target environment variable {:?}", injection.env_name);
        }
        let local_name = local_env_bindings.get(&injection.reference)
            .ok_or_else(|| anyhow::anyhow!("secret reference {:?} is not bound on this executor", injection.reference))?;
        let value = std::env::var(local_name)
            .map_err(|_| anyhow::anyhow!("executor environment variable {:?} for secret {:?} is unavailable", local_name, injection.reference))?;
        out.insert(injection.env_name.clone(), value);
    }
    Ok(out)
}

/// Scrub values that SparkBridge itself injected into the child process.
///
/// Every non-empty injected value is replaced. A minimum length would leave short secrets
/// (a PIN, a one-word passphrase) in stdout/stderr, which then flow into the action result,
/// the action cache, task events and finally the model prompt. The length guard was a
/// readability heuristic, not a safety property.
pub fn redact_known_values(mut text: String, values: impl IntoIterator<Item = String>) -> String {
    // Longest first, so a secret that contains another is replaced as a whole rather than
    // leaving a fragment behind.
    let mut ordered: Vec<String> = values.into_iter().filter(|value| !value.is_empty()).collect();
    ordered.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    for value in ordered {
        if text.contains(&value) {
            text = text.replace(&value, "[REDACTED:injected_secret]");
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_github_token_shape() {
        let result = scan_and_redact("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
        assert!(!result.findings.is_empty());
        assert!(!result.redacted.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }

    // Short injected secrets must not survive into action output, which reaches the cache,
    // task events and the model prompt.
    #[test]
    fn redacts_short_injected_values() {
        assert_eq!(
            redact_known_values("pin=7 and token=ab".into(), ["7".to_string(), "ab".to_string()]),
            "pin=[REDACTED:injected_secret] and token=[REDACTED:injected_secret]"
        );
        // Empty values must not turn into a blanket replacement.
        assert_eq!(redact_known_values("hello".into(), ["".to_string()]), "hello");
        // Overlapping values are replaced whole, longest first.
        assert_eq!(
            redact_known_values("value=hunter2hunter".into(), ["hunter2".to_string(), "hunter2hunter".to_string()]),
            "value=[REDACTED:injected_secret]"
        );
    }
}
