use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceFile {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub media_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationCheck {
    pub id: String,
    pub status: CheckStatus,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub evidence_files: Vec<EvidenceFile>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub runner: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub started_unix_ms: Option<u64>,
    #[serde(default)]
    pub finished_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricThreshold {
    pub metric: String,
    #[serde(default)]
    pub maximum: Option<f64>,
    #[serde(default)]
    pub minimum: Option<f64>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationProfile {
    pub format_version: u32,
    pub release: String,
    pub protocol: String,
    pub database_schema: u32,
    pub required_checks: Vec<String>,
    #[serde(default)]
    pub metric_thresholds: Vec<MetricThreshold>,
    #[serde(default)]
    pub require_source_revision: bool,
    #[serde(default)]
    pub require_evidence_for_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundleInput {
    pub name: String,
    pub sha256: String,
    #[serde(default)]
    pub source_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundleProvenance {
    #[serde(default)]
    pub runner: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub inputs: Vec<BundleInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationBundle {
    pub format_version: u32,
    pub release: String,
    pub protocol: String,
    pub database_schema: u32,
    pub generated_unix_ms: u64,
    #[serde(default)]
    pub bundle_id: Option<String>,
    #[serde(default)]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub provenance: BundleProvenance,
    pub checks: Vec<CertificationCheck>,
    #[serde(default)]
    pub metrics: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationReport {
    pub release_ready: bool,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
}

fn evidence_file_valid(file: &EvidenceFile) -> bool {
    file.sha256.len() == 64 && file.sha256.bytes().all(|c| c.is_ascii_hexdigit())
}

pub fn evaluate(profile: &CertificationProfile, bundle: &CertificationBundle) -> Result<CertificationReport> {
    if profile.format_version != 1 || bundle.format_version != 1 {
        bail!("unsupported certification format version");
    }

    let mut failures = Vec::new();
    let mut warnings = Vec::new();

    if profile.release != bundle.release {
        failures.push(format!(
            "release mismatch: expected {}, got {}",
            profile.release, bundle.release
        ));
    }
    if profile.protocol != bundle.protocol {
        failures.push(format!(
            "protocol mismatch: expected {}, got {}",
            profile.protocol, bundle.protocol
        ));
    }
    if profile.database_schema != bundle.database_schema {
        failures.push(format!(
            "schema mismatch: expected {}, got {}",
            profile.database_schema, bundle.database_schema
        ));
    }
    if profile.require_source_revision
        && bundle
            .source_revision
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        failures.push("missing required source_revision".into());
    }

    let mut by_id = BTreeMap::new();
    for check in &bundle.checks {
        if by_id.insert(check.id.as_str(), check).is_some() {
            failures.push(format!("duplicate check id: {}", check.id));
        }
        if let (Some(started), Some(finished)) = (check.started_unix_ms, check.finished_unix_ms) {
            if finished < started {
                failures.push(format!("check {} finished before it started", check.id));
            }
        }
        for file in &check.evidence_files {
            if !evidence_file_valid(file) {
                failures.push(format!("check {} has invalid evidence digest for {}", check.id, file.name));
            }
        }
    }

    let required: BTreeSet<_> = profile.required_checks.iter().map(String::as_str).collect();
    for id in required {
        match by_id.get(id) {
            None => failures.push(format!("missing required check: {id}")),
            Some(check) if check.status != CheckStatus::Pass => {
                failures.push(format!("required check {id} is {:?}", check.status));
            }
            Some(check)
                if profile.require_evidence_for_pass
                    && check.evidence.is_empty()
                    && check.evidence_files.is_empty() =>
            {
                failures.push(format!("required passing check {id} has no evidence"));
            }
            _ => {}
        }
    }

    for threshold in &profile.metric_thresholds {
        match bundle.metrics.get(&threshold.metric).copied() {
            None if threshold.required => {
                failures.push(format!("missing required metric: {}", threshold.metric));
            }
            None => warnings.push(format!("optional metric not reported: {}", threshold.metric)),
            Some(value) => {
                if !value.is_finite() {
                    failures.push(format!("metric {} is not finite", threshold.metric));
                    continue;
                }
                if let Some(maximum) = threshold.maximum {
                    if value > maximum {
                        failures.push(format!(
                            "metric {}={} exceeds maximum {}",
                            threshold.metric, value, maximum
                        ));
                    }
                }
                if let Some(minimum) = threshold.minimum {
                    if value < minimum {
                        failures.push(format!(
                            "metric {}={} below minimum {}",
                            threshold.metric, value, minimum
                        ));
                    }
                }
            }
        }
    }

    let passed = bundle
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::Pass)
        .count();
    let failed = bundle
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .count();
    let skipped = bundle
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::Skip)
        .count();

    Ok(CertificationReport {
        release_ready: failures.is_empty(),
        passed,
        failed,
        skipped,
        failures,
        warnings,
    })
}

pub fn candidate_profile() -> CertificationProfile {
    CertificationProfile {
        format_version: 1,
        release: "0.12.0".into(),
        protocol: "1.10".into(),
        database_schema: 9,
        required_checks: vec![
            "source.audit".into(),
            "rust.linux-x86_64".into(),
            "rust.linux-aarch64-dgx".into(),
            "rust.macos-arm64".into(),
            "rust.windows-x86_64".into(),
            "e2e.control-plane".into(),
            "e2e.agent-repair".into(),
            "fault.server-restart".into(),
            "fault.executor-disconnect".into(),
            "fault.ollama-restart".into(),
            "drill.backup-restore".into(),
            "drill.upgrade-rollback".into(),
            "compat.protocol-1.9".into(),
            "compat.protocol-1.10".into(),
            "security.audit-chain".into(),
        ],
        metric_thresholds: vec![
            MetricThreshold {
                metric: "gateway_local_overhead_p95_ms".into(),
                maximum: Some(25.0),
                minimum: None,
                required: false,
            },
            MetricThreshold {
                metric: "control_health_p95_ms".into(),
                maximum: Some(100.0),
                minimum: None,
                required: false,
            },
        ],
        require_source_revision: true,
        require_evidence_for_pass: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, status: CheckStatus, evidence: bool) -> CertificationCheck {
        CertificationCheck {
            id: id.into(),
            status,
            platform: None,
            evidence: if evidence { vec!["unit-test".into()] } else { vec![] },
            evidence_files: vec![],
            detail: None,
            runner: None,
            command: None,
            started_unix_ms: None,
            finished_unix_ms: None,
        }
    }

    fn profile() -> CertificationProfile {
        CertificationProfile {
            format_version: 1,
            release: "x".into(),
            protocol: "1.0".into(),
            database_schema: 1,
            required_checks: vec!["a".into()],
            metric_thresholds: vec![],
            require_source_revision: true,
            require_evidence_for_pass: true,
        }
    }

    fn bundle(checks: Vec<CertificationCheck>) -> CertificationBundle {
        CertificationBundle {
            format_version: 1,
            release: "x".into(),
            protocol: "1.0".into(),
            database_schema: 1,
            generated_unix_ms: 0,
            bundle_id: None,
            source_revision: Some("deadbeef".into()),
            provenance: BundleProvenance::default(),
            checks,
            metrics: BTreeMap::new(),
        }
    }

    #[test]
    fn required_skip_blocks_release() {
        let report = evaluate(&profile(), &bundle(vec![check("a", CheckStatus::Skip, true)])).unwrap();
        assert!(!report.release_ready);
    }

    #[test]
    fn all_required_pass_is_ready() {
        let report = evaluate(&profile(), &bundle(vec![check("a", CheckStatus::Pass, true)])).unwrap();
        assert!(report.release_ready);
    }

    #[test]
    fn missing_evidence_blocks_release() {
        let report = evaluate(&profile(), &bundle(vec![check("a", CheckStatus::Pass, false)])).unwrap();
        assert!(!report.release_ready);
    }

    #[test]
    fn missing_source_revision_blocks_release() {
        let mut bundle = bundle(vec![check("a", CheckStatus::Pass, true)]);
        bundle.source_revision = None;
        assert!(!evaluate(&profile(), &bundle).unwrap().release_ready);
    }
}
