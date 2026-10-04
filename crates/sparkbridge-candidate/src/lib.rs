use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sparkbridge_cas::{Cas, Digest};
use sparkbridge_snapshot::{EntryKind, SnapshotEntry, WorkspaceSnapshot};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CandidateOperation {
    CreateFile { path: String, content_digest: Digest, size_bytes: u64, executable: bool },
    ModifyFile { path: String, expected_base_digest: Digest, content_digest: Digest, size_bytes: u64, executable: bool },
    DeleteFile { path: String, expected_base_digest: Digest },
    RenameFile { from_path: String, to_path: String, expected_base_digest: Digest, executable: bool },
    SetExecutable { path: String, expected_base_digest: Digest, executable: bool },
}

impl CandidateOperation {
    pub fn referenced_content_digests(&self) -> Vec<&Digest> {
        match self {
            Self::CreateFile { content_digest, .. } | Self::ModifyFile { content_digest, .. } => vec![content_digest],
            _ => Vec::new(),
        }
    }
    pub fn touched_paths(&self) -> Vec<&str> {
        match self {
            Self::CreateFile { path, .. } | Self::ModifyFile { path, .. } | Self::DeleteFile { path, .. } | Self::SetExecutable { path, .. } => vec![path],
            Self::RenameFile { from_path, to_path, .. } => vec![from_path, to_path],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateManifest {
    pub format_version: u32,
    pub candidate_id: String,
    pub base_snapshot_id: String,
    pub base_manifest_digest: Digest,
    pub description: Option<String>,
    pub operations: Vec<CandidateOperation>,
    pub created_unix_ms: u64,
    pub manifest_digest: Option<Digest>,
}

impl CandidateManifest {
    pub fn store(mut self, cas: &Cas) -> Result<Self> {
        self.manifest_digest = None;
        let bytes = serde_json::to_vec(&self)?;
        self.manifest_digest = Some(cas.put_bytes(None, &bytes)?.digest);
        Ok(self)
    }
}

pub fn validate_candidate(base: &WorkspaceSnapshot, candidate: &CandidateManifest, cas: &Cas) -> Result<()> {
    if candidate.format_version != 1 { bail!("unsupported candidate format version {}", candidate.format_version); }
    if candidate.operations.is_empty() { bail!("candidate has no operations"); }
    if candidate.operations.len() > 10_000 { bail!("candidate operation count exceeds limit"); }
    let entries: BTreeMap<&str, &SnapshotEntry> = base.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut touched = BTreeSet::new();
    for op in &candidate.operations {
        for path in op.touched_paths() {
            validate_logical_path(path)?;
            let key = path.to_lowercase();
            if !touched.insert(key) { bail!("candidate touches a path more than once or case-collides: {path}"); }
        }
        match op {
            CandidateOperation::CreateFile { path, content_digest, size_bytes, .. } => {
                if entries.contains_key(path.as_str()) { bail!("create destination already exists in base snapshot: {path}"); }
                validate_content(cas, content_digest, *size_bytes)?;
            }
            CandidateOperation::ModifyFile { path, expected_base_digest, content_digest, size_bytes, .. } => {
                require_base_file(&entries, path, expected_base_digest)?;
                validate_content(cas, content_digest, *size_bytes)?;
            }
            CandidateOperation::DeleteFile { path, expected_base_digest } | CandidateOperation::SetExecutable { path, expected_base_digest, .. } => {
                require_base_file(&entries, path, expected_base_digest)?;
            }
            CandidateOperation::RenameFile { from_path, to_path, expected_base_digest, .. } => {
                require_base_file(&entries, from_path, expected_base_digest)?;
                if entries.contains_key(to_path.as_str()) { bail!("rename destination already exists in base snapshot: {to_path}"); }
            }
        }
    }
    Ok(())
}

fn require_base_file(entries: &BTreeMap<&str, &SnapshotEntry>, path: &str, expected: &Digest) -> Result<()> {
    let entry = entries.get(path).ok_or_else(|| anyhow::anyhow!("base path does not exist: {path}"))?;
    if entry.kind != EntryKind::File { bail!("base path is not a regular file: {path}"); }
    if entry.digest.as_ref() != Some(expected) { bail!("base digest mismatch for {path}"); }
    Ok(())
}

fn validate_content(cas: &Cas, digest: &Digest, size_bytes: u64) -> Result<()> {
    digest.hex()?;
    let info = cas.fsck_object(digest)?;
    if info.size_bytes != size_bytes { bail!("candidate content size mismatch for {}", digest.0); }
    Ok(())
}

pub fn validate_logical_path(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') { bail!("invalid logical path: {path}"); }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." { bail!("unsafe logical path: {path}"); }
        if component.chars().any(|c| c == '\0') { bail!("NUL in logical path"); }
        let cleaned = component.trim_end_matches(['.', ' ']);
        let stem = cleaned.split('.').next().unwrap_or(cleaned).to_ascii_uppercase();
        if matches!(stem.as_str(), "CON"|"PRN"|"AUX"|"NUL"|"COM1"|"COM2"|"COM3"|"COM4"|"COM5"|"COM6"|"COM7"|"COM8"|"COM9"|"LPT1"|"LPT2"|"LPT3"|"LPT4"|"LPT5"|"LPT6"|"LPT7"|"LPT8"|"LPT9") { bail!("Windows-reserved path: {path}"); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_parent_escape(){ assert!(validate_logical_path("../secret").is_err()); }
    #[test] fn rejects_backslash_paths(){ assert!(validate_logical_path("src\\main.rs").is_err()); }
    #[test] fn accepts_normal_path(){ validate_logical_path("src/main.rs").unwrap(); }
}
