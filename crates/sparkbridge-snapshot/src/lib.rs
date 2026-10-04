use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sparkbridge_cas::{Cas, Digest};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Component, Path}, process::Command, time::UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum EntryKind { File, Directory, Symlink }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry { pub path: String, pub kind: EntryKind, pub digest: Option<Digest>, pub executable: bool, pub symlink_target: Option<String>, pub size_bytes: u64 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommitSummary { pub commit: String, pub author: String, pub authored_unix_seconds: i64, pub subject: String }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState { pub head: Option<String>, pub branch: Option<String>, pub index_fingerprint_sha256: Option<String>, pub dirty: bool, #[serde(default)] pub recent_commits: Vec<GitCommitSummary> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot { pub format_version: u32, pub root_name: String, pub entries: Vec<SnapshotEntry>, pub git: Option<GitState>, pub manifest_digest: Option<Digest> }

#[derive(Debug, Clone)]
pub struct SnapshotOptions { pub respect_gitignore: bool, pub include_hidden: bool, pub max_retries: u32, pub max_file_bytes: u64 }
impl Default for SnapshotOptions { fn default()->Self { Self { respect_gitignore:true, include_hidden:true, max_retries:3, max_file_bytes:128 * 1024 * 1024 } } }

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp { len:u64, modified_ns:u128, file_type:u8 }

pub fn snapshot_workspace(root: &Path, cas: &Cas, options: &SnapshotOptions) -> Result<WorkspaceSnapshot> {
    let root = root.canonicalize().with_context(|| format!("canonicalizing {}", root.display()))?;
    if !root.is_dir() { bail!("workspace root is not a directory"); }
    for attempt in 0..=options.max_retries {
        let git_before = git_state(&root);
        let before = scan_stamps(&root, options)?;
        let mut entries = build_entries(&root, cas, options)?;
        let after = scan_stamps(&root, options)?;
        let git_after = git_state(&root);
        if before == after && git_before == git_after {
            entries.sort_by(|a,b| a.path.cmp(&b.path));
            ensure_portable_paths(&entries)?;
            let git = git_after;
            let mut snapshot = WorkspaceSnapshot { format_version:1, root_name: root.file_name().and_then(|x| x.to_str()).unwrap_or("workspace").to_owned(), entries, git, manifest_digest:None };
            let canonical = serde_json::to_vec(&snapshot)?;
            let info = cas.put_bytes(None, &canonical)?;
            snapshot.manifest_digest = Some(info.digest);
            return Ok(snapshot);
        }
        if attempt == options.max_retries { bail!("SNAPSHOT_BUSY: workspace changed during every consistency scan"); }
    }
    unreachable!()
}

fn walker(root:&Path, options:&SnapshotOptions)->ignore::Walk {
    let mut b=WalkBuilder::new(root); b.add_custom_ignore_filename(".sparkbridgeignore"); b.hidden(!options.include_hidden).git_ignore(options.respect_gitignore).git_exclude(options.respect_gitignore).git_global(options.respect_gitignore).parents(options.respect_gitignore); b.build()
}

fn scan_stamps(root:&Path, options:&SnapshotOptions)->Result<BTreeMap<String,Stamp>> {
    let mut out=BTreeMap::new();
    for result in walker(root, options) { let e=result?; let p=e.path(); if p==root {continue;} let rel=logical_path(root,p)?; if excluded_path(&rel) { continue; } let m=fs::symlink_metadata(p)?; let t=if m.file_type().is_symlink(){2}else if m.is_dir(){1}else{0}; let ns=m.modified().ok().and_then(|t|t.duration_since(UNIX_EPOCH).ok()).map(|d|d.as_nanos()).unwrap_or(0); out.insert(rel,Stamp{len:m.len(),modified_ns:ns,file_type:t}); }
    Ok(out)
}

fn build_entries(root:&Path, cas:&Cas, options:&SnapshotOptions)->Result<Vec<SnapshotEntry>> {
    let mut out=Vec::new();
    for result in walker(root, options) { let e=result?; let p=e.path(); if p==root {continue;} let rel=logical_path(root,p)?; if excluded_path(&rel) { continue; } let m=fs::symlink_metadata(p)?;
        if m.file_type().is_symlink() { let target_path=fs::read_link(p)?; let target=target_path.to_str().ok_or_else(|| anyhow::anyhow!("NON_UTF8_SYMLINK_TARGET: {}", p.display()))?.to_owned(); out.push(SnapshotEntry{path:rel,kind:EntryKind::Symlink,digest:None,executable:false,symlink_target:Some(target),size_bytes:0}); continue; }
        if m.is_dir() { out.push(SnapshotEntry{path:rel,kind:EntryKind::Directory,digest:None,executable:false,symlink_target:None,size_bytes:0}); continue; }
        if m.is_file() { if m.len() > options.max_file_bytes { bail!("FILE_TOO_LARGE: {} is {} bytes (limit {})", rel, m.len(), options.max_file_bytes); } let bytes=fs::read(p)?; let info=cas.put_bytes(None,&bytes)?; out.push(SnapshotEntry{path:rel,kind:EntryKind::File,digest:Some(info.digest),executable:is_executable(&m),symlink_target:None,size_bytes:m.len()}); }
    }
    Ok(out)
}

fn logical_path(root:&Path,p:&Path)->Result<String>{ let rel=p.strip_prefix(root)?; let mut parts=Vec::new(); for c in rel.components(){match c{Component::Normal(x)=>parts.push(x.to_str().ok_or_else(|| anyhow::anyhow!("NON_UTF8_PATH: {}", rel.display()))?.to_owned()), _=>bail!("unsafe path component in {}",rel.display())}} Ok(parts.join("/")) }

fn excluded_path(rel:&str)->bool { rel == ".git" || rel.starts_with(".git/") || rel == ".sparkbridge" || rel.starts_with(".sparkbridge/") }

#[cfg(unix)] fn is_executable(m:&fs::Metadata)->bool { use std::os::unix::fs::PermissionsExt; m.permissions().mode() & 0o111 != 0 }
#[cfg(not(unix))] fn is_executable(_: &fs::Metadata)->bool { false }

fn ensure_portable_paths(entries:&[SnapshotEntry])->Result<()> { let mut folded=BTreeSet::new(); for e in entries { let key=e.path.to_lowercase(); if !folded.insert(key) { bail!("PLATFORM_PATH_COLLISION: {}",e.path); } for part in e.path.split('/') { let cleaned=part.trim_end_matches('.').trim_end_matches(' '); let stem=cleaned.split('.').next().unwrap_or(cleaned).to_ascii_uppercase(); if matches!(stem.as_str(),"CON"|"PRN"|"AUX"|"NUL"|"COM1"|"COM2"|"COM3"|"COM4"|"COM5"|"COM6"|"COM7"|"COM8"|"COM9"|"LPT1"|"LPT2"|"LPT3"|"LPT4"|"LPT5"|"LPT6"|"LPT7"|"LPT8"|"LPT9") { bail!("WINDOWS_RESERVED_PATH: {}",e.path); } } } Ok(()) }

fn git_state(root:&Path)->Option<GitState>{
    let run=|args:&[&str]| -> Option<String> { let o=Command::new("git").args(["-C",root.to_str()?]).args(args).output().ok()?; o.status.success().then(||String::from_utf8_lossy(&o.stdout).trim().to_owned()) };
    let head=run(&["rev-parse","HEAD"]); head.as_ref()?; let branch=run(&["branch","--show-current"]).filter(|s|!s.is_empty()); let index_listing=run(&["ls-files","--stage"]); let index_fingerprint_sha256=index_listing.map(|s| sparkbridge_cas::Digest::from_bytes(s.as_bytes()).0); let dirty=run(&["status","--porcelain=v1","--untracked-files=all"]).is_some_and(|s|!s.is_empty());
    let recent_commits=run(&["log","-n","32","--date=unix","--pretty=format:%H%x1f%an%x1f%at%x1f%s"]).map(|text| text.lines().filter_map(|line| { let mut parts=line.splitn(4,'\x1f'); Some(GitCommitSummary { commit:parts.next()?.to_owned(), author:parts.next()?.to_owned(), authored_unix_seconds:parts.next()?.parse().ok()?, subject:parts.next()?.to_owned() }) }).collect()).unwrap_or_default();
    Some(GitState{head,branch,index_fingerprint_sha256,dirty,recent_commits})
}


#[cfg(test)]
mod tests {
    use super::*;
    fn entry(path:&str)->SnapshotEntry { SnapshotEntry{path:path.into(),kind:EntryKind::File,digest:Some(Digest::from_bytes(path.as_bytes())),executable:false,symlink_target:None,size_bytes:1} }
    #[test] fn rejects_case_collisions(){ assert!(ensure_portable_paths(&[entry("Source/Foo.rs"),entry("source/foo.rs")]).is_err()); }
    #[test] fn rejects_windows_device_names_with_extensions(){ assert!(ensure_portable_paths(&[entry("docs/CON.txt")]).is_err()); }
    #[test] fn accepts_normal_portable_paths(){ ensure_portable_paths(&[entry("src/main.rs"),entry("README.md")]).unwrap(); }
}
