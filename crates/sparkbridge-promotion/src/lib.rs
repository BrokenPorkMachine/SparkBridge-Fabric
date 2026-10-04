use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sparkbridge_candidate::{CandidateManifest, CandidateOperation, validate_logical_path};
use sparkbridge_cas::{Cas, Digest};
use sparkbridge_snapshot::{EntryKind, SnapshotEntry, WorkspaceSnapshot};
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}, time::{Duration, SystemTime}};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionConflict { pub path: String, pub reason: String }

#[derive(Debug, Clone)]
pub enum PlannedChange {
    WriteFile { path: String, expected_current: Option<Digest>, content_digest: Digest, executable: bool },
    DeleteFile { path: String, expected_current: Digest },
    RenameFile { from_path: String, to_path: String, expected_current: Digest, executable: bool },
    SetExecutable { path: String, expected_current: Digest, executable: bool },
}

#[derive(Debug, Clone)]
pub struct PromotionPlan { pub candidate_id: String, pub changes: Vec<PlannedChange>, pub conflicts: Vec<PromotionConflict>, pub merged_files: usize }

pub fn plan_promotion(base: &WorkspaceSnapshot, current: &WorkspaceSnapshot, candidate: &CandidateManifest, cas: &Cas, merge_limit: usize) -> Result<PromotionPlan> {
    let base_map = file_map(base);
    let current_map = file_map(current);
    let current_entries = entry_map(current);
    let mut changes = Vec::new(); let mut conflicts = Vec::new(); let mut merged_files = 0usize;
    for op in &candidate.operations {
        match op {
            CandidateOperation::CreateFile { path, content_digest, executable, .. } => match current_entries.get(path.as_str()) {
                None => changes.push(PlannedChange::WriteFile { path:path.clone(), expected_current:None, content_digest:content_digest.clone(), executable:*executable }),
                Some(e) if e.digest.as_ref() == Some(content_digest) => {},
                _ => conflicts.push(conflict(path, "create destination exists in live workspace")),
            },
            CandidateOperation::ModifyFile { path, expected_base_digest, content_digest, executable, .. } => {
                match current_map.get(path.as_str()) {
                    Some(e) if e.digest.as_ref() == Some(expected_base_digest) => changes.push(PlannedChange::WriteFile { path:path.clone(), expected_current:Some(expected_base_digest.clone()), content_digest:content_digest.clone(), executable:*executable }),
                    Some(e) if e.kind == EntryKind::File => {
                        let Some(current_digest) = e.digest.as_ref() else { conflicts.push(conflict(path,"live file has no digest")); continue; };
                        let base_digest = base_map.get(path.as_str()).and_then(|x| x.digest.as_ref()).unwrap_or(expected_base_digest);
                        match merge_file(cas, base_digest, current_digest, content_digest, merge_limit) {
                            Ok(Some(merged)) => { let info=cas.put_bytes(None, merged.as_bytes())?; changes.push(PlannedChange::WriteFile { path:path.clone(), expected_current:Some(current_digest.clone()), content_digest:info.digest, executable:*executable }); merged_files+=1; },
                            Ok(None) => conflicts.push(conflict(path,"overlapping or non-text three-way changes")),
                            Err(e) => conflicts.push(conflict(path,&format!("merge failed: {e}"))),
                        }
                    }
                    _ => conflicts.push(conflict(path,"live path is missing or no longer a regular file")),
                }
            }
            CandidateOperation::DeleteFile { path, expected_base_digest } => match current_map.get(path.as_str()) {
                None => {},
                Some(e) if e.digest.as_ref() == Some(expected_base_digest) => changes.push(PlannedChange::DeleteFile { path:path.clone(), expected_current:expected_base_digest.clone() }),
                _ => conflicts.push(conflict(path,"live file changed since candidate base; refusing delete")),
            },
            CandidateOperation::RenameFile { from_path, to_path, expected_base_digest, executable } => {
                let source_ok=current_map.get(from_path.as_str()).is_some_and(|e|e.kind==EntryKind::File && e.digest.as_ref()==Some(expected_base_digest));
                let dest=current_entries.get(to_path.as_str());
                if source_ok && dest.is_none() { changes.push(PlannedChange::RenameFile { from_path:from_path.clone(), to_path:to_path.clone(), expected_current:expected_base_digest.clone(), executable:*executable }); }
                else if !current_map.contains_key(from_path.as_str()) && dest.is_some_and(|e| e.digest.as_ref()==Some(expected_base_digest)) { }
                else { conflicts.push(conflict(from_path,"rename source/destination diverged from candidate base")); }
            }
            CandidateOperation::SetExecutable { path, expected_base_digest, executable } => match current_map.get(path.as_str()) {
                Some(e) if e.digest.as_ref()==Some(expected_base_digest) => changes.push(PlannedChange::SetExecutable { path:path.clone(), expected_current:expected_base_digest.clone(), executable:*executable }),
                _ => conflicts.push(conflict(path,"live file changed since candidate base; refusing mode change")),
            },
        }
    }
    Ok(PromotionPlan { candidate_id:candidate.candidate_id.clone(), changes, conflicts, merged_files })
}

fn file_map(snapshot:&WorkspaceSnapshot)->BTreeMap<&str,&SnapshotEntry>{ snapshot.entries.iter().filter(|e|e.kind==EntryKind::File).map(|e|(e.path.as_str(),e)).collect() }
fn entry_map(snapshot:&WorkspaceSnapshot)->BTreeMap<&str,&SnapshotEntry>{ snapshot.entries.iter().map(|e|(e.path.as_str(),e)).collect() }
fn conflict(path:&str,reason:&str)->PromotionConflict{ PromotionConflict{path:path.into(),reason:reason.into()} }

fn merge_file(cas:&Cas, base:&Digest, current:&Digest, candidate:&Digest, limit:usize)->Result<Option<String>> {
    let base=cas.get_bytes(base,limit as u64)?; let current=cas.get_bytes(current,limit as u64)?; let candidate=cas.get_bytes(candidate,limit as u64)?;
    let (Ok(base),Ok(current),Ok(candidate))=(String::from_utf8(base),String::from_utf8(current),String::from_utf8(candidate)) else { return Ok(None); };
    if current==base { return Ok(Some(candidate)); }
    if candidate==base || current==candidate { return Ok(Some(current)); }
    Ok(conservative_three_way(&base,&current,&candidate))
}

pub fn conservative_three_way(base:&str,current:&str,candidate:&str)->Option<String>{
    let ours=single_change(base,current); let theirs=single_change(base,candidate);
    if ours.start == theirs.start { return None; }
    if ours.end <= theirs.start { return Some(apply_two(base,&ours,&theirs)); }
    if theirs.end <= ours.start { return Some(apply_two(base,&theirs,&ours)); }
    None
}

#[derive(Debug)] struct Change{start:usize,end:usize,replacement:String}
fn single_change(base:&str,new:&str)->Change{
    if base==new{return Change{start:0,end:0,replacement:String::new()};}
    let b=base.as_bytes(); let n=new.as_bytes(); let mut prefix=0; while prefix<b.len()&&prefix<n.len()&&b[prefix]==n[prefix]{prefix+=1;}
    while prefix>0 && !base.is_char_boundary(prefix){prefix-=1;}
    let mut bs=b.len(); let mut ns=n.len(); while bs>prefix&&ns>prefix&&b[bs-1]==n[ns-1]{bs-=1;ns-=1;}
    while bs<b.len()&&!base.is_char_boundary(bs){bs+=1;} while ns<n.len()&&!new.is_char_boundary(ns){ns+=1;}
    Change{start:prefix,end:bs,replacement:new[prefix..ns].to_owned()}
}
fn apply_two(base:&str,first:&Change,second:&Change)->String{ let mut out=String::new(); out.push_str(&base[..first.start]); out.push_str(&first.replacement); out.push_str(&base[first.end..second.start]); out.push_str(&second.replacement); out.push_str(&base[second.end..]); out }

#[derive(Debug, Clone, Serialize, Deserialize)] struct Journal{ transaction_id:String, candidate_id:String, state:String, backups:Vec<BackupRecord> }
#[derive(Debug, Clone, Serialize, Deserialize)] struct BackupRecord{ path:String, existed:bool, digest:Option<Digest>, executable:bool }

pub fn apply_transaction(workspace:&Path, plan:&PromotionPlan, cas:&Cas, _lock:&WorkspacePromotionLock)->Result<()> {
    if !plan.conflicts.is_empty(){bail!("promotion plan contains conflicts");}
    recover_incomplete_transactions(workspace,cas)?;
    let txid=Uuid::new_v4().to_string(); let txroot=workspace.join(".sparkbridge/transactions").join(&txid); fs::create_dir_all(txroot.join("backup"))?;
    let mut journal=Journal{transaction_id:txid,candidate_id:plan.candidate_id.clone(),state:"preparing".into(),backups:Vec::new()};
    let touched=collect_paths(&plan.changes); for path in touched { backup_path(workspace,&txroot,&path,cas,&mut journal)?; }
    write_journal(&txroot,&journal)?; journal.state="applying".into(); write_journal(&txroot,&journal)?;
    // The commit marker is part of the transaction. If it cannot be persisted the workspace
    // is not durably promoted, so it must roll back with the rest; reporting an error after
    // the live workspace was already mutated would leave the audit chain claiming failure
    // for a promotion that actually landed.
    let result=(||->Result<()> { for change in &plan.changes { apply_change(workspace,change,cas)?; } journal.state="committed".into(); write_journal(&txroot,&journal) })();
    match result { Ok(())=>{ let _ = fs::remove_dir_all(&txroot); Ok(())}, Err(error)=>{ let rollback=rollback(workspace,&txroot,&journal,cas); if rollback.is_ok(){journal.state="rolled_back".into();let _=write_journal(&txroot,&journal);} match rollback { Ok(())=>Err(error.context("promotion failed; rollback completed")), Err(rb)=>Err(error.context(format!("promotion failed and rollback also failed: {rb:#}"))) } } }
}

pub fn recover_incomplete_transactions(workspace:&Path,cas:&Cas)->Result<()> { let root=workspace.join(".sparkbridge/transactions"); if !root.is_dir(){return Ok(());} for e in fs::read_dir(&root)? { let dir=e?.path(); let jp=dir.join("journal.json"); if !jp.is_file(){continue;} let journal:Journal=serde_json::from_slice(&fs::read(&jp)?)?; if journal.state!="committed"&&journal.state!="rolled_back"{rollback(workspace,&dir,&journal,cas)?; let _=fs::remove_dir_all(dir);} } Ok(()) }

fn collect_paths(changes:&[PlannedChange])->Vec<String>{ let mut v=Vec::new(); for c in changes{match c{PlannedChange::WriteFile{path,..}|PlannedChange::DeleteFile{path,..}|PlannedChange::SetExecutable{path,..}=>v.push(path.clone()),PlannedChange::RenameFile{from_path,to_path,..}=>{v.push(from_path.clone());v.push(to_path.clone());}}} v.sort();v.dedup();v }
fn backup_path(workspace:&Path,txroot:&Path,logical:&str,cas:&Cas,journal:&mut Journal)->Result<()> { let p=safe_path(workspace,logical)?; if !p.exists(){journal.backups.push(BackupRecord{path:logical.into(),existed:false,digest:None,executable:false});return Ok(());} let m=fs::symlink_metadata(&p)?; if !m.is_file()||m.file_type().is_symlink(){bail!("refusing to transactionally modify non-regular file: {logical}");} let bytes=fs::read(&p)?; let info=cas.put_bytes(None,&bytes)?; let backup=txroot.join("backup").join(info.digest.hex()?); if !backup.exists(){fs::copy(&p,&backup)?;} journal.backups.push(BackupRecord{path:logical.into(),existed:true,digest:Some(info.digest),executable:is_executable(&m)}); Ok(()) }
fn write_journal(txroot:&Path,j:&Journal)->Result<()> { let tmp=txroot.join("journal.json.tmp"); let finalp=txroot.join("journal.json"); let bytes=serde_json::to_vec_pretty(j)?; let mut f=OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;f.write_all(&bytes)?;f.sync_all()?;drop(f);fs::rename(tmp,finalp)?;Ok(()) }
fn rollback(workspace:&Path,_txroot:&Path,j:&Journal,cas:&Cas)->Result<()> { for b in j.backups.iter().rev(){ let p=safe_path(workspace,&b.path)?; if b.existed { let digest=b.digest.as_ref().context("backup missing digest")?; let bytes=cas.get_bytes(digest,u64::MAX)?; atomic_write(&p,&bytes)?;set_executable(&p,b.executable)?; } else if p.exists(){ if p.is_dir(){fs::remove_dir_all(&p)?}else{fs::remove_file(&p)?} } } Ok(()) }
fn apply_change(workspace:&Path,c:&PlannedChange,cas:&Cas)->Result<()> { match c { PlannedChange::WriteFile{path,expected_current,content_digest,executable}=>{let p=safe_path(workspace,path)?;verify_expected(&p,expected_current.as_ref())?;let bytes=cas.get_bytes(content_digest,u64::MAX)?;atomic_write(&p,&bytes)?;set_executable(&p,*executable)}, PlannedChange::DeleteFile{path,expected_current}=>{let p=safe_path(workspace,path)?;verify_expected(&p,Some(expected_current))?;fs::remove_file(p)?;Ok(())}, PlannedChange::RenameFile{from_path,to_path,expected_current,executable}=>{let from=safe_path(workspace,from_path)?;let to=safe_path(workspace,to_path)?;verify_expected(&from,Some(expected_current))?;if to.exists(){bail!("rename destination appeared during promotion: {to_path}");}
            if let Some(parent)=to.parent(){fs::create_dir_all(parent)?;}fs::rename(&from,&to)?;set_executable(&to,*executable)}, PlannedChange::SetExecutable{path,expected_current,executable}=>{let p=safe_path(workspace,path)?;verify_expected(&p,Some(expected_current))?;set_executable(&p,*executable)} } }
fn verify_expected(path:&Path,expected:Option<&Digest>)->Result<()> { match expected { None=>{if path.exists(){bail!("path appeared during promotion: {}",path.display())}}, Some(expected)=>{let m=fs::symlink_metadata(path).with_context(||format!("expected live file missing: {}",path.display()))?;if !m.is_file()||m.file_type().is_symlink(){bail!("live path is not a regular file: {}",path.display());}let actual=Digest::from_bytes(&fs::read(path)?);if &actual!=expected{bail!("live file changed during promotion: {}",path.display());}} } Ok(()) }
fn safe_path(root:&Path,logical:&str)->Result<PathBuf>{validate_logical_path(logical)?;let mut p=root.to_path_buf();for part in logical.split('/'){if p.exists(){let m=fs::symlink_metadata(&p)?;if m.file_type().is_symlink(){bail!("symlink ancestor blocks promotion: {}",p.display());}}p.push(part);} if let Some(parent)=p.parent(){ let mut cur=root.to_path_buf(); for comp in parent.strip_prefix(root).unwrap_or(parent).components(){cur.push(comp); if cur.exists()&&fs::symlink_metadata(&cur)?.file_type().is_symlink(){bail!("symlink ancestor blocks promotion: {}",cur.display());}} } Ok(p)}
fn atomic_write(path:&Path,bytes:&[u8])->Result<()> { if let Some(parent)=path.parent(){fs::create_dir_all(parent)?;} let name=path.file_name().and_then(|s|s.to_str()).unwrap_or("file"); let tmp=path.with_file_name(format!(".{name}.sparkbridge-{}.tmp",Uuid::new_v4())); let mut f=OpenOptions::new().create_new(true).write(true).open(&tmp)?;f.write_all(bytes)?;f.sync_all()?;drop(f); // rename(2) atomically replaces an existing regular file; removing it first would open a window where a crash leaves the live file absent.
fs::rename(&tmp,path)?;Ok(()) }
#[cfg(unix)]fn is_executable(m:&fs::Metadata)->bool{use std::os::unix::fs::PermissionsExt;m.permissions().mode()&0o111!=0}#[cfg(not(unix))]fn is_executable(_: &fs::Metadata)->bool{false}
#[cfg(unix)]fn set_executable(path:&Path,value:bool)->Result<()>{use std::os::unix::fs::PermissionsExt;let mut p=fs::metadata(path)?.permissions();let mut mode=p.mode();if value{mode|=0o111}else{mode&=!0o111}p.set_mode(mode);fs::set_permissions(path,p)?;Ok(())}#[cfg(not(unix))]fn set_executable(_: &Path,_:bool)->Result<()>{Ok(())}

pub struct WorkspacePromotionLock{path:PathBuf}
impl WorkspacePromotionLock{pub fn acquire(workspace:&Path)->Result<Self>{let dir=workspace.join(".sparkbridge");fs::create_dir_all(&dir)?;let path=dir.join("promotion.lock");match OpenOptions::new().create_new(true).write(true).open(&path){Ok(mut f)=>{writeln!(f,"pid={} acquired={:?}",std::process::id(),SystemTime::now())?;Ok(Self{path})},Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{let stale=fs::metadata(&path).and_then(|m|m.modified()).ok().and_then(|t|t.elapsed().ok()).is_some_and(|age|age>Duration::from_secs(3600));if stale{fs::remove_file(&path)?;Self::acquire(workspace)}else{bail!("another SparkBridge promotion holds {}",path.display())}},Err(e)=>Err(e.into())}}}impl Drop for WorkspacePromotionLock{fn drop(&mut self){let _=fs::remove_file(&self.path);}}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sparkbridge-promotion-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn merges_disjoint_single_ranges() {
        let base = "alpha\nbeta\ngamma\n";
        let current = "ALPHA\nbeta\ngamma\n";
        let candidate = "alpha\nbeta\nGAMMA\n";
        let merged = conservative_three_way(base, current, candidate).unwrap();
        assert!(merged.contains("ALPHA"));
        assert!(merged.contains("GAMMA"));
    }

    #[test]
    fn rejects_overlapping_ranges() {
        assert!(conservative_three_way("abcdef", "abXXef", "abYYef").is_none());
    }

    #[test]
    fn transaction_applies_verified_write() {
        let root = temp_root("apply");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("a.txt");
        fs::write(&path, b"base").unwrap();
        let cas = Cas::open(root.join("cas")).unwrap();
        let expected = Digest::from_bytes(b"base");
        let replacement = cas.put_bytes(None, b"new").unwrap().digest;
        let plan = PromotionPlan {
            candidate_id: "candidate".into(),
            changes: vec![PlannedChange::WriteFile {
                path: "a.txt".into(),
                expected_current: Some(expected),
                content_digest: replacement,
                executable: false,
            }],
            conflicts: Vec::new(),
            merged_files: 0,
        };
        let lock = WorkspacePromotionLock::acquire(&root).unwrap();
        apply_transaction(&root, &plan, &cas, &lock).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        drop(lock);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn transaction_rolls_back_if_later_precondition_fails() {
        let root = temp_root("rollback");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), b"a-base").unwrap();
        fs::write(root.join("b.txt"), b"b-base").unwrap();
        let cas = Cas::open(root.join("cas")).unwrap();
        let replacement = cas.put_bytes(None, b"a-new").unwrap().digest;
        let plan = PromotionPlan {
            candidate_id: "candidate".into(),
            changes: vec![
                PlannedChange::WriteFile {
                    path: "a.txt".into(),
                    expected_current: Some(Digest::from_bytes(b"a-base")),
                    content_digest: replacement,
                    executable: false,
                },
                PlannedChange::DeleteFile {
                    path: "b.txt".into(),
                    expected_current: Digest::from_bytes(b"not-b-base"),
                },
            ],
            conflicts: Vec::new(),
            merged_files: 0,
        };
        let lock = WorkspacePromotionLock::acquire(&root).unwrap();
        assert!(apply_transaction(&root, &plan, &cas, &lock).is_err());
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"a-base");
        assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"b-base");
        drop(lock);
        let _ = fs::remove_dir_all(root);
    }
}
