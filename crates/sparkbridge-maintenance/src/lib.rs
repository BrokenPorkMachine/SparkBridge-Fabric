use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sparkbridge_protocol::ProtocolVersion;
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry { pub relative_path:String, pub sha256:String, pub size_bytes:u64, #[serde(default)] pub unix_mode:Option<u32> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest { pub format_version:u32, pub created_unix_ms:u64, pub entries:Vec<BackupEntry> }

pub fn create_backup(root: &Path, destination: &Path, include: &[PathBuf], now_ms:u64) -> Result<BackupManifest> {
    fs::create_dir_all(destination)?;
    let payload=destination.join("payload"); fs::create_dir_all(&payload)?;
    let mut entries=Vec::new();
    for rel in include { copy_item(root, &payload, rel, &mut entries)?; }
    entries.sort_by(|a,b| a.relative_path.cmp(&b.relative_path));
    let manifest=BackupManifest{format_version:1,created_unix_ms:now_ms,entries};
    fs::write(destination.join("backup-manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(manifest)
}

pub fn verify_backup(destination:&Path)->Result<BackupManifest>{
    let manifest:BackupManifest=serde_json::from_slice(&fs::read(destination.join("backup-manifest.json"))?)?;
    for entry in &manifest.entries { let path=destination.join("payload").join(&entry.relative_path); let bytes=fs::read(&path).with_context(||format!("reading {}",path.display()))?; if sha256_hex(&bytes)!=entry.sha256 { bail!("backup digest mismatch for {}",entry.relative_path); } }
    Ok(manifest)
}

pub fn restore_backup(destination:&Path, target:&Path, overwrite:bool)->Result<BackupManifest>{
    let manifest=verify_backup(destination)?;
    for entry in &manifest.entries { let src=destination.join("payload").join(&entry.relative_path); let dst=target.join(&entry.relative_path); if dst.exists()&&!overwrite{bail!("restore target exists: {}",dst.display());}
        if let Some(p)=dst.parent(){fs::create_dir_all(p)?} fs::copy(&src,&dst)?; restore_unix_mode(&dst,entry.unix_mode)?; }
    Ok(manifest)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest { pub format_version:u32, pub version:String, pub artifact_name:String, pub artifact_sha256:String, pub artifact_size:u64, #[serde(default)] pub minimum_protocol:Option<String> }

pub const UPDATE_MANIFEST_FORMAT_VERSION: u32 = 1;

pub fn verify_signed_update(manifest_path:&Path, signature_path:&Path, public_key_path:&Path, artifact_path:&Path)->Result<UpdateManifest>{
    let manifest_bytes=fs::read(manifest_path)?;
    let manifest:UpdateManifest=serde_json::from_slice(&manifest_bytes)?;
    if manifest.format_version!=UPDATE_MANIFEST_FORMAT_VERSION { bail!("unsupported update manifest format_version {} (expected {})",manifest.format_version,UPDATE_MANIFEST_FORMAT_VERSION) }
    // `artifact_name` is signed manifest content, so it is still untrusted input until it is
    // constrained: without this a valid signature could stage a write outside --staging-dir.
    if !is_plain_file_name(&manifest.artifact_name) { bail!("update manifest artifact_name must be a bare file name, not a path: {:?}",manifest.artifact_name) }
    let artifact=fs::read(artifact_path)?;
    if artifact.len() as u64 != manifest.artifact_size || sha256_hex(&artifact)!=manifest.artifact_sha256 { bail!("update artifact digest/size mismatch") }
    let key_bytes=decode_material(&fs::read_to_string(public_key_path)?)?;
    let sig_bytes=decode_material(&fs::read_to_string(signature_path)?)?;
    let key_arr:[u8;32]=key_bytes.try_into().map_err(|_|anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    let sig_arr:[u8;64]=sig_bytes.try_into().map_err(|_|anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    let key=VerifyingKey::from_bytes(&key_arr)?; let signature=Signature::from_bytes(&sig_arr);
    key.verify(&manifest_bytes,&signature).context("verifying update signature")?;
    // The protocol floor is signed, so honouring it here is not bypassable by any caller.
    // Without this check an older artifact could be staged onto a newer protocol build.
    if let Some(minimum)=manifest.minimum_protocol.as_deref() { enforce_minimum_protocol(minimum)?; }
    Ok(manifest)
}

/// A staged artifact name must be a single path component inside the staging directory.
fn is_plain_file_name(name:&str)->bool{
    if name.is_empty() || name=="." || name==".." { return false; }
    if name.contains('/') || name.contains('\\') || name.contains('\0') { return false; }
    !Path::new(name).components().any(|c|!matches!(c,std::path::Component::Normal(_)))
}

fn enforce_minimum_protocol(minimum:&str)->Result<()> {
    let (major,minor)=minimum.trim().split_once('.').ok_or_else(||anyhow::anyhow!("minimum_protocol must look like MAJOR.MINOR, got {minimum:?}"))?;
    let major:u16=major.trim().parse().map_err(|_|anyhow::anyhow!("minimum_protocol major is not a number: {minimum:?}"))?;
    let minor:u16=minor.trim().parse().map_err(|_|anyhow::anyhow!("minimum_protocol minor is not a number: {minimum:?}"))?;
    let floor=ProtocolVersion{major,minor};
    if !ProtocolVersion::CURRENT.compatible_with(floor) { bail!("this build speaks protocol {}.{}, but the update requires at least {} which is a different major",ProtocolVersion::CURRENT.major,ProtocolVersion::CURRENT.minor,minimum) }
    if ProtocolVersion::CURRENT.minor<floor.minor { bail!("this build speaks protocol {}.{}, but the update requires at least {}",ProtocolVersion::CURRENT.major,ProtocolVersion::CURRENT.minor,minimum) }
    Ok(())
}

pub fn stage_verified_update(manifest_path:&Path, signature_path:&Path, public_key_path:&Path, artifact_path:&Path, staging_dir:&Path)->Result<PathBuf>{
    let manifest=verify_signed_update(manifest_path,signature_path,public_key_path,artifact_path)?;
    fs::create_dir_all(staging_dir)?;
    let target=staging_dir.join(&manifest.artifact_name); fs::copy(artifact_path,&target)?;
    fs::copy(manifest_path,staging_dir.join("update-manifest.json"))?;
    fs::copy(signature_path,staging_dir.join("update-manifest.sig"))?;
    Ok(target)
}

fn copy_item(root:&Path,payload:&Path,rel:&Path,entries:&mut Vec<BackupEntry>)->Result<()> {
    if rel.is_absolute() || rel.components().any(|c| matches!(c,std::path::Component::ParentDir)) { bail!("backup path must be relative and may not contain ..") }
    let src=root.join(rel); if !src.exists(){return Ok(())}
    let meta=fs::symlink_metadata(&src)?; if meta.file_type().is_symlink(){bail!("backup input may not be a symlink: {}",rel.display())}
    if meta.is_dir(){ for item in fs::read_dir(&src)? { let item=item?; copy_item(root,payload,&rel.join(item.file_name()),entries)?; } return Ok(()) }
    if !meta.is_file(){return Ok(())}
    let bytes=fs::read(&src)?; let dst=payload.join(rel); if let Some(p)=dst.parent(){fs::create_dir_all(p)?} fs::write(&dst,&bytes)?;
    entries.push(BackupEntry{relative_path:rel.to_string_lossy().replace('\\',"/"),sha256:sha256_hex(&bytes),size_bytes:bytes.len() as u64,unix_mode:unix_mode(&meta)}); Ok(())
}
fn sha256_hex(bytes:&[u8])->String{let mut h=Sha256::new();h.update(bytes);hex::encode(h.finalize())}
fn decode_material(value:&str)->Result<Vec<u8>>{let v=value.trim(); if let Ok(b)=hex::decode(v){return Ok(b)} STANDARD.decode(v).context("decoding hex/base64 material")}

#[cfg(unix)]
fn unix_mode(meta:&fs::Metadata)->Option<u32>{ use std::os::unix::fs::PermissionsExt; Some(meta.permissions().mode()) }
#[cfg(not(unix))]
fn unix_mode(_meta:&fs::Metadata)->Option<u32>{ None }
#[cfg(unix)]
fn restore_unix_mode(path:&Path,mode:Option<u32>)->Result<()>{ use std::os::unix::fs::PermissionsExt; if let Some(mode)=mode{fs::set_permissions(path,fs::Permissions::from_mode(mode))?;} Ok(()) }
#[cfg(not(unix))]
fn restore_unix_mode(_path:&Path,_mode:Option<u32>)->Result<()>{ Ok(()) }

#[cfg(test)]
mod certification_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn temp(name:&str)->PathBuf{
        let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let p=std::env::temp_dir().join(format!("sparkbridge-{name}-{}-{nonce}",std::process::id()));
        fs::create_dir_all(&p).unwrap(); p
    }

    #[test]
    fn backup_restore_round_trip() {
        let root=temp("backup-root"); let backup=temp("backup-out"); let restore=temp("restore");
        fs::create_dir_all(root.join("state")).unwrap(); fs::write(root.join("state/db.bin"),b"state-v1").unwrap();
        create_backup(&root,&backup,&[PathBuf::from("state")],1).unwrap(); verify_backup(&backup).unwrap();
        restore_backup(&backup,&restore,false).unwrap();
        assert_eq!(fs::read(restore.join("state/db.bin")).unwrap(),b"state-v1");
        let _=fs::remove_dir_all(root); let _=fs::remove_dir_all(backup); let _=fs::remove_dir_all(restore);
    }

    #[test]
    fn signed_update_verifies_and_stages() {
        let root=temp("update"); let artifact=root.join("artifact.zip"); fs::write(&artifact,b"release-artifact").unwrap();
        let bytes=fs::read(&artifact).unwrap(); let manifest=UpdateManifest{format_version:1,version:"0.12.0".into(),artifact_name:"artifact.zip".into(),artifact_sha256:sha256_hex(&bytes),artifact_size:bytes.len() as u64,minimum_protocol:Some("1.10".into())};
        let manifest_path=root.join("manifest.json"); let manifest_bytes=serde_json::to_vec_pretty(&manifest).unwrap(); fs::write(&manifest_path,&manifest_bytes).unwrap();
        let signing=SigningKey::from_bytes(&[7u8;32]); let signature=signing.sign(&manifest_bytes); let pub_path=root.join("pub"); let sig_path=root.join("sig");
        fs::write(&pub_path,hex::encode(signing.verifying_key().to_bytes())).unwrap(); fs::write(&sig_path,hex::encode(signature.to_bytes())).unwrap();
        verify_signed_update(&manifest_path,&sig_path,&pub_path,&artifact).unwrap();
        let staged=root.join("stage"); let out=stage_verified_update(&manifest_path,&sig_path,&pub_path,&artifact,&staged).unwrap(); assert_eq!(fs::read(out).unwrap(),bytes);
        let _=fs::remove_dir_all(root);
    }

    /// Write a validly signed update manifest with the given fields and return its paths.
    fn signed_manifest(root:&Path,artifact_name:&str,format_version:u32,minimum_protocol:Option<&str>)->(PathBuf,PathBuf,PathBuf,PathBuf,Vec<u8>){
        let artifact=root.join("artifact.zip"); fs::write(&artifact,b"release-artifact").unwrap();
        let bytes=fs::read(&artifact).unwrap();
        let manifest=UpdateManifest{format_version,version:"0.12.0".into(),artifact_name:artifact_name.into(),artifact_sha256:sha256_hex(&bytes),artifact_size:bytes.len() as u64,minimum_protocol:minimum_protocol.map(str::to_string)};
        let manifest_path=root.join("manifest.json"); let manifest_bytes=serde_json::to_vec_pretty(&manifest).unwrap(); fs::write(&manifest_path,&manifest_bytes).unwrap();
        let signing=SigningKey::from_bytes(&[9u8;32]); let signature=signing.sign(&manifest_bytes);
        let pub_path=root.join("pub"); let sig_path=root.join("sig");
        fs::write(&pub_path,hex::encode(signing.verifying_key().to_bytes())).unwrap(); fs::write(&sig_path,hex::encode(signature.to_bytes())).unwrap();
        (manifest_path,sig_path,pub_path,artifact,bytes)
    }

    // A correctly signed manifest must still not be able to stage a write outside the
    // staging directory, so `artifact_name` is constrained to a single path component.
    #[test]
    fn signed_update_rejects_artifact_names_that_escape_staging() {
        for name in ["../escape.zip","../../usr/local/bin/sparkbridge-server","nested/artifact.zip","..",".","/etc/cron.d/x","a\\b.zip",""] {
            let root=temp("update-escape");
            let (manifest,sig,pubk,artifact,_)=signed_manifest(&root,name,1,Some("1.10"));
            let result=stage_verified_update(&manifest,&sig,&pubk,&artifact,&root.join("stage"));
            assert!(result.is_err(),"expected rejection for artifact_name {name:?}");
            let _=fs::remove_dir_all(root);
        }
    }

    #[test]
    fn signed_update_enforces_protocol_floor_and_format_version() {
        // An update requiring a newer minor than this build speaks must be refused, as must
        // a different major, and an unknown manifest format must not be interpreted.
        for minimum in ["1.11","2.0","1.99"] {
            let root=temp("update-floor");
            let (manifest,sig,pubk,artifact,_)=signed_manifest(&root,"artifact.zip",1,Some(minimum));
            assert!(verify_signed_update(&manifest,&sig,&pubk,&artifact).is_err(),"expected refusal for minimum_protocol {minimum}");
            let _=fs::remove_dir_all(root);
        }
        // The current floor is accepted.
        let root=temp("update-floor-ok");
        let (manifest,sig,pubk,artifact,_)=signed_manifest(&root,"artifact.zip",1,Some("1.10"));
        assert!(verify_signed_update(&manifest,&sig,&pubk,&artifact).is_ok());
        let _=fs::remove_dir_all(root);
        // Malformed floors are refused rather than ignored.
        for minimum in ["","1","one.10","1.x"] {
            let root=temp("update-floor-bad");
            let (manifest,sig,pubk,artifact,_)=signed_manifest(&root,"artifact.zip",1,Some(minimum));
            assert!(verify_signed_update(&manifest,&sig,&pubk,&artifact).is_err(),"expected refusal for minimum_protocol {minimum:?}");
            let _=fs::remove_dir_all(root);
        }
        let root=temp("update-format");
        let (manifest,sig,pubk,artifact,_)=signed_manifest(&root,"artifact.zip",99,Some("1.10"));
        assert!(verify_signed_update(&manifest,&sig,&pubk,&artifact).is_err(),"expected refusal for unknown format_version");
        let _=fs::remove_dir_all(root);
    }
}
