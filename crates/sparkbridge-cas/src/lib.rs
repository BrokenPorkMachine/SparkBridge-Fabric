use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(pub String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(format!("sha256:{}", hex::encode(h.finalize())))
    }
    pub fn algorithm(&self) -> &str { "sha256" }
    pub fn hex(&self) -> Result<&str> {
        self.0.strip_prefix("sha256:").filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| anyhow::anyhow!("invalid SHA-256 digest"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo { pub digest: Digest, pub size_bytes: u64 }

#[derive(Debug, Clone)]
pub struct Cas { root: PathBuf }

impl Cas {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("sha256/.tmp"))?;
        Ok(Self { root })
    }
    pub fn root(&self) -> &Path { &self.root }
    pub fn path_for(&self, digest: &Digest) -> Result<PathBuf> {
        let hex = digest.hex()?;
        Ok(self.root.join("sha256").join(&hex[..2]).join(&hex[2..4]).join(hex))
    }
    pub fn contains(&self, digest: &Digest) -> bool { self.path_for(digest).is_ok_and(|p| p.is_file()) }
    pub fn put_bytes(&self, expected: Option<&Digest>, bytes: &[u8]) -> Result<ObjectInfo> {
        let actual = Digest::from_bytes(bytes);
        if let Some(expected) = expected { if expected != &actual { bail!("CAS digest mismatch: expected {}, got {}", expected.0, actual.0); } }
        let final_path = self.path_for(&actual)?;
        if final_path.is_file() { return Ok(ObjectInfo { digest: actual, size_bytes: bytes.len() as u64 }); }
        fs::create_dir_all(final_path.parent().expect("CAS path has parent"))?;
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let tmp = self.root.join("sha256/.tmp").join(format!("{}.part-{}-{now}-{nonce}", actual.hex()?, std::process::id()));
        let mut f = OpenOptions::new().create_new(true).write(true).open(&tmp).context("creating CAS temporary object")?;
        f.write_all(bytes)?; f.sync_all()?; drop(f);
        match fs::rename(&tmp, &final_path) {
            Ok(()) => {},
            Err(_e) if final_path.is_file() => { let _ = fs::remove_file(&tmp); },
            Err(e) => { let _ = fs::remove_file(&tmp); return Err(e).context("committing CAS object"); }
        }
        Ok(ObjectInfo { digest: actual, size_bytes: bytes.len() as u64 })
    }
    pub fn put_reader(&self, expected: &Digest, mut reader: impl Read) -> Result<ObjectInfo> {
        let mut bytes = Vec::new(); reader.read_to_end(&mut bytes)?; self.put_bytes(Some(expected), &bytes)
    }
    pub fn get_bytes(&self, digest: &Digest, max_bytes: u64) -> Result<Vec<u8>> {
        let path = self.path_for(digest)?;
        let meta = fs::metadata(&path).with_context(|| format!("reading CAS object {}", digest.0))?;
        if meta.len() > max_bytes { bail!("CAS object exceeds read limit"); }
        let bytes = fs::read(path)?;
        if Digest::from_bytes(&bytes) != *digest { bail!("CAS object failed digest verification"); }
        Ok(bytes)
    }
    pub fn fsck_object(&self, digest: &Digest) -> Result<ObjectInfo> {
        let path = self.path_for(digest)?; let mut f = File::open(path)?; let mut h = Sha256::new(); let mut n = 0u64; let mut buf = [0u8; 64 * 1024];
        loop { let read = f.read(&mut buf)?; if read == 0 { break; } h.update(&buf[..read]); n = n.saturating_add(read as u64); }
        let actual = Digest(format!("sha256:{}", hex::encode(h.finalize()))); if actual != *digest { bail!("CAS corruption: expected {}, got {}", digest.0, actual.0); }
        Ok(ObjectInfo { digest: digest.clone(), size_bytes: n })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_root(name:&str)->PathBuf { std::env::temp_dir().join(format!("sparkbridge-{name}-{}-{}",std::process::id(), TEMP_COUNTER.fetch_add(1, Ordering::Relaxed))) }
    #[test] fn digest_is_stable(){ assert_eq!(Digest::from_bytes(b"abc").0,"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); }
    #[test] fn transactional_round_trip_and_fsck(){ let root=temp_root("cas"); let cas=Cas::open(&root).unwrap(); let info=cas.put_bytes(None,b"hello SparkBridge").unwrap(); assert_eq!(cas.get_bytes(&info.digest,1024).unwrap(),b"hello SparkBridge"); assert_eq!(cas.fsck_object(&info.digest).unwrap().size_bytes,17); let _=fs::remove_dir_all(root); }
    #[test] fn rejects_wrong_claimed_digest(){ let root=temp_root("bad-digest"); let cas=Cas::open(&root).unwrap(); let wrong=Digest::from_bytes(b"different"); assert!(cas.put_bytes(Some(&wrong),b"payload").is_err()); let _=fs::remove_dir_all(root); }
}
