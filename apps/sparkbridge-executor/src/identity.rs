use anyhow::{Context, Result, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::{Deserialize, Serialize};
use sparkbridge_core::{FabricFeature, NodeId};
use std::{fs, path::{Path, PathBuf}};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: NodeId,
    pub node_secret: String,
    pub fabric_url: String,
    pub accepted_features: Vec<FabricFeature>,
    pub generation: String,
}

#[derive(Clone)]
pub struct LoadedIdentity {
    pub metadata: NodeIdentity,
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub ca_certificate_pem: Vec<u8>,
}

pub struct IdentityStore {
    root: PathBuf,
}

impl IdentityStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn exists(&self) -> bool {
        self.root.join("current.json").is_file()
    }

    pub fn load(&self) -> Result<LoadedIdentity> {
        let current_path = self.root.join("current.json");
        let metadata: NodeIdentity = serde_json::from_slice(
            &fs::read(&current_path).with_context(|| format!("reading {}", current_path.display()))?,
        )?;
        let generation_dir = self.root.join("credentials").join(&metadata.generation);
        Ok(LoadedIdentity {
            metadata,
            certificate_pem: fs::read(generation_dir.join("cert.pem"))?,
            private_key_pem: fs::read(generation_dir.join("key.pem"))?,
            ca_certificate_pem: fs::read(generation_dir.join("ca.pem"))?,
        })
    }

    pub fn commit_generation(
        &self,
        mut metadata: NodeIdentity,
        certificate_pem: &str,
        private_key_pem: &str,
        ca_certificate_pem: &str,
    ) -> Result<()> {
        fs::create_dir_all(self.root.join("credentials"))?;
        let generation = Uuid::new_v4().simple().to_string();
        let final_dir = self.root.join("credentials").join(&generation);
        let temp_dir = self.root.join("credentials").join(format!(".{generation}.tmp"));
        fs::create_dir_all(&temp_dir)?;
        write_private(&temp_dir.join("key.pem"), private_key_pem.as_bytes())?;
        fs::write(temp_dir.join("cert.pem"), certificate_pem.as_bytes())?;
        fs::write(temp_dir.join("ca.pem"), ca_certificate_pem.as_bytes())?;
        fs::rename(&temp_dir, &final_dir)?;

        metadata.generation = generation.clone();
        let encoded = serde_json::to_vec_pretty(&metadata)?;
        let temp_current = self.root.join("current.json.tmp");
        write_private(&temp_current, &encoded)?;
        fs::rename(temp_current, self.root.join("current.json"))?;
        self.prune_old_generations(&generation);
        Ok(())
    }

    fn prune_old_generations(&self, keep: &str) {
        let credentials = self.root.join("credentials");
        let Ok(entries) = fs::read_dir(credentials) else { return; };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy() != keep {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

pub fn new_key_and_csr(node_name: &str) -> Result<(String, String)> {
    let key = KeyPair::generate().context("generating node private key")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "SparkBridge Fabric");
    dn.push(DnType::CommonName, node_name);
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key).context("creating node CSR")?;
    Ok((key.serialize_pem(), csr.pem()?))
}

pub fn combined_identity_pem(loaded: &LoadedIdentity) -> Vec<u8> {
    let mut pem = loaded.certificate_pem.clone();
    if !pem.ends_with(b"\n") {
        pem.push(b'\n');
    }
    pem.extend_from_slice(&loaded.private_key_pem);
    pem
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        bail!("refusing to persist an empty private value");
    }
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // Set 0600 at creation time. Writing first and chmod-ing afterwards leaves the node TLS
    // private key group/world-readable for the duration of the write under a typical umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private file {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    // Enforce the mode even if the file already existed with looser permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
