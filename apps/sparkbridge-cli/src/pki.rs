use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub fn initialize(dir: &Path, server_name: &str, extra_sans: &[String], force: bool) -> Result<()> {
    fs::create_dir_all(dir)?;
    let ca_path = dir.join("ca.pem");
    let ca_key_path = dir.join("ca-key.pem");
    let server_path = dir.join("server.pem");
    let server_key_path = dir.join("server-key.pem");
    let gateway_token_path = dir.join("gateway-token");
    let integration_token_path = dir.join("integration-token");
    if !force && [&ca_path, &ca_key_path, &server_path, &server_key_path, &gateway_token_path, &integration_token_path].iter().any(|p| p.exists()) {
        bail!("PKI files already exist in {}; use --force only if replacement is intentional", dir.display());
    }

    let now = OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate().context("generating CA private key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.not_before = now - Duration::minutes(5);
    ca_params.not_after = now + Duration::days(3650);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::OrganizationName, "SparkBridge Fabric");
    ca_dn.push(DnType::CommonName, "SparkBridge Fabric Root CA");
    ca_params.distinguished_name = ca_dn;
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).context("creating CA certificate")?;

    let mut sans = vec![
        server_name.to_owned(),
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];
    sans.extend(extra_sans.iter().cloned());
    sans.sort();
    sans.dedup();
    let server_key = KeyPair::generate().context("generating server private key")?;
    let mut server_params = CertificateParams::new(sans)?;
    server_params.not_before = now - Duration::minutes(5);
    server_params.not_after = now + Duration::days(825);
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::OrganizationName, "SparkBridge Fabric");
    server_dn.push(DnType::CommonName, server_name);
    server_params.distinguished_name = server_dn;
    let server_cert = server_params.signed_by(&server_key, &ca).context("signing server certificate")?;

    write_private(&ca_key_path, ca.key().serialize_pem().as_bytes())?;
    fs::write(&ca_path, ca.pem())?;
    write_private(&server_key_path, server_key.serialize_pem().as_bytes())?;
    fs::write(&server_path, server_cert.pem())?;
    let gateway_token = random_gateway_token();
    write_private(&gateway_token_path, format!("{gateway_token}\n").as_bytes())?;
    let integration_token = random_gateway_token();
    write_private(&integration_token_path, format!("{integration_token}\n").as_bytes())?;

    let mut hasher = Sha256::new();
    hasher.update(ca.der().as_ref());
    println!("PKI initialized: {}", dir.display());
    println!("CA SHA-256: {}", hex::encode(hasher.finalize()));
    println!("Gateway bearer token written to {}", gateway_token_path.display());
    println!("Integration bearer token written to {}", integration_token_path.display());
    println!("Copy ca.pem to each executor/client over a trusted channel before enrollment/use.");
    Ok(())
}

pub fn rotate_gateway_token(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("{} already exists; pass --force to intentionally rotate it", path.display());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let token = random_gateway_token();
    write_private(path, format!("{token}\n").as_bytes())?;
    println!("Gateway bearer token written to {}", path.display());
    println!("Restart sparkbridge-server after rotating this file.");
    Ok(())
}

fn random_gateway_token() -> String {
    format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // Set 0600 at creation time. Writing first and chmod-ing afterwards leaves the CA
    // private key and the gateway/integration tokens group/world-readable for the duration
    // of the write under a typical umask.
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
