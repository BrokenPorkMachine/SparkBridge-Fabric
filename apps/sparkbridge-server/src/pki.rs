use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use sparkbridge_core::NodeId;
use std::{fs, path::Path};
use time::{Duration, OffsetDateTime};

pub struct IssuedNodeCertificate {
    pub certificate_pem: String,
    pub fingerprint_sha256: String,
    pub not_after_unix_ms: u64,
}

#[derive(Clone)]
pub struct CertificateAuthority {
    ca_certificate_pem: String,
    ca_key_pem: String,
}

impl CertificateAuthority {
    pub fn load(certificate_path: &Path, key_path: &Path) -> Result<Self> {
        Ok(Self {
            ca_certificate_pem: fs::read_to_string(certificate_path)
                .with_context(|| format!("reading {}", certificate_path.display()))?,
            ca_key_pem: fs::read_to_string(key_path)
                .with_context(|| format!("reading {}", key_path.display()))?,
        })
    }

    pub fn certificate_pem(&self) -> &str {
        &self.ca_certificate_pem
    }

    pub fn sign_node_csr(&self, csr_pem: &str, node_id: NodeId, node_name: &str) -> Result<IssuedNodeCertificate> {
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).context("parsing CA private key")?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_certificate_pem, ca_key)
            .context("parsing CA certificate")?;
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("parsing and verifying node CSR")?;

        let now = OffsetDateTime::now_utc();
        let not_after = now + Duration::days(90);
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.not_before = now - Duration::minutes(5);
        params.not_after = not_after;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "SparkBridge Fabric");
        dn.push(DnType::CommonName, format!("sparkbridge-node:{node_id}:{node_name}"));
        params.distinguished_name = dn;

        // Preserve only the CSR public key. The server controls subject, validity and usages.
        csr.params = params;
        let certificate = csr.signed_by(&issuer).context("signing node certificate")?;
        let mut hasher = Sha256::new();
        hasher.update(certificate.der().as_ref());
        let fingerprint_sha256 = hex::encode(hasher.finalize());
        Ok(IssuedNodeCertificate {
            certificate_pem: certificate.pem(),
            fingerprint_sha256,
            not_after_unix_ms: (not_after.unix_timestamp().max(0) as u64).saturating_mul(1000),
        })
    }
}
