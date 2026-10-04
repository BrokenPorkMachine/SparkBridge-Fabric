use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unable to read configuration {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid TOML configuration {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

pub fn load_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, ConfigError> {
    let path = path.as_ref();
    let path_string = path.display().to_string();
    let data = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path_string.clone(),
        source,
    })?;
    toml::from_str(&data).map_err(|source| ConfigError::Parse {
        path: path_string,
        source,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub admin_bind: String,
    pub enrollment_bind: String,
    pub fabric_bind: String,
    pub public_fabric_url: String,
    pub gateway_bind: String,
    pub public_gateway_url: String,
    pub gateway_token_path: PathBuf,
    pub integration_bind: String,
    pub public_integration_url: String,
    pub integration_token_path: PathBuf,
    pub integration_principal_id: String,
    pub dashboard_enabled: bool,
    pub ollama_base_url: String,
    pub inference_max_concurrent_requests: usize,
    pub inference_queue_timeout_seconds: u64,
    pub inference_stream_idle_timeout_seconds: u64,
    pub inference_keep_alive: String,
    pub inference_allowed_models: Vec<String>,
    pub inference_max_request_bytes: usize,
    pub inference_data_boundary: String,
    pub workspace_classifications: BTreeMap<String, String>,
    pub approval_ttl_seconds: u64,
    pub context_secret_scan_enabled: bool,
    pub cas_path: PathBuf,
    pub cas_max_object_bytes: usize,
    pub database_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub heartbeat_stale_seconds: u64,
    pub heartbeat_offline_seconds: u64,
    pub action_lease_seconds: u64,
    pub action_max_timeout_seconds: u64,
    pub action_max_output_bytes: u64,
    pub action_cache_max_entries: usize,
    pub validation_max_targets: usize,
    pub agent_max_run_steps: u32,
    pub agent_context_max_bytes: usize,
    pub agent_context_file_max_bytes: usize,
    pub intelligence_max_file_bytes: u64,
    pub intelligence_ranked_paths: usize,
    pub intelligence_search_limit: usize,
    pub intelligence_max_files: usize,
    pub intelligence_max_symbols: usize,
    pub intelligence_max_references: usize,
    pub log_filter: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            admin_bind: "127.0.0.1:7787".into(),
            enrollment_bind: "0.0.0.0:7788".into(),
            fabric_bind: "0.0.0.0:7789".into(),
            public_fabric_url: "https://127.0.0.1:7789".into(),
            gateway_bind: "0.0.0.0:7790".into(),
            public_gateway_url: "https://127.0.0.1:7790".into(),
            gateway_token_path: PathBuf::from("./pki/gateway-token"),
            integration_bind: "0.0.0.0:7791".into(),
            public_integration_url: "https://127.0.0.1:7791".into(),
            integration_token_path: PathBuf::from("./pki/integration-token"),
            integration_principal_id: "integration-client".into(),
            dashboard_enabled: true,
            ollama_base_url: "http://127.0.0.1:11434".into(),
            inference_max_concurrent_requests: 1,
            inference_queue_timeout_seconds: 120,
            inference_stream_idle_timeout_seconds: 600,
            inference_keep_alive: "2h".into(),
            inference_allowed_models: Vec::new(),
            inference_max_request_bytes: 16 * 1024 * 1024,
            inference_data_boundary: "local_only".into(),
            workspace_classifications: BTreeMap::new(),
            approval_ttl_seconds: 3600,
            context_secret_scan_enabled: true,
            cas_path: PathBuf::from("./state/cas"),
            cas_max_object_bytes: 128 * 1024 * 1024,
            database_path: PathBuf::from("./state/sparkbridge.db"),
            ca_cert_path: PathBuf::from("./pki/ca.pem"),
            ca_key_path: PathBuf::from("./pki/ca-key.pem"),
            server_cert_path: PathBuf::from("./pki/server.pem"),
            server_key_path: PathBuf::from("./pki/server-key.pem"),
            heartbeat_stale_seconds: 30,
            heartbeat_offline_seconds: 120,
            action_lease_seconds: 30,
            action_max_timeout_seconds: 3600,
            action_max_output_bytes: 4 * 1024 * 1024,
            action_cache_max_entries: 10_000,
            validation_max_targets: 16,
            agent_max_run_steps: 16,
            agent_context_max_bytes: 512 * 1024,
            agent_context_file_max_bytes: 128 * 1024,
            intelligence_max_file_bytes: 4 * 1024 * 1024,
            intelligence_ranked_paths: 24,
            intelligence_search_limit: 100,
            intelligence_max_files: 50_000,
            intelligence_max_symbols: 100_000,
            intelligence_max_references: 250_000,
            log_filter: "sparkbridge_server=info,tower_http=info".into(),
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.heartbeat_stale_seconds == 0 {
            return Err(ConfigError::Validation("heartbeat_stale_seconds must be greater than zero".into()));
        }
        if self.heartbeat_offline_seconds <= self.heartbeat_stale_seconds {
            return Err(ConfigError::Validation(
                "heartbeat_offline_seconds must be greater than heartbeat_stale_seconds".into(),
            ));
        }

        if self.action_lease_seconds < 5 {
            return Err(ConfigError::Validation("action_lease_seconds must be at least 5".into()));
        }
        if self.action_max_timeout_seconds == 0 || self.action_max_output_bytes < 1024 {
            return Err(ConfigError::Validation("action timeout/output limits must be positive and output >= 1024 bytes".into()));
        }
        if self.action_cache_max_entries == 0 || self.validation_max_targets == 0 || self.validation_max_targets > 64 {
            return Err(ConfigError::Validation("action_cache_max_entries must be > 0 and validation_max_targets must be 1..=64".into()));
        }
        if self.agent_max_run_steps == 0 || self.agent_max_run_steps > 128 {
            return Err(ConfigError::Validation("agent_max_run_steps must be between 1 and 128".into()));
        }
        if self.agent_context_file_max_bytes < 1024 || self.agent_context_max_bytes < self.agent_context_file_max_bytes {
            return Err(ConfigError::Validation("agent context limits are invalid".into()));
        }
        if self.intelligence_max_file_bytes < 1024 || self.intelligence_ranked_paths == 0 || self.intelligence_search_limit == 0 || self.intelligence_max_files == 0 || self.intelligence_max_symbols == 0 || self.intelligence_max_references == 0 {
            return Err(ConfigError::Validation("repository intelligence limits are invalid".into()));
        }
        if !self.public_fabric_url.starts_with("https://") {
            return Err(ConfigError::Validation("public_fabric_url must use https://".into()));
        }
        if !self.public_gateway_url.starts_with("https://") {
            return Err(ConfigError::Validation("public_gateway_url must use https://".into()));
        }
        if !self.public_integration_url.starts_with("https://") {
            return Err(ConfigError::Validation("public_integration_url must use https://".into()));
        }
        if self.integration_principal_id.trim().is_empty() {
            return Err(ConfigError::Validation("integration_principal_id may not be empty".into()));
        }
        if !is_loopback_http_url(&self.ollama_base_url) {
            return Err(ConfigError::Validation(
                "ollama_base_url must use http:// and resolve to localhost/loopback".into(),
            ));
        }
        if self.inference_max_concurrent_requests == 0 {
            return Err(ConfigError::Validation(
                "inference_max_concurrent_requests must be greater than zero".into(),
            ));
        }
        if self.inference_max_concurrent_requests > u32::MAX as usize {
            return Err(ConfigError::Validation(
                "inference_max_concurrent_requests exceeds scheduler limit".into(),
            ));
        }
        if self.inference_queue_timeout_seconds == 0 || self.inference_stream_idle_timeout_seconds == 0 {
            return Err(ConfigError::Validation(
                "inference queue/idle timeouts must be greater than zero".into(),
            ));
        }
        if self.inference_keep_alive.trim().is_empty() {
            return Err(ConfigError::Validation("inference_keep_alive may not be empty".into()));
        }
        if self.cas_max_object_bytes < 1024 {
            return Err(ConfigError::Validation("cas_max_object_bytes must be at least 1024".into()));
        }
        if !matches!(self.inference_data_boundary.as_str(), "local_only" | "private_remote" | "public_cloud") {
            return Err(ConfigError::Validation("inference_data_boundary must be local_only, private_remote, or public_cloud".into()));
        }
        for (workspace, classification) in &self.workspace_classifications {
            if workspace.trim().is_empty() || !matches!(classification.as_str(), "public" | "private" | "confidential" | "restricted") {
                return Err(ConfigError::Validation("workspace_classifications contains an invalid workspace or classification".into()));
            }
        }
        if self.approval_ttl_seconds < 60 {
            return Err(ConfigError::Validation("approval_ttl_seconds must be at least 60".into()));
        }
        if self.inference_max_request_bytes < 1024 {
            return Err(ConfigError::Validation(
                "inference_max_request_bytes must be at least 1024".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutorConfig {
    pub enrollment_url: String,
    pub fabric_url: Option<String>,
    pub ca_cert_path: PathBuf,
    pub identity_dir: PathBuf,
    pub enrollment_token: Option<String>,
    pub name: Option<String>,
    pub heartbeat_seconds: u64,
    pub reconnect_initial_seconds: u64,
    pub reconnect_max_seconds: u64,
    pub workspace_roots: Vec<PathBuf>,
    pub local_cas_path: PathBuf,
    pub snapshot_max_retries: u32,
    pub snapshot_max_file_bytes: u64,
    pub workspace_bindings: BTreeMap<String, PathBuf>,
    pub action_poll_seconds: u64,
    pub action_lease_renew_seconds: u64,
    pub action_outbox_path: PathBuf,
    pub action_sandbox_path: PathBuf,
    pub action_allowed_env: Vec<String>,
    pub action_allowed_commands: Vec<String>,
    pub secret_env_bindings: BTreeMap<String, String>,
    pub action_allow_linux_network_none: bool,
    pub intelligence_native_max_files: usize,
    pub intelligence_native_file_max_bytes: u64,
    pub intelligence_lsp_commands: BTreeMap<String, Vec<String>>,
    pub log_filter: String,
}

fn default_lsp_commands() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        ("rust".into(), vec!["rust-analyzer".into()]),
        ("c_cpp".into(), vec!["clangd".into()]),
        ("swift".into(), vec!["sourcekit-lsp".into()]),
        ("csharp".into(), vec!["Microsoft.CodeAnalysis.LanguageServer".into()]),
    ])
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            enrollment_url: "https://127.0.0.1:7788".into(),
            fabric_url: None,
            ca_cert_path: PathBuf::from("./pki/ca.pem"),
            identity_dir: PathBuf::from("./state/executor-identity"),
            enrollment_token: None,
            name: None,
            heartbeat_seconds: 10,
            reconnect_initial_seconds: 1,
            reconnect_max_seconds: 60,
            workspace_roots: vec![PathBuf::from(".")],
            local_cas_path: PathBuf::from("./state/executor-cas"),
            snapshot_max_retries: 3,
            snapshot_max_file_bytes: 128 * 1024 * 1024,
            workspace_bindings: BTreeMap::new(),
            action_poll_seconds: 2,
            action_lease_renew_seconds: 10,
            action_outbox_path: PathBuf::from("./state/action-outbox"),
            action_sandbox_path: PathBuf::from("./state/action-sandboxes"),
            action_allowed_env: vec!["CI".into(), "RUST_BACKTRACE".into(), "RUST_LOG".into()],
            action_allowed_commands: vec![
                "git".into(), "cargo".into(), "rustc".into(), "cmake".into(), "ninja".into(),
                "clang".into(), "clang++".into(), "gcc".into(), "g++".into(), "python3".into(),
                "python".into(), "node".into(), "npm".into(), "dotnet".into(), "java".into(),
                "swift".into(), "xcodebuild".into(), "msbuild".into(),
            ],
            secret_env_bindings: BTreeMap::new(),
            action_allow_linux_network_none: true,
            intelligence_native_max_files: 256,
            intelligence_native_file_max_bytes: 1024 * 1024,
            intelligence_lsp_commands: default_lsp_commands(),
            log_filter: "sparkbridge_executor=info".into(),
        }
    }
}

impl ExecutorConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enrollment_url.starts_with("https://") {
            return Err(ConfigError::Validation("enrollment_url must use https://".into()));
        }
        if let Some(url) = &self.fabric_url {
            if !url.starts_with("https://") {
                return Err(ConfigError::Validation("fabric_url must use https://".into()));
            }
        }
        if self.heartbeat_seconds == 0 {
            return Err(ConfigError::Validation("heartbeat_seconds must be greater than zero".into()));
        }
        if self.reconnect_initial_seconds == 0 {
            return Err(ConfigError::Validation("reconnect_initial_seconds must be greater than zero".into()));
        }
        if self.workspace_roots.is_empty() {
            return Err(ConfigError::Validation("workspace_roots may not be empty".into()));
        }
        if self.snapshot_max_file_bytes < 1024 {
            return Err(ConfigError::Validation("snapshot_max_file_bytes must be at least 1024".into()));
        }
        if self.snapshot_max_retries > 20 {
            return Err(ConfigError::Validation("snapshot_max_retries must be <= 20".into()));
        }
        if self.intelligence_native_max_files == 0 || self.intelligence_native_file_max_bytes < 1024 {
            return Err(ConfigError::Validation("native intelligence limits are invalid".into()));
        }
        for (language, argv) in &self.intelligence_lsp_commands {
            if language.trim().is_empty() || argv.first().is_some_and(|value| value.trim().is_empty()) {
                return Err(ConfigError::Validation("intelligence_lsp_commands contains an invalid entry".into()));
            }
        }
        if self.reconnect_max_seconds < self.reconnect_initial_seconds {
            return Err(ConfigError::Validation(
                "reconnect_max_seconds must be greater than or equal to reconnect_initial_seconds".into(),
            ));
        }
        if self.action_poll_seconds == 0 || self.action_lease_renew_seconds == 0 {
            return Err(ConfigError::Validation("action poll/lease renewal intervals must be greater than zero".into()));
        }
        for (workspace_id, path) in &self.workspace_bindings {
            if workspace_id.trim().is_empty() || path.as_os_str().is_empty() {
                return Err(ConfigError::Validation("workspace_bindings entries require non-empty IDs and paths".into()));
            }
        }
        if self.action_allowed_commands.is_empty() {
            return Err(ConfigError::Validation("action_allowed_commands may not be empty when remote actions are enabled".into()));
        }
        for (reference, env_name) in &self.secret_env_bindings {
            if reference.trim().is_empty() || env_name.trim().is_empty() {
                return Err(ConfigError::Validation("secret_env_bindings entries require non-empty reference and environment variable name".into()));
            }
        }
        for command in &self.action_allowed_commands {
            let path = Path::new(command);
            if command.trim().is_empty() || path.components().count() != 1 {
                return Err(ConfigError::Validation("action_allowed_commands must contain command names, not paths".into()));
            }
        }
        Ok(())
    }
}


/// Ollama must never be reachable off-box. The authority is parsed rather than matched as a
/// string prefix: `http://127.0.0.1:11434@evil.example` satisfies a
/// `starts_with("http://127.0.0.1:")` test while its real host is `evil.example`, which
/// would silently forward every prompt (including assembled workspace source) off-host.
fn is_loopback_http_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value.trim()) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    // Userinfo is never legitimate here and is the standard way to hide a remote host
    // behind a loopback-looking authority.
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.host() {
        // Exact match only: `localhost.evil.example` is a remote host.
        Some(Host::Domain("localhost")) => true,
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_server_config_uses_defaults() {
        let cfg: ServerConfig = toml::from_str("admin_bind = \"127.0.0.1:9000\"").expect("parse config");
        assert_eq!(cfg.admin_bind, "127.0.0.1:9000");
        assert_eq!(cfg.fabric_bind, "0.0.0.0:7789");
        cfg.validate().expect("defaulted config should validate");
    }

    #[test]
    fn rejects_insecure_fabric_url() {
        let cfg = ServerConfig { public_fabric_url: "http://example.invalid:7789".into(), ..Default::default() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_heartbeat_order() {
        let base = ServerConfig::default();
        let cfg = ServerConfig { heartbeat_offline_seconds: base.heartbeat_stale_seconds, ..base };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ollama_must_remain_loopback_only() {
        let remote = ServerConfig { ollama_base_url: "http://10.0.0.5:11434".into(), ..Default::default() };
        assert!(remote.validate().is_err());
        let loopback = ServerConfig { ollama_base_url: "http://localhost:11434".into(), ..Default::default() };
        assert!(loopback.validate().is_ok());
    }

    #[test]
    fn ollama_loopback_check_parses_the_authority() {
        for accepted in [
            "http://127.0.0.1:11434",
            "http://127.0.0.1",
            "http://127.5.5.5:11434",
            "http://localhost:11434",
            "http://LOCALHOST:11434",
            "http://[::1]:11434",
            "  http://127.0.0.1:11434/  ",
        ] {
            assert!(is_loopback_http_url(accepted), "expected loopback: {accepted}");
        }
        for rejected in [
            // A remote host hidden behind a loopback-looking authority via userinfo.
            "http://127.0.0.1:11434@evil.example.com",
            "http://[::1]:11434@evil.example.com",
            "http://localhost:11434@evil.example.com",
            "http://user@127.0.0.1:11434",
            // Near-miss hostnames and schemes.
            "http://localhost.evil.example:11434",
            "http://notlocalhost:11434",
            "http://127.0.0.1.evil.example:11434",
            "https://127.0.0.1:11434",
            "http://0.0.0.0:11434",
            "http://[::]:11434",
            "http://169.254.169.254",
            "file:///etc/passwd",
            "127.0.0.1:11434",
            "",
        ] {
            assert!(!is_loopback_http_url(rejected), "expected rejection: {rejected}");
        }
    }

    #[test]
    fn ollama_url_with_userinfo_is_rejected_by_validate() {
        let cfg = ServerConfig {
            ollama_base_url: "http://127.0.0.1:11434@evil.example.com".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn executor_requires_https_and_sane_backoff() {
        let insecure = ExecutorConfig { enrollment_url: "http://example.invalid:7788".into(), ..Default::default() };
        assert!(insecure.validate().is_err());
        let base = ExecutorConfig { enrollment_url: "https://example.invalid:7788".into(), ..Default::default() };
        let backoff = ExecutorConfig { reconnect_initial_seconds: 30, reconnect_max_seconds: 10, ..base };
        assert!(backoff.validate().is_err());
    }
}
