use anyhow::{Context, Result, bail};
use sparkbridge_diagnostics::normalize_diagnostics;
use sparkbridge_protocol::{ActionExecutionResult, ActionNetworkPolicy, ActionSpec, ExecutionDomainDescriptor, ExecutionDomainKind, ToolchainFingerprint};
use sparkbridge_cache::fingerprint_digest;
use sparkbridge_secrets::{redact_known_values, scan_and_redact};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::{Component, Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, process::{Child, Command}, time};
use tokio_util::sync::CancellationToken;
use tracing::warn;

const DISCOVERY_TOOLS: &[&str] = &[
    "git", "cargo", "rustc", "cmake", "ninja", "clang", "clang++", "gcc", "g++",
    "python3", "python", "node", "npm", "dotnet", "java", "swift", "xcodebuild",
    "msbuild", "powershell", "pwsh", "wsl", "docker", "podman",
];

// `allow_linux_network_none` and the bubblewrap capability/metadata entries only exist on
// Linux. Keep the public signature uniform across platforms and silence the resulting
// non-Linux dead-code warnings rather than diverging the API per platform.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables, unused_mut))]
pub fn discover_execution_domains(workspaces: impl IntoIterator<Item = String>, allowed_commands: &[String], allow_linux_network_none: bool) -> Vec<ExecutionDomainDescriptor> {
    let workspace_ids: Vec<String> = workspaces.into_iter().collect();
    let mut capabilities = discover_tools(allowed_commands);
    let mut metadata = BTreeMap::new();
    #[cfg(target_os = "linux")]
    if allow_linux_network_none && command_exists("bwrap") {
        capabilities.push("network:none".into());
        metadata.insert("network.none".into(), "bubblewrap".into());
    }
    capabilities.sort();
    capabilities.dedup();
    let toolchain = build_toolchain_fingerprint("host", &capabilities);
    vec![ExecutionDomainDescriptor {
        id: "host".into(),
        kind: ExecutionDomainKind::Host,
        display_name: format!("{} {} host", std::env::consts::OS, std::env::consts::ARCH),
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        capabilities,
        workspace_ids,
        metadata,
        toolchain: Some(toolchain),
    }]
}

fn discover_tools(allowed_commands: &[String]) -> Vec<String> {
    let mut found = BTreeSet::new();
    for tool in DISCOVERY_TOOLS {
        if allowed_commands.iter().any(|allowed| allowed == tool) && command_exists(tool) {
            found.insert((*tool).to_owned());
        }
    }
    found.into_iter().collect()
}

fn build_toolchain_fingerprint(domain: &str, capabilities: &[String]) -> ToolchainFingerprint {
    let mut command_versions = BTreeMap::new();
    for command in capabilities.iter().filter(|c| !c.contains(':')) {
        if let Some(path) = command_path(command) {
            let version = command_version(command).unwrap_or_else(|| "unknown".into());
            command_versions.insert(command.clone(), format!("{}|{}", path.display(), version));
        }
    }
    let mut environment = BTreeMap::new();
    for key in ["SDKROOT", "DEVELOPER_DIR", "CC", "CXX", "RUSTUP_TOOLCHAIN", "DOTNET_ROOT", "JAVA_HOME"] {
        if let Ok(value) = env::var(key) { environment.insert(key.into(), value); }
    }
    let mut fingerprint = ToolchainFingerprint {
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        domain: domain.into(),
        executor_version: env!("CARGO_PKG_VERSION").into(),
        command_versions,
        environment,
        digest: String::new(),
    };
    fingerprint.digest = fingerprint_digest(&fingerprint).unwrap_or_else(|_| "unavailable".into());
    fingerprint
}

fn command_version(command: &str) -> Option<String> {
    let candidates: Vec<Vec<&str>> = match command {
        "xcodebuild" => vec![vec!["-version"]],
        "msbuild" => vec![vec!["-version"], vec!["/version"]],
        _ => vec![vec!["--version"], vec!["-version"]],
    };
    for args in candidates {
        if let Ok(output) = StdCommand::new(command).args(&args).output() {
            let mut text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if text.is_empty() { text = String::from_utf8_lossy(&output.stderr).trim().to_owned(); }
            if !text.is_empty() { return Some(text.lines().next().unwrap_or("unknown").chars().take(256).collect()); }
        }
    }
    None
}

fn command_path(command: &str) -> Option<PathBuf> {
    let candidate = Path::new(command);
    if candidate.components().count() > 1 { return candidate.is_file().then(|| candidate.to_path_buf()); }
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let plain = directory.join(command);
        if plain.is_file() { return Some(plain); }
        #[cfg(target_os = "windows")]
        for suffix in ["exe", "cmd", "bat", "com"] {
            let candidate = directory.join(format!("{command}.{suffix}"));
            if candidate.is_file() { return Some(candidate); }
        }
    }
    None
}

fn command_exists(command: &str) -> bool {
    let candidate = Path::new(command);
    if candidate.components().count() > 1 {
        return candidate.is_file();
    }
    let Some(path) = env::var_os("PATH") else { return false; };
    for directory in env::split_paths(&path) {
        let plain = directory.join(command);
        if plain.is_file() { return true; }
        #[cfg(target_os = "windows")]
        {
            for suffix in ["exe", "cmd", "bat", "com"] {
                if directory.join(format!("{command}.{suffix}")).is_file() { return true; }
            }
        }
    }
    false
}

pub async fn execute_action(
    spec: &ActionSpec,
    workspace_root: &Path,
    allowed_env: &[String],
    allowed_commands: &[String],
    secret_env: &BTreeMap<String, String>,
    allow_linux_network_none: bool,
    cancellation: CancellationToken,
) -> Result<ActionExecutionResult> {
    validate_spec(spec, workspace_root, allowed_env, allowed_commands, secret_env, allow_linux_network_none)?;
    let started = Instant::now();
    let cwd = resolve_cwd(workspace_root, &spec.relative_cwd)?;
    let mut command = build_command(spec, &cwd)?;
    command.current_dir(&cwd).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().pre_exec(|| {
            if libc::setsid() == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        });
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    for (key, value) in secret_env {
        command.env(key, value);
    }

    let mut child = command.spawn().with_context(|| format!("spawning {}", spec.argv[0]))?;
    let pid = child.id();
    let stdout = child.stdout.take().context("child stdout unavailable")?;
    let stderr = child.stderr.take().context("child stderr unavailable")?;
    let max_output = spec.max_output_bytes.max(1024) as usize;
    let stdout_task = tokio::spawn(read_limited(stdout, max_output));
    let stderr_task = tokio::spawn(read_limited(stderr, max_output));

    let timeout = Duration::from_millis(spec.timeout_ms.max(1));
    let (status, timed_out, cancelled) = tokio::select! {
        result = child.wait() => (Some(result.context("waiting for action process")?), false, false),
        _ = time::sleep(timeout) => {
            terminate_process_tree(&mut child, pid).await;
            (child.wait().await.ok(), true, false)
        }
        _ = cancellation.cancelled() => {
            terminate_process_tree(&mut child, pid).await;
            (child.wait().await.ok(), false, true)
        }
    };

    let (stdout_bytes, stdout_truncated) = stdout_task.await.context("joining stdout collector")??;
    let (stderr_bytes, stderr_truncated) = stderr_task.await.context("joining stderr collector")??;
    let secret_values: Vec<String> = secret_env.values().cloned().collect();
    let stdout = redact_known_values(String::from_utf8_lossy(&stdout_bytes).into_owned(), secret_values.clone());
    let stderr = redact_known_values(String::from_utf8_lossy(&stderr_bytes).into_owned(), secret_values);
    // Process output is another untrusted path into the control plane/model context.
    // Redact recognizable credential shapes even when they were not injected through
    // SparkBridge (for example a test accidentally printing a token from a local file).
    let stdout = scan_and_redact(&stdout).redacted;
    let stderr = scan_and_redact(&stderr).redacted;
    let mut diagnostics = normalize_diagnostics(&stdout, &stderr);
    normalize_diagnostic_paths(&mut diagnostics, workspace_root);

    Ok(ActionExecutionResult {
        exit_code: status.and_then(|s| s.code()),
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        timed_out,
        cancelled,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        diagnostics,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn validate_spec(spec: &ActionSpec, workspace_root: &Path, allowed_env: &[String], allowed_commands: &[String], secret_env: &BTreeMap<String, String>, allow_linux_network_none: bool) -> Result<()> {
    if spec.argv.is_empty() || spec.argv[0].trim().is_empty() {
        bail!("action argv must contain an executable");
    }
    let executable = &spec.argv[0];
    if Path::new(executable).components().count() != 1 {
        bail!("action executable must be a command name, not a path");
    }
    if !allowed_commands.iter().any(|allowed| allowed == executable) {
        bail!("action executable {executable:?} is not allowed by executor policy");
    }
    match spec.network_policy {
        ActionNetworkPolicy::Unrestricted => {}
        ActionNetworkPolicy::None => {
            #[cfg(target_os = "linux")]
            if !allow_linux_network_none || !command_exists("bwrap") { bail!("network=none requires executor opt-in and bubblewrap (bwrap) on this Linux executor"); }
            #[cfg(not(target_os = "linux"))]
            bail!("network=none is not enforceable on this executor platform in v0.12");
        }
        ActionNetworkPolicy::DependencyFetch | ActionNetworkPolicy::DeclaredHosts => {
            bail!("dependency_fetch/declared_hosts network policies are not yet enforceable in v0.12");
        }
    }
    if !workspace_root.is_dir() {
        bail!("workspace root does not exist or is not a directory: {}", workspace_root.display());
    }
    let allowed: BTreeSet<&str> = allowed_env.iter().map(String::as_str).collect();
    for key in spec.env.keys() {
        if !allowed.contains(key.as_str()) {
            bail!("action environment variable {key:?} is not allowed by executor policy");
        }
    }
    for key in secret_env.keys() {
        if spec.env.contains_key(key) { bail!("secret injection target {key:?} collides with ordinary action environment"); }
    }
    let _ = resolve_cwd(workspace_root, &spec.relative_cwd)?;
    Ok(())
}

fn resolve_cwd(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute() { bail!("action cwd must be relative to its workspace binding"); }
    for component in relative.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => bail!("action cwd may not escape workspace root"),
            _ => {}
        }
    }
    let cwd = root.join(relative);
    let canonical_root = root.canonicalize().context("canonicalizing workspace root")?;
    let canonical_cwd = cwd.canonicalize().with_context(|| format!("canonicalizing action cwd {}", cwd.display()))?;
    if !canonical_cwd.starts_with(&canonical_root) {
        bail!("action cwd escapes configured workspace root");
    }
    Ok(canonical_cwd)
}


fn normalize_diagnostic_paths(diagnostics: &mut [sparkbridge_diagnostics::Diagnostic], workspace_root: &Path) {
    let canonical_root = workspace_root.canonicalize().unwrap_or_else(|_| workspace_root.to_path_buf());
    for diagnostic in diagnostics {
        let Some(raw) = diagnostic.file.as_deref() else { continue; };
        let path = Path::new(raw);
        if path.is_absolute() {
            if let Ok(relative) = path.strip_prefix(&canonical_root) {
                diagnostic.file = Some(relative.components().filter_map(|c| match c { Component::Normal(v) => v.to_str(), _ => None }).collect::<Vec<_>>().join("/"));
            }
        } else {
            diagnostic.file = Some(raw.replace('\\', "/"));
        }
    }
}

// `cwd` is only consumed by the Linux bubblewrap sandbox path; on other platforms
// `validate_spec` rejects `network=none`, so the parameter is intentionally unused.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn build_command(spec: &ActionSpec, cwd: &Path) -> Result<Command> {
    match spec.domain.as_str() {
        "host" => {
            #[cfg(target_os = "linux")]
            if spec.network_policy == ActionNetworkPolicy::None {
                let mut command = Command::new("bwrap");
                command.args(["--unshare-net", "--bind", "/", "/", "--dev-bind", "/dev", "/dev", "--proc", "/proc", "--chdir"]);
                command.arg(cwd);
                command.arg("--");
                command.arg(&spec.argv[0]);
                command.args(&spec.argv[1..]);
                return Ok(command);
            }
            let mut command = Command::new(&spec.argv[0]);
            command.args(&spec.argv[1..]);
            Ok(command)
        }
        other => bail!("unsupported execution domain {other:?} on this executor"),
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> Result<(Vec<u8>, bool)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut kept = Vec::with_capacity(limit.min(64 * 1024));
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buf).await.context("reading child output")?;
        if count == 0 { break; }
        let remaining = limit.saturating_sub(kept.len());
        if remaining > 0 {
            kept.extend_from_slice(&buf[..count.min(remaining)]);
        }
        if count > remaining { truncated = true; }
    }
    Ok((kept, truncated))
}

async fn terminate_process_tree(child: &mut Child, pid: Option<u32>) {
    if let Some(pid) = pid {
        #[cfg(target_os = "windows")]
        {
            let pid_string = pid.to_string();
            let _ = Command::new("taskkill").args(["/PID", pid_string.as_str(), "/T", "/F"]).status().await;
        }
        #[cfg(unix)]
        {
            let group = -(pid as i32);
            unsafe { libc::kill(group, libc::SIGTERM); }
            time::sleep(Duration::from_millis(250)).await;
            unsafe { libc::kill(group, libc::SIGKILL); }
        }
    }
    if let Err(error) = child.start_kill() {
        warn!(%error, "failed to signal action root process");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_rejects_parent_escape() {
        let root = std::env::current_dir().unwrap();
        assert!(resolve_cwd(&root, "../escape").is_err());
    }
}
