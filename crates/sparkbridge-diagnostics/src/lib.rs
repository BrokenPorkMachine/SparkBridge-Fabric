use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Note,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
    pub code: Option<String>,
    pub message: String,
    pub tool: Option<String>,
}

pub fn normalize_diagnostics(stdout: &str, stderr: &str) -> Vec<Diagnostic> {
    stderr.lines().chain(stdout.lines()).filter_map(parse_line).collect()
}

fn unix_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s*(?P<sev>error|warning|note)(?:\[(?P<code>[^\]]+)\])?:\s*(?P<msg>.+)$").expect("valid unix diagnostic regex"))
}

fn msvc_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?P<file>.+?)\((?P<line>\d+)(?:,(?P<col>\d+))?\):\s*(?P<sev>error|warning)\s*(?P<code>[A-Za-z]+\d+)?\s*:\s*(?P<msg>.+)$").expect("valid MSVC diagnostic regex"))
}

fn simple_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?P<sev>error|warning|note)(?:\[(?P<code>[^\]]+)\])?:\s*(?P<msg>.+)$").expect("valid simple diagnostic regex"))
}

fn parse_line(line: &str) -> Option<Diagnostic> {
    // GCC/Clang/Swift/Rust style: path:line:column: error|warning|note: message
    if let Some(c) = unix_pattern().captures(line) {
        return Some(Diagnostic {
            severity: severity(&c["sev"]),
            file: Some(c["file"].to_owned()),
            line: c["line"].parse().ok(),
            column: c["col"].parse().ok(),
            code: c.name("code").map(|m| m.as_str().to_owned()),
            message: c["msg"].trim().to_owned(),
            tool: None,
        });
    }

    // MSVC/MSBuild: path(line,column): error C1234: message
    if let Some(c) = msvc_pattern().captures(line) {
        return Some(Diagnostic {
            severity: severity(&c["sev"]),
            file: Some(c["file"].to_owned()),
            line: c["line"].parse().ok(),
            column: c.name("col").and_then(|m| m.as_str().parse().ok()),
            code: c.name("code").map(|m| m.as_str().to_owned()),
            message: c["msg"].trim().to_owned(),
            tool: Some("msvc".into()),
        });
    }

    simple_pattern().captures(line).map(|c| Diagnostic {
        severity: severity(&c["sev"]),
        file: None,
        line: None,
        column: None,
        code: c.name("code").map(|m| m.as_str().to_owned()),
        message: c["msg"].trim().to_owned(),
        tool: None,
    })
}

fn severity(value: &str) -> DiagnosticSeverity {
    match value {
        "error" => DiagnosticSeverity::Error,
        "warning" => DiagnosticSeverity::Warning,
        "note" => DiagnosticSeverity::Note,
        _ => DiagnosticSeverity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_diagnostic() {
        let d = normalize_diagnostics("", "src/main.rs:12:3: error[E0001]: nope");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].line, Some(12));
        assert_eq!(d[0].code.as_deref(), Some("E0001"));
    }

    #[test]
    fn parses_msvc_diagnostic() {
        let d = normalize_diagnostics("", r"C:\src\foo.cpp(42,7): error C2664: bad conversion");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].column, Some(7));
    }

    #[test]
    fn ignores_regular_output() {
        assert!(normalize_diagnostics("Compiling project", "").is_empty());
    }
}
