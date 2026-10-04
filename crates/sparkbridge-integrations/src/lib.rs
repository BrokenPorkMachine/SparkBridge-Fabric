use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MCP_PROTOCOL_MODERN: &str = "2026-07-28";
pub const MCP_PROTOCOL_LEGACY: &str = "2025-11-25";

#[derive(Debug, Clone)]
pub struct IntegrationAuth {
    token_hash: String,
}

impl IntegrationAuth {
    pub fn new(token: &str) -> Result<Self, String> {
        let token = token.trim();
        if token.len() < 32 { return Err("integration token must contain at least 32 characters".into()); }
        Ok(Self { token_hash: sha256_hex(token.as_bytes()) })
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
        let value = headers.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing integration bearer token".into()))?;
        let supplied = sha256_hex(value.trim().as_bytes());
        if !constant_time_eq(self.token_hash.as_bytes(), supplied.as_bytes()) {
            return Err((StatusCode::UNAUTHORIZED, "invalid integration bearer token".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    #[serde(default)] pub id: Option<Value>,
    pub method: String,
    #[serde(default)] pub params: Value,
    #[serde(default, rename = "_meta")] pub meta: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")] pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")] pub error: Option<McpError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError { pub code: i64, pub message: String, #[serde(skip_serializing_if="Option::is_none")] pub data: Option<Value> }

impl McpResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self { Self { jsonrpc:"2.0".into(), id, result:Some(result), error:None } }
    pub fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self { Self { jsonrpc:"2.0".into(), id, result:None, error:Some(McpError{code,message:message.into(),data:None}) } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename="inputSchema")] pub input_schema: Value,
}

pub fn text_tool_result(value: impl Into<String>) -> Value {
    serde_json::json!({"content":[{"type":"text","text":value.into()}],"isError":false})
}

pub fn json_tool_result(value: &Value) -> Value {
    text_tool_result(serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSummary {
    pub version: String,
    pub protocol: String,
    pub nodes_online: usize,
    pub tasks_active: usize,
    pub actions_active: usize,
    pub validations_active: usize,
    pub inference_active: u64,
    pub inference_queued: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiModel { pub id: String, pub object: String, pub created: u64, pub owned_by: String }

pub fn openai_models_from_ollama(value: &Value, created: u64) -> Value {
    let data = value.get("models").and_then(Value::as_array).cloned().unwrap_or_default().into_iter().filter_map(|m| {
        let id = m.get("name").or_else(|| m.get("model")).and_then(Value::as_str)?.to_owned();
        Some(serde_json::json!({"id":id,"object":"model","created":created,"owned_by":"ollama"}))
    }).collect::<Vec<_>>();
    serde_json::json!({"object":"list","data":data})
}

fn sha256_hex(bytes: &[u8]) -> String { let mut h=Sha256::new(); h.update(bytes); hex::encode(h.finalize()) }
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool { if a.len()!=b.len(){return false} let mut diff=0u8; for (&x,&y) in a.iter().zip(b){diff|=x^y;} diff==0 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn openai_model_conversion() { let v=serde_json::json!({"models":[{"name":"coder:latest"}]}); let out=openai_models_from_ollama(&v,1); assert_eq!(out["data"][0]["id"],"coder:latest"); }
}
