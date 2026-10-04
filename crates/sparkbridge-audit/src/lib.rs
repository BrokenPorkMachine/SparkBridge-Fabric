use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub sequence: u64,
    pub event_id: String,
    pub previous_hash: String,
    pub kind: String,
    pub principal_id: Option<String>,
    pub resource: Option<String>,
    pub created_unix_ms: u64,
    pub payload: Value,
}

pub fn new_event_id() -> String { Uuid::new_v4().to_string() }

pub fn hash_envelope(envelope: &AuditEnvelope) -> String {
    let canonical = canonical_json(&serde_json::to_value(envelope).expect("serializable audit envelope"));
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => serde_json::to_string(v).expect("serializable string"),
        Value::Array(values) => format!("[{}]", values.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let body = entries.into_iter().map(|(key, value)| {
                format!("{}:{}", serde_json::to_string(key).expect("serializable key"), canonical_json(value))
            }).collect::<Vec<_>>().join(",");
            format!("{{{body}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn object_key_order_does_not_change_hash() {
        let a: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }
}
