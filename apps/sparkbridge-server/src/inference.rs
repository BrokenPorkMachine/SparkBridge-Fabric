use anyhow::{Context, Result, bail};
use async_stream::stream;
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sparkbridge_config::ServerConfig;
use sparkbridge_protocol::{
    CancellationResponse, InferenceMetricsSnapshot, InferenceProviderHealth, InferenceTrace,
    ResidencyAction, ResidencyRequest, ResidencyResponse,
};
use std::{
    collections::HashMap,
    fs,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, watch};
use tracing::warn;
use uuid::Uuid;

pub type GatewayError = (StatusCode, String);

#[derive(Clone)]
pub struct InferenceGateway {
    provider: OllamaProvider,
    token_hash: Arc<String>,
    semaphore: Arc<Semaphore>,
    max_concurrent: u32,
    cancellations: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
    telemetry: Arc<Telemetry>,
    queue_timeout: Duration,
    stream_idle_timeout: Duration,
    default_keep_alive: Arc<String>,
    allowed_models: Arc<Vec<String>>,
}

impl InferenceGateway {
    pub fn new(config: &ServerConfig) -> Result<Self> {
        let raw_token = fs::read_to_string(&config.gateway_token_path).with_context(|| {
            format!(
                "reading inference gateway token {}",
                config.gateway_token_path.display()
            )
        })?;
        let raw_token = raw_token.trim();
        if raw_token.len() < 32 {
            bail!("gateway token must contain at least 32 characters");
        }

        Ok(Self {
            provider: OllamaProvider::new(&config.ollama_base_url)?,
            token_hash: Arc::new(hash_secret(raw_token)),
            semaphore: Arc::new(Semaphore::new(config.inference_max_concurrent_requests)),
            max_concurrent: config.inference_max_concurrent_requests as u32,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            telemetry: Arc::new(Telemetry::default()),
            queue_timeout: Duration::from_secs(config.inference_queue_timeout_seconds),
            stream_idle_timeout: Duration::from_secs(config.inference_stream_idle_timeout_seconds),
            default_keep_alive: Arc::new(config.inference_keep_alive.clone()),
            allowed_models: Arc::new(config.inference_allowed_models.clone()),
        })
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), GatewayError> {
        let value = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing gateway bearer token".into()))?;

        let presented_hash = hash_secret(value);
        if !constant_time_eq(presented_hash.as_bytes(), self.token_hash.as_bytes()) {
            return Err((StatusCode::UNAUTHORIZED, "invalid gateway bearer token".into()));
        }
        Ok(())
    }

    pub async fn health(&self) -> Result<InferenceProviderHealth, GatewayError> {
        self.provider.health().await.map_err(provider_error)
    }

    pub async fn models(&self) -> Result<Value, GatewayError> {
        self.provider.models().await.map_err(provider_error)
    }

    pub async fn running(&self) -> Result<Value, GatewayError> {
        self.provider.running().await.map_err(provider_error)
    }

    pub fn metrics(&self) -> InferenceMetricsSnapshot {
        self.telemetry.snapshot()
    }

    pub async fn residency(
        &self,
        request: ResidencyRequest,
    ) -> Result<ResidencyResponse, GatewayError> {
        self.validate_model(&request.model)?;
        let action = request.action;
        let model = request.model;
        let _exclusive = tokio::time::timeout(
            self.queue_timeout,
            self.semaphore.clone().acquire_many_owned(self.max_concurrent),
        )
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "timed out waiting for exclusive model residency control".into()))?
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "inference scheduler is shutting down".into()))?;
        let keep_alive = match action {
            ResidencyAction::Load => request
                .keep_alive
                .unwrap_or_else(|| Value::String((*self.default_keep_alive).clone())),
            ResidencyAction::Unload => json!(0),
        };
        let body = json!({
            "model": &model,
            "prompt": "",
            "stream": false,
            "keep_alive": keep_alive,
        });
        let provider_response = self
            .provider
            .post_json("/api/generate", &body)
            .await
            .map_err(provider_error)?;
        Ok(ResidencyResponse {
            model,
            action,
            provider_response,
        })
    }

    pub fn cancel(&self, request_id: &str) -> CancellationResponse {
        let sender = self
            .cancellations
            .lock()
            .ok()
            .and_then(|map| map.get(request_id).cloned());
        let cancelled = sender.map(|sender| sender.send(true).is_ok()).unwrap_or(false);
        CancellationResponse {
            request_id: request_id.to_owned(),
            cancelled,
        }
    }


    pub async fn agent_chat_json(&self, model: &str, system: &str, user: &str) -> Result<Value, GatewayError> {
        self.validate_model(model)?;
        self.telemetry.total_requests.fetch_add(1, Ordering::Relaxed);
        let queue_started = Instant::now();
        let mut queue_guard = QueueGuard::new(self.telemetry.clone());
        let permit = tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "inference queue timeout".into()))?
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "inference scheduler is shutting down".into()))?;
        queue_guard.finish();
        self.telemetry.active_requests.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let request_id = Uuid::new_v4().to_string();
        let body = json!({
            "model": model,
            "messages": [
                {"role":"system", "content": system},
                {"role":"user", "content": user}
            ],
            "stream": false,
            "format": "json",
            "keep_alive": (*self.default_keep_alive).clone()
        });
        let result = self.provider.post_json("/api/chat", &body).await;
        drop(permit);
        self.telemetry.active_requests.fetch_sub(1, Ordering::Relaxed);
        match result {
            Ok(value) => {
                self.telemetry.completed_requests.fetch_add(1, Ordering::Relaxed);
                let queue_duration_ms = elapsed_ms(&queue_started).saturating_sub(elapsed_ms(&started));
                if let Ok(mut slot) = self.telemetry.last_request.lock() {
                    *slot = Some(InferenceTrace {
                        request_id, kind: "agent_chat".into(), model: model.into(), started_unix_ms: unix_ms(), finished_unix_ms: unix_ms(),
                        wall_duration_ms: elapsed_ms(&started), queue_duration_ms, provider_connect_duration_ms: 0, first_chunk_ms: None,
                        total_duration_ns: value.get("total_duration").and_then(Value::as_u64),
                        load_duration_ns: value.get("load_duration").and_then(Value::as_u64),
                        prompt_eval_count: value.get("prompt_eval_count").and_then(Value::as_u64),
                        prompt_eval_cached_count: value.get("prompt_eval_cached_count").and_then(Value::as_u64),
                        prompt_eval_duration_ns: value.get("prompt_eval_duration").and_then(Value::as_u64),
                        eval_count: value.get("eval_count").and_then(Value::as_u64), eval_duration_ns: value.get("eval_duration").and_then(Value::as_u64),
                        prompt_tokens_per_second: None, generation_tokens_per_second: None, cancelled: false, error: None,
                    });
                }
                Ok(value)
            }
            Err(error) => {
                self.telemetry.failed_requests.fetch_add(1, Ordering::Relaxed);
                Err(provider_error(error))
            }
        }
    }

    pub async fn stream_generate(&self, body: Value) -> Result<Response<Body>, GatewayError> {
        self.stream_request("generate", "/api/generate", body).await
    }

    pub async fn stream_chat(&self, body: Value) -> Result<Response<Body>, GatewayError> {
        self.stream_request("chat", "/api/chat", body).await
    }

    async fn stream_request(
        &self,
        kind: &'static str,
        path: &'static str,
        mut body: Value,
    ) -> Result<Response<Body>, GatewayError> {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.trim().is_empty())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "request must contain a non-empty model".into()))?
            .to_owned();
        self.validate_model(&model)?;

        let object = body
            .as_object_mut()
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "inference request must be a JSON object".into()))?;
        object.insert("stream".into(), Value::Bool(true));
        object
            .entry("keep_alive")
            .or_insert_with(|| Value::String((*self.default_keep_alive).clone()));

        self.telemetry.total_requests.fetch_add(1, Ordering::Relaxed);
        let request_started_unix_ms = unix_ms();
        let request_started = Instant::now();
        let queue_started = Instant::now();
        let mut queue_guard = QueueGuard::new(self.telemetry.clone());
        let permit = match tokio::time::timeout(
            self.queue_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                self.telemetry.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Err((StatusCode::SERVICE_UNAVAILABLE, "inference scheduler is shutting down".into()));
            }
            Err(_) => {
                self.telemetry.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Err((StatusCode::SERVICE_UNAVAILABLE, "inference queue timeout".into()));
            }
        };
        queue_guard.finish();
        let queue_duration_ms = elapsed_ms(&queue_started);
        self.telemetry.active_requests.fetch_add(1, Ordering::Relaxed);

        let request_id = Uuid::new_v4().to_string();
        let provider_connect_started = Instant::now();
        let upstream = match self.provider.post_stream(path, &body).await {
            Ok(response) => response,
            Err(error) => {
                self.telemetry.active_requests.fetch_sub(1, Ordering::Relaxed);
                self.telemetry.failed_requests.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return Err(provider_error(error));
            }
        };

        let provider_connect_duration_ms = elapsed_ms(&provider_connect_started);
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        if let Ok(mut map) = self.cancellations.lock() {
            map.insert(request_id.clone(), cancel_tx);
        }

        let guard = RequestGuard::new(
            self.telemetry.clone(),
            self.cancellations.clone(),
            request_id.clone(),
            kind,
            model.clone(),
            request_started_unix_ms,
            request_started,
            queue_duration_ms,
            provider_connect_duration_ms,
        );
        let idle_timeout = self.stream_idle_timeout;

        let output = stream! {
            let _permit = permit;
            let mut guard = guard;
            let mut source = upstream.bytes_stream();
            let mut parse_buffer = Vec::<u8>::new();
            let mut final_metrics = ProviderMetrics::default();
            let mut cancelled = false;
            let mut terminal_error: Option<String> = None;

            loop {
                let next = tokio::select! {
                    changed = cancel_rx.changed() => {
                        if changed.is_ok() && *cancel_rx.borrow() {
                            cancelled = true;
                            None
                        } else {
                            continue;
                        }
                    }
                    item = tokio::time::timeout(idle_timeout, source.next()) => {
                        match item {
                            Ok(item) => item,
                            Err(_) => {
                                terminal_error = Some(format!("upstream stream idle for more than {} seconds", idle_timeout.as_secs()));
                                None
                            }
                        }
                    }
                };

                let Some(next) = next else { break };
                match next {
                    Ok(chunk) => {
                        guard.mark_first_chunk();
                        parse_buffer.extend_from_slice(&chunk);
                        parse_complete_lines(&mut parse_buffer, &mut final_metrics);
                        yield Ok::<Bytes, io::Error>(chunk);
                    }
                    Err(error) => {
                        terminal_error = Some(error.to_string());
                        break;
                    }
                }
            }

            if !parse_buffer.is_empty() {
                parse_metric_line(&parse_buffer, &mut final_metrics);
            }
            guard.finish(final_metrics, cancelled, terminal_error.clone());

            if let Some(error) = terminal_error {
                yield Err(io::Error::other(error));
            }
        };

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .header(header::CACHE_CONTROL, "no-cache, no-transform")
            .header("x-accel-buffering", "no")
            .header("x-sparkbridge-request-id", request_id)
            .body(Body::from_stream(output))
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
    }

    pub async fn openai_chat_completions(&self, mut body: Value) -> Result<Response<Body>, GatewayError> {
        let model = body.get("model").and_then(Value::as_str).filter(|v| !v.trim().is_empty())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "request must contain a non-empty model".into()))?.to_owned();
        self.validate_model(&model)?;
        let stream_requested = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
        if !stream_requested {
            self.telemetry.total_requests.fetch_add(1, Ordering::Relaxed);
            let queue_started = Instant::now();
            let mut queue_guard = QueueGuard::new(self.telemetry.clone());
            let permit = tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned()).await
                .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "inference queue timeout".into()))?
                .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "inference scheduler is shutting down".into()))?;
            queue_guard.finish();
            self.telemetry.active_requests.fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let value = self.provider.post_json("/v1/chat/completions", &body).await.map_err(provider_error);
            drop(permit);
            self.telemetry.active_requests.fetch_sub(1, Ordering::Relaxed);
            match value {
                Ok(value) => {
                    self.telemetry.completed_requests.fetch_add(1, Ordering::Relaxed);
                    let trace = InferenceTrace {
                        request_id: Uuid::new_v4().to_string(), kind:"openai_chat".into(), model,
                        started_unix_ms: unix_ms().saturating_sub(elapsed_ms(&started)), finished_unix_ms: unix_ms(),
                        wall_duration_ms: elapsed_ms(&started), queue_duration_ms: elapsed_ms(&queue_started).saturating_sub(elapsed_ms(&started)),
                        provider_connect_duration_ms:0, first_chunk_ms:None, total_duration_ns:None, load_duration_ns:None,
                        prompt_eval_count:None, prompt_eval_cached_count:None, prompt_eval_duration_ns:None, eval_count:None, eval_duration_ns:None,
                        prompt_tokens_per_second:None, generation_tokens_per_second:None, cancelled:false, error:None,
                    };
                    if let Ok(mut slot)=self.telemetry.last_request.lock(){*slot=Some(trace)}
                    Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE,"application/json")
                        .body(Body::from(serde_json::to_vec(&value).map_err(|e|(StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))?))
                        .map_err(|e|(StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))
                }
                Err(error) => { self.telemetry.failed_requests.fetch_add(1, Ordering::Relaxed); Err(error) }
            }
        } else {
            let object=body.as_object_mut().ok_or_else(||(StatusCode::BAD_REQUEST,"request must be a JSON object".into()))?;
            object.insert("stream".into(),Value::Bool(true));
            self.telemetry.total_requests.fetch_add(1, Ordering::Relaxed);
            let request_started_unix_ms=unix_ms(); let request_started=Instant::now(); let queue_started=Instant::now();
            let mut queue_guard=QueueGuard::new(self.telemetry.clone());
            let permit=tokio::time::timeout(self.queue_timeout,self.semaphore.clone().acquire_owned()).await
                .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"inference queue timeout".into()))?
                .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"inference scheduler is shutting down".into()))?;
            queue_guard.finish(); let queue_duration_ms=elapsed_ms(&queue_started); self.telemetry.active_requests.fetch_add(1,Ordering::Relaxed);
            let request_id=Uuid::new_v4().to_string(); let connect_started=Instant::now();
            let upstream=match self.provider.post_stream("/v1/chat/completions",&body).await { Ok(v)=>v, Err(e)=>{self.telemetry.active_requests.fetch_sub(1,Ordering::Relaxed);self.telemetry.failed_requests.fetch_add(1,Ordering::Relaxed);drop(permit);return Err(provider_error(e));} };
            let provider_connect_duration_ms=elapsed_ms(&connect_started); let (cancel_tx,mut cancel_rx)=watch::channel(false);
            if let Ok(mut map)=self.cancellations.lock(){map.insert(request_id.clone(),cancel_tx);}
            let guard=RequestGuard::new(self.telemetry.clone(),self.cancellations.clone(),request_id.clone(),"openai_chat",model,request_started_unix_ms,request_started,queue_duration_ms,provider_connect_duration_ms);
            let idle_timeout=self.stream_idle_timeout;
            let output=stream!{ let _permit=permit; let mut guard=guard; let mut source=upstream.bytes_stream(); let mut cancelled=false; let mut terminal_error:Option<String>=None;
                loop { let next=tokio::select!{ changed=cancel_rx.changed()=>{if changed.is_ok()&&*cancel_rx.borrow(){cancelled=true;None}else{continue}}, item=tokio::time::timeout(idle_timeout,source.next())=>match item{Ok(v)=>v,Err(_)=>{terminal_error=Some(format!("upstream stream idle for more than {} seconds",idle_timeout.as_secs()));None}}}; let Some(next)=next else{break}; match next{Ok(chunk)=>{guard.mark_first_chunk();yield Ok::<Bytes,io::Error>(chunk)},Err(e)=>{terminal_error=Some(e.to_string());break}} }
                guard.finish(ProviderMetrics::default(),cancelled,terminal_error.clone()); if let Some(error)=terminal_error{yield Err(io::Error::other(error));}
            };
            Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE,"text/event-stream").header(header::CACHE_CONTROL,"no-cache, no-transform").header("x-accel-buffering","no").header("x-sparkbridge-request-id",request_id).body(Body::from_stream(output)).map_err(|e|(StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))
        }
    }

    fn validate_model(&self, model: &str) -> Result<(), GatewayError> {
        if !self.allowed_models.is_empty() && !self.allowed_models.iter().any(|item| item == model) {
            return Err((StatusCode::FORBIDDEN, format!("model {model:?} is not allowed by gateway policy")));
        }
        Ok(())
    }
}

trait InferenceProvider {
    async fn health(&self) -> Result<InferenceProviderHealth>;
    async fn models(&self) -> Result<Value>;
    async fn running(&self) -> Result<Value>;
    async fn post_json(&self, path: &str, body: &Value) -> Result<Value>;
    async fn post_stream(&self, path: &str, body: &Value) -> Result<reqwest::Response>;
}

#[derive(Clone)]
struct OllamaProvider {
    client: Client,
    base_url: Arc<String>,
}

impl OllamaProvider {
    fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .context("building pooled Ollama HTTP client")?;
        Ok(Self {
            client,
            base_url: Arc::new(base_url.trim_end_matches('/').to_owned()),
        })
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .with_context(|| format!("requesting Ollama {path}"))?;
        decode_json_response(response).await
    }
}

impl InferenceProvider for OllamaProvider {
    async fn health(&self) -> Result<InferenceProviderHealth> {
        let value = self.get_json("/api/version").await?;
        Ok(InferenceProviderHealth {
            status: "ok".into(),
            provider: "ollama".into(),
            provider_version: value.get("version").and_then(Value::as_str).map(str::to_owned),
            base_url: (*self.base_url).clone(),
        })
    }

    async fn models(&self) -> Result<Value> {
        self.get_json("/api/tags").await
    }

    async fn running(&self) -> Result<Value> {
        self.get_json("/api/ps").await
    }

    async fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .with_context(|| format!("requesting Ollama {path}"))?;
        decode_json_response(response).await
    }

    async fn post_stream(&self, path: &str, body: &Value) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .with_context(|| format!("starting Ollama stream {path}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            bail!("Ollama returned {status}: {message}");
        }
        Ok(response)
    }
}

async fn decode_json_response(response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        bail!("Ollama returned {status}: {message}");
    }
    response.json().await.context("decoding Ollama JSON response")
}

#[derive(Default)]
struct Telemetry {
    active_requests: AtomicU64,
    queued_requests: AtomicU64,
    total_requests: AtomicU64,
    completed_requests: AtomicU64,
    cancelled_requests: AtomicU64,
    failed_requests: AtomicU64,
    last_request: Mutex<Option<InferenceTrace>>,
}

impl Telemetry {
    fn finish(&self, trace: InferenceTrace) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
        if trace.cancelled {
            self.cancelled_requests.fetch_add(1, Ordering::Relaxed);
        } else if trace.error.is_some() {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.completed_requests.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut slot) = self.last_request.lock() {
            *slot = Some(trace);
        }
    }

    fn snapshot(&self) -> InferenceMetricsSnapshot {
        InferenceMetricsSnapshot {
            active_requests: self.active_requests.load(Ordering::Relaxed),
            queued_requests: self.queued_requests.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            completed_requests: self.completed_requests.load(Ordering::Relaxed),
            cancelled_requests: self.cancelled_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            last_request: self.last_request.lock().ok().and_then(|value| value.clone()),
        }
    }
}

struct QueueGuard {
    telemetry: Arc<Telemetry>,
    active: bool,
}

impl QueueGuard {
    fn new(telemetry: Arc<Telemetry>) -> Self {
        telemetry.queued_requests.fetch_add(1, Ordering::Relaxed);
        Self { telemetry, active: true }
    }

    fn finish(&mut self) {
        if self.active {
            self.telemetry.queued_requests.fetch_sub(1, Ordering::Relaxed);
            self.active = false;
        }
    }
}

impl Drop for QueueGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

struct RequestGuard {
    telemetry: Arc<Telemetry>,
    cancellations: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
    request_id: String,
    kind: &'static str,
    model: String,
    started_unix_ms: u64,
    started: Instant,
    queue_duration_ms: u64,
    provider_connect_duration_ms: u64,
    first_chunk_ms: Option<u64>,
    finished: bool,
}

impl RequestGuard {
    // The guard records every timing stage the telemetry contract requires; the field list
    // is the record itself, so a wrapper struct would only rename the same values.
    #[allow(clippy::too_many_arguments)]
    fn new(
        telemetry: Arc<Telemetry>,
        cancellations: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
        request_id: String,
        kind: &'static str,
        model: String,
        started_unix_ms: u64,
        started: Instant,
        queue_duration_ms: u64,
        provider_connect_duration_ms: u64,
    ) -> Self {
        Self {
            telemetry,
            cancellations,
            request_id,
            kind,
            model,
            started_unix_ms,
            started,
            queue_duration_ms,
            provider_connect_duration_ms,
            first_chunk_ms: None,
            finished: false,
        }
    }

    fn mark_first_chunk(&mut self) {
        if self.first_chunk_ms.is_none() {
            self.first_chunk_ms = Some(elapsed_ms(&self.started));
        }
    }

    fn finish(&mut self, metrics: ProviderMetrics, cancelled: bool, error: Option<String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.remove_cancellation();
        let trace = self.trace(metrics, cancelled, error);
        self.telemetry.finish(trace);
    }

    fn trace(&self, metrics: ProviderMetrics, cancelled: bool, error: Option<String>) -> InferenceTrace {
        InferenceTrace {
            request_id: self.request_id.clone(),
            kind: self.kind.to_owned(),
            model: self.model.clone(),
            started_unix_ms: self.started_unix_ms,
            finished_unix_ms: unix_ms(),
            wall_duration_ms: elapsed_ms(&self.started),
            queue_duration_ms: self.queue_duration_ms,
            provider_connect_duration_ms: self.provider_connect_duration_ms,
            first_chunk_ms: self.first_chunk_ms,
            total_duration_ns: metrics.total_duration_ns,
            load_duration_ns: metrics.load_duration_ns,
            prompt_eval_count: metrics.prompt_eval_count,
            prompt_eval_cached_count: metrics.prompt_eval_cached_count,
            prompt_eval_duration_ns: metrics.prompt_eval_duration_ns,
            eval_count: metrics.eval_count,
            eval_duration_ns: metrics.eval_duration_ns,
            prompt_tokens_per_second: prompt_tokens_per_second(
                metrics.prompt_eval_count,
                metrics.prompt_eval_cached_count,
                metrics.prompt_eval_duration_ns,
            ),
            generation_tokens_per_second: tokens_per_second(metrics.eval_count, metrics.eval_duration_ns),
            cancelled,
            error,
        }
    }

    fn remove_cancellation(&self) {
        if let Ok(mut map) = self.cancellations.lock() {
            map.remove(&self.request_id);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.remove_cancellation();
        let trace = self.trace(
            ProviderMetrics::default(),
            true,
            Some("downstream stream disconnected before completion".into()),
        );
        self.telemetry.finish(trace);
    }
}

#[derive(Debug, Default)]
struct ProviderMetrics {
    total_duration_ns: Option<u64>,
    load_duration_ns: Option<u64>,
    prompt_eval_count: Option<u64>,
    prompt_eval_cached_count: Option<u64>,
    prompt_eval_duration_ns: Option<u64>,
    eval_count: Option<u64>,
    eval_duration_ns: Option<u64>,
}

fn parse_complete_lines(buffer: &mut Vec<u8>, metrics: &mut ProviderMetrics) {
    while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = buffer.drain(..=index).collect();
        parse_metric_line(&line, metrics);
    }
}

fn parse_metric_line(line: &[u8], metrics: &mut ProviderMetrics) {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return;
    };
    if value.get("done").and_then(Value::as_bool) != Some(true) {
        return;
    }
    metrics.total_duration_ns = u64_field(&value, "total_duration");
    metrics.load_duration_ns = u64_field(&value, "load_duration");
    metrics.prompt_eval_count = u64_field(&value, "prompt_eval_count");
    metrics.prompt_eval_cached_count = u64_field(&value, "prompt_eval_cached_count");
    metrics.prompt_eval_duration_ns = u64_field(&value, "prompt_eval_duration");
    metrics.eval_count = u64_field(&value, "eval_count");
    metrics.eval_duration_ns = u64_field(&value, "eval_duration");
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn prompt_tokens_per_second(
    count: Option<u64>,
    cached: Option<u64>,
    duration_ns: Option<u64>,
) -> Option<f64> {
    let count = count?;
    let uncached = count.saturating_sub(cached.unwrap_or(0));
    tokens_per_second(Some(uncached), duration_ns)
}

fn tokens_per_second(count: Option<u64>, duration_ns: Option<u64>) -> Option<f64> {
    let count = count?;
    let duration_ns = duration_ns?;
    if duration_ns == 0 {
        return None;
    }
    Some((count as f64) * 1_000_000_000.0 / duration_ns as f64)
}

fn hash_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn provider_error(error: anyhow::Error) -> GatewayError {
    warn!(%error, "inference provider request failed");
    (StatusCode::BAD_GATEWAY, error.to_string())
}

fn elapsed_ms(started: &Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_final_ollama_metrics() {
        let mut metrics = ProviderMetrics::default();
        parse_metric_line(
            br#"{"done":true,"total_duration":100,"load_duration":10,"prompt_eval_count":20,"prompt_eval_cached_count":5,"prompt_eval_duration":30,"eval_count":40,"eval_duration":50}"#,
            &mut metrics,
        );
        assert_eq!(metrics.total_duration_ns, Some(100));
        assert_eq!(metrics.prompt_eval_cached_count, Some(5));
        assert_eq!(metrics.eval_count, Some(40));
    }

    #[test]
    fn calculates_token_rate() {
        assert_eq!(tokens_per_second(Some(100), Some(2_000_000_000)), Some(50.0));
        assert_eq!(tokens_per_second(Some(100), Some(0)), None);
        assert_eq!(prompt_tokens_per_second(Some(100), Some(20), Some(1_000_000_000)), Some(80.0));
    }

    #[test]
    fn token_hash_is_stable() {
        assert_eq!(hash_secret("abc"), hash_secret("abc"));
        assert_ne!(hash_secret("abc"), hash_secret("abcd"));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
