#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text()

checks: list[tuple[str, bool]] = []
def check(name: str, condition: bool) -> None:
    checks.append((name, condition))

cargo = text("Cargo.toml")
config = text("crates/sparkbridge-config/src/lib.rs")
core = text("crates/sparkbridge-core/src/lib.rs")
protocol = text("crates/sparkbridge-protocol/src/lib.rs")
server = text("apps/sparkbridge-server/src/main.rs")
inference = text("apps/sparkbridge-server/src/inference.rs")
cli = text("apps/sparkbridge-cli/src/main.rs")
pki = text("apps/sparkbridge-cli/src/pki.rs")
example = text("config/server.example.toml")

check("workspace version is 0.12.0", 'version = "0.12.0"' in cargo)
check("protocol minor is 1.10", "PROTOCOL_MINOR: u16 = 10" in protocol)
check("Ollama URL is loopback validated", "is_loopback_http_url" in config and "ollama_base_url must use http://" in config)
check("gateway has independent TLS listener", "gateway_bind" in config and "gateway_tls" in server)
check("gateway authentication is bearer based", 'strip_prefix("Bearer ")' in inference and "gateway_token_path" in config)
check("gateway digest comparison is constant time", "constant_time_eq" in inference)
check("PKI bootstrap creates gateway token", 'join("gateway-token")' in pki and "random_gateway_token" in pki)
check("gateway token rotation exists", "rotate_gateway_token" in pki and "GatewayTokenCommand" in cli)
check("provider abstraction exists", "trait InferenceProvider" in inference and "impl InferenceProvider for OllamaProvider" in inference)
check("iteration 3 gateway features negotiate", "ITERATION_3_GATEWAY" in core and all(x in core for x in ["InferenceGateway", "InferenceStreaming", "ModelResidency"]))
check("server advertises iteration 3", "ITERATION_3_GATEWAY" in server)
check("pooled localhost client exists", "pool_idle_timeout" in inference and "pool_max_idle_per_host" in inference and "tcp_keepalive" in inference)
check("generate streaming exists", '"/api/v1/inference/generate"' in server and "stream_generate" in inference)
check("chat streaming exists", '"/api/v1/inference/chat"' in server and "stream_chat" in inference)
check("gateway forces streaming", 'insert("stream".into(), Value::Bool(true))' in inference)
check("anti-buffering response headers exist", '"x-accel-buffering"' in inference and '"no-cache, no-transform"' in inference)
check("bounded concurrency exists", "Semaphore::new" in inference and "inference_max_concurrent_requests" in config)
check("queue timeout exists", "inference_queue_timeout_seconds" in config and "inference queue timeout" in inference)
check("stream idle timeout exists", "inference_stream_idle_timeout_seconds" in config and "upstream stream idle" in inference)
check("keep alive is centrally injected", 'entry("keep_alive")' in inference and 'or_insert_with(|| Value::String((*self.default_keep_alive).clone()))' in inference and "inference_keep_alive" in config)
check("model allowlist exists", "inference_allowed_models" in config and "validate_model" in inference)
check("model list endpoint exists", '"/api/v1/inference/models"' in server and '"/api/tags"' in inference)
check("running models endpoint exists", '"/api/v1/inference/running"' in server and '"/api/ps"' in inference)
check("model load/unload exists", "ResidencyAction::Load" in inference and "ResidencyAction::Unload" in inference)
check("residency changes are exclusive", "acquire_many_owned(self.max_concurrent)" in inference)
check("request cancellation exists", 'delete(inference_cancel)' in server and "watch::channel" in inference)
check("request IDs are returned", '"x-sparkbridge-request-id"' in inference)
check("RAII request cleanup exists", "impl Drop for RequestGuard" in inference and "remove_cancellation" in inference)
check("queue cleanup is RAII", "impl Drop for QueueGuard" in inference)
check("Ollama final metrics are parsed", '"prompt_eval_cached_count"' in inference and '"eval_duration"' in inference)
check("gateway timing telemetry exists", "queue_duration_ms" in protocol and "provider_connect_duration_ms" in protocol and "first_chunk_ms" in protocol)
check("prompt/decode token rates are computed", "prompt_tokens_per_second" in protocol and "generation_tokens_per_second" in protocol and "tokens_per_second" in inference)
check("telemetry excludes prompt content", "InferenceTrace" in protocol and "prompt:" not in protocol.split("pub struct InferenceTrace",1)[1].split("}",1)[0])
check("request body limit is configurable", "inference_max_request_bytes" in config and "DefaultBodyLimit::max(config.inference_max_request_bytes)" in server)
check("CLI can stream chat/generate", "stream_inference" in cli and "InferenceCommand::Chat" in cli and "InferenceCommand::Generate" in cli)
check("CLI supports cancellation", "InferenceCommand::Cancel" in cli)
check("example config keeps Ollama local", 'ollama_base_url = "http://127.0.0.1:11434"' in example)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(("PASS" if ok else "FAIL") + ": " + name)

if failed:
    print(f"\n{len(failed)} inference-gateway invariant(s) failed", file=sys.stderr)
    sys.exit(1)

print(f"\nInference Gateway audit passed: {len(checks)} invariants")
