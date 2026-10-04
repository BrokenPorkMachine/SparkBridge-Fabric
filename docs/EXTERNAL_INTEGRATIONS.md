# External Integrations — v0.11

## Authentication

External clients use the TLS listener configured by `integration_bind` and authenticate with the bearer token in `integration_token_path`.

```http
Authorization: Bearer <integration-token>
```

Do not use the inference gateway token on this listener. Do not expose the loopback admin API to obtain external integration support.

## Principal binding

Every external task is rewritten to `integration_principal_id`. The default `integration-client` service principal has `Read`, `Snapshot`, `CandidateCreate` and `Execute`, but lacks `Promote`, `Approve`, `UseSecret` and `ManagePolicy`.

Workspace policy still applies. Add `integration-client` to `allowed_principals` only for workspaces that IDE/MCP clients may access.

## MCP

Endpoint:

```text
POST /mcp
```

v0.11 implements a deliberately small stateless tool surface. Supported protocol methods:

```text
server/discover
initialize
notifications/initialized
tools/list
tools/call
```

Tools:

```text
sparkbridge.tasks.list
sparkbridge.tasks.get
sparkbridge.tasks.run
sparkbridge.intelligence.search
sparkbridge.intelligence.symbols
sparkbridge.actions.list
sparkbridge.validations.list
```

The 2026-07-28 modern discovery response is supported. The complete subscriptions/listen and MCP Tasks extension are not implemented in v0.11.

## IDE REST API

```text
GET  /api/v1/integrations/summary
GET  /api/v1/integrations/tasks
POST /api/v1/integrations/tasks
GET  /api/v1/integrations/tasks/{id}
GET  /api/v1/integrations/tasks/{id}/events
POST /api/v1/integrations/tasks/{id}/run
GET  /api/v1/integrations/actions
GET  /api/v1/integrations/validations
```

Task creation accepts the ordinary `TaskCreateRequest`, but the server ignores any submitted principal and substitutes the configured integration principal.

## OpenAI compatibility

```text
GET  /v1/models
POST /v1/chat/completions
```

The chat endpoint is routed through SparkBridge admission control and the Ollama provider's OpenAI-compatible API. Streaming responses remain SSE.

## Ollama compatibility

```text
GET  /api/tags
GET  /api/ps
POST /api/generate
POST /api/chat
```

Streaming generate/chat stays immediate. Ollama itself continues to listen only on loopback.

## Dashboard

```text
GET /dashboard
```

The HTML shell is public on the integration TLS listener, but it contains no operational data. Summary data requires the integration bearer token. The bundled UI stores the entered token only in `sessionStorage`.
