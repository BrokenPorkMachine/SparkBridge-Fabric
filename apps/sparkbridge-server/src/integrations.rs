use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use sparkbridge_core::SPARKBRIDGE_VERSION;
use sparkbridge_integrations::{
    IntegrationSummary, McpRequest, McpResponse, McpTool, MCP_PROTOCOL_LEGACY,
    MCP_PROTOCOL_MODERN, json_tool_result, openai_models_from_ollama,
};
use sparkbridge_policy::{authorize_workspace as policy_authorize_workspace, classification_allows_boundary, effective_classification};
use sparkbridge_protocol::{Permission, PolicyDecision, ProtocolVersion};
use sparkbridge_task::{TaskCreateRequest, TaskRecord, TaskRunRequest, TaskRunResponse};
use uuid::Uuid;

use crate::{ApiError, AppState, agent_runtime, internal_error, parse_inference_boundary, repository, unix_ms, workspace_policy_for};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(integration_health))
        .route("/version", get(integration_version))
        .route("/dashboard", get(dashboard))
        .route("/api/v1/integrations/summary", get(summary))
        .route("/api/v1/integrations/tasks", get(tasks_list).post(tasks_create))
        .route("/api/v1/integrations/tasks/{task_id}", get(task_get))
        .route("/api/v1/integrations/tasks/{task_id}/run", post(task_run))
        .route("/api/v1/integrations/tasks/{task_id}/events", get(task_events))
        .route("/api/v1/integrations/actions", get(actions_list))
        .route("/api/v1/integrations/validations", get(validations_list))
        .route("/mcp", post(mcp))
        .route("/v1/models", get(openai_models))
        .route("/v1/chat/completions", post(openai_chat))
        .route("/api/tags", get(ollama_tags))
        .route("/api/ps", get(ollama_running))
        .route("/api/generate", post(ollama_generate))
        .route("/api/chat", post(ollama_chat))
}

fn auth(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> { state.integration_auth.authorize(headers) }

fn task_runtime_lock(state:&AppState,task_id:&str)->Result<std::sync::Arc<tokio::sync::Mutex<()>>,ApiError>{
    let mut locks=state.task_locks.lock().map_err(|_|(StatusCode::INTERNAL_SERVER_ERROR,"task lock registry poisoned".into()))?;
    Ok(locks.entry(task_id.to_string()).or_insert_with(||std::sync::Arc::new(tokio::sync::Mutex::new(()))).clone())
}

async fn integration_health(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
    auth(&state,&headers)?; Ok(Json(json!({"status":"ok","version":SPARKBRIDGE_VERSION,"protocol":ProtocolVersion::CURRENT,"surface":"integration"})))
}
async fn integration_version(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{auth(&state,&headers)?;Ok(Json(json!({"version":SPARKBRIDGE_VERSION,"protocol":ProtocolVersion::CURRENT}))) }

async fn summary(State(state):State<AppState>,headers:HeaderMap)->Result<Json<IntegrationSummary>,ApiError>{
    auth(&state,&headers)?;
    let now=unix_ms();
    // Every other integration endpoint scopes to `integration_principal_id`; the summary
    // must too, otherwise one integration client can enumerate other principals' activity.
    let principal=&state.config.integration_principal_id;
    let nodes=state.store.list_nodes(now,state.config.heartbeat_stale_seconds,state.config.heartbeat_offline_seconds).map_err(internal_error)?;
    let tasks=state.store.list_tasks().map_err(internal_error)?.into_iter().filter(|t|&t.spec.principal_id==principal).collect::<Vec<_>>();
    let actions=state.store.list_actions().map_err(internal_error)?.into_iter().filter(|a|&a.spec.principal_id==principal).collect::<Vec<_>>();
    let validations=state.store.list_validation_runs().map_err(internal_error)?.into_iter().filter(|v|&v.principal_id==principal).collect::<Vec<_>>();
    let metrics=state.inference.metrics();
    Ok(Json(IntegrationSummary{
        version:SPARKBRIDGE_VERSION.into(), protocol:format!("{}.{}",ProtocolVersion::CURRENT.major,ProtocolVersion::CURRENT.minor),
        nodes_online:nodes.iter().filter(|n|matches!(n.status,sparkbridge_protocol::NodeStatus::Online)).count(),
        tasks_active:tasks.iter().filter(|t|!t.status.terminal()).count(),
        actions_active:actions.iter().filter(|a|!matches!(a.status,sparkbridge_protocol::ActionStatus::Succeeded|sparkbridge_protocol::ActionStatus::Failed|sparkbridge_protocol::ActionStatus::Cancelled|sparkbridge_protocol::ActionStatus::TimedOut|sparkbridge_protocol::ActionStatus::Lost)).count(),
        validations_active:validations.iter().filter(|v|matches!(v.status,sparkbridge_protocol::ValidationRunStatus::Running|sparkbridge_protocol::ValidationRunStatus::AwaitingApproval)).count(),
        inference_active:metrics.active_requests,inference_queued:metrics.queued_requests,
    }))
}

async fn tasks_list(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Vec<TaskRecord>>,ApiError>{
    auth(&state,&headers)?; let principal=&state.config.integration_principal_id;
    let tasks=state.store.list_tasks().map_err(internal_error)?.into_iter().filter(|t|&t.spec.principal_id==principal).collect(); Ok(Json(tasks))
}
async fn task_get(State(state):State<AppState>,Path(task_id):Path<String>,headers:HeaderMap)->Result<Json<TaskRecord>,ApiError>{
    auth(&state,&headers)?; let task=state.store.get_task(&task_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    if task.spec.principal_id!=state.config.integration_principal_id{return Err((StatusCode::FORBIDDEN,"task is owned by another principal".into()))} Ok(Json(task))
}
async fn task_events(State(state):State<AppState>,Path(task_id):Path<String>,headers:HeaderMap)->Result<Json<Vec<sparkbridge_task::TaskEvent>>,ApiError>{
    auth(&state,&headers)?; let task=state.store.get_task(&task_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    if task.spec.principal_id!=state.config.integration_principal_id{return Err((StatusCode::FORBIDDEN,"task is owned by another principal".into()))}
    state.store.list_task_events(&task_id).map(Json).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))
}

async fn tasks_create(State(state):State<AppState>,headers:HeaderMap,Json(mut request):Json<TaskCreateRequest>)->Result<(StatusCode,Json<TaskRecord>),ApiError>{
    auth(&state,&headers)?;
    request.spec.principal_id=state.config.integration_principal_id.clone();
    request.spec.validate().map_err(|e|(StatusCode::BAD_REQUEST,e))?;
    let base=state.store.get_snapshot(&request.spec.base_snapshot_id).map_err(|e|(StatusCode::NOT_FOUND,format!("base snapshot not found: {e}")))?;
    if base.workspace_id!=request.spec.workspace_id{return Err((StatusCode::BAD_REQUEST,"task workspace_id does not match base snapshot".into()))}
    let principal=state.store.get_principal(&request.spec.principal_id).map_err(|e|(StatusCode::FORBIDDEN,format!("integration principal unavailable: {e}")))?;
    let policy=workspace_policy_for(&state,&request.spec.workspace_id)?;
    // Require Allow, not merely "not Deny": `require_approval_for` yields Ask, and there is no
    // approval workflow for task creation, so treating Ask as permitted would silently
    // ignore a configured approval requirement.
    if policy_authorize_workspace(&principal,&policy,Permission::CandidateCreate)!=PolicyDecision::Allow{return Err((StatusCode::FORBIDDEN,"integration principal is not authorized for this workspace, or this workspace requires approval for candidate creation".into()))}
    request.spec.data_classification=effective_classification(request.spec.data_classification,policy.classification);
    let boundary=parse_inference_boundary(&state.config.inference_data_boundary);
    if !classification_allows_boundary(request.spec.data_classification,boundary){return Err((StatusCode::FORBIDDEN,"task data classification is incompatible with inference boundary".into()))}
    let now=unix_ms(); let record=TaskRecord::new(Uuid::new_v4().to_string(),request.spec,now);
    let record=state.store.create_task(&record,now).map_err(internal_error)?;
    state.store.append_audit("integration.task.created",Some(record.spec.principal_id.clone()),Some(format!("task:{}",record.task_id)),json!({"workspace_id":record.spec.workspace_id}),now).map_err(internal_error)?;
    Ok((StatusCode::CREATED,Json(record)))
}

async fn task_run(State(state):State<AppState>,Path(task_id):Path<String>,headers:HeaderMap,Json(request):Json<TaskRunRequest>)->Result<Json<TaskRunResponse>,ApiError>{
    auth(&state,&headers)?;
    let task=state.store.get_task(&task_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    if task.spec.principal_id!=state.config.integration_principal_id{return Err((StatusCode::FORBIDDEN,"task is owned by another principal".into()))}
    let lock=task_runtime_lock(&state,&task_id)?;
    let _guard=lock.lock().await; agent_runtime::run_task(&state,&task_id,request.max_steps).await.map(Json)
}
async fn actions_list(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Vec<sparkbridge_protocol::ActionRecord>>,ApiError>{auth(&state,&headers)?;let principal=&state.config.integration_principal_id;let rows=state.store.list_actions().map_err(internal_error)?.into_iter().filter(|a|&a.spec.principal_id==principal).collect();Ok(Json(rows))}
async fn validations_list(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Vec<sparkbridge_protocol::ValidationRunRecord>>,ApiError>{auth(&state,&headers)?;let principal=&state.config.integration_principal_id;let rows=state.store.list_validation_runs().map_err(internal_error)?.into_iter().filter(|v|&v.principal_id==principal).collect();Ok(Json(rows))}

async fn openai_models(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{auth(&state,&headers)?;let models=state.inference.models().await?;Ok(Json(openai_models_from_ollama(&models,unix_ms()/1000)))}
async fn openai_chat(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<Value>)->Result<Response,ApiError>{
    auth(&state,&headers)?;
    let model=body.get("model").and_then(Value::as_str).unwrap_or("unknown");
    state.store.append_audit("integration.inference.openai",Some(state.config.integration_principal_id.clone()),Some(format!("model:{model}")),json!({"stream":body.get("stream").and_then(Value::as_bool).unwrap_or(false)}),unix_ms()).map_err(internal_error)?;
    state.inference.openai_chat_completions(body).await
}
async fn ollama_tags(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{auth(&state,&headers)?;state.inference.models().await.map(Json)}
async fn ollama_running(State(state):State<AppState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{auth(&state,&headers)?;state.inference.running().await.map(Json)}
async fn ollama_generate(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<Value>)->Result<Response,ApiError>{auth(&state,&headers)?;state.inference.stream_generate(body).await}
async fn ollama_chat(State(state):State<AppState>,headers:HeaderMap,Json(body):Json<Value>)->Result<Response,ApiError>{auth(&state,&headers)?;state.inference.stream_chat(body).await}

async fn mcp(State(state):State<AppState>,headers:HeaderMap,Json(request):Json<McpRequest>)->Result<Json<McpResponse>,ApiError>{
    auth(&state,&headers)?;
    let id=request.id.clone();
    let response=match request.method.as_str(){
        "server/discover"=>McpResponse::ok(id,json!({"protocolVersion":MCP_PROTOCOL_MODERN,"serverInfo":{"name":"SparkBridge Fabric","version":SPARKBRIDGE_VERSION},"capabilities":{"tools":{}}})),
        "initialize"=>McpResponse::ok(id,json!({"protocolVersion":request.params.get("protocolVersion").and_then(Value::as_str).unwrap_or(MCP_PROTOCOL_LEGACY),"serverInfo":{"name":"SparkBridge Fabric","version":SPARKBRIDGE_VERSION},"capabilities":{"tools":{"listChanged":false}}})),
        "notifications/initialized"=>McpResponse::ok(id,json!({})),
        "tools/list"=>McpResponse::ok(id,json!({"tools":mcp_tools()})),
        "tools/call"=>mcp_call(&state,id,&request.params).await,
        _=>McpResponse::err(id,-32601,format!("method not found: {}",request.method)),
    };
    Ok(Json(response))
}

fn mcp_tools()->Vec<McpTool>{vec![
    McpTool{name:"sparkbridge.tasks.list".into(),description:"List durable SparkBridge agent tasks".into(),input_schema:json!({"type":"object","properties":{},"additionalProperties":false})},
    McpTool{name:"sparkbridge.tasks.get".into(),description:"Get one durable SparkBridge task".into(),input_schema:json!({"type":"object","properties":{"task_id":{"type":"string"}},"required":["task_id"],"additionalProperties":false})},
    McpTool{name:"sparkbridge.tasks.run".into(),description:"Advance one durable task by a bounded number of deterministic steps".into(),input_schema:json!({"type":"object","properties":{"task_id":{"type":"string"},"max_steps":{"type":"integer","minimum":1,"maximum":32}},"required":["task_id"],"additionalProperties":false})},
    McpTool{name:"sparkbridge.intelligence.search".into(),description:"Exact lexical search against an immutable snapshot".into(),input_schema:json!({"type":"object","properties":{"snapshot_id":{"type":"string"},"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["snapshot_id","query"],"additionalProperties":false})},
    McpTool{name:"sparkbridge.intelligence.symbols".into(),description:"Search snapshot-keyed symbols".into(),input_schema:json!({"type":"object","properties":{"snapshot_id":{"type":"string"},"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["snapshot_id","query"],"additionalProperties":false})},
    McpTool{name:"sparkbridge.actions.list".into(),description:"List durable remote actions and their states".into(),input_schema:json!({"type":"object","properties":{},"additionalProperties":false})},
    McpTool{name:"sparkbridge.validations.list".into(),description:"List multi-platform validation matrices".into(),input_schema:json!({"type":"object","properties":{},"additionalProperties":false})},
]}

async fn mcp_call(state:&AppState,id:Option<Value>,params:&Value)->McpResponse{
    let name=params.get("name").and_then(Value::as_str).unwrap_or(""); let args=params.get("arguments").cloned().unwrap_or_else(||json!({}));
    let result:Result<Value,ApiError>=match name{
        "sparkbridge.tasks.list"=>state.store.list_tasks().map(|v|serde_json::to_value(v.into_iter().filter(|t|t.spec.principal_id==state.config.integration_principal_id).collect::<Vec<_>>()).unwrap_or(Value::Null)).map_err(internal_error),
        "sparkbridge.tasks.get"=>match args.get("task_id").and_then(Value::as_str){Some(v)=>match state.store.get_task(v){Ok(x) if x.spec.principal_id==state.config.integration_principal_id=>Ok(serde_json::to_value(x).unwrap_or(Value::Null)),Ok(_)=>Err((StatusCode::FORBIDDEN,"task is owned by another principal".into())),Err(e)=>Err((StatusCode::NOT_FOUND,e.to_string()))},None=>Err((StatusCode::BAD_REQUEST,"task_id required".into()))},
        "sparkbridge.tasks.run"=>{let task_id=args.get("task_id").and_then(Value::as_str).unwrap_or("");let steps=args.get("max_steps").and_then(Value::as_u64).unwrap_or(4) as u32;if task_id.is_empty(){Err((StatusCode::BAD_REQUEST,"task_id required".into()))}else{match state.store.get_task(task_id){Ok(t) if t.spec.principal_id==state.config.integration_principal_id=>match task_runtime_lock(state,task_id){Ok(lock)=>{let _guard=lock.lock().await;agent_runtime::run_task(state,task_id,steps).await.map(|x|serde_json::to_value(x).unwrap_or(Value::Null))},Err(e)=>Err(e)},Ok(_)=>Err((StatusCode::FORBIDDEN,"task is owned by another principal".into())),Err(e)=>Err((StatusCode::NOT_FOUND,e.to_string()))}}},
        "sparkbridge.intelligence.search"=>{let sid=args.get("snapshot_id").and_then(Value::as_str).unwrap_or("");let q=args.get("query").and_then(Value::as_str).unwrap_or("");let limit=args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;if sid.is_empty()||q.is_empty(){Err((StatusCode::BAD_REQUEST,"snapshot_id and query required".into()))}else{authorize_snapshot_read(state,sid).and_then(|_|repository::search(state,sid,q,limit)).map(|x|serde_json::to_value(x).unwrap_or(Value::Null))}},
        "sparkbridge.intelligence.symbols"=>{let sid=args.get("snapshot_id").and_then(Value::as_str).unwrap_or("");let q=args.get("query").and_then(Value::as_str).unwrap_or("");let limit=args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;if sid.is_empty()||q.is_empty(){Err((StatusCode::BAD_REQUEST,"snapshot_id and query required".into()))}else{authorize_snapshot_read(state,sid).and_then(|_|repository::symbols(state,sid,q,limit)).map(|x|serde_json::to_value(x).unwrap_or(Value::Null))}},
        "sparkbridge.actions.list"=>state.store.list_actions().map(|v|serde_json::to_value(v.into_iter().filter(|a|a.spec.principal_id==state.config.integration_principal_id).collect::<Vec<_>>()).unwrap_or(Value::Null)).map_err(internal_error),
        "sparkbridge.validations.list"=>state.store.list_validation_runs().map(|v|serde_json::to_value(v.into_iter().filter(|x|x.principal_id==state.config.integration_principal_id).collect::<Vec<_>>()).unwrap_or(Value::Null)).map_err(internal_error),
        _=>Err((StatusCode::NOT_FOUND,format!("unknown MCP tool {name}"))),
    };
    let outcome=if result.is_ok(){"ok"}else{"error"};
    let _=state.store.append_audit("integration.mcp.tool",Some(state.config.integration_principal_id.clone()),Some(format!("mcp:{name}")),json!({"outcome":outcome}),unix_ms());
    match result{Ok(v)=>McpResponse::ok(id,json_tool_result(&v)),Err((_,message))=>McpResponse::err(id,-32000,message)}
}

fn authorize_snapshot_read(state:&AppState,snapshot_id:&str)->Result<(),ApiError>{
    let snapshot=state.store.get_snapshot(snapshot_id).map_err(|e|(StatusCode::NOT_FOUND,e.to_string()))?;
    let principal=state.store.get_principal(&state.config.integration_principal_id).map_err(|e|(StatusCode::FORBIDDEN,e.to_string()))?;
    let policy=workspace_policy_for(state,&snapshot.workspace_id)?;
    // Require Allow so `require_approval_for: ["read"]` actually gates MCP repository reads.
    if policy_authorize_workspace(&principal,&policy,Permission::Read)!=PolicyDecision::Allow{return Err((StatusCode::FORBIDDEN,"integration principal is not authorized to read this workspace, or this workspace requires approval for reads".into()))}
    Ok(())
}

async fn dashboard(State(state):State<AppState>,headers:HeaderMap)->Result<impl IntoResponse,ApiError>{
    // Every other integration handler authenticates first; auth is a per-handler call here,
    // so an omitted one silently makes the route public.
    auth(&state,&headers)?;
    if !state.config.dashboard_enabled{return Err((StatusCode::NOT_FOUND,"dashboard disabled".into()))}
    Ok(Html(DASHBOARD_HTML))
}

const DASHBOARD_HTML:&str=r#"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>SparkBridge Fabric</title><style>body{font:15px system-ui;background:#0b0d10;color:#e8eaed;margin:0}main{max-width:1100px;margin:40px auto;padding:0 24px}h1{font-size:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{background:#15191f;border:1px solid #2a3038;border-radius:12px;padding:18px}.n{font-size:30px;font-weight:700}input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #39414b;background:#11151a;color:#eee}button{cursor:pointer}pre{white-space:pre-wrap;background:#11151a;padding:14px;border-radius:10px}</style></head><body><main><h1>SparkBridge Fabric</h1><p>Integration dashboard. The bearer token stays in this browser tab only.</p><p><input id='token' type='password' placeholder='integration token' size='44'> <button onclick='load()'>Refresh</button></p><div class='grid' id='grid'></div><pre id='status'></pre></main><script>async function load(){let t=document.getElementById('token').value;sessionStorage.setItem('sbtoken',t);let r=await fetch('/api/v1/integrations/summary',{headers:{Authorization:'Bearer '+t}});let s=await r.text();if(!r.ok){status.textContent=s;return}let j=JSON.parse(s);let pairs=[['Online nodes',j.nodes_online],['Active tasks',j.tasks_active],['Active actions',j.actions_active],['Active validations',j.validations_active],['Inference active',j.inference_active],['Inference queued',j.inference_queued]];grid.innerHTML=pairs.map(x=>`<div class=card><div>${x[0]}</div><div class=n>${x[1]}</div></div>`).join('');status.textContent=`SparkBridge ${j.version} · protocol ${j.protocol}`;}token.value=sessionStorage.getItem('sbtoken')||'';</script></body></html>"#;
