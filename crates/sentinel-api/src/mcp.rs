//! Streamable HTTP transport for the version-pinned MCP contract.
//!
//! The transport authenticates every request against the MCP OAuth audience.
//! Session identifiers are random capabilities for protocol state only: the
//! table stores their digests and every use still requires a live access token.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{UnixMillis, UserId, auth::Scopes};
use sentinel_protocol::{
    error::{ApiError, ErrorCode},
    mcp::{self as contract, ApiCall, Backend},
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    State,
    auth::{self, Identity},
    http::{Header, Request},
    routes::{self, Reply, Route},
};

const MAX_SESSIONS: usize = 1024;
/// Sessions one account may hold. A new one past it replaces that account's
/// least recently used session, so one account can neither take the whole
/// table from everyone else nor lock itself out.
const MAX_SESSIONS_PER_USER: usize = 16;
const _: () = assert!(MAX_SESSIONS_PER_USER >= 1 && MAX_SESSIONS_PER_USER * 4 <= MAX_SESSIONS);
const SESSION_IDLE: Duration = Duration::from_secs(60 * 60);
const MAX_RESPONSE_BYTES: usize = 8 << 20;
const JSON_RPC: &str = "2.0";

#[derive(Clone, Copy)]
struct Session {
    user: UserId,
    last_used: Instant,
    initialized: bool,
}

/// Small bounded protocol-state table. The key is `BLAKE3(session id)`, never
/// the bearer-like value returned to the client.
#[derive(Default)]
pub(crate) struct Sessions {
    entries: Mutex<HashMap<[u8; 32], Session>>,
}

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Session>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn create(&self, user: UserId) -> Result<String, ApiError> {
        self.create_at(user, Instant::now())
    }

    fn create_at(&self, user: UserId, now: Instant) -> Result<String, ApiError> {
        let mut entries = self.lock();
        // One pass: drop idle sessions and find this account's share and
        // its least recently used session.
        let mut held = 0;
        let mut oldest: Option<([u8; 32], Instant)> = None;
        entries.retain(|digest, session| {
            let live = now.saturating_duration_since(session.last_used) < SESSION_IDLE;
            if live && session.user == user {
                held += 1;
                if oldest.is_none_or(|(_, at)| session.last_used < at) {
                    oldest = Some((*digest, session.last_used));
                }
            }
            live
        });
        if held >= MAX_SESSIONS_PER_USER
            && let Some((digest, _)) = oldest
        {
            entries.remove(&digest);
        }
        if entries.len() >= MAX_SESSIONS {
            return Err(
                ApiError::new(ErrorCode::RateLimited, "MCP session capacity reached")
                    .with_detail("retry_after_ms", 1000),
            );
        }
        let secret = Secret::generate();
        let digest = secret.digest();
        let mut presented = String::with_capacity(Secret::TEXT_LEN);
        secret.expose(&mut presented);
        entries.insert(
            digest.0,
            Session {
                user,
                last_used: now,
                initialized: false,
            },
        );
        Ok(presented)
    }

    fn touch(&self, value: &str, user: UserId) -> Result<[u8; 32], ApiError> {
        self.touch_at(value, user, Instant::now())
    }

    fn touch_at(&self, value: &str, user: UserId, now: Instant) -> Result<[u8; 32], ApiError> {
        let secret = Secret::parse(value).ok_or_else(session_not_found)?;
        let digest = secret.digest();
        let mut entries = self.lock();
        let Some(session) = entries.get_mut(&digest.0) else {
            return Err(session_not_found());
        };
        if now.saturating_duration_since(session.last_used) >= SESSION_IDLE {
            entries.remove(&digest.0);
            return Err(session_not_found());
        }
        if session.user != user {
            return Err(session_not_found());
        }
        session.last_used = now;
        Ok(digest.0)
    }

    fn initialized(&self, digest: &[u8; 32]) -> bool {
        self.lock()
            .get(digest)
            .is_some_and(|session| session.initialized)
    }

    fn mark_initialized(&self, digest: &[u8; 32]) -> Result<(), ApiError> {
        let mut entries = self.lock();
        let Some(session) = entries.get_mut(digest) else {
            return Err(session_not_found());
        };
        session.initialized = true;
        Ok(())
    }

    fn remove(&self, digest: &[u8; 32]) {
        self.lock().remove(digest);
    }
}

fn session_not_found() -> ApiError {
    ApiError::new(ErrorCode::NotFound, "MCP session not found")
}

fn validate_origin(state: &State, request: &Request) -> Result<(), ApiError> {
    if routes::header_value(request, "origin").is_some_and(|origin| origin != state.oauth.origin) {
        return Err(ApiError::new(ErrorCode::Forbidden, "origin is not allowed"));
    }
    Ok(())
}

fn identity(state: &State, request: &Request) -> Result<Identity, ApiError> {
    auth::identify_mcp(
        &state.store,
        routes::header_value(request, "authorization"),
        UnixMillis::now(),
    )
    .map_err(|refusal| match refusal {
        auth::Refusal::Unauthenticated => ApiError::new(
            ErrorCode::Unauthenticated,
            "valid MCP bearer token required",
        ),
        auth::Refusal::Busy => ApiError::new(ErrorCode::RateLimited, "controller busy; retry")
            .with_detail("retry_after_ms", 1000),
        auth::Refusal::Csrf | auth::Refusal::Fault => {
            ApiError::new(ErrorCode::Internal, "controller fault")
        }
    })
}

fn accepts(request: &Request, media_type: &str) -> bool {
    routes::header_value(request, "accept").is_some_and(|header| {
        header.split(',').any(|part| {
            let token = part.split(';').next().unwrap_or("").trim();
            token.eq_ignore_ascii_case(media_type)
        })
    })
}

/// The Streamable HTTP version header (MCP 2025-11-25, "Protocol Version
/// Header"). An unsupported value is `400 Bad Request` — still carrying the
/// `unsupported_version` code and the supported revision. An absent header
/// is accepted: every request after `initialize` belongs to a session, and
/// a session only ever negotiated [`contract::PROTOCOL_VERSION`], which is
/// the "other way to identify the version" the specification allows.
fn protocol_header(request: &Request) -> Result<(), Reply> {
    match routes::header_value(request, "mcp-protocol-version") {
        None => Ok(()),
        Some(version) if version == contract::PROTOCOL_VERSION => Ok(()),
        Some(_) => {
            let error = ApiError::new(
                ErrorCode::UnsupportedVersion,
                "MCP-Protocol-Version names an unsupported revision",
            )
            .with_detail("supported", contract::PROTOCOL_VERSION);
            Err(Reply::Json(400, json!(error), Vec::new()))
        }
    }
}

/// The request's session. A missing `Mcp-Session-Id` is `400` (the client
/// must send one); an unknown or expired one is `404`, which tells the
/// client to initialize a new session.
fn session_digest(
    state: &State,
    request: &Request,
    identity: &Identity,
) -> Result<[u8; 32], ApiError> {
    let value = routes::header_value(request, "mcp-session-id").ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "Mcp-Session-Id is required after initialize",
        )
    })?;
    state.mcp_sessions.touch(value, identity.user)
}

fn json_response(value: Value, headers: Vec<Header>) -> Route {
    let body = serde_json::to_string(&value)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "controller fault"))?;
    bounded(body, headers)
}

/// A serialized JSON-RPC answer within the response limit.
fn bounded(body: String, headers: Vec<Header>) -> Route {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            "MCP response exceeds the configured limit",
        )
        .with_detail("limit_bytes", MAX_RESPONSE_BYTES));
    }
    Ok(Reply::JsonText(200, body, headers))
}

pub(crate) fn post(state: &State, request: &mut Request) -> Route {
    validate_origin(state, request)?;
    let who = identity(state, request)?;
    if routes::header_value(request, "content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "Content-Type must be application/json",
        ));
    }
    if !accepts(request, "application/json") || !accepts(request, "text/event-stream") {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "Accept must include application/json and text/event-stream",
        ));
    }
    let bytes = routes::body_limit(request, contract::MAX_MESSAGE_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid JSON-RPC message"))?;
    let object = value.as_object().ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "JSON-RPC message must be an object",
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSON_RPC) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "unsupported JSON-RPC envelope",
        ));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "JSON-RPC method is required"))?;
    let id = object.get("id").cloned();
    let params = match object.get("params") {
        None => None,
        Some(Value::Object(params)) => Some(params),
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "JSON-RPC params must be an object",
            ));
        }
    };
    if id
        .as_ref()
        .is_some_and(|id| !id.is_string() && !id.is_number())
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "JSON-RPC id must be a string or number",
        ));
    }

    if method == "initialize" {
        let id = id.ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "initialize requires a request id",
            )
        })?;
        if routes::header_value(request, "mcp-session-id").is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "initialize cannot reuse an MCP session",
            ));
        }
        let params = params.ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidRequest, "initialize params are required")
        })?;
        if !params.get("capabilities").is_some_and(Value::is_object)
            || !params.get("clientInfo").is_some_and(Value::is_object)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "initialize requires clientInfo and capabilities objects",
            ));
        }
        // Lifecycle version negotiation: whatever revision the client asks
        // for, the answer names the one this server supports, and the
        // client decides whether to continue.
        if !params.get("protocolVersion").is_some_and(Value::is_string) {
            return Ok(rpc_error(
                Some(id),
                -32602,
                "initialize requires a protocolVersion string",
                400,
            ));
        }
        let session = state.mcp_sessions.create(who.user)?;
        let result = json!({
            "protocolVersion": contract::PROTOCOL_VERSION,
            "capabilities": { "tools": {"listChanged": false}, "resources": {"subscribe": false, "listChanged": false} },
            "serverInfo": { "name": "sentinel", "title": "Sentinel CI", "version": env!("CARGO_PKG_VERSION") }
        });
        let presented = vec![routes::header("mcp-session-id", &session)];
        return json_response(rpc_result(Some(id), result), presented);
    }

    if let Err(reply) = protocol_header(request) {
        return Ok(reply);
    }
    let digest = session_digest(state, request, &who)?;

    if method.starts_with("notifications/") {
        if method == "notifications/initialized" {
            state.mcp_sessions.mark_initialized(&digest)?;
        }
        return Ok(Reply::Empty(202, Vec::new()));
    }
    if !state.mcp_sessions.initialized(&digest) && method != "ping" {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "MCP session has not been initialized",
        ));
    }
    let Some(id) = id else {
        return Ok(Reply::Empty(202, Vec::new()));
    };
    let empty = Map::new();
    let params = params.unwrap_or(&empty);
    match method {
        "ping" => raw_result(&id, "{}"),
        // The static catalogue and documents are serialized once per process.
        "tools/list" => raw_result(&id, contract::tools_list_json()),
        "resources/list" => raw_result(&id, contract::resources_list_json()),
        "resources/templates/list" => raw_result(&id, r#"{"resourceTemplates":[]}"#),
        "resources/read" => {
            let uri = params.get("uri").and_then(Value::as_str);
            match uri.and_then(contract::read_resource_json) {
                Some(result) => raw_result(&id, result),
                None => Ok(rpc_error(Some(id), -32002, "resource not found", 200)),
            }
        }
        "tools/call" => call_tool(state, request, &who, &id, params),
        _ => Ok(rpc_error(Some(id), -32601, "method not found", 200)),
    }
}

/// A JSON-RPC result whose `result` is already serialized JSON.
fn raw_result(id: &Value, result: &str) -> Route {
    let id = serde_json::to_string(id)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "controller fault"))?;
    let mut body = String::with_capacity(40 + id.len() + result.len());
    body.push_str(r#"{"jsonrpc":"2.0","id":"#);
    body.push_str(&id);
    body.push_str(r#","result":"#);
    body.push_str(result);
    body.push('}');
    bounded(body, Vec::new())
}

/// A `tools/call` result: the payload once as structured content and once
/// as its JSON text, which the specification asks of a tool returning
/// structured content. Serialized in one pass over borrowed parts.
#[derive(Serialize)]
struct ToolReply<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: ToolResult<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult<'a> {
    content: [TextContent<'a>; 1],
    structured_content: &'a Value,
    is_error: bool,
}

#[derive(Serialize)]
struct TextContent<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

fn call_tool(
    state: &State,
    request: &Request,
    who: &Identity,
    id: &Value,
    params: &Map<String, Value>,
) -> Route {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "tool name is required"))?;
    let empty = Map::new();
    let args = match params.get("arguments") {
        None => &empty,
        Some(Value::Object(args)) => args,
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "tool arguments must be an object",
            ));
        }
    };
    let required = match name {
        "get_logs" | "get_failure" => Scopes::LOGS_READ,
        "dispatch" | "rerun_job" | "cancel" => Scopes::RUNS_WRITE,
        "list_secret_metadata" | "get_secret_metadata" | "list_secret_bindings" => {
            Scopes::SECRETS_METADATA
        }
        "validate_pipeline" => Scopes::NONE,
        _ => Scopes::RUNS_READ,
    };
    auth::require_scope(who, required)?;

    let default_tenant = match who.principal.tenant {
        Some(tenant) if needs_default_tenant(name, args) => state
            .store
            .read(|connection| sentinel_store::lookup::tenant_slug(connection, tenant))
            .map_err(routes::store_error)?,
        _ => String::new(),
    };
    let default_tenant = (!default_tenant.is_empty()).then_some(default_tenant.as_str());
    let mut backend = ApiBackend {
        state,
        request,
        identity: *who,
        default_tenant,
        scope_denied: None,
    };
    let outcome = contract::execute_tool(&mut backend, name, args);
    if let Some(error) = backend.scope_denied {
        return Err(error);
    }
    let (payload, is_error) = match &outcome {
        Ok(value) => (value, false),
        Err(error) => (error, true),
    };
    let text = serde_json::to_string(payload)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "controller fault"))?;
    let reply = ToolReply {
        jsonrpc: JSON_RPC,
        id,
        result: ToolResult {
            content: [TextContent {
                kind: "text",
                text: &text,
            }],
            structured_content: payload,
            is_error,
        },
    };
    let body = serde_json::to_string(&reply)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "controller fault"))?;
    bounded(body, Vec::new())
}

fn needs_default_tenant(name: &str, args: &Map<String, Value>) -> bool {
    args.get("tenant").is_none_or(Value::is_null)
        && matches!(
            name,
            "list_runs"
                | "explain_queue"
                | "dispatch"
                | "list_secret_metadata"
                | "get_secret_metadata"
                | "list_secret_bindings"
        )
}

struct ApiBackend<'a, 'r> {
    state: &'a State,
    request: &'a Request<'r>,
    identity: Identity,
    default_tenant: Option<&'a str>,
    scope_denied: Option<ApiError>,
}

impl Backend for ApiBackend<'_, '_> {
    fn default_tenant(&self) -> Option<&str> {
        self.default_tenant
    }

    /// The API route authorizes, scope included, exactly as for any other
    /// caller; a scope refusal it answers is lifted to the HTTP `403` with
    /// its `insufficient_scope` challenge so the client can step up.
    fn call_api(&mut self, call: ApiCall) -> Result<Value, Value> {
        let (path, query) = call.path.split_once('?').unwrap_or((&call.path, ""));
        let body = if call.body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&call.body).unwrap_or_default()
        };
        let mut headers = Vec::with_capacity(2);
        if !body.is_empty() {
            headers.push(routes::header("content-type", "application/json"));
        }
        if let Some(key) = call.idempotency_key.as_deref() {
            headers.push(routes::header("idempotency-key", key));
        }
        let mut child = self.request.internal(
            call.method.to_owned(),
            call.path.clone(),
            headers,
            body,
            self.identity,
        );
        match routes::route(self.state, &mut child, call.method, path, query) {
            Ok(Reply::Json(status, value, _)) if (200..300).contains(&status) => Ok(value),
            Ok(Reply::Empty(status, _)) if (200..300).contains(&status) => Ok(json!({})),
            Ok(_) => Err(api_error_value(
                ErrorCode::Internal,
                "unexpected API response",
            )),
            Err(error) => {
                let value = serde_json::to_value(&error)
                    .unwrap_or_else(|_| api_error_value(ErrorCode::Internal, "controller fault"));
                if error.code == ErrorCode::Forbidden
                    && error
                        .details
                        .as_ref()
                        .is_some_and(|details| details.get("scope").is_some())
                {
                    self.scope_denied = Some(error);
                }
                Err(value)
            }
        }
    }

    fn validate_pipeline(&mut self, pipeline: &str) -> Result<Value, Value> {
        match sentinel_pipeline::compile_str(pipeline) {
            Ok(compiled) => serde_json::to_value(sentinel_pipeline::Explanation::of(&compiled))
                .map_err(|_| {
                    api_error_value(
                        ErrorCode::Internal,
                        "could not serialize pipeline explanation",
                    )
                }),
            Err(error) => {
                let (stage, position) = match error {
                    sentinel_pipeline::Error::Yaml(error) => {
                        ("yaml", Some(json!({"line":error.line,"column":error.col})))
                    }
                    sentinel_pipeline::Error::Schema(_) => ("schema", None),
                    sentinel_pipeline::Error::Compile(_) => ("compile", None),
                };
                let message = match stage {
                    "yaml" => "pipeline YAML is invalid",
                    "schema" => "pipeline does not match the schema",
                    _ => "pipeline dependency or expression validation failed",
                };
                let mut value = api_error_value(ErrorCode::InvalidRequest, message);
                value["details"] = json!({"stage":stage});
                if let Some(position) = position {
                    value["details"]["position"] = position;
                }
                Err(value)
            }
        }
    }
}

fn api_error_value(code: ErrorCode, message: &str) -> Value {
    serde_json::to_value(ApiError::new(code, message)).unwrap_or(Value::Null)
}

pub(crate) fn get(state: &State, request: &mut Request) -> Route {
    validate_origin(state, request)?;
    let who = identity(state, request)?;
    if routes::header_value(request, "mcp-session-id").is_some() {
        if let Err(reply) = protocol_header(request) {
            return Ok(reply);
        }
        session_digest(state, request, &who)?;
    }
    Ok(Reply::Json(
        405,
        json!({"error":"server-initiated SSE is not supported"}),
        vec![routes::header("allow", "POST, DELETE")],
    ))
}

pub(crate) fn delete(state: &State, request: &mut Request) -> Route {
    validate_origin(state, request)?;
    let who = identity(state, request)?;
    if let Err(reply) = protocol_header(request) {
        return Ok(reply);
    }
    let digest = session_digest(state, request, &who)?;
    state.mcp_sessions.remove(&digest);
    Ok(Reply::Empty(200, Vec::new()))
}

fn rpc_result(id: Option<Value>, result: Value) -> Value {
    json!({"jsonrpc":JSON_RPC,"id":id,"result":result})
}

fn rpc_error(id: Option<Value>, code: i32, message: &str, status: u16) -> Reply {
    Reply::Json(
        status,
        json!({"jsonrpc":JSON_RPC,"id":id,"error":{"code":code,"message":message}}),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P11-5: one account cannot take the table from everyone else; its
    /// seventeenth session replaces its least recently used one.
    #[test]
    fn mcp_sessions_are_capped_per_user_with_lru_eviction() {
        let sessions = Sessions::default();
        let (flood, other) = (UserId::new(), UserId::new());
        let start = Instant::now();
        let at = |n: u64| start + Duration::from_millis(n);
        let ids: Vec<String> = (0..MAX_SESSIONS_PER_USER as u64)
            .map(|n| sessions.create_at(flood, at(n)).unwrap())
            .collect();
        // Use the first so the second becomes the least recently used.
        sessions.touch_at(&ids[0], flood, at(100)).unwrap();
        for n in 0..(MAX_SESSIONS as u64) {
            sessions.create_at(flood, at(200 + n)).unwrap();
        }
        let held = |user| sessions.lock().values().filter(|s| s.user == user).count();
        assert_eq!(held(flood), MAX_SESSIONS_PER_USER);
        assert!(sessions.create_at(other, at(5_000)).is_ok());
        assert_eq!(
            sessions
                .touch_at(&ids[1], flood, at(5_001))
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        // Idle sessions expire.
        let late = at(5_001) + SESSION_IDLE;
        let fresh = sessions.create_at(other, at(5_002)).unwrap();
        assert_eq!(
            sessions
                .touch_at(&fresh, other, late + Duration::from_secs(1))
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn session_ids_are_random_hashed_and_bound_to_the_authenticated_user() {
        let sessions = Sessions::default();
        let user = UserId::new();
        let other = UserId::new();
        let id = sessions.create(user).unwrap();
        let secret = Secret::parse(&id).unwrap();
        assert!(sessions.lock().contains_key(&secret.digest().0));
        assert!(sessions.touch(&id, user).is_ok());
        assert_eq!(
            sessions.touch(&id, other).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            sessions.touch("not-a-session", user).unwrap_err().code,
            ErrorCode::NotFound
        );
    }
}
