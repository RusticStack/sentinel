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
use serde_json::{Map, Value, json};

use crate::{
    State,
    auth::{self, Identity},
    http::{Header, Request},
    routes::{self, Reply, Route},
};

const MAX_SESSIONS: usize = 1024;
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
        let now = Instant::now();
        let mut entries = self.lock();
        entries
            .retain(|_, session| now.saturating_duration_since(session.last_used) < SESSION_IDLE);
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
        let secret = Secret::parse(value).ok_or_else(session_not_found)?;
        let digest = secret.digest();
        let now = Instant::now();
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

fn protocol_header(request: &Request) -> Result<(), ApiError> {
    if routes::header_value(request, "mcp-protocol-version") == Some(contract::PROTOCOL_VERSION) {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::UnsupportedVersion,
            "MCP-Protocol-Version is required and unsupported",
        )
        .with_detail("supported", contract::PROTOCOL_VERSION))
    }
}

fn session_digest(
    state: &State,
    request: &Request,
    identity: &Identity,
) -> Result<[u8; 32], ApiError> {
    let value = routes::header_value(request, "mcp-session-id").ok_or_else(session_not_found)?;
    state.mcp_sessions.touch(value, identity.user)
}

fn json_response(value: Value, headers: Vec<Header>) -> Route {
    let body = serde_json::to_string(&value)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "controller fault"))?;
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
        if params.get("protocolVersion").and_then(Value::as_str) != Some(contract::PROTOCOL_VERSION)
        {
            return Ok(rpc_error(
                Some(id),
                -32602,
                "unsupported protocol version",
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

    protocol_header(request)?;
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
    let params = params.cloned().unwrap_or_default();
    match method {
        "ping" => json_response(rpc_result(Some(id), json!({})), Vec::new()),
        "tools/list" => json_response(
            rpc_result(Some(id), json!({ "tools": contract::tool_definitions() })),
            Vec::new(),
        ),
        "resources/list" => json_response(
            rpc_result(
                Some(id),
                json!({ "resources": contract::resource_definitions() }),
            ),
            Vec::new(),
        ),
        "resources/templates/list" => json_response(
            rpc_result(Some(id), json!({ "resourceTemplates": [] })),
            Vec::new(),
        ),
        "resources/read" => {
            let uri = params.get("uri").and_then(Value::as_str);
            match uri.and_then(contract::read_resource) {
                Some(result) => json_response(rpc_result(Some(id), result), Vec::new()),
                None => Ok(rpc_error(Some(id), -32002, "resource not found", 200)),
            }
        }
        "tools/call" => call_tool(state, request, &who, Some(id), &params),
        _ => Ok(rpc_error(Some(id), -32601, "method not found", 200)),
    }
}

fn call_tool(
    state: &State,
    request: &Request,
    who: &Identity,
    id: Option<Value>,
    params: &Map<String, Value>,
) -> Route {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "tool name is required"))?;
    let args = match params.get("arguments") {
        None => Map::new(),
        Some(Value::Object(args)) => args.clone(),
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
        "list_secret_metadata" | "get_secret_metadata" => Scopes::SECRETS_METADATA,
        "validate_pipeline" => Scopes::NONE,
        _ => Scopes::RUNS_READ,
    };
    auth::require_scope(who, required)?;

    let default_tenant = match who.principal.tenant {
        Some(tenant) if needs_default_tenant(name, &args) => state
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
    let outcome = contract::execute_tool(&mut backend, name, &args);
    if let Some(error) = backend.scope_denied {
        return Err(error);
    }
    let result = match outcome {
        Ok(value) => {
            json!({ "content": [{"type":"text", "text": value.to_string()}], "structuredContent": value, "isError": false })
        }
        Err(error) => {
            json!({ "content": [{"type":"text", "text": error.to_string()}], "structuredContent": error, "isError": true })
        }
    };
    json_response(rpc_result(id, result), Vec::new())
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

    fn call_api(&mut self, call: ApiCall) -> Result<Value, Value> {
        let required = if call.method == "GET" {
            if call.path.contains("/logs?")
                || call.path.contains("/failure?")
                || call.path.ends_with("/logs")
                || call.path.ends_with("/failure")
            {
                Scopes::LOGS_READ
            } else if call.path.contains("/secrets") {
                Scopes::SECRETS_METADATA
            } else {
                Scopes::RUNS_READ
            }
        } else {
            Scopes::RUNS_WRITE
        };
        if let Err(error) = auth::require_scope(&self.identity, required) {
            self.scope_denied = Some(error.clone());
            return Err(serde_json::to_value(error).unwrap_or(Value::Null));
        }
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
            Err(error) => Err(serde_json::to_value(error)
                .unwrap_or_else(|_| api_error_value(ErrorCode::Internal, "controller fault"))),
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
        protocol_header(request)?;
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
    protocol_header(request)?;
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
