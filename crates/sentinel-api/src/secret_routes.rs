//! Secret routes (S02–S04): metadata reads, raw-byte versioned writes, env
//! imports, repository allowlists, bindings and single-version revocation.
//!
//! Every handler validates its path, query, headers and body shape before
//! it resolves the tenant slug or repository name, and it resolves them with
//! the membership-checked [`authz::member_tenant_by_slug`] inside the same
//! store transaction that authorizes and performs the operation. A foreign
//! tenant or repository is therefore the same `not_found` as a missing one
//! on every route (P10S-3), and a write costs one writer transaction, not a
//! read followed by a write (P10C-11).
//!
//! Stored retry fingerprints are keyed MACs under a subkey of the master key
//! (P10S-1): a copy of the database cannot confirm a guessed value.

use std::sync::Arc;

use sentinel_auth::sealed::Key;
use sentinel_core::{RepoId, TenantId, UnixMillis, auth::Scopes};
use sentinel_protocol::{
    error::{ApiError, ErrorCode},
    idempotency::{Fingerprint, IdempotencyKey},
};
use sentinel_store::{Error as StoreError, auth as authz, lookup, secrets};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    State,
    auth::{self, Identity},
    http::Request,
    routes::{Reply, Route, err, header_value, identify, ok, parse, store_error},
};

/// Longest repository name the store accepts.
const MAX_REPO_NAME: usize = 128;

pub(crate) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    slug: &str,
    kind: &str,
    rest: &[&str],
    query: &str,
) -> Route {
    match (kind, method, rest) {
        ("secrets", "GET", []) => list(state, request, slug, query),
        ("secrets", "POST", ["import"]) => import(state, request, slug, query),
        ("secrets", "GET", [name]) => describe(state, request, slug, name, query),
        ("secrets", "PUT", [name]) => put(state, request, slug, name, query),
        ("secrets", "DELETE", [name]) => delete(state, request, slug, name, query),
        ("secrets", "GET", [name, "allow"]) => allowed(state, request, slug, name, query),
        ("secrets", "PUT", [name, "allow"]) => allow(state, request, slug, name, query, true),
        ("secrets", "DELETE", [name, "allow"]) => allow(state, request, slug, name, query, false),
        ("secrets", "POST", [name, "versions", version, "revoke"]) => {
            revoke(state, request, slug, name, version, query)
        }
        ("secret-bindings", "GET", []) => bindings(state, request, slug, query),
        ("secret-bindings", "PUT", [name]) => bind(state, request, slug, name, query),
        ("secret-bindings", "DELETE", [name]) => unbind(state, request, slug, name, query),
        _ => Err(err(ErrorCode::NotFound, "no such route")),
    }
}

/// A plaintext request body, wiped when dropped on every path.
struct WipeBytes(Vec<u8>);
impl Drop for WipeBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct WipeRecords(Vec<(String, Vec<u8>)>);
impl Drop for WipeRecords {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.fill(0);
        }
    }
}

/// Read a secret-bearing body within `limit`, into a buffer that is wiped
/// on every path and sized from `Content-Length` up front, so a declared
/// body is never reallocated and no unwiped partial copy is freed.
fn secret_body(request: &mut Request, limit: usize) -> Result<WipeBytes, ApiError> {
    use std::io::Read;
    let declared = request.body_length();
    if declared.is_some_and(|n| n > limit) {
        return Err(
            err(ErrorCode::PayloadTooLarge, "body too large").with_detail("limit_bytes", limit)
        );
    }
    let mut bytes = WipeBytes(Vec::with_capacity(declared.unwrap_or(0).min(limit) + 1));
    request
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes.0)
        .map_err(|_| err(ErrorCode::InvalidRequest, "unreadable body"))?;
    if bytes.0.len() > limit {
        return Err(
            err(ErrorCode::PayloadTooLarge, "body too large").with_detail("limit_bytes", limit)
        );
    }
    Ok(bytes)
}

/// The query parameters a secret route reads, percent-decoded once
/// (`form_urlencoded`), so `repo=org%2Fapp` names the repository `org/app`
/// (P10C-6). A repeated parameter is refused rather than guessed at.
#[derive(Default)]
struct Params {
    repo: Option<String>,
    after: Option<String>,
    limit: Option<String>,
    job: Option<String>,
    step: Option<String>,
}

fn params(query: &str) -> Result<Params, ApiError> {
    let mut out = Params::default();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match &*key {
            "repo" => &mut out.repo,
            "after" => &mut out.after,
            "limit" => &mut out.limit,
            "job" => &mut out.job,
            "step" => &mut out.step,
            _ => continue,
        };
        if slot.is_some() {
            return Err(err(
                ErrorCode::InvalidRequest,
                format!("query parameter {key} given twice"),
            ));
        }
        *slot = Some(value.into_owned());
    }
    if let Some(repo) = &out.repo
        && (repo.is_empty() || repo.len() > MAX_REPO_NAME || repo.chars().any(char::is_control))
    {
        return Err(err(ErrorCode::InvalidRequest, "invalid repository name"));
    }
    Ok(out)
}

fn name_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn checked_name(name: &str) -> Result<(), ApiError> {
    if name_valid(name) {
        Ok(())
    } else {
        Err(err(ErrorCode::InvalidRequest, "invalid secret name"))
    }
}

fn selector_valid(value: &str) -> bool {
    value.is_empty() || sentinel_pipeline::schema::valid_id(value)
}

fn read_identity(state: &State, request: &Request) -> Result<Identity, ApiError> {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::SECRETS_METADATA)?;
    Ok(who)
}

fn write_identity(state: &State, request: &Request) -> Result<Identity, ApiError> {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::SECRETS_WRITE)?;
    Ok(who)
}

/// Resolve `slug` (membership-checked) and the optional repository name in
/// the caller's own transaction. A foreign tenant or repository and a
/// missing one are the same `NotFound`.
fn resolve(
    conn: &sentinel_store::Connection,
    who: &Identity,
    slug: &str,
    repo: Option<&str>,
) -> Result<(TenantId, secrets::Scope), StoreError> {
    let tenant = authz::member_tenant_by_slug(conn, who.principal, slug)?;
    let scope = match repo {
        Some(name) => secrets::Scope::Repo(lookup::repo_by_name(conn, tenant, name)?),
        None => secrets::Scope::Tenant(tenant),
    };
    Ok((tenant, scope))
}

fn metadata(value: &secrets::Metadata) -> Value {
    json!({
        "id": value.id.to_string(),
        "tenant": value.tenant.to_string(),
        "repo": value.repo.map(|id| id.to_string()),
        "name": value.name,
        "version": value.version,
        "active": value.active,
        "created_ms": value.created_ms,
        "updated_ms": value.updated_ms,
    })
}

fn scope_repo(scope: secrets::Scope) -> Option<RepoId> {
    match scope {
        secrets::Scope::Tenant(_) => None,
        secrets::Scope::Repo(repo) => Some(repo),
    }
}

fn page_limit(limit: Option<&str>) -> Result<u16, ApiError> {
    let limit = limit
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|_| err(ErrorCode::InvalidRequest, "invalid page size"))?
        .unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(err(ErrorCode::InvalidRequest, "invalid page size"));
    }
    Ok(limit)
}

fn list(state: &State, request: &Request, slug: &str, query: &str) -> Route {
    let who = read_identity(state, request)?;
    let params = params(query)?;
    let limit = page_limit(params.limit.as_deref())?;
    let after = params.after.unwrap_or_default();
    if after.len() > 64 {
        return Err(err(ErrorCode::InvalidRequest, "invalid secret page"));
    }
    let (tenant, scope, rows) = state
        .store
        .read(|conn| {
            let (tenant, scope) = resolve(conn, &who, slug, params.repo.as_deref())?;
            let rows = secrets::list(conn, who.principal, scope, &after, limit)?;
            Ok((tenant, scope, rows))
        })
        .map_err(store_error)?;
    let next = (rows.len() == limit as usize)
        .then(|| rows.last().map(|row| row.name.clone()))
        .flatten();
    ok(json!({
        "tenant": tenant.to_string(),
        "repo": scope_repo(scope).map(|id| id.to_string()),
        "secrets": rows.iter().map(metadata).collect::<Vec<_>>(),
        "next": next,
    }))
}

fn describe(state: &State, request: &Request, slug: &str, name: &str, query: &str) -> Route {
    let who = read_identity(state, request)?;
    checked_name(name)?;
    let params = params(query)?;
    let (tenant, found) = state
        .store
        .read(|conn| {
            let (tenant, scope) = resolve(conn, &who, slug, params.repo.as_deref())?;
            Ok((tenant, secrets::describe(conn, who.principal, scope, name)?))
        })
        .map_err(store_error)?;
    ok(json!({"tenant": tenant.to_string(), "secret": metadata(&found)}))
}

fn write_key(state: &State) -> Result<Arc<Key>, ApiError> {
    state
        .secret_key
        .as_ref()
        .cloned()
        .ok_or_else(|| err(ErrorCode::Internal, "secret storage key is unavailable"))
}

fn if_match(request: &Request) -> Result<u64, ApiError> {
    header_value(request, "if-match")
        .ok_or_else(|| {
            err(
                ErrorCode::InvalidRequest,
                "If-Match current version is required",
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            err(
                ErrorCode::InvalidRequest,
                "If-Match must be a secret version",
            )
        })
}

fn idempotency_key(request: &Request) -> Result<IdempotencyKey, ApiError> {
    header_value(request, "idempotency-key")
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "Idempotency-Key is required"))
        .and_then(|value| IdempotencyKey::parse(value).map_err(ApiError::from))
}

/// The request half of a keyed fingerprint, computed before the writer so
/// the value is hashed off the single writer thread: route, name, expected
/// versions and body, each length-delimited.
fn request_mac(key: &Key, route: &str, name: &str, expected: &[u8], body: &[u8]) -> [u8; 16] {
    let mut mac = key.fingerprinter();
    for part in [route.as_bytes(), name.as_bytes(), expected] {
        mac.update(&(part.len() as u32).to_be_bytes()).update(part);
    }
    mac.update(&(body.len() as u64).to_be_bytes()).update(body);
    mac.finish().to_le_bytes()
}

/// Bind the request MAC to the resolved scope, inside the writer: a few
/// dozen bytes, still keyed.
fn scoped_fingerprint(key: &Key, request: &[u8; 16], scope: secrets::Scope) -> Fingerprint {
    let mut mac = key.fingerprinter();
    mac.update(request);
    match scope {
        secrets::Scope::Tenant(tenant) => mac.update(&[0]).update(tenant.as_bytes()),
        secrets::Scope::Repo(repo) => mac.update(&[1]).update(repo.as_bytes()),
    };
    Fingerprint(mac.finish())
}

/// A value-free fingerprint for a delete, which carries no secret material:
/// FNV over route, scope, name and expected version is enough there.
fn delete_fingerprint(scope: secrets::Scope, name: &str, expected: u64) -> Fingerprint {
    let mut bytes = Vec::with_capacity(1 + 16 + name.len() + 8);
    match scope {
        secrets::Scope::Tenant(tenant) => {
            bytes.push(0);
            bytes.extend_from_slice(tenant.as_bytes());
        }
        secrets::Scope::Repo(repo) => {
            bytes.push(1);
            bytes.extend_from_slice(repo.as_bytes());
        }
    }
    bytes.extend_from_slice(&expected.to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    Fingerprint::of(&bytes)
}

fn replay_json(bytes: &[u8]) -> Result<Value, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("secret idempotency response"))
}

fn put(state: &State, request: &mut Request, slug: &str, name: &str, query: &str) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let expected = if_match(request)?;
    let idempotency = idempotency_key(request)?;
    let params = params(query)?;
    let key = write_key(state)?;
    let mut bytes = secret_body(request, secrets::MAX_VALUE)?;
    if bytes.0.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret value must not be empty",
        ));
    }
    let request_mac = request_mac(&key, "secret.put", name, &expected.to_be_bytes(), &bytes.0);
    let principal = who.user.to_string();
    let (slug, name, repo) = (slug.to_owned(), name.to_owned(), params.repo);
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, repo.as_deref())?;
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.put",
                key: idempotency,
                fingerprint: scoped_fingerprint(&key, &request_mac, scope),
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                bytes.0.fill(0);
                return replay_json(&response);
            }
            let written = secrets::put(
                tx,
                who.principal,
                secrets::Update {
                    scope,
                    name: &name,
                    expected,
                    value: &bytes.0,
                },
                &key,
                now,
            )?;
            bytes.0.fill(0);
            let response = json!({"tenant": tenant.to_string(), "secret": metadata(&written)});
            secrets::idempotency_save(tx, idempotency, response.to_string().as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    Ok(Reply::Json(200, value, Vec::new()))
}

fn delete(state: &State, request: &Request, slug: &str, name: &str, query: &str) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let expected = if_match(request)?;
    let idempotency = idempotency_key(request)?;
    let params = params(query)?;
    let principal = who.user.to_string();
    let (slug, name, repo) = (slug.to_owned(), name.to_owned(), params.repo);
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, repo.as_deref())?;
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.delete",
                key: idempotency,
                fingerprint: delete_fingerprint(scope, &name, expected),
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                return replay_json(&response);
            }
            let deleted = secrets::delete(tx, who.principal, scope, &name, expected, now)?;
            let response = json!({"tenant": tenant.to_string(), "secret": metadata(&deleted)});
            secrets::idempotency_save(tx, idempotency, response.to_string().as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    ok(value)
}

fn expected_versions(value: &str) -> Result<std::collections::HashMap<String, u64>, ApiError> {
    let invalid = || {
        err(
            ErrorCode::InvalidRequest,
            "invalid secret import version list",
        )
    };
    if value.len() > 12_000 {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret import version list is too large",
        ));
    }
    let mut out = std::collections::HashMap::new();
    for item in value.split(',') {
        let (name, version) = item.split_once('=').ok_or_else(invalid)?;
        if !name_valid(name) || out.contains_key(name) {
            return Err(invalid());
        }
        out.insert(
            name.to_owned(),
            version.parse::<u64>().map_err(|_| invalid())?,
        );
    }
    if out.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "secret import version list is empty",
        ));
    }
    Ok(out)
}

fn import(state: &State, request: &mut Request, slug: &str, query: &str) -> Route {
    let who = write_identity(state, request)?;
    let idempotency = idempotency_key(request)?;
    let expected_raw = header_value(request, "if-match")
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "If-Match versions are required"))?
        .to_owned();
    let expected = expected_versions(&expected_raw)?;
    let params = params(query)?;
    let key = write_key(state)?;
    let mut bytes = secret_body(request, sentinel_protocol::secrets::MAX_IMPORT_BYTES)?;
    let records = sentinel_protocol::secrets::parse_env_file(&bytes.0)
        .map_err(|error| err(ErrorCode::InvalidRequest, error.to_string()))?;
    let mut records = WipeRecords(records);
    if records.0.len() != expected.len()
        || records
            .0
            .iter()
            .any(|(name, _)| !expected.contains_key(name))
    {
        return Err(err(
            ErrorCode::InvalidRequest,
            "If-Match must name every imported secret exactly once",
        ));
    }
    let request_mac = request_mac(&key, "secret.import", "", expected_raw.as_bytes(), &bytes.0);
    let principal = who.user.to_string();
    let (slug, repo) = (slug.to_owned(), params.repo);
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, repo.as_deref())?;
            secrets::authorize(tx, who.principal, scope, true)?;
            let idempotency = secrets::Idempotency {
                tenant,
                principal: &principal,
                route: "secret.import",
                key: idempotency,
                fingerprint: scoped_fingerprint(&key, &request_mac, scope),
            };
            if let Some(response) = secrets::idempotency_replay(tx, idempotency, now)? {
                bytes.0.fill(0);
                return replay_json(&response);
            }
            let written = secrets::put_all(
                tx,
                who.principal,
                scope,
                records.0.iter().map(|(name, value)| {
                    (name.as_str(), expected[name.as_str()], value.as_slice())
                }),
                &key,
                now,
            )?;
            bytes.0.fill(0);
            for (_, value) in &mut records.0 {
                value.fill(0);
            }
            let response = json!({
                "tenant": tenant.to_string(),
                "secrets": written.iter().map(metadata).collect::<Vec<_>>(),
            });
            secrets::idempotency_save(tx, idempotency, response.to_string().as_bytes(), now)?;
            Ok(response)
        })
        .map_err(store_error)?;
    ok(value)
}

/// `GET /tenants/{slug}/secrets/{name}/allow?after&limit`: the repositories
/// a tenant secret is allowed in, keyset by repository ID.
fn allowed(state: &State, request: &Request, slug: &str, name: &str, query: &str) -> Route {
    let who = read_identity(state, request)?;
    checked_name(name)?;
    let params = params(query)?;
    let limit = page_limit(params.limit.as_deref())?;
    let after: Option<RepoId> = params
        .after
        .as_deref()
        .map(|value| {
            value
                .parse()
                .map_err(|_| err(ErrorCode::InvalidRequest, "invalid allowlist page"))
        })
        .transpose()?;
    let (tenant, rows) = state
        .store
        .read(|conn| {
            let tenant = authz::member_tenant_by_slug(conn, who.principal, slug)?;
            Ok((
                tenant,
                secrets::list_allowed(conn, who.principal, tenant, name, after, limit)?,
            ))
        })
        .map_err(store_error)?;
    let next = (rows.len() == limit as usize)
        .then(|| rows.last().map(|(id, _)| id.to_string()))
        .flatten();
    ok(json!({
        "tenant": tenant.to_string(),
        "secret": name,
        "repos": rows.iter().map(|(id, repo)| json!({"id": id.to_string(), "name": repo})).collect::<Vec<_>>(),
        "next": next,
    }))
}

/// `PUT|DELETE /tenants/{slug}/secrets/{name}/allow?repo=NAME`: allow a
/// tenant secret in one repository, or stop allowing it (which also removes
/// its bindings there). Idempotent state changes, so a retry is safe
/// without an idempotency key.
fn allow(
    state: &State,
    request: &Request,
    slug: &str,
    name: &str,
    query: &str,
    allowed: bool,
) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let params = params(query)?;
    let repo = params
        .repo
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "repo is required"))?;
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, Some(&repo))?;
            let repo_id = scope_repo(scope).ok_or(StoreError::NotFound)?;
            secrets::allow_repo(tx, who.principal, tenant, &name, repo_id, allowed, now)?;
            Ok(json!({
                "tenant": tenant.to_string(),
                "secret": name,
                "repo": repo_id.to_string(),
                "allowed": allowed,
            }))
        })
        .map_err(store_error)?;
    ok(value)
}

/// `POST /tenants/{slug}/secrets/{name}/versions/{version}/revoke?repo`:
/// permanently revoke one version. Idempotent; the answer is the secret's
/// metadata after the change.
fn revoke(
    state: &State,
    request: &Request,
    slug: &str,
    name: &str,
    version: &str,
    query: &str,
) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let version = version
        .parse::<u64>()
        .ok()
        .filter(|v| (1..=i64::MAX as u64).contains(v))
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "invalid secret version"))?;
    let params = params(query)?;
    let (slug, name, repo) = (slug.to_owned(), name.to_owned(), params.repo);
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, repo.as_deref())?;
            secrets::revoke_version(tx, who.principal, scope, &name, version, now)?;
            let current = secrets::describe(tx, who.principal, scope, &name)?;
            Ok(json!({
                "tenant": tenant.to_string(),
                "secret": metadata(&current),
                "revoked_version": version,
            }))
        })
        .map_err(store_error)?;
    ok(value)
}

fn binding_json(binding: &secrets::Binding) -> Value {
    json!({
        "repo": binding.repo.to_string(),
        "job": binding.job,
        "step": binding.step,
        "name": binding.name,
        "secret": binding.secret.to_string(),
        "override_tenant": binding.override_tenant,
    })
}

/// `GET /tenants/{slug}/secret-bindings?repo=NAME&after=JOB/STEP/NAME&limit`.
fn bindings(state: &State, request: &Request, slug: &str, query: &str) -> Route {
    let who = read_identity(state, request)?;
    let params = params(query)?;
    let limit = page_limit(params.limit.as_deref())?;
    let repo = params
        .repo
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "repo is required"))?;
    let after = match params.after.as_deref() {
        None | Some("") => None,
        Some(value) => {
            let mut parts = value.splitn(3, '/');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(job), Some(step), Some(name))
                    if selector_valid(job) && selector_valid(step) && name_valid(name) =>
                {
                    Some((job.to_owned(), step.to_owned(), name.to_owned()))
                }
                _ => return Err(err(ErrorCode::InvalidRequest, "invalid binding page")),
            }
        }
    };
    let (tenant, repo_id, rows) = state
        .store
        .read(|conn| {
            let (tenant, scope) = resolve(conn, &who, slug, Some(&repo))?;
            let repo_id = scope_repo(scope).ok_or(StoreError::NotFound)?;
            let after = after
                .as_ref()
                .map(|(j, s, n)| (j.as_str(), s.as_str(), n.as_str()));
            let rows = secrets::list_bindings(conn, who.principal, repo_id, after, limit)?;
            Ok((tenant, repo_id, rows))
        })
        .map_err(store_error)?;
    let next = (rows.len() == limit as usize)
        .then(|| {
            rows.last()
                .map(|b| format!("{}/{}/{}", b.job, b.step, b.name))
        })
        .flatten();
    ok(json!({
        "tenant": tenant.to_string(),
        "repo": repo_id.to_string(),
        "bindings": rows.iter().map(binding_json).collect::<Vec<_>>(),
        "next": next,
    }))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindBody {
    #[serde(default)]
    from_tenant: bool,
    #[serde(default)]
    override_tenant: bool,
}

fn selectors(params: &Params) -> Result<(String, String), ApiError> {
    let job = params.job.clone().unwrap_or_default();
    let step = params.step.clone().unwrap_or_default();
    if !selector_valid(&job) || !selector_valid(&step) || (job.is_empty() && !step.is_empty()) {
        return Err(err(ErrorCode::InvalidRequest, "invalid job or step"));
    }
    Ok((job, step))
}

/// `PUT /tenants/{slug}/secret-bindings/{name}?repo&job&step` with an
/// optional `{"from_tenant": bool, "override_tenant": bool}` body. Replaces
/// the binding at that selector; repeating it is harmless.
fn bind(state: &State, request: &mut Request, slug: &str, name: &str, query: &str) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let params = params(query)?;
    let repo = params
        .repo
        .clone()
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "repo is required"))?;
    let (job, step) = selectors(&params)?;
    let body = crate::routes::body_limit(request, 256)?;
    let options: BindBody = if body.is_empty() {
        BindBody::default()
    } else {
        parse(&body)?
    };
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, Some(&repo))?;
            let repo_id = scope_repo(scope).ok_or(StoreError::NotFound)?;
            let binding = secrets::bind_named(
                tx,
                who.principal,
                repo_id,
                &job,
                &step,
                &name,
                options.from_tenant,
                options.override_tenant,
                now,
            )?;
            Ok(json!({"tenant": tenant.to_string(), "binding": binding_json(&binding)}))
        })
        .map_err(store_error)?;
    ok(value)
}

/// `DELETE /tenants/{slug}/secret-bindings/{name}?repo&job&step`: remove
/// that binding if present; repeating it is harmless.
fn unbind(state: &State, request: &Request, slug: &str, name: &str, query: &str) -> Route {
    let who = write_identity(state, request)?;
    checked_name(name)?;
    let params = params(query)?;
    let repo = params
        .repo
        .clone()
        .ok_or_else(|| err(ErrorCode::InvalidRequest, "repo is required"))?;
    let (job, step) = selectors(&params)?;
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let now = UnixMillis::now();
    let value = state
        .store
        .writer()
        .write(move |tx| {
            let (tenant, scope) = resolve(tx, &who, &slug, Some(&repo))?;
            let repo_id = scope_repo(scope).ok_or(StoreError::NotFound)?;
            secrets::unbind(tx, who.principal, repo_id, &job, &step, &name, now)?;
            Ok(json!({
                "tenant": tenant.to_string(),
                "repo": repo_id.to_string(),
                "job": job,
                "step": step,
                "name": name,
                "bound": false,
            }))
        })
        .map_err(store_error)?;
    ok(value)
}
