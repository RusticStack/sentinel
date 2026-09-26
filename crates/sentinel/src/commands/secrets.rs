//! Protected-input secret commands. Values are held only long enough to send
//! the request; output and every error contain metadata or fixed diagnostics.
//!
//! Writes are retry-safe across invocations: every write carries one
//! idempotency key (`--idempotency-key`, or a generated one), and a write
//! whose outcome is unknown (exit 6) reports that key and the expected
//! version it was sent with, so rerunning with both replays the first
//! result instead of rotating again.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, IsTerminal, Write},
    path::Path,
};

use serde_json::{Value, json};

use crate::{
    bounded,
    client::{self, Client, Error, Exit, Output},
    commands::{SecretCommand, SecretRepoArgs, SecretScopeArgs, tenant},
};

const MAX_LIST: usize = 10_000;
const MAX_REPO_NAME: usize = 128;

struct WriteInput<'a> {
    name: &'a str,
    scope: &'a SecretScopeArgs,
    file: Option<&'a Path>,
    stdin: bool,
    requested_version: Option<u64>,
    idempotency: Option<&'a str>,
    rotation_only: bool,
}

struct WipeBytes(Vec<u8>);
impl Drop for WipeBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct WipeEntries(Vec<(String, Vec<u8>)>);
impl Drop for WipeEntries {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.fill(0);
        }
    }
}

pub fn run(client: &Client, output: Output, command: SecretCommand) -> Result<(), Error> {
    match command {
        SecretCommand::Set {
            name,
            scope,
            file,
            stdin,
            if_version,
            idempotency_key,
        } => write_secret(
            client,
            output,
            WriteInput {
                name: &name,
                scope: &scope,
                file: file.as_deref(),
                stdin,
                requested_version: if_version,
                idempotency: idempotency_key.as_deref(),
                rotation_only: false,
            },
        ),
        SecretCommand::Rotate {
            name,
            scope,
            file,
            stdin,
            if_version,
            idempotency_key,
        } => write_secret(
            client,
            output,
            WriteInput {
                name: &name,
                scope: &scope,
                file: file.as_deref(),
                stdin,
                requested_version: Some(if_version),
                idempotency: idempotency_key.as_deref(),
                rotation_only: true,
            },
        ),
        SecretCommand::List { scope } => list(client, output, &scope),
        SecretCommand::Describe { name, scope } => describe(client, output, &scope, &name),
        SecretCommand::Delete {
            name,
            scope,
            if_version,
            idempotency_key,
        } => delete(
            client,
            output,
            &scope,
            &name,
            if_version,
            idempotency_key.as_deref(),
        ),
        SecretCommand::Import {
            scope,
            env_file,
            preview,
            if_versions,
            idempotency_key,
        } => import(
            client,
            output,
            &scope,
            &env_file,
            Import {
                preview,
                pinned: if_versions.as_deref(),
                idempotency: idempotency_key.as_deref(),
            },
        ),
        SecretCommand::Bind {
            name,
            target,
            job,
            step,
            from_tenant,
            override_tenant,
        } => bind(
            client,
            output,
            &name,
            &target,
            Selector {
                job: job.as_deref(),
                step: step.as_deref(),
            },
            json!({"from_tenant": from_tenant, "override_tenant": override_tenant}),
        ),
        SecretCommand::Unbind {
            name,
            target,
            job,
            step,
        } => unbind(
            client,
            output,
            &name,
            &target,
            Selector {
                job: job.as_deref(),
                step: step.as_deref(),
            },
        ),
        SecretCommand::Bindings { target } => bindings(client, output, &target),
        SecretCommand::Allow { name, target } => allow(client, output, &name, &target, true),
        SecretCommand::Deny { name, target } => allow(client, output, &name, &target, false),
        SecretCommand::Allowed { name, tenant } => allowed(client, output, &name, tenant),
        SecretCommand::RevokeVersion {
            name,
            scope,
            revoke,
        } => revoke_version(client, output, &name, &scope, revoke),
    }
}

fn validate_name(name: &str) -> Result<(), Error> {
    let bytes = name.as_bytes();
    if !(1..=64).contains(&bytes.len())
        || !(bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        || !bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return Err(Error::usage("secret names must match [A-Z_][A-Z0-9_]*"));
    }
    Ok(())
}

/// The store's rule for repository names: 1–128 bytes, no control
/// characters. Anything else (`/` included, as in `RusticStack/app`) is
/// percent-encoded into the query rather than refused (P10C-6).
fn validate_repo(repo: &str) -> Result<(), Error> {
    if repo.is_empty() || repo.len() > MAX_REPO_NAME || repo.chars().any(char::is_control) {
        return Err(Error::usage(
            "repository names are 1 to 128 bytes without control characters",
        ));
    }
    Ok(())
}

fn scope_path(client: &Client, scope: &SecretScopeArgs) -> Result<(String, Option<String>), Error> {
    let tenant = tenant(client, scope.tenant.clone())?;
    if let Some(repo) = &scope.repo {
        validate_repo(repo)?;
    }
    let path = format!("/api/v1/tenants/{tenant}/secrets");
    Ok((path, scope.repo.clone()))
}

/// `path?k=v&…`, every value form-encoded; `None` values are skipped.
fn with_query(path: &str, pairs: &[(&str, Option<&str>)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if let Some(value) = value {
            query.append_pair(key, value);
        }
    }
    let query = query.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

fn secret_path(base: &str, name: &str, repo: Option<&str>) -> String {
    with_query(&format!("{base}/{name}"), &[("repo", repo)])
}

/// Every metadata record in the scope, in name order; stops early once a
/// page passes `until` (the greatest name the caller needs).
fn all_metadata(
    client: &Client,
    scope: &SecretScopeArgs,
    until: Option<&str>,
) -> Result<Vec<Value>, Error> {
    let (base, repo) = scope_path(client, scope)?;
    let mut after = String::new();
    let mut output = Vec::new();
    loop {
        let page = client.get(&with_query(
            &base,
            &[
                ("repo", repo.as_deref()),
                ("limit", Some("100")),
                ("after", Some(&after)),
            ],
        ))?;
        let items = page["secrets"]
            .as_array()
            .ok_or_else(|| Error::remote("controller returned an invalid secret list"))?;
        for item in items {
            if output.len() == MAX_LIST {
                return Err(Error::usage("secret list exceeds 10000 records"));
            }
            output.push(item.clone());
        }
        let Some(next) = page["next"].as_str().filter(|s| !s.is_empty()) else {
            break;
        };
        if until.is_some_and(|last| next >= last) {
            break;
        }
        after.clear();
        after.push_str(next);
    }
    Ok(output)
}

fn list(client: &Client, output: Output, scope: &SecretScopeArgs) -> Result<(), Error> {
    let values = all_metadata(client, scope, None)?;
    let document = json!({"schema":"sentinel.secrets/1", "secrets":values});
    client::emit(output, &document, || {
        let mut text = String::new();
        for secret in document["secrets"].as_array().into_iter().flatten() {
            text.push_str(&metadata_line(secret));
            text.push('\n');
        }
        text
    });
    Ok(())
}

fn describe(
    client: &Client,
    output: Output,
    scope: &SecretScopeArgs,
    name: &str,
) -> Result<(), Error> {
    validate_name(name)?;
    let (base, repo) = scope_path(client, scope)?;
    let value = client.get(&secret_path(&base, name, repo.as_deref()))?;
    let secret = value["secret"].clone();
    if !secret.is_object() {
        return Err(Error::remote("controller returned invalid secret metadata"));
    }
    client::emit(output, &secret, || metadata_line(&secret));
    Ok(())
}

/// A write that may or may not have been applied (exit 6) names the exact
/// retry that replays it: the same idempotency key and expected version(s).
/// Nothing here contains a value.
fn retry_hint(mut error: Error, key: &str, expected: (&str, &str)) -> Error {
    if error.exit != Exit::Busy {
        return error;
    }
    let (flag, versions) = expected;
    error.message = format!(
        "{}; the write may have been applied: rerun with --idempotency-key {key} {flag} {versions} to replay it instead of writing again",
        error
            .message
            .replace("`sentinel run list`", "`sentinel secret describe`")
    );
    let mut document = error.document();
    document["details"]["idempotency_key"] = Value::from(key);
    error.api = Some(document);
    error
}

fn write_secret(client: &Client, output: Output, input: WriteInput<'_>) -> Result<(), Error> {
    let WriteInput {
        name,
        scope,
        file,
        stdin,
        requested_version,
        idempotency,
        rotation_only,
    } = input;
    validate_name(name)?;
    let idempotency = idempotency_key(idempotency)?;
    let value = WipeBytes(read_input(file, stdin)?);
    if value.0.is_empty() || value.0.len() > sentinel_protocol::secrets::MAX_SECRET_BYTES {
        return Err(Error::usage("secret value must be 1 to 65536 bytes"));
    }
    let (base, repo) = scope_path(client, scope)?;
    let endpoint = secret_path(&base, name, repo.as_deref());
    let expected = match requested_version {
        Some(version) => version,
        None => match client.get(&endpoint) {
            Ok(answer) => {
                if answer["secret"]["active"] != true {
                    return Err(Error::new(
                        Exit::Conflict,
                        "deleted secret names cannot be reused",
                    ));
                }
                answer["secret"]["version"]
                    .as_u64()
                    .ok_or_else(|| Error::remote("controller returned invalid secret version"))?
            }
            Err(error) if error.exit == Exit::NotFound && !rotation_only => 0,
            Err(error) => return Err(error),
        },
    };
    if rotation_only && expected == 0 {
        return Err(Error::usage("rotation requires a nonzero --if-version"));
    }
    let expected_text = expected.to_string();
    let headers = [("if-match", expected_text.as_str())];
    let answer = client
        .put_bytes(
            &endpoint,
            &value.0,
            "application/octet-stream",
            &headers,
            &idempotency,
        )
        .map_err(|error| retry_hint(error, &idempotency, ("--if-version", &expected_text)))?;
    let secret = answer["secret"].clone();
    if !secret.is_object() {
        return Err(Error::remote("controller returned invalid secret metadata"));
    }
    client::emit(output, &secret, || metadata_line(&secret));
    Ok(())
}

fn delete(
    client: &Client,
    output: Output,
    scope: &SecretScopeArgs,
    name: &str,
    expected: u64,
    idempotency: Option<&str>,
) -> Result<(), Error> {
    validate_name(name)?;
    if expected == 0 {
        return Err(Error::usage("--if-version must be nonzero"));
    }
    let (base, repo) = scope_path(client, scope)?;
    let endpoint = secret_path(&base, name, repo.as_deref());
    let version = expected.to_string();
    let key = idempotency_key(idempotency)?;
    let answer = client
        .delete_with(&endpoint, &[("if-match", &version)], &key)
        .map_err(|error| retry_hint(error, &key, ("--if-version", &version)))?;
    let secret = answer["secret"].clone();
    if !secret.is_object() {
        return Err(Error::remote("controller returned invalid secret metadata"));
    }
    client::emit(output, &secret, || metadata_line(&secret));
    Ok(())
}

struct Import<'a> {
    preview: bool,
    pinned: Option<&'a str>,
    idempotency: Option<&'a str>,
}

/// `NAME=V,…` as `--if-versions` takes it: every parsed name exactly once.
fn parse_pin(text: &str, names: &[&str]) -> Result<Vec<u64>, Error> {
    let invalid = || Error::usage("--if-versions must list every imported NAME=version once");
    let mut pinned: HashMap<&str, u64> = HashMap::with_capacity(names.len());
    for item in text.split(',') {
        let (name, version) = item.split_once('=').ok_or_else(invalid)?;
        let version = version.parse().map_err(|_| invalid())?;
        if pinned.insert(name, version).is_some() {
            return Err(invalid());
        }
    }
    if pinned.len() != names.len() {
        return Err(invalid());
    }
    names
        .iter()
        .map(|name| pinned.get(name).copied().ok_or_else(invalid))
        .collect()
}

fn import(
    client: &Client,
    output: Output,
    scope: &SecretScopeArgs,
    path: &Path,
    options: Import<'_>,
) -> Result<(), Error> {
    let key = idempotency_key(options.idempotency)?;
    let bytes = WipeBytes(read_protected_file(
        path,
        sentinel_protocol::secrets::MAX_IMPORT_BYTES,
    )?);
    let entries = sentinel_protocol::secrets::parse_env_file(&bytes.0)
        .map_err(|error| Error::usage(error.to_string()))?;
    let entries = WipeEntries(entries);
    let names: Vec<&str> = entries.0.iter().map(|(name, _)| name.as_str()).collect();
    let versions: Vec<u64> = match options.pinned {
        // A pin from --preview: the server refuses the whole import if any
        // name moved since, so a rotation in between is never overwritten.
        Some(pin) => parse_pin(pin, &names)?,
        None => {
            let until = names.iter().copied().max();
            let observed: HashMap<String, (u64, bool)> = all_metadata(client, scope, until)?
                .into_iter()
                .filter_map(|secret| {
                    Some((
                        secret["name"].as_str()?.to_owned(),
                        (secret["version"].as_u64()?, secret["active"] == true),
                    ))
                })
                .collect();
            let mut versions = Vec::with_capacity(names.len());
            let mut document = Vec::with_capacity(names.len());
            for (name, value) in &entries.0 {
                let (version, active) = observed.get(name).copied().unwrap_or((0, true));
                let (quoted, padded) = sentinel_protocol::secrets::literal_hints(value);
                versions.push(version);
                document.push((name.as_str(), version, active, quoted, padded));
            }
            if options.preview {
                return preview(output, &document);
            }
            if let Some((name, ..)) = document.iter().find(|entry| !entry.2) {
                return Err(Error::new(
                    Exit::Conflict,
                    format!("{name} was deleted; deleted secret names cannot be reused"),
                ));
            }
            versions
        }
    };
    let expected = pin_text(names.iter().copied().zip(versions.iter().copied()));
    let (base, repo) = scope_path(client, scope)?;
    let endpoint = with_query(&format!("{base}/import"), &[("repo", repo.as_deref())]);
    let answer = client
        .post_bytes(
            &endpoint,
            &bytes.0,
            "text/plain; charset=utf-8",
            &[("if-match", &expected)],
            &key,
        )
        .map_err(|error| retry_hint(error, &key, ("--if-versions", &expected)))?;
    let values = answer["secrets"].clone();
    if !values.is_array() {
        return Err(Error::remote("controller returned invalid import metadata"));
    }
    let document = json!({"schema":"sentinel.secrets/1","secrets":values});
    client::emit(output, &document, || {
        let mut text = String::new();
        for secret in document["secrets"].as_array().into_iter().flatten() {
            text.push_str(&metadata_line(secret));
            text.push('\n');
        }
        text
    });
    Ok(())
}

fn pin_text<'a>(pairs: impl Iterator<Item = (&'a str, u64)>) -> String {
    let mut out = String::new();
    for (index, (name, version)) in pairs.enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(&version.to_string());
    }
    out
}

/// Names, expected versions and literal hints only, plus the exact
/// `--if-versions` pin that binds a later import to what was previewed.
fn preview(output: Output, entries: &[(&str, u64, bool, bool, bool)]) -> Result<(), Error> {
    let pin = pin_text(entries.iter().map(|entry| (entry.0, entry.1)));
    let items: Vec<Value> = entries
        .iter()
        .map(|(name, version, active, quoted, padded)| {
            json!({
                "name": name,
                "expected_version": version,
                "active": active,
                "quoted": quoted,
                "surrounding_whitespace": padded,
            })
        })
        .collect();
    let document = json!({
        "schema": "sentinel.secret-import-preview/1",
        "secrets": items,
        "if_versions": pin,
    });
    client::emit(output, &document, || {
        let mut text = String::new();
        for (name, version, active, quoted, padded) in entries {
            text.push_str(&format!("{name} expected_version={version}"));
            if !active {
                text.push_str(" deleted (import will refuse it)");
            }
            if *quoted {
                text.push_str(" warning: value is wrapped in quotes, which are stored literally");
            }
            if *padded {
                text.push_str(" warning: value starts or ends with whitespace");
            }
            text.push('\n');
        }
        text.push_str(&format!("pin: --if-versions {pin}\n"));
        text
    });
    Ok(())
}

struct Selector<'a> {
    job: Option<&'a str>,
    step: Option<&'a str>,
}

fn repo_target(client: &Client, target: &SecretRepoArgs) -> Result<String, Error> {
    validate_repo(&target.repo)?;
    let tenant = tenant(client, target.tenant.clone())?;
    Ok(tenant)
}

fn binding_path(
    client: &Client,
    name: &str,
    target: &SecretRepoArgs,
    at: &Selector<'_>,
) -> Result<String, Error> {
    validate_name(name)?;
    let tenant = repo_target(client, target)?;
    Ok(with_query(
        &format!("/api/v1/tenants/{tenant}/secret-bindings/{name}"),
        &[
            ("repo", Some(&target.repo)),
            ("job", at.job),
            ("step", at.step),
        ],
    ))
}

fn binding_line(binding: &Value) -> String {
    let field = |key| {
        binding[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
    };
    format!(
        "{} job={} step={} secret={}{}",
        binding["name"].as_str().unwrap_or("<unknown>"),
        field("job"),
        field("step"),
        binding["secret"].as_str().unwrap_or("-"),
        if binding["override_tenant"] == true {
            " override_tenant"
        } else {
            ""
        }
    )
}

fn bind(
    client: &Client,
    output: Output,
    name: &str,
    target: &SecretRepoArgs,
    at: Selector<'_>,
    options: Value,
) -> Result<(), Error> {
    let path = binding_path(client, name, target, &at)?;
    let answer = client.put(&path, &options)?;
    let binding = answer["binding"].clone();
    if !binding.is_object() {
        return Err(Error::remote(
            "controller returned invalid binding metadata",
        ));
    }
    client::emit(output, &binding, || binding_line(&binding));
    Ok(())
}

fn unbind(
    client: &Client,
    output: Output,
    name: &str,
    target: &SecretRepoArgs,
    at: Selector<'_>,
) -> Result<(), Error> {
    let path = binding_path(client, name, target, &at)?;
    let answer = client.delete(&path)?;
    client::emit(output, &answer, || format!("{name} unbound\n"));
    Ok(())
}

fn bindings(client: &Client, output: Output, target: &SecretRepoArgs) -> Result<(), Error> {
    let tenant = repo_target(client, target)?;
    let base = format!("/api/v1/tenants/{tenant}/secret-bindings");
    let mut after = String::new();
    let mut items = Vec::new();
    loop {
        let page = client.get(&with_query(
            &base,
            &[
                ("repo", Some(&target.repo)),
                ("limit", Some("100")),
                ("after", (!after.is_empty()).then_some(after.as_str())),
            ],
        ))?;
        let rows = page["bindings"]
            .as_array()
            .ok_or_else(|| Error::remote("controller returned an invalid binding list"))?;
        for row in rows {
            if items.len() == MAX_LIST {
                return Err(Error::usage("binding list exceeds 10000 records"));
            }
            items.push(row.clone());
        }
        let Some(next) = page["next"].as_str().filter(|s| !s.is_empty()) else {
            break;
        };
        after = next.to_owned();
    }
    let document = json!({"schema": "sentinel.secret-bindings/1", "bindings": items});
    client::emit(output, &document, || {
        let mut text = String::new();
        for binding in document["bindings"].as_array().into_iter().flatten() {
            text.push_str(&binding_line(binding));
            text.push('\n');
        }
        text
    });
    Ok(())
}

fn allow(
    client: &Client,
    output: Output,
    name: &str,
    target: &SecretRepoArgs,
    allowed: bool,
) -> Result<(), Error> {
    validate_name(name)?;
    let tenant = repo_target(client, target)?;
    let path = with_query(
        &format!("/api/v1/tenants/{tenant}/secrets/{name}/allow"),
        &[("repo", Some(&target.repo))],
    );
    let answer = if allowed {
        client.put(&path, &json!({}))?
    } else {
        client.delete(&path)?
    };
    client::emit(output, &answer, || {
        format!(
            "{name} {} in {}\n",
            if allowed { "allowed" } else { "not allowed" },
            target.repo
        )
    });
    Ok(())
}

fn allowed(
    client: &Client,
    output: Output,
    name: &str,
    tenant_flag: Option<String>,
) -> Result<(), Error> {
    validate_name(name)?;
    let tenant = tenant(client, tenant_flag)?;
    let base = format!("/api/v1/tenants/{tenant}/secrets/{name}/allow");
    let mut after = String::new();
    let mut repos = Vec::new();
    loop {
        let page = client.get(&with_query(
            &base,
            &[
                ("limit", Some("100")),
                ("after", (!after.is_empty()).then_some(after.as_str())),
            ],
        ))?;
        let rows = page["repos"]
            .as_array()
            .ok_or_else(|| Error::remote("controller returned an invalid allowlist"))?;
        for row in rows {
            if repos.len() == MAX_LIST {
                return Err(Error::usage("allowlist exceeds 10000 records"));
            }
            repos.push(row.clone());
        }
        let Some(next) = page["next"].as_str().filter(|s| !s.is_empty()) else {
            break;
        };
        after = next.to_owned();
    }
    let document = json!({"schema": "sentinel.secret-allowlist/1", "secret": name, "repos": repos});
    client::emit(output, &document, || {
        let mut text = String::new();
        for repo in document["repos"].as_array().into_iter().flatten() {
            text.push_str(repo["name"].as_str().unwrap_or("<unknown>"));
            text.push('\n');
        }
        text
    });
    Ok(())
}

fn revoke_version(
    client: &Client,
    output: Output,
    name: &str,
    scope: &SecretScopeArgs,
    version: u64,
) -> Result<(), Error> {
    validate_name(name)?;
    if version == 0 || version > i64::MAX as u64 {
        return Err(Error::usage(
            "the version must be a positive secret version",
        ));
    }
    let (base, repo) = scope_path(client, scope)?;
    let path = with_query(
        &format!("{base}/{name}/versions/{version}/revoke"),
        &[("repo", repo.as_deref())],
    );
    let answer = client.post(&path, &json!({}), None)?;
    let secret = answer["secret"].clone();
    if !secret.is_object() {
        return Err(Error::remote("controller returned invalid secret metadata"));
    }
    client::emit(output, &answer, || {
        format!("revoked version {version}; {}", metadata_line(&secret))
    });
    Ok(())
}

fn idempotency_key(value: Option<&str>) -> Result<String, Error> {
    if let Some(value) = value {
        sentinel_protocol::idempotency::IdempotencyKey::parse(value)
            .map_err(|_| Error::usage("idempotency key must be 1 to 64 printable ASCII bytes"))?;
        return Ok(value.to_owned());
    }
    let secret = sentinel_auth::secret::Secret::generate();
    let mut value = String::with_capacity(sentinel_auth::secret::Secret::TEXT_LEN);
    secret.expose(&mut value);
    Ok(value)
}

fn read_input(file: Option<&Path>, stdin_flag: bool) -> Result<Vec<u8>, Error> {
    if let Some(path) = file {
        return read_protected_file(path, sentinel_protocol::secrets::MAX_SECRET_BYTES);
    }
    let stdin = io::stdin();
    if stdin_flag {
        if stdin.is_terminal() {
            return Err(Error::usage(
                "--stdin requires redirected input; values on stdin preserve all bytes",
            ));
        }
        return read_stdin(stdin.lock());
    }
    if stdin.is_terminal() {
        read_hidden()
    } else {
        read_stdin(stdin.lock())
    }
}

/// Redirected stdin, byte for byte (a trailing newline is part of the
/// value), bounded.
fn read_stdin(input: impl io::Read) -> Result<Vec<u8>, Error> {
    bounded::read(input, sentinel_protocol::secrets::MAX_SECRET_BYTES as u64)
        .map_err(|_| Error::usage("secret stdin must be at most 65536 bytes"))
}

fn read_protected_file(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| Error::usage("cannot open the secret input file"))?;
    if !metadata.file_type().is_file() {
        return Err(Error::usage(
            "secret input must be a regular file, not a link",
        ));
    }
    let mut file =
        File::open(path).map_err(|_| Error::usage("cannot open the secret input file"))?;
    let opened = file
        .metadata()
        .map_err(|_| Error::usage("cannot inspect the secret input file"))?;
    if !opened.is_file() {
        return Err(Error::usage("secret input must be a regular file"));
    }
    crate::keystore::file::check_private_input(path, &file)?;
    bounded::read(&mut file, limit as u64)
        .map_err(|_| Error::usage("secret input file is unreadable or exceeds its byte limit"))
}

const PROMPT_MULTILINE: &str =
    "the hidden prompt accepts one line; use --file or --stdin for multi-line values";

/// The hidden prompt's line editor, fed raw terminal input. It never
/// truncates: a value longer than the limit, a paste with more than one
/// line, Ctrl+C and Ctrl+D on an empty line are refusals (P10C-3). The
/// buffer is wiped when dropped.
struct PromptLine {
    bytes: WipeBytes,
    limit: usize,
}

impl PromptLine {
    fn new(limit: usize) -> Self {
        Self {
            bytes: WipeBytes(Vec::new()),
            limit,
        }
    }

    /// Feed one chunk. `Ok(true)` when the line ended in this chunk;
    /// anything after the terminator (other than the `\n` of a CRLF) is
    /// another line and refused.
    fn feed(&mut self, chunk: &[u8]) -> Result<bool, Error> {
        for (index, &byte) in chunk.iter().enumerate() {
            match byte {
                b'\r' | b'\n' => {
                    let rest = &chunk[index + 1..];
                    let rest = if byte == b'\r' {
                        rest.strip_prefix(b"\n").unwrap_or(rest)
                    } else {
                        rest
                    };
                    if !rest.is_empty() {
                        return Err(Error::usage(PROMPT_MULTILINE));
                    }
                    return Ok(true);
                }
                0x03 => return Err(Error::usage("secret entry canceled")),
                0x04 if self.bytes.0.is_empty() => {
                    return Err(Error::usage("secret value is empty"));
                }
                0x7f | 0x08 => {
                    // Remove one whole UTF-8 character.
                    while let Some(last) = self.bytes.0.pop() {
                        if last & 0xC0 != 0x80 {
                            break;
                        }
                    }
                }
                _ => {
                    if self.bytes.0.len() == self.limit {
                        return Err(Error::usage(
                            "secret value must be at most 65536 bytes; use --file or --stdin",
                        ));
                    }
                    self.bytes.0.push(byte);
                }
            }
        }
        Ok(false)
    }

    fn finish(mut self) -> Result<Vec<u8>, Error> {
        if self.bytes.0.is_empty() {
            return Err(Error::usage("secret value is empty"));
        }
        Ok(std::mem::take(&mut self.bytes.0))
    }
}

fn prompt() -> Result<(), Error> {
    eprint!("Secret value (hidden): ");
    io::stderr()
        .flush()
        .map_err(|_| Error::remote("cannot write secret prompt"))
}

/// Unix: raw input (no echo, no canonical line limit, no signal keys, so
/// Ctrl+C reaches the editor and the terminal state is always restored);
/// any input still pending after the line is a paste of more lines and is
/// refused. `TCSAFLUSH` on restore discards it, so none reaches the shell.
#[cfg(unix)]
fn read_hidden() -> Result<Vec<u8>, Error> {
    use std::os::fd::AsRawFd;
    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: an all-zero termios is a valid value for tcgetattr to fill.
    let mut old = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `fd` is the live stdin descriptor and `old` a writable termios.
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input; use --file or --stdin",
        ));
    }
    let mut raw = old;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    // SAFETY: `raw` is derived from the valid terminal state just read.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input; use --file or --stdin",
        ));
    }
    struct Restore {
        fd: libc::c_int,
        state: libc::termios,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restores the state captured from this same live fd;
            // TCSAFLUSH also discards any unread (pasted) input.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.state);
            }
        }
    }
    let _restore = Restore { fd, state: old };
    prompt()?;
    let mut line = PromptLine::new(sentinel_protocol::secrets::MAX_SECRET_BYTES);
    let mut chunk = [0u8; 4096];
    let done = loop {
        // SAFETY: `chunk` is writable for its whole length.
        let read = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if read < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            chunk.fill(0);
            return Err(Error::usage("cannot read secret input"));
        }
        if read == 0 {
            break false;
        }
        let fed = line.feed(&chunk[..read as usize]);
        chunk.fill(0);
        if fed? {
            break true;
        }
    };
    eprintln!();
    if done {
        let mut pending = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd; a zero timeout never blocks.
        if unsafe { libc::poll(&mut pending, 1, 0) } > 0 {
            return Err(Error::usage(PROMPT_MULTILINE));
        }
    }
    line.finish()
}

/// Windows: the console in raw mode (no echo, no line editing, Ctrl+C as a
/// character), read with `ReadConsoleW`. After the line, any pending key
/// press is the rest of a paste: it is refused, and the input buffer is
/// flushed on every path so no pasted line reaches the shell or its
/// history.
#[cfg(windows)]
fn read_hidden() -> Result<Vec<u8>, Error> {
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE},
        System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, FlushConsoleInputBuffer,
            GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, PeekConsoleInputW, ReadConsoleW,
            STD_INPUT_HANDLE, SetConsoleMode,
        },
    };
    let not_console = || {
        Error::usage(
            "standard input is not a console (mintty or MSYS?); use --file, or pipe the value with --stdin",
        )
    };
    // SAFETY: GetStdHandle has no preconditions; the result is checked.
    let handle: HANDLE = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(not_console());
    }
    let mut old = 0u32;
    // SAFETY: `handle` is the process's standard input handle, checked
    // above, and `old` is a writable mode value.
    if unsafe { GetConsoleMode(handle, &mut old) } == 0 {
        return Err(not_console());
    }
    let raw = old & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    // SAFETY: `handle` is a console input handle (GetConsoleMode succeeded).
    if unsafe { SetConsoleMode(handle, raw) } == 0 {
        return Err(not_console());
    }
    struct Restore(HANDLE, u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: the handle is the live console input handle; flushing
            // drops unread (pasted) input and the mode captured earlier is
            // put back.
            unsafe {
                FlushConsoleInputBuffer(self.0);
                SetConsoleMode(self.0, self.1);
            }
        }
    }
    let _restore = Restore(handle, old);
    prompt()?;
    let mut line = PromptLine::new(sentinel_protocol::secrets::MAX_SECRET_BYTES);
    let mut units = [0u16; 512];
    let mut carry: Option<u16> = None;
    let mut utf8 = WipeBytes(Vec::with_capacity(units.len() * 3));
    let done = loop {
        let mut read = 0u32;
        // SAFETY: `units` is writable for the length passed; no control
        // structure is used.
        let ok = unsafe {
            ReadConsoleW(
                handle,
                units.as_mut_ptr().cast(),
                units.len() as u32,
                &mut read,
                std::ptr::null(),
            )
        };
        if ok == 0 {
            units.fill(0);
            return Err(Error::usage("cannot read secret input"));
        }
        if read == 0 {
            break false;
        }
        utf8.0.clear();
        let mut pending: Vec<u16> = carry.take().into_iter().collect();
        pending.extend_from_slice(&units[..read as usize]);
        units.fill(0);
        // A high surrogate at the end waits for its pair in the next read.
        if pending.last().is_some_and(|u| (0xD800..0xDC00).contains(u)) {
            carry = pending.pop();
        }
        for decoded in char::decode_utf16(pending.iter().copied()) {
            let c = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
            let mut buffer = [0u8; 4];
            utf8.0
                .extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            buffer.fill(0);
        }
        pending.fill(0);
        if line.feed(&utf8.0)? {
            break true;
        }
    };
    eprintln!();
    if done {
        let mut records = [INPUT_RECORD::default(); 64];
        let mut count = 0u32;
        // SAFETY: `records` is writable for the length passed; peeking
        // leaves the events in the buffer for the flush on restore.
        let ok = unsafe {
            PeekConsoleInputW(
                handle,
                records.as_mut_ptr(),
                records.len() as u32,
                &mut count,
            )
        };
        let typed = ok != 0
            && records[..count as usize].iter().any(|record| {
                // SAFETY: the union is read as a key event only when the
                // record says it is one.
                u32::from(record.EventType) == KEY_EVENT
                    && unsafe { record.Event.KeyEvent.bKeyDown != 0 }
                    && unsafe { record.Event.KeyEvent.uChar.UnicodeChar } != 0
            });
        if typed {
            return Err(Error::usage(PROMPT_MULTILINE));
        }
    }
    line.finish()
}

fn metadata_line(secret: &Value) -> String {
    let name = secret["name"].as_str().unwrap_or("<unknown>");
    let scope = if secret["repo"].is_null() {
        "tenant"
    } else {
        "repo"
    };
    format!(
        "{name} {scope} version={} active={} updated_ms={}",
        secret["version"].as_u64().unwrap_or_default(),
        secret["active"].as_bool().unwrap_or(false),
        secret["updated_ms"].as_i64().unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_follow_the_store_contract() {
        assert!(validate_name("_TOKEN_2").is_ok());
        for name in ["", "token", "1TOKEN", "TOKEN-NAME", "TOKEN.NAME"] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name(&"A".repeat(65)).is_err());
    }

    #[test]
    fn repository_names_follow_the_store_rule_and_are_encoded() {
        assert!(validate_repo("RusticStack/app").is_ok());
        assert!(validate_repo("").is_err());
        assert!(validate_repo(&"r".repeat(129)).is_err());
        assert!(validate_repo("a\nb").is_err());
        assert_eq!(
            secret_path("/s", "T", Some("RusticStack/app")),
            "/s/T?repo=RusticStack%2Fapp"
        );
    }

    #[test]
    fn stdin_preserves_every_byte_including_line_endings() {
        assert_eq!(read_stdin(&b"value\r\n"[..]).unwrap(), b"value\r\n");
        assert_eq!(read_stdin(&b"\xff\x00"[..]).unwrap(), b"\xff\x00");
        let big = vec![b'x'; sentinel_protocol::secrets::MAX_SECRET_BYTES + 1];
        assert!(read_stdin(&big[..]).is_err());
    }

    /// P10C-3: the prompt strips one terminator (LF, CR or CRLF), edits
    /// with backspace, and refuses instead of truncating: more than the
    /// limit, a second pasted line, Ctrl+C, and Ctrl+D or Enter on an
    /// empty line.
    #[test]
    fn the_prompt_line_never_truncates_and_refuses_pastes() {
        let line = |chunks: &[&[u8]], limit: usize| {
            let mut line = PromptLine::new(limit);
            for chunk in chunks {
                if line.feed(chunk)? {
                    return line.finish();
                }
            }
            line.finish()
        };
        assert_eq!(line(&[b"secret\n"], 16).unwrap(), b"secret");
        assert_eq!(line(&[b"secret\r\n"], 16).unwrap(), b"secret");
        assert_eq!(line(&[b"secret\r"], 16).unwrap(), b"secret");
        assert_eq!(line(&[b"sec", b"ret\n"], 16).unwrap(), b"secret");
        assert_eq!(line(&[b"secrex\x7ft\n"], 16).unwrap(), b"secret");
        assert_eq!(line(&["caf\u{e9}\x7fe\n".as_bytes()], 16).unwrap(), b"cafe");
        for (chunks, limit) in [
            (&[&b"0123456789\n"[..]][..], 9),
            (&[&b"line one\nline two\n"[..]][..], 64),
            (&[&b"line one\r\nline two"[..]][..], 64),
            (&[&b"abc\x03"[..]][..], 64),
            (&[&b"\x04"[..]][..], 64),
            (&[&b"\n"[..]][..], 64),
        ] {
            let refused = line(chunks, limit).unwrap_err();
            assert_eq!(refused.exit, Exit::Usage);
            assert!(!refused.message.contains("line one"));
        }
        assert!(
            line(&[b"a\nb"], 64)
                .unwrap_err()
                .message
                .contains("--file or --stdin")
        );
    }

    #[test]
    fn a_preview_pin_must_name_every_entry_once() {
        assert_eq!(parse_pin("B=2,A=0", &["A", "B"]).unwrap(), [0, 2]);
        for bad in ["A=0", "A=0,B=1,C=2", "A=0,A=1", "A=x,B=1", "A0,B=1"] {
            assert!(parse_pin(bad, &["A", "B"]).is_err(), "{bad}");
        }
        assert_eq!(pin_text([("A", 0), ("B", 2)].into_iter()), "A=0,B=2");
    }

    #[test]
    fn an_unknown_outcome_names_the_replaying_retry() {
        let busy = Error::new(
            Exit::Busy,
            "outcome_unknown: check (for example with `sentinel run list`)",
        );
        let hinted = retry_hint(busy, "k-123", ("--if-version", "4"));
        assert!(
            hinted
                .message
                .contains("--idempotency-key k-123 --if-version 4")
        );
        assert!(hinted.message.contains("sentinel secret describe"));
        assert_eq!(hinted.document()["details"]["idempotency_key"], "k-123");
        let conflict = retry_hint(
            Error::new(Exit::Conflict, "conflict"),
            "k",
            ("--if-version", "1"),
        );
        assert_eq!(conflict.message, "conflict");
    }

    #[test]
    fn protected_file_input_is_bounded_and_refuses_links() {
        let dir = tempfile::tempdir().unwrap();
        let secure_dir = dir.path().join("secure");
        crate::keystore::file::ensure_private_dir(&secure_dir).unwrap();
        let file = secure_dir.join("secret.bin");
        fs::write(&file, b"bytes\xff").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_protected_file(&file, 16).unwrap(), b"bytes\xff");
        assert!(read_protected_file(&file, 5).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = secure_dir.join("secret-link");
            symlink(&file, &link).unwrap();
            assert!(read_protected_file(&link, 16).is_err());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_protected_file(&file, 16).is_err());
        }
    }

    /// P10C-8: a file that inherits a broader ACL (the temp directory's
    /// Administrators and others) is refused with the `icacls` fix.
    #[cfg(windows)]
    #[test]
    fn a_permissive_windows_file_is_refused_with_the_icacls_fix() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("inherited.txt");
        fs::write(&file, b"value").unwrap();
        let refused = read_protected_file(&file, 16).unwrap_err();
        assert_eq!(refused.exit, Exit::Usage);
        assert!(refused.message.contains("icacls"), "{}", refused.message);
        assert!(!refused.message.contains("value"));
    }
}
