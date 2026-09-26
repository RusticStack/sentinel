//! Protected-input secret commands. Values are held only long enough to send
//! the request; output and every error contain metadata or fixed diagnostics.

use std::{
    fs::{self, File},
    io::{self, BufRead, IsTerminal, Write},
    path::Path,
};

use serde_json::{Value, json};

use crate::{
    bounded,
    client::{self, Client, Error, Exit, Output},
    commands::{SecretCommand, SecretScopeArgs, segment, tenant},
};

const MAX_LIST: usize = 10_000;

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
            idempotency_key,
        } => import(
            client,
            output,
            &scope,
            &env_file,
            preview,
            idempotency_key.as_deref(),
        ),
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

fn scope_path(client: &Client, scope: &SecretScopeArgs) -> Result<(String, Option<String>), Error> {
    let tenant = tenant(client, scope.tenant.clone())?.to_owned();
    if let Some(repo) = &scope.repo {
        segment("repository", repo)?;
    }
    let path = format!("/api/v1/tenants/{tenant}/secrets");
    Ok((path, scope.repo.clone()))
}

fn query_scope(path: &str, repo: Option<&str>, suffix: &str) -> String {
    let mut out = String::with_capacity(path.len() + suffix.len() + 32);
    out.push_str(path);
    let mut query = form_urlencoded::Serializer::new(String::new());
    if let Some(repo) = repo {
        query.append_pair("repo", repo);
    }
    if !suffix.is_empty() {
        for (key, value) in form_urlencoded::parse(suffix.as_bytes()) {
            query.append_pair(&key, &value);
        }
    }
    let query = query.finish();
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    out
}

fn secret_path(base: &str, name: &str, repo: Option<&str>) -> String {
    let mut path = format!("{base}/{name}");
    if let Some(repo) = repo {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("repo", repo);
        path.push('?');
        path.push_str(&query.finish());
    }
    path
}

fn all_metadata(client: &Client, scope: &SecretScopeArgs) -> Result<Vec<Value>, Error> {
    let (base, repo) = scope_path(client, scope)?;
    let mut after = String::new();
    let mut output = Vec::new();
    loop {
        let suffix = format!("limit=100&after={after}");
        let page = client.get(&query_scope(&base, repo.as_deref(), &suffix))?;
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
        after.clear();
        after.push_str(next);
    }
    Ok(output)
}

fn list(client: &Client, output: Output, scope: &SecretScopeArgs) -> Result<(), Error> {
    let values = all_metadata(client, scope)?;
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
    let idempotency = idempotency_key(idempotency)?;
    let headers = [("if-match", expected_text.as_str())];
    let response = client.put_bytes(
        &endpoint,
        &value.0,
        "application/octet-stream",
        &headers,
        &idempotency,
    );
    let answer = response?;
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
    let answer = client.delete_with(&endpoint, &[("if-match", &version)], &key)?;
    let secret = answer["secret"].clone();
    if !secret.is_object() {
        return Err(Error::remote("controller returned invalid secret metadata"));
    }
    client::emit(output, &secret, || metadata_line(&secret));
    Ok(())
}

fn import(
    client: &Client,
    output: Output,
    scope: &SecretScopeArgs,
    path: &Path,
    preview: bool,
    idempotency: Option<&str>,
) -> Result<(), Error> {
    let bytes = WipeBytes(read_protected_file(
        path,
        sentinel_protocol::secrets::MAX_IMPORT_BYTES,
    )?);
    let entries = sentinel_protocol::secrets::parse_env_file(&bytes.0)
        .map_err(|error| Error::usage(error.to_string()))?;
    let entries = WipeEntries(entries);
    let metadata = all_metadata(client, scope)?;
    let mut versions = Vec::with_capacity(entries.0.len());
    for (name, _) in &entries.0 {
        let version = metadata
            .iter()
            .find(|secret| secret["name"].as_str() == Some(name))
            .and_then(|secret| secret["version"].as_u64())
            .unwrap_or(0);
        versions.push((name.clone(), version));
    }
    if preview {
        let items: Vec<Value> = versions
            .iter()
            .map(|(name, version)| json!({"name":name,"expected_version":version}))
            .collect();
        let document = json!({"schema":"sentinel.secret-import-preview/1","secrets":items});
        client::emit(output, &document, || {
            let mut text = String::new();
            for (name, version) in &versions {
                text.push_str(&format!("{name} expected_version={version}\n"));
            }
            text
        });
        return Ok(());
    }
    let mut expected = String::with_capacity(versions.len() * 20);
    for (index, (name, version)) in versions.iter().enumerate() {
        if index != 0 {
            expected.push(',');
        }
        expected.push_str(name);
        expected.push('=');
        expected.push_str(&version.to_string());
    }
    let (base, repo) = scope_path(client, scope)?;
    let endpoint = query_scope(&format!("{base}/import"), repo.as_deref(), "");
    let key = idempotency_key(idempotency)?;
    let answer = client.post_bytes(
        &endpoint,
        &bytes.0,
        "text/plain; charset=utf-8",
        &[("if-match", &expected)],
        &key,
    )?;
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
        return bounded::read(
            stdin.lock(),
            sentinel_protocol::secrets::MAX_SECRET_BYTES as u64,
        )
        .map_err(|_| Error::usage("secret stdin must be at most 65536 bytes"));
    }
    if stdin.is_terminal() {
        read_hidden()
    } else {
        bounded::read(
            stdin.lock(),
            sentinel_protocol::secrets::MAX_SECRET_BYTES as u64,
        )
        .map_err(|_| Error::usage("secret stdin must be at most 65536 bytes"))
    }
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

#[cfg(unix)]
fn read_hidden() -> Result<Vec<u8>, Error> {
    use std::os::fd::AsRawFd;
    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: `fd` is the live stdin descriptor and `old` points to a
    // writable termios value owned by this stack frame.
    let mut old = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `tcgetattr` reads terminal state for the open stdin descriptor.
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input",
        ));
    }
    let mut hidden = old;
    hidden.c_lflag &= !libc::ECHO;
    // SAFETY: `hidden` is copied from the valid terminal state just read.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input",
        ));
    }
    struct Restore {
        fd: libc::c_int,
        state: libc::termios,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restore the terminal state captured from this live fd.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.state);
            }
        }
    }
    let _restore = Restore { fd, state: old };
    read_prompt_line(&stdin)
}

#[cfg(windows)]
fn read_hidden() -> Result<Vec<u8>, Error> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input",
        ));
    }
    let mut old = 0u32;
    // SAFETY: handle is the process's live console input handle.
    if unsafe { GetConsoleMode(handle, &mut old) } == 0
        || unsafe { SetConsoleMode(handle, old & !ENABLE_ECHO_INPUT) } == 0
    {
        return Err(Error::usage(
            "cannot disable terminal echo for secret input",
        ));
    }
    struct Restore(windows_sys::Win32::Foundation::HANDLE, u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restore the mode captured from the process console.
            unsafe {
                SetConsoleMode(self.0, self.1);
            }
        }
    }
    let _restore = Restore(handle, old);
    read_prompt_line(&io::stdin())
}

fn read_prompt_line(stdin: &io::Stdin) -> Result<Vec<u8>, Error> {
    eprint!("Secret value (hidden): ");
    io::stderr()
        .flush()
        .map_err(|_| Error::remote("cannot write secret prompt"))?;
    let mut input = stdin.lock();
    let mut bytes = Vec::new();
    loop {
        let buffer = input
            .fill_buf()
            .map_err(|_| Error::usage("cannot read secret input"))?;
        if buffer.is_empty() {
            break;
        }
        let take = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > sentinel_protocol::secrets::MAX_SECRET_BYTES + 2 {
            return Err(Error::usage("secret value must be at most 65536 bytes"));
        }
        let finished = buffer
            .get(..take)
            .is_some_and(|part| part.last() == Some(&b'\n'));
        bytes.extend_from_slice(&buffer[..take]);
        input.consume(take);
        if finished {
            break;
        }
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    eprintln!();
    if bytes.is_empty() {
        return Err(Error::usage("secret value is empty"));
    }
    if bytes.len() > sentinel_protocol::secrets::MAX_SECRET_BYTES {
        return Err(Error::usage("secret value must be at most 65536 bytes"));
    }
    Ok(bytes)
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
}
