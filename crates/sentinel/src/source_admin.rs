//! Host-local source provisioning, and the store entry points it reuses.
//!
//! Repository binding has two legitimate authorities: an authenticated tenant
//! administrator through the same live authorization layer as every other
//! client operation, and the controller's own host — the operator who can
//! already open the database. The CLI is the second; the future API route is
//! the first. A host-local operation still records which account it is
//! attributed to.
use crate::{
    admin::{self, Error},
    cli::{SourceArgs, SourceCommand},
};
use sentinel_core::{InstallationId, RepoId, TenantId, UnixMillis, UserId};
use sentinel_protocol::source::{Binding, Credential, MAX_SOURCE_BYTES};
use sentinel_store::{
    MASTER_KEY_FILE, auth, intake, poll, registration, registration::Authority, sources,
    sources_forge,
};
use serde::Deserialize;
use std::{io::Read, path::Path, sync::Arc};

fn fail(message: &str) -> Error {
    Error {
        message: message.into(),
    }
}
fn bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("cannot read source input"))?;
    if bytes.len() > limit {
        return Err(fail("source input exceeds limit"));
    }
    Ok(bytes)
}
fn file(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    bounded(
        std::fs::File::open(path).map_err(|_| fail("cannot open source configuration"))?,
        limit,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    app_id: u64,
    private_key_file: std::path::PathBuf,
    /// Where GitHub should link a check's details: the API's public base URL.
    /// Absent means checks carry no `details_url`.
    public_url: Option<String>,
    /// Another GitHub API endpoint (Enterprise, or a test stub). Absent means
    /// `https://api.github.com`.
    api_url: Option<String>,
}

/// The App plus the deployment-facing settings beside it.
pub struct GithubApp {
    pub app: Arc<sentinel_github::app::App>,
    pub public_url: Option<String>,
}

/// An absolute `http(s)` base URL with no query, fragment or credentials.
fn public_url(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| fail("public URL must be http(s)"))?;
    if rest.is_empty()
        || trimmed.len() > 256
        || rest.contains(['?', '#', '@', ' '])
        || !rest.contains('.') && !rest.starts_with("localhost") && !rest.starts_with("127.0.0.1")
    {
        return Err(fail("invalid public URL"));
    }
    Ok(trimmed.to_owned())
}

pub fn load_app(root: &Path) -> Result<Option<GithubApp>, Error> {
    let path = root.join("github-app.json");
    if !path.exists() {
        return Ok(None);
    }
    let config: AppConfig = serde_json::from_slice(&file(&path, 4096)?)
        .map_err(|_| fail("invalid GitHub App configuration"))?;
    if !config.private_key_file.is_absolute() {
        return Err(fail("App key path must be absolute"));
    }
    use std::os::unix::fs::PermissionsExt;
    let input =
        std::fs::File::open(&config.private_key_file).map_err(|_| fail("cannot open App key"))?;
    let metadata = input
        .metadata()
        .map_err(|_| fail("cannot inspect App key"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(fail("App key must be an owner-only regular file"));
    }
    let bytes = bounded(input, 16 * 1024)?;
    let pem = std::str::from_utf8(&bytes).map_err(|_| fail("invalid App key"))?;
    let mut app =
        sentinel_github::app::App::new(config.app_id, pem).map_err(|_| fail("invalid App key"))?;
    if let Some(api_url) = &config.api_url {
        app = app
            .with_endpoint(api_url)
            .map_err(|_| fail("invalid GitHub API endpoint"))?;
    }
    let public_url = config.public_url.as_deref().map(public_url).transpose()?;
    Ok(Some(GithubApp {
        app: Arc::new(app),
        public_url,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookConfig {
    secret: String,
}

/// The GitHub App's webhook secret, when the deployment configured one. The
/// route only exists with it; without the file there is nothing to verify.
pub fn load_webhook_secret(root: &Path) -> Result<Option<Arc<[u8]>>, Error> {
    let path = root.join("github-webhook.json");
    if !path.exists() {
        return Ok(None);
    }
    let config: WebhookConfig = serde_json::from_slice(&file(&path, 4096)?)
        .map_err(|_| fail("invalid GitHub webhook configuration"))?;
    let secret = config.secret.as_bytes();
    if !(16..=256).contains(&secret.len()) || secret.iter().any(|b| !(0x20..0x7f).contains(b)) {
        return Err(fail(
            "GitHub webhook secret must be 16-256 printable ASCII bytes",
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path)
        .map_err(|_| fail("cannot inspect GitHub webhook configuration"))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(fail("GitHub webhook configuration must be owner-only"));
    }
    Ok(Some(Arc::from(secret)))
}

pub fn load_destinations(root: &Path) -> Result<Vec<String>, Error> {
    let path = root.join("source-destinations.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let destinations: Vec<String> = serde_json::from_slice(&file(&path, 16 * 1024)?)
        .map_err(|_| fail("invalid source destination policy"))?;
    if destinations.len() > 128
        || destinations.iter().any(|d| {
            sentinel_protocol::source::remote(&format!("{d}/repo.git")) != Some(d.as_str())
        })
    {
        return Err(fail("invalid source destination policy"));
    }
    Ok(destinations)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    binding: Binding,
    credential: Credential,
    forge: Option<Forge>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forge {
    installation: String,
    repository_id: u64,
}

pub fn run(args: &SourceArgs) -> Result<(), Error> {
    let store = admin::open(&args.data, true)?;
    // The CLI's authority is holding the database file; the actor is
    // attribution recorded in the audit, not a boundary to guess at.
    let actor: UserId = args.actor.parse().map_err(|_| fail("invalid actor ID"))?;
    let now = UnixMillis::now();
    let host = Authority::HostLocal;
    let repo = |s: &str| {
        s.parse::<RepoId>()
            .map_err(|_| fail("invalid repository ID"))
    };
    let tenant = |s: &str| s.parse::<TenantId>().map_err(|_| fail("invalid tenant ID"));
    let installation = |s: &str| {
        s.parse::<InstallationId>()
            .map_err(|_| fail("invalid installation ID"))
    };
    let denied = |_: sentinel_store::Error| {
        fail("source operation refused; check authority, expected version and binding")
    };
    match &args.command {
        SourceCommand::Create { tenant: t, name } => {
            let tenant = tenant(t)?;
            let id = RepoId::new();
            let name = name.clone();
            store
                .writer()
                .write(move |tx| auth::create_repo_trusted(tx, tenant, id, &name, now))
                .map_err(denied)?;
            sentinel::outln!("{}", serde_json::json!({"repo":id.to_string()}));
        }
        SourceCommand::Bind { repo: r, expected } => {
            let repo = repo(r)?;
            let expected = *expected;
            let input: Input =
                serde_json::from_slice(&bounded(std::io::stdin().lock(), MAX_SOURCE_BYTES)?)
                    .map_err(|_| fail("invalid source binding input"))?;
            let destinations = load_destinations(&args.data.data_dir)?;
            let key = sentinel_auth::sealed::Key::load(&args.data.data_dir.join(MASTER_KEY_FILE))
                .map_err(|_| fail("cannot load sealing key"))?;
            let forge = input
                .forge
                .map(|f| Ok((installation(&f.installation)?, f.repository_id)))
                .transpose()?;
            let version = store
                .writer()
                .write(move |tx| {
                    sources::bind(
                        tx,
                        host,
                        Some(actor),
                        sources::Update {
                            repo,
                            expected,
                            binding: &input.binding,
                            credential: &input.credential,
                            forge,
                        },
                        &destinations,
                        &key,
                        now,
                    )
                })
                .map_err(|e| fail(&format!("source bind refused: {e}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({"repo":repo.to_string(),"version":version})
            );
        }
        SourceCommand::Show { repo: r } => {
            let repo = repo(r)?;
            let (m, hook_token, polling) = store
                .read(|c| {
                    Ok((
                        sources::metadata_trusted(c, repo)?,
                        intake::token_issued(c, repo)?,
                        poll::of_repo(c, repo)?,
                    ))
                })
                .map_err(denied)?;
            let polling = polling.map(|p| {
                serde_json::json!({"interval_ms":p.interval_ms,"refs":p.refs,"next_poll_ms":p.next_poll_ms,"failures":p.failures,"last_error":p.last_error,"baselined":p.baselined})
            });
            sentinel::outln!(
                "{}",
                serde_json::json!({"repo":repo.to_string(),"binding":m.binding,"version":m.version,"revoked":m.revoked,"hook_token_ms":hook_token.map(|t|t.0),"poll":polling,"forge":m.forge.map(|(i,r)|serde_json::json!({"installation":i.to_string(),"repository_id":r}))})
            );
        }
        SourceCommand::Revoke { repo: r, expected } => {
            let repo = repo(r)?;
            let expected = *expected;
            store
                .writer()
                .write(move |tx| sources::revoke(tx, host, Some(actor), repo, expected, now))
                .map_err(denied)?;
            sentinel::outln!(
                "{}",
                serde_json::json!({"revoked":true,"version":expected+1})
            );
        }
        SourceCommand::HookToken { repo: r, revoke } => {
            let repo = repo(r)?;
            if *revoke {
                store
                    .writer()
                    .write(move |tx| intake::revoke_token(tx, host, repo, now))
                    .map_err(denied)?;
                sentinel::outln!(
                    "{}",
                    serde_json::json!({"repo":repo.to_string(),"revoked":true})
                );
            } else {
                let secret = store
                    .writer()
                    .write(move |tx| intake::issue_token(tx, host, repo, now))
                    .map_err(denied)?;
                // The one presentation: only the secret reaches stdout, so a
                // shell can redirect it without a parser in between.
                sentinel::outln!("{}", intake::hook_token_text(&secret));
            }
        }
        SourceCommand::Poll {
            repo: r,
            interval,
            refs,
            disable,
        } => {
            let repo = repo(r)?;
            if *disable {
                store
                    .writer()
                    .write(move |tx| poll::disable(tx, host, Some(actor), repo, now))
                    .map_err(denied)?;
                sentinel::outln!(
                    "{}",
                    serde_json::json!({"repo":repo.to_string(),"polling":false})
                );
            } else {
                let interval = interval
                    .as_deref()
                    .ok_or_else(|| fail("--interval is required to enable polling"))?;
                let interval_ms = admin::duration_ms(interval, poll::MAX_INTERVAL_MS)?;
                let refs: Vec<String> = refs
                    .as_deref()
                    .ok_or_else(|| fail("--refs is required to enable polling"))?
                    .split(',')
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .map(String::from)
                    .collect();
                let spec = poll::Spec {
                    interval_ms,
                    refs: refs.clone(),
                };
                store
                    .writer()
                    .write(move |tx| poll::configure(tx, host, Some(actor), repo, &spec, now))
                    .map_err(|e| fail(&format!("poll configuration refused: {e}")))?;
                sentinel::outln!(
                    "{}",
                    serde_json::json!({"repo":repo.to_string(),"polling":true,"interval_ms":interval_ms,"refs":refs})
                );
            }
        }
        SourceCommand::RefreshInstallation {
            external_id,
            expected,
        } => {
            let app = load_app(&args.data.data_dir)?
                .ok_or_else(|| fail("GitHub App is not configured"))?;
            let snapshot = app
                .app
                .installation(*external_id, now.0)
                .map_err(|_| fail("GitHub installation refresh failed"))?;
            let expected = *expected;
            let id = store
                .writer()
                .write(move |tx| {
                    sources_forge::refresh(
                        tx,
                        sources_forge::Snapshot {
                            external_id: snapshot.id,
                            account_id: snapshot.account_id,
                            login: &snapshot.login,
                            personal: snapshot.personal,
                            suspended: snapshot.suspended,
                            permissions_valid: snapshot.permissions_valid,
                            expected,
                        },
                        now,
                    )
                })
                .map_err(denied)?;
            sentinel::outln!(
                "{}",
                serde_json::json!({"installation":id.to_string(),"version":expected+1})
            );
        }
        SourceCommand::BindInstallation {
            installation: i,
            tenant: t,
        } => {
            let id = installation(i)?;
            let tenant = tenant(t)?;
            store
                .writer()
                .write(move |tx| registration::bind_installation_trusted(tx, id, tenant, now))
                .map_err(denied)?;
            sentinel::outln!("{}", serde_json::json!({"bound":true}));
        }
        SourceCommand::RemoveInstallation { installation: i } => {
            let id = installation(i)?;
            store
                .writer()
                .write(move |tx| sources_forge::remove(tx, id))
                .map_err(denied)?;
            sentinel::outln!("{}", serde_json::json!({"disabled":true}));
        }
    }
    Ok(())
}
