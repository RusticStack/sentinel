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

/// Judged on the opened handle, not the path, so a link or a swapped file cannot pass.
/// Errors name `what` and the rule broken, never the path or any content.
fn secret_input(path: &Path, limit: usize, what: &str) -> Result<Vec<u8>, Error> {
    use sentinel_auth::secret_file::{self, Refusal};
    let mut input = secret_file::open(path).map_err(|refusal| {
        fail(&match refusal {
            Refusal::GroupOrOtherAccess => format!("{what} must be owner-only"),
            Refusal::WrongOwner => format!("{what} must be owned by this user"),
            Refusal::NotRegular => format!("{what} must be a regular file, not a link"),
            Refusal::Unreadable => format!("cannot read {what}"),
        })
    })?;
    secret_file::read(&mut input, limit)
        .map_err(|_| fail(&format!("cannot read {what}")))?
        .ok_or_else(|| fail(&format!("{what} exceeds limit")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    app_id: u64,
    private_key_file: std::path::PathBuf,
    public_url: Option<String>,
    api_url: Option<String>,
    member_recheck_secs: Option<u64>,
    member_grace_secs: Option<u64>,
}

pub struct GithubApp {
    pub app: Arc<sentinel_github::app::App>,
    pub public_url: Option<String>,
    pub members: sentinel_checks::members::Config,
}

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
    // The web interface is served at the root of its origin, so a path would only make dead check links.
    if !sentinel_github::manifest::is_origin(trimmed) {
        return Err(fail("public URL must be an origin without a path"));
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
    let mut bytes = secret_input(&config.private_key_file, 16 * 1024, "App key")?;
    let app = std::str::from_utf8(&bytes)
        .map_err(|_| fail("invalid App key"))
        .and_then(|pem| {
            sentinel_github::app::App::new(config.app_id, pem).map_err(|_| fail("invalid App key"))
        });
    sentinel_auth::secret::wipe(&mut bytes);
    let mut app = app?;
    if let Some(api_url) = &config.api_url {
        app = app
            .with_endpoint(api_url)
            .map_err(|_| fail("invalid GitHub API endpoint"))?;
    }
    let public_url = config.public_url.as_deref().map(public_url).transpose()?;
    let mut members = sentinel_checks::members::Config::default();
    let recheck = config.member_recheck_secs.unwrap_or(3_600);
    let grace = config.member_grace_secs.unwrap_or(86_400);
    if !(60..=86_400).contains(&recheck)
        || !(300..=2_592_000).contains(&grace)
        || grace < recheck.saturating_mul(2)
    {
        return Err(fail(
            "member_recheck_secs must be 60 to 86400 and member_grace_secs 300 to 2592000, at least twice the recheck interval",
        ));
    }
    members.timing.recheck_ms = (recheck * 1_000) as i64;
    members.timing.grace_ms = (grace * 1_000) as i64;
    Ok(Some(GithubApp {
        app: Arc::new(app),
        public_url,
        members,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookConfig {
    secret: String,
}

pub fn load_webhook_secret(root: &Path) -> Result<Option<Arc<[u8]>>, Error> {
    let path = root.join("github-webhook.json");
    if !path.exists() {
        return Ok(None);
    }
    let mut bytes = secret_input(&path, 4096, "GitHub webhook configuration")?;
    let parsed = serde_json::from_slice::<WebhookConfig>(&bytes);
    sentinel_auth::secret::wipe(&mut bytes);
    let mut config = parsed.map_err(|_| fail("invalid GitHub webhook configuration"))?;
    let secret = config.secret.as_bytes();
    let valid =
        (16..=256).contains(&secret.len()) && secret.iter().all(|b| (0x20..0x7f).contains(b));
    let secret: Option<Arc<[u8]>> = valid.then(|| Arc::from(secret));
    sentinel_auth::secret::wipe_string(&mut config.secret);
    secret
        .map(Some)
        .ok_or_else(|| fail("GitHub webhook secret must be 16-256 printable ASCII bytes"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInConfig {
    client_id: String,
    client_secret_file: std::path::PathBuf,
    web_url: Option<String>,
    api_url: Option<String>,
}

// The client secret never enters the configuration file, the database or a log line.
pub fn load_sign_in(root: &Path) -> Result<Option<sentinel_api::GithubSignIn>, Error> {
    let path = root.join("github-sign-in.json");
    if !path.exists() {
        return Ok(None);
    }
    let config: SignInConfig = serde_json::from_slice(&file(&path, 4096)?)
        .map_err(|_| fail("invalid GitHub sign-in configuration"))?;
    if !config.client_secret_file.is_absolute() {
        return Err(fail("GitHub sign-in client_secret_file must be absolute"));
    }
    let client_secret =
        sentinel_github::oauth::read_secret(&config.client_secret_file).map_err(|_| {
            fail(
                "cannot read the GitHub sign-in client secret file (it must be an \
                 owner-only regular file owned by this user, not a link)",
            )
        })?;
    let endpoints = match (&config.web_url, &config.api_url) {
        (None, None) => sentinel_github::oauth::Endpoints::github(),
        (Some(web), Some(api)) => sentinel_github::oauth::Endpoints::enterprise(web, api)
            .map_err(|_| fail("GitHub sign-in web_url and api_url must be https"))?,
        _ => {
            return Err(fail(
                "GitHub sign-in web_url and api_url go together (GitHub Enterprise Server)",
            ));
        }
    };
    Ok(Some(sentinel_api::GithubSignIn {
        client_id: config.client_id,
        client_secret,
        endpoints,
    }))
}

/// The GitHub App in force at start, from the files or else from the store (manifest flow).
pub struct Github {
    pub current: sentinel_github::app::Current,
    pub source: Option<sentinel_api::AppSource>,
    /// The base of a check's `details_url`: the file's `public_url`, or the controller's.
    pub details_url: Option<String>,
    pub members: sentinel_checks::members::Config,
    pub webhook_secret: Option<Arc<[u8]>>,
    pub sign_in: Option<sentinel_api::GithubSignIn>,
    /// A stored manifest App was found but the files took precedence.
    pub stored_ignored: bool,
}

/// Files win: when any of `github-app.json`, `github-webhook.json` and `github-sign-in.json`
/// exists, the deployment is configured by files exactly as before and a stored App is not
/// used. Otherwise a stored manifest App, opened with `master.key`, is put in force.
pub fn load_github(
    root: &Path,
    store: &sentinel_store::Store,
    key: Option<&sentinel_auth::sealed::Key>,
    public_url: Option<&str>,
) -> Result<Github, Error> {
    let app = load_app(root).map_err(|_| fail("cannot load GitHub App configuration"))?;
    let webhook_secret =
        load_webhook_secret(root).map_err(|_| fail("cannot load the GitHub webhook secret"))?;
    let sign_in = load_sign_in(root)?;
    let stored = store
        .read(sentinel_store::github_app::facts)
        .map_err(|_| fail("cannot read the stored GitHub App"))?
        .is_some();
    if app.is_some() || webhook_secret.is_some() || sign_in.is_some() {
        let (current, details_url, members) = match app {
            Some(app) => (Some(app.app), app.public_url, app.members),
            None => (None, None, sentinel_checks::members::Config::default()),
        };
        return Ok(Github {
            current: current.into(),
            source: Some(sentinel_api::AppSource::Files),
            details_url,
            members,
            webhook_secret,
            sign_in,
            stored_ignored: stored,
        });
    }
    let mut github = Github {
        current: sentinel_github::app::Current::default(),
        source: None,
        details_url: public_url.map(str::to_owned),
        members: sentinel_checks::members::Config::default(),
        webhook_secret: None,
        sign_in: None,
        stored_ignored: false,
    };
    if !stored {
        return Ok(github);
    }
    let key = key.ok_or_else(|| fail("the stored GitHub App needs master.key"))?;
    let credentials = store
        .read(|c| sentinel_store::github_app::load(c, key))
        .map_err(|_| fail("master.key does not open the stored GitHub App"))?
        .ok_or_else(|| fail("the stored GitHub App disappeared"))?;
    let app = sentinel_github::app::App::new(credentials.facts.app_id, &credentials.pem)
        .map_err(|_| fail("the stored GitHub App key is unusable"))?;
    github.current.set(Arc::new(app));
    github.webhook_secret = credentials
        .webhook_secret
        .as_deref()
        .map(|secret| Arc::from(secret.as_bytes()));
    github.sign_in = Some(sentinel_api::GithubSignIn {
        client_id: credentials.facts.client_id.clone(),
        client_secret: credentials.client_secret.clone(),
        endpoints: sentinel_github::oauth::Endpoints::github(),
    });
    github.source = Some(sentinel_api::AppSource::Manifest);
    Ok(github)
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
                // Stdout carries only the secret, so a shell can redirect it without a parser.
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
        SourceCommand::GithubBacking { tenant: t, off } => {
            let tenant = tenant(t)?;
            let github = !*off;
            store
                .writer()
                .write(move |tx| {
                    sentinel_store::github_members::set_backing_trusted(tx, tenant, github, now)
                })
                .map_err(denied)?;
            sentinel::outln!("{}", serde_json::json!({"github_backed":github}));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn loaded(root: &Path) -> Option<sentinel_api::GithubSignIn> {
        load_sign_in(root).unwrap_or_else(|error| panic!("{}", error.message))
    }

    fn write(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn github_sign_in_reads_an_owner_only_secret_file_and_never_echoes_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(loaded(dir.path()).is_none(), "absent is off");
        let secret = dir.path().join("client-secret");
        let config = dir.path().join("github-sign-in.json");
        write(&secret, "s3cret-client-value\n", 0o600);
        let body = |extra: &str| {
            format!(
                r#"{{"client_id":"Iv1.abc","client_secret_file":"{}"{extra}}}"#,
                secret.display()
            )
        };
        write(&config, &body(""), 0o600);
        let sign_in = loaded(dir.path()).unwrap();
        assert_eq!(sign_in.client_secret, "s3cret-client-value");
        assert!(!format!("{sign_in:?}").contains("s3cret"));

        write(
            &config,
            &body(r#","web_url":"https://gh.corp","api_url":"https://gh.corp/api/v3""#),
            0o600,
        );
        assert!(loaded(dir.path()).is_some());
        for (extra, mode) in [
            (r#","web_url":"https://gh.corp""#, 0o600),
            (
                r#","web_url":"http://gh.corp","api_url":"https://gh.corp/api/v3""#,
                0o600,
            ),
            (r#","client_secret":"inline""#, 0o600),
            ("", 0o644),
        ] {
            write(&secret, "s3cret-client-value\n", mode);
            write(&config, &body(extra), 0o600);
            let error = load_sign_in(dir.path()).expect_err(extra);
            assert!(!error.message.contains("s3cret"), "{}", error.message);
            assert!(!error.message.contains("inline"), "{}", error.message);
        }
        write(&secret, "s3cret-client-value\n", 0o600);
        write(
            &config,
            r#"{"client_id":"Iv1.abc","client_secret_file":"relative"}"#,
            0o600,
        );
        assert!(load_sign_in(dir.path()).is_err());

        let link = dir.path().join("client-secret-link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        write(
            &config,
            &format!(
                r#"{{"client_id":"Iv1.abc","client_secret_file":"{}"}}"#,
                link.display()
            ),
            0o600,
        );
        let error = load_sign_in(dir.path()).unwrap_err();
        assert!(!error.message.contains("s3cret"), "{}", error.message);
    }

    #[test]
    fn the_webhook_secret_file_is_judged_on_its_open_handle() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            load_webhook_secret(dir.path())
                .map_err(|e| e.message)
                .unwrap()
                .is_none()
        );
        let path = dir.path().join("github-webhook.json");
        let body = r#"{"secret":"a-webhook-secret-value"}"#;
        write(&path, body, 0o600);
        let secret = load_webhook_secret(dir.path())
            .map_err(|e| e.message)
            .unwrap()
            .unwrap();
        assert_eq!(&*secret, b"a-webhook-secret-value");
        write(&path, body, 0o640);
        let error = load_webhook_secret(dir.path()).err().unwrap();
        assert!(!error.message.contains("a-webhook"), "{}", error.message);
        let real = dir.path().join("real.json");
        write(&real, body, 0o600);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(load_webhook_secret(dir.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        write(&path, r#"{"secret":"short"}"#, 0o600);
        assert!(load_webhook_secret(dir.path()).is_err());
    }

    #[test]
    fn the_app_public_url_is_the_web_origin_with_no_path() {
        assert_eq!(
            public_url("https://ci.example.com/").map_err(|e| e.message),
            Ok("https://ci.example.com".to_owned())
        );
        for bad in [
            "https://ci.example.com/sentinel",
            "https://ci.example.com/a/b/",
        ] {
            assert!(public_url(bad).is_err(), "{bad}");
        }
    }
}
