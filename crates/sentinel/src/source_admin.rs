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
    MASTER_KEY_FILE, auth, registration, registration::Authority, sources, sources_forge,
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
}

pub fn load_app(root: &Path) -> Result<Option<Arc<sentinel_github::app::App>>, Error> {
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
    Ok(Some(Arc::new(
        sentinel_github::app::App::new(config.app_id, pem).map_err(|_| fail("invalid App key"))?,
    )))
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
            println!("{}", serde_json::json!({"repo":id.to_string()}));
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
            println!(
                "{}",
                serde_json::json!({"repo":repo.to_string(),"version":version})
            );
        }
        SourceCommand::Show { repo: r } => {
            let repo = repo(r)?;
            let m = store
                .read(|c| sources::metadata_trusted(c, repo))
                .map_err(denied)?;
            println!(
                "{}",
                serde_json::json!({"repo":repo.to_string(),"binding":m.binding,"version":m.version,"revoked":m.revoked,"forge":m.forge.map(|(i,r)|serde_json::json!({"installation":i.to_string(),"repository_id":r}))})
            );
        }
        SourceCommand::Revoke { repo: r, expected } => {
            let repo = repo(r)?;
            let expected = *expected;
            store
                .writer()
                .write(move |tx| sources::revoke(tx, host, Some(actor), repo, expected, now))
                .map_err(denied)?;
            println!(
                "{}",
                serde_json::json!({"revoked":true,"version":expected+1})
            );
        }
        SourceCommand::RefreshInstallation {
            external_id,
            expected,
        } => {
            let app = load_app(&args.data.data_dir)?
                .ok_or_else(|| fail("GitHub App is not configured"))?;
            let snapshot = app
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
            println!(
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
            println!("{}", serde_json::json!({"bound":true}));
        }
        SourceCommand::RemoveInstallation { installation: i } => {
            let id = installation(i)?;
            store
                .writer()
                .write(move |tx| sources_forge::remove(tx, id))
                .map_err(denied)?;
            println!("{}", serde_json::json!({"disabled":true}));
        }
    }
    Ok(())
}
