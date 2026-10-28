//! Passwords come from standard input only, never argv, so they stay out of the process list.

use std::io::IsTerminal;

use sentinel_core::{
    InvitationId, RepoId, SessionId, TenantId, TokenId, UnixMillis, UserId, WorkerId,
    auth::{Permissions, Role},
};
use sentinel_store::{
    Durability, MASTER_KEY_FILE, METADATA_FILE, Store, email,
    local_auth::{self, Event},
    lookup, mfa, oauth, operations,
    registration::{
        self, Authority, DeploymentPolicy, InstallationBinding, Registration, TenantCreation, Terms,
    },
    sign_in,
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers,
};

use crate::cli::{
    AccountArgs, AccountCommand, AdminArgs, AdminCommand, DataDir, IdentityArgs, IdentityCommand,
    InviteArgs, InviteCommand, KeyArgs, KeyCommand, MailArgs, MailCommand, MfaArgs, MfaCommand,
    OauthClientArgs, OauthClientCommand, ObjectsArgs, ObjectsCommand, PolicyArgs, PolicyCommand,
    PoolArgs, PoolCommand, SessionArgs, SessionCommand, TenantArgs, TenantCommand, TokenArgs,
    TokenCommand, WorkerArgs, WorkerCommand,
};

pub struct Error {
    pub message: String,
}

pub(crate) fn fail(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
    }
}

fn read_mfa_code() -> Result<String, Error> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(fail(
            "read the six-digit code from standard input, for example: sentinel admin mfa confirm ... < code-file",
        ));
    }
    let mut code = sentinel::bounded::read(stdin.lock(), 8)
        .map_err(|_| fail("the code on standard input must be six ASCII digits"))?;
    if code.last() == Some(&b'\n') {
        code.pop();
        if code.last() == Some(&b'\r') {
            code.pop();
        }
    }
    if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
        return Err(fail("the code on standard input must be six ASCII digits"));
    }
    String::from_utf8(code).map_err(|_| fail("the code on standard input must be six ASCII digits"))
}

fn read_password() -> Result<Vec<u8>, Error> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(fail(
            "read the password from standard input, for example: sentinel admin bootstrap ... < secret-file",
        ));
    }
    // Bounded: an endless source such as /dev/zero is refused, not buffered.
    let limit = sentinel_auth::password::MAX_LEN as u64 + 2;
    let mut password = match sentinel::bounded::read(stdin.lock(), limit) {
        Ok(bytes) => bytes,
        Err(sentinel::bounded::ReadError::TooLarge { .. }) => {
            return Err(fail(format!(
                "the password on standard input is longer than {} bytes",
                sentinel_auth::password::MAX_LEN
            )));
        }
        Err(error) => {
            return Err(fail(format!(
                "cannot read the password from standard input: {error}"
            )));
        }
    };
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err(fail("no password was supplied on standard input"));
    }
    Ok(password)
}

pub(crate) fn open(data: &DataDir, reporting: bool) -> Result<Store, Error> {
    if !data.data_dir.is_absolute() {
        return Err(fail("data_dir must be an absolute path"));
    }
    let path = data.data_dir.join(METADATA_FILE);
    if reporting && !path.exists() {
        return Err(fail(format!(
            "no controller database at {}",
            path.display()
        )));
    }
    let (store, snapshot) = sentinel_store::upgrade::open_upgrading(&path, Durability::Full)
        .map_err(|error| fail(format!("cannot open {}: {error}", path.display())))?;
    if let Some(snapshot) = snapshot {
        eprintln!(
            "the database was upgraded to schema {}; the copy from before is {}",
            sentinel_store::schema::LATEST,
            snapshot.display()
        );
    }
    Ok(store)
}

pub fn run(args: AdminArgs) -> Result<(), Error> {
    let now = sentinel_core::UnixMillis::now();
    match &args.command {
        AdminCommand::Source(args) => crate::source_admin::run(args)?,
        AdminCommand::Intake(args) => crate::intake_admin::run(args)?,
        AdminCommand::Objects(args) => objects(args)?,
        AdminCommand::Backup(args) => backup(args)?,
        AdminCommand::Upgrade {
            command: crate::cli::UpgradeCommand::Check { data },
        } => upgrade_check(data)?,
        AdminCommand::Diagnostics { data, integrity } => diagnostics(data, *integrity)?,
        AdminCommand::Restore {
            from,
            id,
            key,
            data_dir,
        } => restore(from, id.as_deref(), key.as_deref(), data_dir)?,
        AdminCommand::Tailcat(args) => crate::tailcat_admin::run(args).map_err(fail)?,
        AdminCommand::Bootstrap {
            data,
            username,
            display_name,
        } => {
            let store = open(data, false)?;
            let password = read_password()?;
            let user = local_auth::bootstrap(&store, username, display_name, &password, now)
                .map_err(|error| match error {
                    sentinel_store::Error::Forbidden => fail(
                        "bootstrap is already complete; use `sentinel admin recover` for a locked-out administrator",
                    ),
                    sentinel_store::Error::InvalidInput("password") => fail(format!(
                        "the password must be {}-{} bytes and not only spacing",
                        sentinel_auth::password::MIN_LEN,
                        sentinel_auth::password::MAX_LEN
                    )),
                    other => fail(format!("bootstrap failed: {other}")),
                })?;
            sentinel::outln!("super admin {username} created as {user}");
        }
        AdminCommand::Recover { data, username } => {
            let store = open(data, true)?;
            let password = read_password()?;
            let user =
                local_auth::recover(&store, username, &password, now).map_err(
                    |error| match error {
                        sentinel_store::Error::NotFound => {
                            fail("no local account with that username")
                        }
                        sentinel_store::Error::InvalidInput(what) => {
                            fail(format!("invalid {what}"))
                        }
                        other => fail(format!("recovery failed: {other}")),
                    },
                )?;
            sentinel::outln!("password reset and sessions revoked for {user}");
        }
        AdminCommand::Status { data } => {
            let store = open(data, true)?;
            let (available, admins, sessions, recent) = store
                .read(|conn| {
                    Ok((
                        local_auth::bootstrap_available(conn)?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM users WHERE kind = 0 AND super_admin = 1 AND active = 1",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM sessions WHERE revoked_ms IS NULL
                             AND idle_deadline_ms > ?1 AND absolute_deadline_ms > ?1",
                            [now.0],
                            |r| r.get::<_, i64>(0),
                        )?,
                        local_auth::recent_audit(conn, 10)?,
                    ))
                })
                .map_err(|error| fail(format!("cannot read authentication state: {error}")))?;
            sentinel::outln!("bootstrap available: {available}");
            sentinel::outln!("active super admins: {admins}");
            sentinel::outln!("live sessions: {sessions}");
            for record in recent {
                let scope = if record.host_local {
                    "host-local"
                } else {
                    "remote"
                };
                sentinel::outln!(
                    "  {} {} {scope}{}",
                    record.at.0,
                    Event::name(record.event),
                    record
                        .subject
                        .map(|id| format!(" subject={id}"))
                        .unwrap_or_default()
                );
            }
        }
        AdminCommand::Token(args) => token(args, now)?,
        AdminCommand::Identity(args) => identity(args, now)?,
        AdminCommand::Policy(args) => policy(args, now)?,
        AdminCommand::OauthClient(args) => oauth_client(args, now)?,
        AdminCommand::Invite(args) => invite(args, now)?,
        AdminCommand::Account(args) => account(args, now)?,
        AdminCommand::Mail(args) => mail(args)?,
        AdminCommand::Key(args) => key(args)?,
        AdminCommand::Mfa(args) => second_factor(args, now)?,
        AdminCommand::Session(args) => session(args, now)?,
        AdminCommand::Tenant(args) => tenant(args, now)?,
        AdminCommand::Pool(args) => pool(args, now)?,
        AdminCommand::Worker(args) => worker(args, now)?,
        AdminCommand::Logs {
            data,
            attempt,
            follow,
        } => logs(data, attempt, *follow)?,
        AdminCommand::Cancel { data, job, run } => {
            cancel(data, job.as_deref(), run.as_deref(), now)?
        }
    }
    Ok(())
}

fn scope(text: &str) -> Result<Permissions, Error> {
    let mut permissions = Permissions::NONE;
    for name in text.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        permissions = permissions.union(match name {
            "read" => Permissions::READ,
            "run" => Permissions::RUN,
            "secrets" => Permissions::WRITE_SECRETS,
            "tenant-admin" => Permissions::TENANT_ADMIN,
            "platform-admin" => Permissions::PLATFORM_ADMIN,
            other => {
                return Err(fail(format!(
                    "unknown scope {other}; use read, run, secrets, tenant-admin or platform-admin"
                )));
            }
        });
    }
    if permissions == Permissions::NONE {
        return Err(fail("a credential needs at least one scope"));
    }
    Ok(permissions)
}

fn scope_names(permissions: Permissions) -> String {
    let mut names = Vec::with_capacity(5);
    for (bit, name) in [
        (Permissions::READ, "read"),
        (Permissions::RUN, "run"),
        (Permissions::WRITE_SECRETS, "secrets"),
        (Permissions::TENANT_ADMIN, "tenant-admin"),
        (Permissions::PLATFORM_ADMIN, "platform-admin"),
    ] {
        if permissions.contains(bit) {
            names.push(name);
        }
    }
    names.join(",")
}

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn lifetime_ms(text: &str) -> Result<i64, Error> {
    duration_ms(text, tokens::MAX_LIFETIME_MS)
}

pub(crate) fn duration_ms(text: &str, max_ms: i64) -> Result<i64, Error> {
    // Split on the last character boundary; a byte offset could land inside a multibyte unit.
    let (digits, unit) = text.split_at(text.char_indices().last().map_or(0, |(at, _)| at));
    let scale = match unit {
        "d" => DAY_MS,
        "h" => 60 * 60 * 1000,
        "m" => 60 * 1000,
        "s" => 1000,
        _ => return Err(fail("duration must end in d, h, m or s, as in 30d")),
    };
    let value: i64 = digits
        .parse()
        .map_err(|_| fail("duration must be a whole number of units, as in 30d"))?;
    value
        .checked_mul(scale)
        .filter(|ms| (1..=max_ms).contains(ms))
        .ok_or_else(|| {
            fail(format!(
                "duration must be between 1s and {}d",
                max_ms / DAY_MS
            ))
        })
}

fn diagnostics(data: &DataDir, integrity: bool) -> Result<(), Error> {
    if !data.data_dir.is_absolute() {
        return Err(fail("data_dir must be an absolute path"));
    }
    let bundle = sentinel_store::bundle::collect_offline(
        &data.data_dir,
        sentinel_core::UnixMillis::now().0,
        integrity,
    )
    .map_err(|error| fail(format!("cannot read {}: {error}", data.data_dir.display())))?;
    sentinel::outln!("{bundle:#}");
    Ok(())
}

fn upgrade_check(data: &DataDir) -> Result<(), Error> {
    if !data.data_dir.is_absolute() {
        return Err(fail("data_dir must be an absolute path"));
    }
    let report = sentinel_store::upgrade::preflight(&data.data_dir).map_err(|error| {
        fail(format!(
            "cannot inspect {}: {error}",
            data.data_dir.display()
        ))
    })?;
    let i = &report.inspection;
    sentinel::outln!(
        "{}",
        serde_json::json!({
            "fresh": i.fresh,
            "schema": { "database": i.database, "binary": i.binary },
            "pending_migrations": i.pending,
            "newer_database": i.newer,
            "newer_needs_schema": i.needs,
            "integrity": i.integrity,
            "database_bytes": i.bytes,
            "free_bytes": report.free_bytes,
            "needed_bytes": report.needed_bytes,
            "sealed_values": report.sealed_values,
            "key_present": report.key_present,
            "worker_protocol": {
                "min": sentinel_protocol::negotiate::SUPPORTED_MIN.0,
                "max": sentinel_protocol::negotiate::SUPPORTED_MAX.0,
            },
            "workers": report.workers.iter().map(|w| serde_json::json!({
                "name": w.name,
                "protocol": w.protocol,
                "software": w.software,
                "last_seen_ms": w.last_seen_ms,
                "refused_after_upgrade": w.refused,
            })).collect::<Vec<_>>(),
            "blocking": report.blocking,
        })
    );
    if report.blocking.is_empty() {
        Ok(())
    } else {
        Err(fail(format!(
            "{} blocking finding(s)",
            report.blocking.len()
        )))
    }
}

fn backup_id(dir: &std::path::Path, id: Option<&str>) -> Result<String, Error> {
    match id {
        Some(id) => Ok(id.to_owned()),
        None => sentinel_store::backup::list(dir)
            .map_err(|error| fail(format!("cannot list backups: {error}")))?
            .pop()
            .ok_or_else(|| fail(format!("no backup in {}", dir.display()))),
    }
}

fn backup(args: &crate::cli::BackupArgs) -> Result<(), Error> {
    use crate::cli::BackupCommand;
    use sentinel_store::backup;
    match &args.command {
        BackupCommand::Create { data, to } => {
            if !to.is_absolute() || to.starts_with(&data.data_dir) {
                return Err(fail(
                    "--to must be an absolute directory outside the data directory",
                ));
            }
            let store = open(data, true)?;
            let objects = sentinel_store::objects::Objects::open(&data.data_dir)
                .map_err(|error| fail(format!("cannot open the object store: {error}")))?;
            let report = backup::create(
                &store,
                &objects,
                &data.data_dir,
                to,
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|error| fail(format!("backup failed: {error}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "id": report.id,
                    "took_ms": report.took_ms,
                    "metadata_bytes": report.metadata_bytes,
                    "objects": report.objects,
                    "objects_copied": report.objects_copied,
                    "object_bytes_copied": report.object_bytes_copied,
                    "objects_remote_only": report.objects_remote,
                    "objects_corrupt": report.objects_corrupt,
                    "objects_missing": report.objects_missing,
                    "partials_removed": report.partials_removed,
                    "manifests": report.manifests,
                    "log_files_copied": report.log_files_copied,
                    "log_bytes_copied": report.log_bytes_copied,
                    "config_files": report.config_files,
                    "key_ids": report.key_ids,
                })
            );
            if !report.objects_corrupt.is_empty() || !report.objects_missing.is_empty() {
                return Err(fail(
                    "some objects were missing or failed their digest and were not backed up; run admin objects verify",
                ));
            }
        }
        BackupCommand::List { dir } => {
            let ids =
                backup::list(dir).map_err(|error| fail(format!("cannot list backups: {error}")))?;
            for id in ids {
                if let Ok(m) = backup::manifest(dir, &id) {
                    sentinel::outln!(
                        "{}",
                        serde_json::json!({
                            "id": id,
                            "schema": m["schema"],
                            "version": m["version"],
                            "metadata_bytes": m["metadata"]["bytes"],
                            "objects": m["objects"]["rows"],
                            "key_ids": m["key"]["key_ids"],
                        })
                    );
                }
            }
        }
        BackupCommand::Verify { dir, id } => {
            let id = backup_id(dir, id.as_deref())?;
            let check = backup::verify(dir, &id)
                .map_err(|error| fail(format!("cannot verify {id}: {error}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "id": id,
                    "ok": check.ok(),
                    "integrity": check.integrity,
                    "metadata_matches": check.metadata_matches,
                    "objects_checked": check.objects_checked,
                    "objects_remote_only": check.objects_remote,
                    "manifests_checked": check.manifests_checked,
                    "missing": check.missing,
                    "corrupt": check.corrupt,
                })
            );
            if !check.ok() {
                return Err(fail(format!("backup {id} failed verification")));
            }
        }
        BackupCommand::Prune { dir, keep } => {
            let pruned = backup::prune(dir, *keep)
                .map_err(|error| fail(format!("cannot prune: {error}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "removed_backups": pruned.backups,
                    "removed_objects": pruned.objects,
                    "removed_manifests": pruned.manifests,
                    "removed_log_files": pruned.log_files,
                })
            );
        }
    }
    Ok(())
}

fn restore(
    from: &std::path::Path,
    id: Option<&str>,
    key: Option<&std::path::Path>,
    data_dir: &std::path::Path,
) -> Result<(), Error> {
    if !data_dir.is_absolute() || !from.is_absolute() {
        return Err(fail("--from and --data-dir must be absolute paths"));
    }
    let id = backup_id(from, id)?;
    let started = std::time::Instant::now();
    let restored = sentinel_store::backup::restore(from, &id, data_dir, key)
        .map_err(|error| fail(format!("cannot restore {id}: {error}")))?;
    let copied = started.elapsed();
    let store = open(
        &crate::cli::DataDir {
            data_dir: data_dir.to_path_buf(),
        },
        true,
    )?;
    let objects = sentinel_store::objects::Objects::open(data_dir)
        .map_err(|error| fail(format!("cannot open the object store: {error}")))?;
    let recovery = store
        .read(|c| objects.recover(c))
        .map_err(|error| fail(format!("recovery failed: {error}")))?;
    sentinel::outln!(
        "{}",
        serde_json::json!({
            "id": id,
            "data_dir": data_dir.display().to_string(),
            "objects": restored.objects,
            "objects_remote_only": restored.objects_remote,
            "manifests": restored.manifests,
            "log_files": restored.log_files,
            "config_files": restored.config_files,
            "key_checked": restored.key_checked,
            "copy_ms": copied.as_millis() as u64,
            "total_ms": started.elapsed().as_millis() as u64,
            "recovery": {
                "orphans": recovery.orphans.len(),
                "corrupt": recovery.corrupt.len(),
                "missing": recovery.missing.len(),
            },
        })
    );
    if restored.objects_remote > 0 {
        eprintln!(
            "{} objects live only in the external S3 copy: configure the same [s3] section to read them",
            restored.objects_remote
        );
    }
    Ok(())
}

fn tenant_storage(
    data: &DataDir,
    tenant: &str,
    repo: Option<&str>,
    quota: Option<u64>,
    log_retention: Option<&str>,
    artifact_retention: Option<&str>,
    inherit: &[String],
) -> Result<(), Error> {
    use sentinel_store::retention;
    const MAX_MS: i64 = retention::MAX_RETENTION_MS;
    let store = open(data, true)?;
    let (slug, name) = (tenant.to_owned(), repo.map(str::to_owned));
    let (tenant, repo) = store
        .read(move |conn| {
            let tenant = lookup::tenant_by_slug_any(conn, &slug)?;
            let repo = name
                .map(|n| lookup::repo_by_name(conn, tenant, &n))
                .transpose()?;
            Ok((tenant, repo))
        })
        .map_err(|_| fail("no such tenant or repository"))?;
    let log_ms = log_retention.map(|d| duration_ms(d, MAX_MS)).transpose()?;
    let artifact_ms = artifact_retention
        .map(|d| duration_ms(d, MAX_MS))
        .transpose()?;
    for name in inherit {
        if !matches!(
            name.as_str(),
            "quota" | "log-retention" | "artifact-retention" | "all"
        ) {
            return Err(fail(
                "--inherit takes quota, log-retention, artifact-retention or all",
            ));
        }
    }
    let changing =
        quota.is_some() || log_ms.is_some() || artifact_ms.is_some() || !inherit.is_empty();
    if changing {
        let inherit = inherit.to_vec();
        let (d, rest) = store
            .writer()
            .write(move |tx| {
                let d = retention::installed(tx)?;
                let mut policy = retention::policy(tx, tenant, repo)?;
                for name in &inherit {
                    match name.as_str() {
                        "quota" => policy.quota_bytes = None,
                        "log-retention" => policy.log_retention_ms = None,
                        "artifact-retention" => policy.artifact_retention_ms = None,
                        _ => policy = retention::Policy::default(),
                    }
                }
                policy.quota_bytes = quota.or(policy.quota_bytes);
                policy.log_retention_ms = log_ms.or(policy.log_retention_ms);
                policy.artifact_retention_ms = artifact_ms.or(policy.artifact_retention_ms);
                let rest = retention::set(
                    tx,
                    &Authority::HostLocal,
                    &d,
                    tenant,
                    repo,
                    policy,
                    UnixMillis::now(),
                )?;
                Ok((d, rest))
            })
            .map_err(|error| fail(format!("cannot set the storage policy: {error}")))?;
        retention::finish_reapply(&store, &d, tenant, repo, rest)
            .map_err(|error| fail(format!("cannot re-apply the storage policy: {error}")))?;
    }
    let report = store
        .read(move |conn| {
            let d = retention::installed(conn)?;
            let own = retention::policy(conn, tenant, repo)?;
            let effective = retention::effective(conn, &d, tenant, repo)?;
            let usage = match repo {
                Some(repo) => {
                    let u = retention::repo_usage(conn, tenant, repo)?;
                    serde_json::json!({"artifact_bytes": u.artifact_bytes, "log_bytes": u.log_bytes})
                }
                None => {
                    let u = retention::tenant_usage(conn, tenant)?;
                    serde_json::json!({"object_bytes": u.object_bytes, "log_bytes": u.log_bytes})
                }
            };
            Ok(serde_json::json!({
                "tenant": tenant.to_string(),
                "repo": repo.map(|r| r.to_string()),
                "policy": {
                    "quota_bytes": own.quota_bytes,
                    "log_retention_ms": own.log_retention_ms,
                    "artifact_retention_ms": own.artifact_retention_ms,
                },
                "effective": {
                    "tenant_quota_bytes": effective.tenant_quota_bytes,
                    "repo_quota_bytes": effective.repo_quota_bytes,
                    "log_retention_ms": effective.log_retention_ms,
                    "artifact_retention_ms": effective.artifact_retention_ms,
                },
                "usage": usage,
            }))
        })
        .map_err(|error| fail(format!("cannot read the storage policy: {error}")))?;
    sentinel::outln!("{report}");
    Ok(())
}

fn resolve_user(store: &Store, value: &str) -> Result<UserId, Error> {
    let unknown = || fail("no account with that username, address or identifier");
    if value.contains('@') {
        let owned = value.to_owned();
        return store
            .read(move |conn| email::user_by_address(conn, &owned))
            .ok()
            .flatten()
            .ok_or_else(unknown);
    }
    if let Ok(id) = value.parse::<UserId>() {
        return store
            .read(move |conn| lookup::known_user(conn, id))
            .map(|()| id)
            .map_err(|_| unknown());
    }
    let owned = value.to_owned();
    store
        .read(move |conn| lookup::user_by_username(conn, &owned))
        .map_err(|_| unknown())
}

fn resolve_target(
    store: &Store,
    tenant: Option<&String>,
    repo: Option<&String>,
) -> Result<(Option<TenantId>, Option<RepoId>), Error> {
    let Some(slug) = tenant else {
        if repo.is_some() {
            return Err(fail("--repo requires --tenant"));
        }
        return Ok((None, None));
    };
    let owned = slug.clone();
    let tenant = store
        .read(move |conn| lookup::tenant_by_slug(conn, &owned))
        .map_err(|_| fail("no active tenant with that slug"))?;
    let Some(name) = repo else {
        return Ok((Some(tenant), None));
    };
    let owned = name.clone();
    let repo = store
        .read(move |conn| lookup::repo_by_name(conn, tenant, &owned))
        .map_err(|_| fail("no repository with that name in that tenant"))?;
    Ok((Some(tenant), Some(repo)))
}

fn token(args: &TokenArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        TokenCommand::Issue {
            data,
            user,
            name,
            scope: requested,
            tenant,
            repo,
            expires_in,
        } => {
            let store = open(data, true)?;
            let permissions = scope(requested)?;
            let lifetime_ms = lifetime_ms(expires_in)?;
            let user = resolve_user(&store, user)?;
            let (tenant, repo) = resolve_target(&store, tenant.as_ref(), repo.as_ref())?;
            let granted = tokens::provision(
                &store,
                Grant {
                    user,
                    name,
                    permissions,
                    tenant,
                    repo,
                    lifetime_ms,
                },
                now,
            )
            .map_err(|error| match error {
                sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                other => fail(format!("the account cannot hold that credential: {other}")),
            })?;
            sentinel::outln!("{}", sentinel_auth::token::format(&granted.secret));
            eprintln!(
                "issued {} for {user}, scope {}, expires at {} (shown once)",
                granted.id,
                scope_names(permissions),
                granted.expires.0
            );
        }
        TokenCommand::List { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let records = store
                .read(|conn| tokens::list(conn, Authority::HostLocal, user, 100))
                .map_err(|error| fail(format!("cannot list credentials: {error}")))?;
            for record in records {
                sentinel::outln!(
                    "{} scope={} expires={}{}{} {}",
                    record.id,
                    scope_names(record.permissions),
                    record.expires.0,
                    record
                        .last_used
                        .map(|at| format!(" last_used={}", at.0))
                        .unwrap_or_default(),
                    if record.revoked { " revoked" } else { "" },
                    record.name
                );
            }
        }
        TokenCommand::Revoke { data, id } => {
            let store = open(data, true)?;
            let id: TokenId = id
                .parse()
                .map_err(|_| fail("expected a tok_ credential identifier"))?;
            tokens::revoke_host_local(&store, id, now).map_err(|error| match error {
                sentinel_store::Error::NotFound => fail("no credential with that identifier"),
                other => fail(format!("revocation failed: {other}")),
            })?;
            eprintln!("revoked {id}");
        }
        WorkerCommand::Policy {
            data,
            id,
            cpu_millis,
            memory_bytes,
            disk_bytes,
            priority,
        } => {
            let store = open(data, true)?;
            let id: WorkerId = id
                .parse()
                .map_err(|_| fail("expected a wrk_ worker identifier"))?;
            let change = (
                ceiling_flag(cpu_millis.as_deref(), "--cpu-millis")?,
                ceiling_flag(memory_bytes.as_deref(), "--memory-bytes")?,
                ceiling_flag(disk_bytes.as_deref(), "--disk-bytes")?,
                *priority,
            );
            let changing = cpu_millis.is_some()
                || memory_bytes.is_some()
                || disk_bytes.is_some()
                || priority.is_some();
            let view = store
                .writer()
                .write(move |tx| {
                    if changing {
                        let current = workers::host_view(tx, Authority::HostLocal, id)?.policy;
                        let policy = workers::HostPolicy {
                            cpu_millis: change.0.unwrap_or(current.cpu_millis),
                            memory_bytes: change.1.unwrap_or(current.memory_bytes),
                            disk_bytes: change.2.unwrap_or(current.disk_bytes),
                            priority: change.3.unwrap_or(current.priority),
                        };
                        workers::set_policy(tx, Authority::HostLocal, id, policy)?;
                    }
                    workers::host_view(tx, Authority::HostLocal, id)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no live worker with that identifier"),
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot change the policy: {other}")),
                })?;
            let show =
                |value: Option<i64>| value.map_or_else(|| "none".to_owned(), |v| v.to_string());
            sentinel::outln!(
                "approved  cpu_millis={} memory_bytes={} disk_bytes={} priority={}",
                show(view.policy.cpu_millis),
                show(view.policy.memory_bytes),
                show(view.policy.disk_bytes),
                view.policy.priority
            );
            sentinel::outln!(
                "reported  cpu_millis={} memory_bytes={} disk_bytes={} (0: not stated)",
                view.reported_cpu_millis,
                view.reported_memory_bytes,
                view.reported_disk_bytes
            );
            sentinel::outln!(
                "effective cpu_millis={} memory_bytes={} disk_bytes={} (0 disk: not enforced)",
                view.effective_cpu_millis,
                view.effective_memory_bytes,
                view.effective_disk_bytes
            );
            if changing {
                eprintln!("policy of {id} replaced; running work keeps its resources");
            }
        }
        WorkerCommand::Uninstall { data, id } => {
            let store = open(data, true)?;
            let id: WorkerId = id
                .parse()
                .map_err(|_| fail("expected a wrk_ worker identifier"))?;
            store
                .writer()
                .write(move |tx| workers::request_uninstall(tx, Authority::HostLocal, id, now))
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no live worker with that identifier"),
                    other => fail(format!("cannot request the uninstall: {other}")),
                })?;
            eprintln!(
                "{id} is draining; the controller revokes it, with its node key, once its accepted work has settled"
            );
        }
    }
    Ok(())
}

/// `None`: flag absent, leave the ceiling alone. `Some(None)`: `none`, remove it.
fn ceiling_flag(text: Option<&str>, flag: &str) -> Result<Option<Option<i64>>, Error> {
    match text {
        None => Ok(None),
        Some("none") => Ok(Some(None)),
        Some(number) => number
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .map(|value| Some(Some(value)))
            .ok_or_else(|| fail(format!("{flag} takes a positive number or `none`"))),
    }
}

fn identity(args: &IdentityArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        IdentityCommand::List { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let identities = store
                .read(|conn| sign_in::identities(conn, Authority::HostLocal, user))
                .map_err(|error| fail(format!("cannot list identities: {error}")))?;
            for identity in identities {
                sentinel::outln!(
                    "{} subject={} linked={}",
                    identity.provider,
                    identity.subject,
                    identity.linked.0
                );
            }
        }
        IdentityCommand::Unlink {
            data,
            user,
            provider,
        } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            sign_in::unlink_host_local(&store, user, provider, now).map_err(
                |error| match error {
                    sentinel_store::Error::NotFound => {
                        fail("that account has no link with that provider")
                    }
                    other => fail(format!("unlink failed: {other}")),
                },
            )?;
            eprintln!("unlinked {provider} from {user}");
        }
    }
    Ok(())
}

fn policy(args: &PolicyArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        PolicyCommand::Show { data } => {
            let store = open(data, true)?;
            let policy = store
                .read(registration::policy)
                .map_err(|error| fail(format!("cannot read the policy: {error}")))?;
            sentinel::outln!("registration: {}", registration_name(policy.registration));
            sentinel::outln!(
                "tenant creation: {}",
                tenant_creation_name(policy.tenant_creation)
            );
            sentinel::outln!(
                "installation binding: {}",
                installation_binding_name(policy.installation_binding)
            );
            let clients = store
                .read(oauth::client_registration)
                .map_err(|error| fail(format!("cannot read the policy: {error}")))?;
            sentinel::outln!("oauth client registration: {}", clients.as_str());
        }
        PolicyCommand::Set {
            data,
            registration: wanted,
            tenant_creation,
            installation_binding,
            oauth_client_registration,
        } => {
            let store = open(data, true)?;
            let clients = oauth_client_registration
                .as_deref()
                .map(|mode| {
                    oauth::ClientRegistration::parse(mode).ok_or_else(|| {
                        fail(format!(
                            "unknown OAuth client registration mode {mode}; use off, metadata or open"
                        ))
                    })
                })
                .transpose()?;
            let current = store
                .read(registration::policy)
                .map_err(|error| fail(format!("cannot read the policy: {error}")))?;
            let policy = DeploymentPolicy {
                registration: match wanted.as_deref() {
                    None => current.registration,
                    Some("closed") => Registration::Closed,
                    Some("invite-only") => Registration::InviteOnly,
                    Some("approval-required") => Registration::ApprovalRequired,
                    Some(other) => {
                        return Err(fail(format!(
                            "unknown registration mode {other}; use closed, invite-only or approval-required"
                        )));
                    }
                },
                tenant_creation: match tenant_creation.as_deref() {
                    None => current.tenant_creation,
                    Some("super-admin-only") => TenantCreation::SuperAdminOnly,
                    Some("approved-users") => TenantCreation::ApprovedUsers,
                    Some(other) => {
                        return Err(fail(format!(
                            "unknown tenant creation mode {other}; use super-admin-only or approved-users"
                        )));
                    }
                },
                installation_binding: match installation_binding.as_deref() {
                    None => current.installation_binding,
                    Some("super-admin-only") => InstallationBinding::SuperAdminOnly,
                    Some("tenant-admins") => InstallationBinding::TenantAdmins,
                    Some(other) => {
                        return Err(fail(format!(
                            "unknown installation binding mode {other}; use super-admin-only or tenant-admins"
                        )));
                    }
                },
            };
            store
                .writer()
                .write(move |tx| {
                    registration::set_policy(tx, Authority::HostLocal, policy, now)?;
                    match clients {
                        Some(mode) => {
                            oauth::set_client_registration(tx, Authority::HostLocal, mode, now)
                        }
                        None => Ok(()),
                    }
                })
                .map_err(|error| fail(format!("cannot change the policy: {error}")))?;
            if let Some(mode) = clients {
                eprintln!("oauth_client_registration={}", mode.as_str());
            }
            eprintln!(
                "registration={} tenants={} installations={}",
                registration_name(policy.registration),
                tenant_creation_name(policy.tenant_creation),
                installation_binding_name(policy.installation_binding)
            );
        }
    }
    Ok(())
}

fn oauth_client(args: &OauthClientArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        OauthClientCommand::List { data } => {
            let store = open(data, true)?;
            let clients = store
                .read(|conn| oauth::registered_clients(conn, now))
                .map_err(|error| fail(format!("cannot list OAuth clients: {error}")))?;
            for client in clients {
                sentinel::outln!(
                    "{} kind={} created={} grants={}{} name={:?}{}",
                    client.id,
                    match client.kind {
                        oauth::McpRegistrationKind::Dynamic => "dcr",
                        oauth::McpRegistrationKind::Metadata => "cimd",
                    },
                    client.created.0,
                    client.live_grants,
                    client
                        .disabled
                        .map(|at| format!(" disabled={}", at.0))
                        .unwrap_or_default(),
                    client.name,
                    client
                        .metadata_url
                        .map(|url| format!(" url={url}"))
                        .unwrap_or_default(),
                );
            }
        }
        OauthClientCommand::Disable { data, client }
        | OauthClientCommand::Enable { data, client } => {
            let disable = matches!(args.command, OauthClientCommand::Disable { .. });
            let store = open(data, true)?;
            let id = client.clone();
            let revoked = store
                .writer()
                .write(move |tx| {
                    oauth::set_client_disabled(tx, Authority::HostLocal, &id, disable, now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no registered OAuth client by that identifier or URL"),
                    sentinel_store::Error::Conflict => fail(
                        "the deployment already holds its limit of enabled registrations; disable another first",
                    ),
                    other => fail(format!("cannot change the client: {other}")),
                })?;
            if disable {
                eprintln!("disabled {client}; revoked {revoked} grant(s)");
            } else {
                eprintln!("enabled {client}");
            }
        }
    }
    Ok(())
}

const fn registration_name(value: Registration) -> &'static str {
    match value {
        Registration::Closed => "closed",
        Registration::InviteOnly => "invite-only",
        Registration::ApprovalRequired => "approval-required",
    }
}
const fn tenant_creation_name(value: TenantCreation) -> &'static str {
    match value {
        TenantCreation::SuperAdminOnly => "super-admin-only",
        TenantCreation::ApprovedUsers => "approved-users",
    }
}
const fn installation_binding_name(value: InstallationBinding) -> &'static str {
    match value {
        InstallationBinding::SuperAdminOnly => "super-admin-only",
        InstallationBinding::TenantAdmins => "tenant-admins",
    }
}

fn role(value: &str) -> Result<Role, Error> {
    match value {
        "reader" => Ok(Role::Reader),
        "operator" => Ok(Role::Operator),
        "admin" => Ok(Role::TenantAdmin),
        other => Err(fail(format!(
            "unknown role {other}; use reader, operator or admin"
        ))),
    }
}

const fn role_name(value: Role) -> &'static str {
    match value {
        Role::Reader => "reader",
        Role::Operator => "operator",
        Role::TenantAdmin => "admin",
    }
}

fn invite_email(
    data: &DataDir,
    store: &Store,
    (tenant, wanted): (TenantId, Role),
    address: &str,
    lifetime_ms: i64,
    print_link: bool,
    now: UnixMillis,
) -> Result<(), Error> {
    let key = if print_link {
        None
    } else {
        master_key(data).ok().map(std::sync::Arc::new)
    };
    let address = address.to_owned();
    let invited = store
        .writer()
        .write(move |tx| {
            registration::invite_by_email(
                tx,
                Authority::HostLocal,
                Terms {
                    tenant: Some(tenant),
                    role: Some(wanted),
                    identity: None,
                    lifetime_ms,
                },
                &address,
                key.as_deref(),
                now,
            )
        })
        .map_err(|error| match error {
            sentinel_store::Error::InvalidInput("organization backed by GitHub") => {
                fail("this organization's members come from GitHub; email invitations do not apply")
            }
            sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
            sentinel_store::Error::Overloaded => {
                fail("too many email invitations for this organization this hour")
            }
            other => fail(format!("cannot create the invitation: {other}")),
        })?;
    let invitation = invited.invitation;
    if invited.queued {
        eprintln!(
            "issued {} expiring at {}; the message is queued for delivery",
            invitation.id, invitation.expires.0
        );
    } else {
        sentinel::outln!("{}", sentinel_auth::token::format(&invitation.secret));
        eprintln!(
            "issued {} expiring at {} (shown once); no message was queued, so pass the secret on",
            invitation.id, invitation.expires.0
        );
    }
    Ok(())
}

fn invite(args: &InviteArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        InviteCommand::Create {
            data,
            tenant,
            role: wanted,
            identity,
            expires_in,
            email,
            print_link,
        } => {
            let store = open(data, true)?;
            let lifetime_ms = lifetime_ms(expires_in)?;
            let (tenant, _) = resolve_target(&store, tenant.as_ref(), None)?;
            let wanted = wanted.as_deref().map(role).transpose()?;
            if tenant.is_some() != wanted.is_some() {
                return Err(fail("--tenant and --role are given together or not at all"));
            }
            if let Some(address) = email {
                let (Some(tenant), Some(wanted)) = (tenant, wanted) else {
                    return Err(fail("--email needs --tenant and --role"));
                };
                return invite_email(
                    data,
                    &store,
                    (tenant, wanted),
                    address,
                    lifetime_ms,
                    *print_link,
                    now,
                );
            }
            let bound: Option<(String, String)> = match identity.as_deref() {
                None => None,
                Some(value) => {
                    let (provider, subject) = value.split_once(':').ok_or_else(|| {
                        fail("--identity is <provider>:<subject>, such as github:4242")
                    })?;
                    Some((provider.to_owned(), subject.to_owned()))
                }
            };
            let invitation = store
                .writer()
                .write(move |tx| {
                    registration::invite(
                        tx,
                        Authority::HostLocal,
                        Terms {
                            tenant,
                            role: wanted,
                            identity: bound
                                .as_ref()
                                .map(|(provider, subject)| (provider.as_str(), subject.as_str())),
                            lifetime_ms,
                        },
                        now,
                    )
                })
                .map_err(|error| match error {
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot create the invitation: {other}")),
                })?;
            sentinel::outln!("{}", sentinel_auth::token::format(&invitation.secret));
            eprintln!(
                "issued {} expiring at {} (shown once)",
                invitation.id, invitation.expires.0
            );
        }
        InviteCommand::List { data, tenant } => {
            let store = open(data, true)?;
            let (tenant, _) = resolve_target(&store, tenant.as_ref(), None)?;
            let records = store
                .read(|conn| registration::invitations(conn, Authority::HostLocal, tenant, 100))
                .map_err(|error| fail(format!("cannot list invitations: {error}")))?;
            for record in records {
                sentinel::outln!(
                    "{} expires={}{}{}{}{}",
                    record.id,
                    record.expires.0,
                    record
                        .role
                        .map(|role| format!(" role={}", role_name(role)))
                        .unwrap_or_default(),
                    record
                        .identity
                        .map(|(provider, subject)| format!(" identity={provider}:{subject}"))
                        .unwrap_or_default(),
                    if record.redeemed { " redeemed" } else { "" },
                    if record.revoked { " revoked" } else { "" }
                );
            }
        }
        InviteCommand::Revoke { data, id } => {
            let store = open(data, true)?;
            let id: InvitationId = id
                .parse()
                .map_err(|_| fail("expected an inv_ invitation identifier"))?;
            store
                .writer()
                .write(move |tx| registration::revoke_invitation(tx, Authority::HostLocal, id, now))
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no invitation with that identifier"),
                    other => fail(format!("revocation failed: {other}")),
                })?;
            eprintln!("revoked {id}");
        }
    }
    Ok(())
}

fn mail(args: &MailArgs) -> Result<(), Error> {
    match &args.command {
        MailCommand::Status { data } => {
            let store = open(data, true)?;
            let (enabled, url, (pending, delivered, abandoned)) = store
                .read(|conn| {
                    Ok((
                        email::delivery_enabled(conn)?,
                        email::public_url(conn)?,
                        email::counts(conn)?,
                    ))
                })
                .map_err(|error| fail(format!("cannot read the outbox: {error}")))?;
            sentinel::outln!(
                "delivery={} public_url={} pending={pending} delivered={delivered} abandoned={abandoned}",
                if enabled { "on" } else { "off" },
                url.as_deref().unwrap_or("-")
            );
        }
    }
    Ok(())
}

fn account(args: &AccountArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        AccountCommand::Pending { data } => {
            let store = open(data, true)?;
            let applications = store
                .read(|conn| registration::pending(conn, Authority::HostLocal, 100))
                .map_err(|error| fail(format!("cannot list applications: {error}")))?;
            for application in applications {
                sentinel::outln!(
                    "{} applied={} {}",
                    application.user,
                    application.applied.0,
                    application.display_name
                );
            }
        }
        AccountCommand::Approve { data, user } | AccountCommand::Reject { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let approve = matches!(args.command, AccountCommand::Approve { .. });
            store
                .writer()
                .write(move |tx| {
                    if approve {
                        registration::approve(tx, Authority::HostLocal, user, now)
                    } else {
                        registration::reject(tx, Authority::HostLocal, user, now)
                    }
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound if approve => {
                        fail("no pending account with that identifier")
                    }
                    sentinel_store::Error::NotFound => fail("no account with that identifier"),
                    other => fail(format!("the decision failed: {other}")),
                })?;
            eprintln!("{} {user}", if approve { "approved" } else { "rejected" });
        }
        AccountCommand::EmailLink {
            data,
            user,
            email: address,
            public_url,
        } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let address = address.clone();
            let issued = store
                .writer()
                .write(move |tx| {
                    email::issue_link(tx, Authority::HostLocal, user, address.as_deref(), now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => {
                        fail("nothing to verify: the account claims no address (give --email)")
                    }
                    sentinel_store::Error::Conflict => {
                        fail("another account already verified that address")
                    }
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot issue the link: {other}")),
                })?;
            let base = match public_url {
                Some(url) => Some(url.trim_end_matches('/').to_owned()),
                None => store.read(email::public_url).ok().flatten(),
            };
            let mut secret = String::new();
            issued.secret.expose(&mut secret);
            match &base {
                Some(base) => sentinel::outln!("{base}/verify-email#token={secret}"),
                None => sentinel::outln!("{secret}"),
            }
            sentinel_auth::secret::wipe_string(&mut secret);
            eprintln!(
                "issued for {user} expiring at {} (shown once; earlier links no longer work){}",
                issued.expires.0,
                if base.is_none() {
                    "; append the secret to <public_url>/verify-email#token="
                } else {
                    ""
                }
            );
        }
        AccountCommand::EmailVerify { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            store
                .writer()
                .write(move |tx| email::verify_host_local(tx, Authority::HostLocal, user, now))
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => {
                        fail("the account has no unverified address to vouch for")
                    }
                    sentinel_store::Error::Conflict => {
                        fail("another account already verified that address")
                    }
                    other => fail(format!("cannot verify the address: {other}")),
                })?;
            eprintln!("verified the address of {user}");
        }
    }
    Ok(())
}

fn key(args: &KeyArgs) -> Result<(), Error> {
    match &args.command {
        KeyCommand::Create { data } => {
            if !data.data_dir.is_absolute() {
                return Err(fail("data_dir must be an absolute path"));
            }
            let path = data.data_dir.join(MASTER_KEY_FILE);
            sentinel_auth::sealed::Key::create(&path)
                .map_err(|error| fail(format!("cannot create the key: {error:?}")))?;
            eprintln!(
                "wrote {}; keep it out of database backups and losing it loses every sealed value",
                path.display()
            );
        }
        KeyCommand::Reseal {
            data,
            retire,
            backup,
        } => reseal(data, *retire, backup.as_deref())?,
        KeyCommand::Rotate { data, backup } => {
            if !data.data_dir.is_absolute() || !backup.is_absolute() {
                return Err(fail("data_dir and backup must be absolute paths"));
            }
            let path = data.data_dir.join(MASTER_KEY_FILE);
            // Hold the database ownership lock: a running controller must not keep the old key in memory.
            let _owner = data
                .data_dir
                .join(METADATA_FILE)
                .exists()
                .then(|| open(data, true))
                .transpose()?;
            let id = sentinel_auth::sealed::Key::rotate(&path, backup)
                .map_err(|error| fail(format!("cannot rotate the key: {error:?}")))?;
            eprintln!(
                "activated key {id}; retain {} and the pre-rotation backup {} with their matching database snapshots",
                path.display(),
                backup.display()
            );
        }
    }
    Ok(())
}

fn reseal(data: &DataDir, retire: bool, backup: Option<&std::path::Path>) -> Result<(), Error> {
    if !data.data_dir.is_absolute() || backup.is_some_and(|b| !b.is_absolute()) {
        return Err(fail("data_dir and backup must be absolute paths"));
    }
    let path = data.data_dir.join(MASTER_KEY_FILE);
    let store = open(data, true)?;
    let key = std::sync::Arc::new(
        sentinel_auth::sealed::Key::load(&path)
            .map_err(|error| fail(format!("cannot load {}: {error:?}", path.display())))?,
    );
    let progress = sentinel_store::reseal::reseal_all(&store, std::sync::Arc::clone(&key))
        .map_err(|error| {
            fail(format!(
                "reseal stopped ({error}); values already moved stay moved, rerun to continue"
            ))
        })?;
    eprintln!(
        "resealed {} of {} sealed values under key {}",
        progress.resealed,
        progress.examined,
        key.active_id()
    );
    if !retire {
        return Ok(());
    }
    let backup = backup.ok_or_else(|| fail("--retire needs --backup"))?;
    let stale = store
        .read(|conn| sentinel_store::reseal::stale(conn, &key))
        .map_err(|error| fail(format!("cannot check sealed values: {error}")))?;
    if stale != 0 {
        return Err(fail(format!(
            "{stale} sealed values still need a retired key; nothing was retired"
        )));
    }
    let retired = sentinel_auth::sealed::Key::retire(&path, backup)
        .map_err(|error| fail(format!("cannot retire keys: {error:?}")))?;
    if retired == 0 {
        eprintln!("only the active key remains; nothing to retire");
    } else {
        eprintln!(
            "retired {retired} keys; {} now holds key {} only, and {} holds the file as it was",
            path.display(),
            key.active_id(),
            backup.display()
        );
    }
    Ok(())
}

fn master_key(data: &DataDir) -> Result<sentinel_auth::sealed::Key, Error> {
    let path = data.data_dir.join(MASTER_KEY_FILE);
    sentinel_auth::sealed::Key::load(&path).map_err(|_| {
        fail(format!(
            "cannot load {}; create it with `sentinel admin key create`",
            path.display()
        ))
    })
}

fn second_factor(args: &MfaArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        MfaCommand::Enroll { data, user } => {
            let store = open(data, true)?;
            let key = master_key(data)?;
            let user = resolve_user(&store, user)?;
            let label = store
                .read(|conn| local_auth::username_of(conn, user))
                .map_err(|error| fail(format!("cannot read the account: {error}")))?
                .unwrap_or_else(|| user.to_string());
            let enrollment =
                mfa::begin_enrollment_host_local(&store, &key, user, "Sentinel", &label, now)
                    .map_err(|error| match error {
                        sentinel_store::Error::Conflict => fail(
                            "that account already has a second factor; remove it with `sentinel admin mfa disable` first",
                        ),
                        sentinel_store::Error::NotFound => {
                            fail("that account is not an active human account")
                        }
                        other => fail(format!("cannot begin enrollment: {other}")),
                    })?;
            eprintln!(
                "add this to the authenticator app, then run `sentinel admin mfa confirm` with a code from it; it is shown once"
            );
            sentinel::outln!("{}", enrollment.provisioning_uri);
        }
        MfaCommand::Confirm { data, user } => {
            let code = read_mfa_code()?;
            let store = open(data, true)?;
            let key = master_key(data)?;
            let user = resolve_user(&store, user)?;
            let codes = mfa::confirm_enrollment_host_local(&store, &key, user, &code, now)
                .map_err(|error| match error {
                    sentinel_store::Error::Forbidden => {
                        fail("that code is not valid now; use the one the app shows at this moment")
                    }
                    sentinel_store::Error::NotFound => {
                        fail("no enrollment is waiting; run `sentinel admin mfa enroll` first")
                    }
                    other => fail(format!("cannot confirm enrollment: {other}")),
                })?;
            eprintln!("second factor enrolled for {user}; the recovery codes are shown once");
            for code in &codes {
                sentinel::outln!("{}", code.expose());
            }
        }
        MfaCommand::Codes { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let codes =
                mfa::reissue_recovery_codes_host_local(&store, user, now).map_err(|error| {
                    match error {
                        sentinel_store::Error::NotFound => {
                            fail("that account has no second factor")
                        }
                        other => fail(format!("cannot reissue recovery codes: {other}")),
                    }
                })?;
            eprintln!("recovery codes replaced for {user}; the new set is shown once");
            for code in &codes {
                sentinel::outln!("{}", code.expose());
            }
        }
        MfaCommand::Status { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let (enrolled, remaining) = store
                .read(|conn| {
                    Ok((
                        mfa::enrolled(conn, user)?,
                        mfa::recovery_codes_remaining(conn, user)?,
                    ))
                })
                .map_err(|error| fail(format!("cannot read second-factor state: {error}")))?;
            sentinel::outln!("enrolled: {enrolled}");
            sentinel::outln!("recovery codes remaining: {remaining}");
        }
        MfaCommand::Disable { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            mfa::disable_host_local(&store, user, now).map_err(|error| match error {
                sentinel_store::Error::NotFound => fail("that account has no second factor"),
                other => fail(format!("cannot remove the second factor: {other}")),
            })?;
            eprintln!("second factor removed and sessions revoked for {user}");
        }
    }
    Ok(())
}

fn session(args: &SessionArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        SessionCommand::List { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let records = store
                .read(|conn| local_auth::sessions(conn, Authority::HostLocal, user, 100))
                .map_err(|error| fail(format!("cannot list sessions: {error}")))?;
            for record in records {
                sentinel::outln!(
                    "{} created={} idle_until={} until={}{}{}",
                    record
                        .id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "(unnamed)".into()),
                    record.created.0,
                    record.idle_deadline.0,
                    record.absolute_deadline.0,
                    record
                        .stepped_up
                        .map(|at| format!(" stepped_up={}", at.0))
                        .unwrap_or_default(),
                    if record.revoked { " revoked" } else { "" }
                );
            }
        }
        SessionCommand::Revoke { data, user, id } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let id: SessionId = id
                .parse()
                .map_err(|_| fail("expected a ses_ session identifier"))?;
            store
                .writer()
                .write(move |tx| {
                    local_auth::revoke_session(tx, Authority::HostLocal, user, id, now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no live session with that identifier"),
                    other => fail(format!("revocation failed: {other}")),
                })?;
            eprintln!("revoked {id}");
        }
        SessionCommand::LogoutAll { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let revoked = local_auth::revoke_all_host_local(&store, user, now)
                .map_err(|error| fail(format!("logout-all failed: {error}")))?;
            eprintln!("revoked {revoked} session(s) for {user}");
        }
    }
    Ok(())
}

fn tenant(args: &TenantArgs, now: UnixMillis) -> Result<(), Error> {
    let (data, slug, suspend) = match &args.command {
        TenantCommand::Create { data, slug } => {
            let store = open(data, true)?;
            let id = TenantId::new();
            let owned = slug.clone();
            store
                .writer()
                .write(move |tx| {
                    let slug = sentinel_core::auth::Namespace::parse(&owned)
                        .ok_or(sentinel_store::Error::InvalidInput("namespace slug"))?;
                    tenancy::create_organization(tx, Authority::HostLocal, id, slug, now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot create the namespace: {other}")),
                })?;
            sentinel::outln!("{id}");
            return Ok(());
        }
        TenantCommand::Quota {
            data,
            tenant,
            bytes,
            clear,
        } => {
            if *bytes == Some(0) || (bytes.is_some() && *clear) {
                return Err(fail("give --bytes with a positive value, or --clear"));
            }
            let store = open(data, true)?;
            let owned = tenant.clone();
            let id = store
                .read(move |conn| lookup::tenant_by_slug_any(conn, &owned))
                .map_err(|_| fail("no tenant with that slug"))?;
            let objects = sentinel_store::objects::Objects::open(&data.data_dir)
                .map_err(|error| fail(format!("cannot open the object store: {error}")))?;
            if let Ok(d) = store.read(sentinel_store::retention::installed) {
                objects.set_deployment(d);
            }
            match (bytes, clear) {
                (Some(bytes), _) => {
                    let bytes = *bytes;
                    store
                        .writer()
                        .write(move |tx| objects.set_quota(tx, id, bytes))
                        .map_err(|error| fail(format!("cannot set the quota: {error}")))?;
                    eprintln!("quota for {id} set to {bytes} bytes");
                }
                (None, true) => {
                    store
                        .writer()
                        .write(move |tx| objects.clear_quota(tx, id))
                        .map_err(|error| fail(format!("cannot clear the quota: {error}")))?;
                    eprintln!("quota for {id} cleared; the configured default applies");
                }
                (None, false) => {
                    let report = store
                        .read(move |conn| Ok((objects.usage(conn, id)?, objects.quota(conn, id)?)))
                        .map_err(|error| fail(format!("cannot read the quota: {error}")))?;
                    sentinel::outln!(
                        "{}",
                        serde_json::json!({
                            "tenant": id.to_string(),
                            "used_bytes": report.0,
                            "quota_bytes": report.1,
                        })
                    );
                }
            }
            return Ok(());
        }
        TenantCommand::Storage {
            data,
            tenant,
            repo,
            quota,
            log_retention,
            artifact_retention,
            inherit,
        } => {
            return tenant_storage(
                data,
                tenant,
                repo.as_deref(),
                *quota,
                log_retention.as_deref(),
                artifact_retention.as_deref(),
                inherit,
            );
        }
        TenantCommand::Suspend { data, tenant } => (data, tenant, true),
        TenantCommand::Reactivate { data, tenant } => (data, tenant, false),
    };
    let store = open(data, true)?;
    let owned = slug.clone();
    let id = store
        .read(move |conn| lookup::tenant_by_slug_any(conn, &owned))
        .map_err(|_| fail("no tenant with that slug"))?;
    if suspend {
        let done = store
            .writer()
            .write(move |tx| tenancy::suspend(tx, Authority::HostLocal, id, now))
            .map_err(|error| match error {
                sentinel_store::Error::NotFound => fail("that tenant is already suspended"),
                other => fail(format!("suspension failed: {other}")),
            })?;
        eprintln!(
            "suspended {id}: {} credential(s) revoked, {} invitation(s) revoked, {} job(s) canceled, {} running job(s) asked to stop",
            done.tokens_revoked,
            done.invitations_revoked,
            done.jobs_canceled,
            done.jobs_cancel_requested
        );
    } else {
        store
            .writer()
            .write(move |tx| tenancy::reactivate(tx, Authority::HostLocal, id, now))
            .map_err(|error| match error {
                sentinel_store::Error::NotFound => fail("that tenant is not suspended"),
                other => fail(format!("reactivation failed: {other}")),
            })?;
        eprintln!("reactivated {id}");
    }
    Ok(())
}

fn pool(args: &PoolArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        PoolCommand::Create { data, name, tenant } => {
            let store = open(data, true)?;
            let (owner, _) = resolve_target(&store, tenant.as_ref(), None)?;
            let kind = owner.map_or(PoolKind::Shared, PoolKind::Dedicated);
            let id = sentinel_core::PoolId::new();
            let name = name.clone();
            store
                .writer()
                .write(move |tx| {
                    tenancy::create_pool(tx, Authority::HostLocal, id, &name, kind, now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot create the pool: {other}")),
                })?;
            sentinel::outln!("{id}");
        }
        PoolCommand::Grant { data, pool, tenant } | PoolCommand::Revoke { data, pool, tenant } => {
            let store = open(data, true)?;
            let grant = matches!(args.command, PoolCommand::Grant { .. });
            let (tenant, _) = resolve_target(&store, Some(tenant), None)?;
            let tenant = tenant.expect("resolved");
            let owned = pool.clone();
            let pool = store
                .read(move |conn| lookup::pool_by_name(conn, &owned))
                .map_err(|_| fail("no pool with that name"))?;
            store
                .writer()
                .write(move |tx| {
                    if grant {
                        tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, now)
                    } else {
                        tenancy::revoke_pool_grant(tx, Authority::HostLocal, pool, tenant, now)
                    }
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => {
                        fail("that tenant holds no grant on that pool")
                    }
                    other => fail(format!("cannot change the grant: {other}")),
                })?;
            eprintln!(
                "{} {pool} for {tenant}",
                if grant { "granted" } else { "revoked" }
            );
        }
        PoolCommand::List { data, tenant } => {
            let store = open(data, true)?;
            let (tenant, _) = resolve_target(&store, Some(tenant), None)?;
            let tenant = tenant.expect("resolved");
            let pools = store
                .read(|conn| tenancy::pools_for_tenant(conn, Authority::HostLocal, tenant))
                .map_err(|error| fail(format!("cannot list pools: {error}")))?;
            for record in pools {
                sentinel::outln!(
                    "{} {} {}{}",
                    record.id,
                    record.name,
                    match record.kind {
                        PoolKind::Dedicated(_) => "dedicated",
                        PoolKind::Shared => "shared",
                    },
                    if record.active { "" } else { " inactive" }
                );
            }
        }
    }
    Ok(())
}

fn worker(args: &WorkerArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        WorkerCommand::Enroll {
            data,
            pool,
            expires_in,
            transport,
            cpu_millis,
            memory_bytes,
            disk_bytes,
            priority,
        } => {
            let store = open(data, true)?;
            let lifetime_ms = lifetime_ms(expires_in)?;
            if lifetime_ms > workers::MAX_ENROLLMENT_MS {
                return Err(fail("enrollment lifetime is at most 1d"));
            }
            let owned = pool.clone();
            let pool = store
                .read(move |conn| lookup::pool_by_name(conn, &owned))
                .map_err(|_| fail("no pool with that name"))?;
            let terms = workers::EnrollmentTerms {
                pool,
                lifetime_ms,
                policy: workers::HostPolicy {
                    cpu_millis: *cpu_millis,
                    memory_bytes: *memory_bytes,
                    disk_bytes: *disk_bytes,
                    priority: *priority,
                },
                tailcat: *transport == crate::cli::EnrollTransport::Tailcat,
            };
            let tailcat = terms.tailcat;
            let enrollment = store
                .writer()
                .write(move |tx| {
                    workers::issue_enrollment_with(tx, Authority::HostLocal, terms, now)
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("that pool is not active"),
                    sentinel_store::Error::InvalidInput(what) => fail(format!("invalid {what}")),
                    other => fail(format!("cannot issue the enrollment: {other}")),
                })?;
            sentinel::outln!("{}", sentinel_auth::token::format(&enrollment.secret));
            eprintln!(
                "issued {} for pool {} expiring at {} (shown once)",
                enrollment.id, enrollment.pool, enrollment.expires.0
            );
            if tailcat {
                eprintln!(
                    "tailcat: authorize the worker's key with `sentinel admin tailcat authorize --enrollment {}`",
                    enrollment.id
                );
            }
        }
        WorkerCommand::List { data, pool } => {
            let store = open(data, true)?;
            let owned = pool.clone();
            let pool = store
                .read(move |conn| lookup::pool_by_name(conn, &owned))
                .map_err(|_| fail("no pool with that name"))?;
            let live = store
                .read(|conn| workers::in_pool(conn, Authority::HostLocal, pool))
                .map_err(|error| fail(format!("cannot list workers: {error}")))?;
            for w in live {
                sentinel::outln!(
                    "{} {} {:?} protocol={} capabilities={:#x}{}",
                    w.id,
                    w.name,
                    w.negotiated.arch,
                    w.negotiated.protocol.0,
                    w.negotiated.capabilities.0,
                    w.last_seen
                        .map(|at| format!(" last_seen={}", at.0))
                        .unwrap_or_default()
                );
            }
        }
        WorkerCommand::Drain { data, id } | WorkerCommand::Undrain { data, id } => {
            let store = open(data, true)?;
            let drain = matches!(args.command, WorkerCommand::Drain { .. });
            let id: WorkerId = id
                .parse()
                .map_err(|_| fail("expected a wrk_ worker identifier"))?;
            store
                .writer()
                .write(move |tx| {
                    if drain {
                        workers::drain(tx, Authority::HostLocal, id, now)
                    } else {
                        workers::undrain(tx, Authority::HostLocal, id)
                    }
                })
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no live worker with that identifier"),
                    other => fail(format!("cannot change the drain state: {other}")),
                })?;
            eprintln!("{} {id}", if drain { "draining" } else { "undrained" });
        }
        WorkerCommand::Revoke { data, id } => {
            let store = open(data, true)?;
            let id: WorkerId = id
                .parse()
                .map_err(|_| fail("expected a wrk_ worker identifier"))?;
            store
                .writer()
                .write(move |tx| workers::revoke(tx, Authority::HostLocal, id, now))
                .map_err(|error| match error {
                    sentinel_store::Error::NotFound => fail("no live worker with that identifier"),
                    other => fail(format!("revocation failed: {other}")),
                })?;
            eprintln!("revoked {id}");
        }
    }
    Ok(())
}

fn cancel(
    data: &DataDir,
    job: Option<&str>,
    run: Option<&str>,
    now: UnixMillis,
) -> Result<(), Error> {
    let store = open(data, true)?;
    match (job, run) {
        (Some(job), None) => {
            let job: sentinel_core::JobId = job
                .parse()
                .map_err(|_| fail("expected a job_ identifier"))?;
            let tenant = store
                .read(move |c| lookup::job_tenant(c, job))
                .map_err(|_| fail("no job with that identifier"))?;
            let outcome = store
                .writer()
                .write(move |tx| {
                    let outcome = sentinel_store::dispatch::cancel(tx, tenant, job, now)?;
                    operations::record(
                        tx,
                        tenant,
                        operations::Action::CancelJob,
                        *job.as_bytes(),
                        operations::Actor::HostLocal,
                        now,
                    )?;
                    Ok(outcome)
                })
                .map_err(|error| fail(format!("cannot cancel: {error}")))?;
            eprintln!("{job}: {outcome:?}");
        }
        (None, Some(run)) => {
            let run: sentinel_core::RunId = run
                .parse()
                .map_err(|_| fail("expected a run_ identifier"))?;
            let tenant = store
                .read(move |c| lookup::run_tenant(c, run))
                .map_err(|_| fail("no run with that identifier"))?;
            let count = store
                .writer()
                .write(move |tx| {
                    let count = sentinel_store::dispatch::cancel_run(tx, tenant, run, now)?;
                    operations::record(
                        tx,
                        tenant,
                        operations::Action::CancelRun,
                        *run.as_bytes(),
                        operations::Actor::HostLocal,
                        now,
                    )?;
                    Ok(count)
                })
                .map_err(|error| fail(format!("cannot cancel: {error}")))?;
            eprintln!("{run}: cancellation recorded for {count} job(s)");
        }
        _ => return Err(fail("give exactly one of --job or --run")),
    }
    Ok(())
}

fn objects(args: &ObjectsArgs) -> Result<(), Error> {
    let objects = sentinel_store::objects::Objects::open(&args.data.data_dir)
        .map_err(|error| fail(format!("cannot open the object store: {error}")))?;
    match args.command {
        ObjectsCommand::Recover => {
            // tmp/ holds in-flight writes; sweeping it under a live controller deletes staged bodies.
            let store = open(&args.data, true)?;
            let report = store
                .read(|conn| objects.recover(conn))
                .map_err(|error| fail(format!("recovery failed: {error}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "staged": report.staged,
                    "orphans": report.orphans.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "corrupt": report.corrupt.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "missing": report.missing.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                })
            );
        }
        ObjectsCommand::Verify => {
            let store = open(&args.data, true)?;
            let corrupt = store
                .read(|conn| objects.verify(conn))
                .map_err(|error| fail(format!("verification failed: {error}")))?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "corrupt": corrupt
                        .iter()
                        .map(|c| serde_json::json!({
                            "tenant": c.tenant.to_string(),
                            "digest": c.digest.to_string(),
                            "path": c.path.display().to_string(),
                        }))
                        .collect::<Vec<_>>(),
                })
            );
        }
        ObjectsCommand::Sweep => {
            // A live controller may have a client mid-chunk, so this runs only on a stopped store.
            let store = open(&args.data, true)?;
            let swept = store
                .writer()
                .write(move |tx| objects.sweep_uploads(tx, sentinel_core::UnixMillis::now()))
                .map_err(|error| fail(format!("sweep failed: {error}")))?;
            sentinel::outln!("{}", serde_json::json!({ "expired": swept }));
        }
        ObjectsCommand::Reclaim => {
            // Row deletions commit before their files unlink, so a stopped store is safe.
            let store = open(&args.data, true)?;
            let now = sentinel_core::UnixMillis::now();
            let objects = std::sync::Arc::new(objects);
            let report = store
                .writer()
                .write({
                    let objects = std::sync::Arc::clone(&objects);
                    move |tx| {
                        let uploads = objects.sweep_uploads(tx, now)?;
                        let leases = objects.sweep_leases(tx, now)?;
                        let manifests =
                            sentinel_store::artifacts::sweep_expired(tx, &objects, now, 4096)?;
                        let indexed = objects.index_refs(tx, 4096)?;
                        let reclaimed = objects.reclaim(tx, now, 4096)?;
                        Ok::<_, sentinel_store::Error>((
                            uploads, leases, manifests, indexed, reclaimed,
                        ))
                    }
                })
                .map_err(|error| fail(format!("reclaim failed: {error}")))?;
            let (uploads, leases, manifests, indexed, reclaimed) = report;
            let manifest_files = manifests.len();
            let (objects_reclaimed, bytes_reclaimed) = (reclaimed.objects, reclaimed.bytes);
            let mut doomed = manifests;
            doomed.extend(reclaimed.doomed);
            {
                let objects = std::sync::Arc::clone(&objects);
                store
                    .writer()
                    .write(move |tx| objects.unlink(tx, &doomed))
                    .map_err(|error| fail(format!("unlink failed: {error}")))?;
            }
            let mut orphans = 0u32;
            loop {
                let (found, done) = store
                    .read(|conn| objects.orphans(conn, 4096, u32::MAX))
                    .map_err(|error| fail(format!("orphan sweep failed: {error}")))?;
                let objects = std::sync::Arc::clone(&objects);
                orphans += store
                    .writer()
                    .write(move |tx| objects.unlink(tx, &found))
                    .map_err(|error| fail(format!("orphan sweep failed: {error}")))?;
                if done {
                    break;
                }
            }
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "expired_uploads": uploads,
                    "expired_leases": leases,
                    "manifest_files_removed": manifest_files,
                    "manifests_indexed": indexed,
                    "objects_reclaimed": objects_reclaimed,
                    "bytes_reclaimed": bytes_reclaimed,
                    "orphan_files_removed": orphans,
                })
            );
        }
        ObjectsCommand::Status => {
            let store = open(&args.data, true)?;
            let report = store
                .read(|conn| {
                    let mut stmt = conn.prepare(
                        "SELECT u.tenant_id, u.bytes + u.log_bytes,
                                (SELECT quota_bytes FROM storage_policies q
                                 WHERE q.tenant_id = u.tenant_id AND q.repo_id = X'')
                         FROM tenant_usage u ORDER BY u.bytes + u.log_bytes DESC",
                    )?;
                    let mut tenants = Vec::new();
                    let mut rows = stmt.query([])?;
                    while let Some(row) = rows.next()? {
                        let raw = row.get::<_, Vec<u8>>(0)?;
                        let tenant = TenantId::from_bytes(
                            <[u8; 16]>::try_from(raw.as_slice())
                                .map_err(|_| sentinel_store::Error::Corrupt("tenant id"))?,
                        )
                        .map_err(|_| sentinel_store::Error::Corrupt("tenant id"))?;
                        tenants.push((
                            tenant.to_string(),
                            row.get::<_, i64>(1)? as u64,
                            row.get::<_, Option<i64>>(2)?.map(|q| q as u64),
                        ));
                    }
                    Ok(tenants)
                })
                .map_err(|error| fail(format!("cannot read storage state: {error}")))?;
            let free = sentinel_store::space::free_bytes(&args.data.data_dir).ok();
            let total = sentinel_store::space::total_bytes(&args.data.data_dir).ok();
            let sized = total.map(sentinel_store::space::default_watermarks);
            let metadata = store.metadata_bytes();
            let deployment = report.iter().map(|(_, used, _)| used).sum::<u64>();
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "free_bytes": free,
                    "filesystem_bytes": total,
                    "metadata_bytes": metadata,
                    "metadata_reserve_bytes": metadata
                        .saturating_mul(sentinel_store::space::METADATA_RESERVE_FACTOR),
                    "sized_watermarks": sized.map(|m| serde_json::json!({
                        "reserve_bytes": m.reserve,
                        "low_watermark_bytes": m.low,
                        "high_watermark_bytes": m.high,
                    })),
                    "stored_bytes": deployment,
                    "tenants": report.iter().map(|(t, used, quota)| serde_json::json!({
                        "tenant": t,
                        "used_bytes": used,
                        "quota_bytes": quota,
                    })).collect::<Vec<_>>(),
                })
            );
        }
    }
    Ok(())
}

fn logs(data: &DataDir, attempt: &str, follow: bool) -> Result<(), Error> {
    use std::io::Write;
    let attempt: sentinel_core::AttemptId = attempt
        .parse()
        .map_err(|_| fail("expected an att_ attempt identifier"))?;
    let root = data.data_dir.join(sentinel_store::logs::LOGS_DIR);
    let dir = open(data, true).ok().and_then(|store| {
        store
            .read(|c| {
                let job = sentinel_store::lookup::attempt_job(c, attempt)?;
                let run = sentinel_store::lookup::job_run(c, job)?;
                Ok(root
                    .join(run.to_string())
                    .join(job.to_string())
                    .join(attempt.to_string()))
            })
            .ok()
    });
    let flat = root.join(format!("{attempt}.log"));
    let (mut stdout, mut stderr) = (std::io::stdout().lock(), std::io::stderr().lock());
    let mut after = 0u64;
    loop {
        let result = match &dir {
            Some(dir) => {
                sentinel_store::logs::read_dir(dir, after, 1024, None).or_else(|e| match e {
                    sentinel_store::Error::NotFound => {
                        sentinel_store::logs::read_tail(&flat, after, 1024, None)
                    }
                    e => Err(e),
                })
            }
            None => sentinel_store::logs::read_tail(&flat, after, 1024, None),
        };
        let tail = match result {
            Ok(tail) => tail,
            Err(sentinel_store::Error::NotFound) if follow => {
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            }
            Err(sentinel_store::Error::NotFound) => {
                return Err(fail("no log for that attempt on this controller"));
            }
            Err(error) => return Err(fail(format!("cannot read the log: {error}"))),
        };
        for frame in &tail.frames {
            let out: &mut dyn Write = match frame.stream {
                sentinel_protocol::logs::Stream::Stdout => &mut stdout,
                sentinel_protocol::logs::Stream::Stderr => &mut stderr,
            };
            match out.write_all(&frame.bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(error) => return Err(fail(format!("cannot write: {error}"))),
            }
            after = frame.seq;
        }
        stdout.flush().ok();
        stderr.flush().ok();
        if tail.complete {
            for (from, to) in &tail.gaps {
                eprintln!("[sentinel: frames {from}-{to} were lost on the worker]");
            }
            return Ok(());
        }
        if !follow {
            eprintln!("[sentinel: log incomplete; use --follow to wait for the rest]");
            return Ok(());
        }
        if tail.frames.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_need_a_unit_and_never_split_a_character() {
        assert_eq!(duration_ms("7d", 30 * DAY_MS).ok(), Some(7 * DAY_MS));
        assert_eq!(duration_ms("90s", DAY_MS).ok(), Some(90_000));
        for bad in ["30д", "é", "", "d", "0d", "1.5d"] {
            assert!(duration_ms(bad, 30 * DAY_MS).is_err(), "{bad}");
        }
    }
}
