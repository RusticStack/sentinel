//! Host-local administration of local login.
//!
//! Authority here is the operating system's: the command opens the controller's
//! database file directly, so only a user who already has that access can admit
//! the first super admin or recover a locked-out account. Nothing in this module
//! is reachable over the network, and the server process does not expose it.
//!
//! Passwords are read from standard input only. They never appear in argv, in
//! the process list, in shell history, in diagnostics or in an error message.

use std::io::{IsTerminal, Read};

use sentinel_core::{RepoId, TenantId, TokenId, UnixMillis, UserId, auth::Permissions};
use sentinel_store::{
    Durability, METADATA_FILE, Store,
    local_auth::{self, Event},
    lookup, sign_in,
    tokens::{self, Grant},
};

use crate::cli::{
    AdminArgs, AdminCommand, DataDir, IdentityArgs, IdentityCommand, TokenArgs, TokenCommand,
};

pub struct Error {
    pub message: String,
}

fn fail(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
    }
}

/// Read the password as raw bytes from standard input, dropping one trailing
/// newline so a piped file or heredoc works. Bytes are preserved otherwise: a
/// passphrase is not trimmed, normalized or re-encoded.
fn read_password() -> Result<Vec<u8>, Error> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(fail(
            "read the password from standard input, for example: sentinel admin bootstrap ... < secret-file",
        ));
    }
    let mut password = Vec::with_capacity(64);
    stdin.read_to_end(&mut password).map_err(|error| {
        fail(format!(
            "cannot read the password from standard input: {error}"
        ))
    })?;
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

/// Open the controller's database in its data directory. Reporting refuses to
/// create one: `status` against a mistyped path must say so, not answer about a
/// new empty database it just made.
fn open(data: &DataDir, reporting: bool) -> Result<Store, Error> {
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
    Store::open(&path, Durability::Full)
        .map_err(|error| fail(format!("cannot open {}: {error}", path.display())))
}

pub fn run(args: AdminArgs) -> Result<(), Error> {
    let now = sentinel_core::UnixMillis::now();
    match &args.command {
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
            println!("super admin {username} created as {user}");
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
            println!("password reset and sessions revoked for {user}");
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
            println!("bootstrap available: {available}");
            println!("active super admins: {admins}");
            println!("live sessions: {sessions}");
            for record in recent {
                let scope = if record.host_local {
                    "host-local"
                } else {
                    "remote"
                };
                println!(
                    "  {} {} {scope}{}",
                    record.at.0,
                    event_name(record.event),
                    record
                        .subject
                        .map(|id| format!(" subject={id}"))
                        .unwrap_or_default()
                );
            }
        }
        AdminCommand::Token(args) => token(args, now)?,
        AdminCommand::Identity(args) => identity(args, now)?,
    }
    Ok(())
}

/// Scope vocabulary for the host-local command. These names map onto the stored
/// permission bits; the OAuth scope vocabulary is a separate surface (A09) and
/// is not defined by this parser.
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

/// Whole units only (`30d`, `12h`, `90m`, `45s`). A lifetime is an operator
/// decision, so it is stated plainly rather than parsed loosely.
fn lifetime_ms(text: &str) -> Result<i64, Error> {
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    let scale = match unit {
        "d" => DAY_MS,
        "h" => 60 * 60 * 1000,
        "m" => 60 * 1000,
        "s" => 1000,
        _ => return Err(fail("lifetime must end in d, h, m or s, as in 30d")),
    };
    let value: i64 = digits
        .parse()
        .map_err(|_| fail("lifetime must be a whole number of units, as in 30d"))?;
    value
        .checked_mul(scale)
        .filter(|ms| (1..=tokens::MAX_LIFETIME_MS).contains(ms))
        .ok_or_else(|| {
            fail(format!(
                "lifetime must be between 1s and {}d",
                tokens::MAX_LIFETIME_MS / DAY_MS
            ))
        })
}

/// Resolve a `usr_` identifier or a local username. Host-local lookups read the
/// database directly: the operator already has that access, and there is no
/// session to authorize them with before any credential exists.
fn resolve_user(store: &Store, value: &str) -> Result<UserId, Error> {
    let unknown = || fail("no active account with that username or identifier");
    if let Ok(id) = value.parse::<UserId>() {
        return store
            .read(move |conn| lookup::active_user(conn, id))
            .map(|()| id)
            .map_err(|_| unknown());
    }
    let owned = value.to_owned();
    store
        .read(move |conn| lookup::user_by_username(conn, &owned))
        .map_err(|_| unknown())
}

/// Resolve the optional tenant/repository narrowing by their operator-facing
/// names. The store still refuses a repository outside the named tenant.
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
            // The secret is the only thing on stdout, so a redirect captures it
            // exactly; everything an operator reads goes to stderr.
            println!("{}", sentinel_auth::token::format(&granted.secret));
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
            // Host-local listing acts as the account itself, and metadata is all
            // that exists to read: no secret is recoverable from these rows.
            let principal =
                sentinel_core::auth::Principal::new(user, Permissions::NONE, None, None);
            let records = store
                .read(|conn| tokens::list(conn, principal, user, 100))
                .map_err(|error| fail(format!("cannot list credentials: {error}")))?;
            for record in records {
                println!(
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
    }
    Ok(())
}

/// Linking only ever happens through a verified provider sign-in, so there is
/// no host-local link command: an operator who could type a subject could sign
/// in as anybody. Removing a wrong link is the host-local repair path.
fn identity(args: &IdentityArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        IdentityCommand::List { data, user } => {
            let store = open(data, true)?;
            let user = resolve_user(&store, user)?;
            let principal =
                sentinel_core::auth::Principal::new(user, Permissions::NONE, None, None);
            let identities = store
                .read(|conn| sign_in::identities(conn, principal, user))
                .map_err(|error| fail(format!("cannot list identities: {error}")))?;
            for identity in identities {
                println!(
                    "{} subject={} linked={}",
                    identity.provider, identity.subject, identity.linked.0
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

const fn event_name(event: Event) -> &'static str {
    match event {
        Event::Bootstrap => "bootstrap",
        Event::LoginAccepted => "login-accepted",
        Event::LoginRejected => "login-rejected",
        Event::LoginLocked => "login-locked",
        Event::Logout => "logout",
        Event::LogoutAll => "logout-all",
        Event::PasswordChanged => "password-changed",
        Event::PasswordRecovered => "password-recovered",
        Event::SuperAdminGranted => "super-admin-granted",
        Event::SuperAdminRevoked => "super-admin-revoked",
        Event::AccountActivated => "account-activated",
        Event::AccountDeactivated => "account-deactivated",
        Event::TokenIssued => "token-issued",
        Event::TokenRevoked => "token-revoked",
        Event::IdentityLinked => "identity-linked",
        Event::IdentityUnlinked => "identity-unlinked",
    }
}
