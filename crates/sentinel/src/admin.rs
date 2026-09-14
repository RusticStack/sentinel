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

use sentinel_core::{
    InvitationId, RepoId, SessionId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Permissions, Role},
};
use sentinel_store::{
    Durability, MASTER_KEY_FILE, METADATA_FILE, Store,
    local_auth::{self, Event},
    lookup, mfa,
    registration::{
        self, Authority, DeploymentPolicy, InstallationBinding, Registration, TenantCreation, Terms,
    },
    sign_in,
    tokens::{self, Grant},
};

use crate::cli::{
    AccountArgs, AccountCommand, AdminArgs, AdminCommand, DataDir, IdentityArgs, IdentityCommand,
    InviteArgs, InviteCommand, KeyArgs, KeyCommand, MfaArgs, MfaCommand, PolicyArgs, PolicyCommand,
    SessionArgs, SessionCommand, TokenArgs, TokenCommand,
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
        AdminCommand::Policy(args) => policy(args, now)?,
        AdminCommand::Invite(args) => invite(args, now)?,
        AdminCommand::Account(args) => account(args, now)?,
        AdminCommand::Key(args) => key(args)?,
        AdminCommand::Mfa(args) => second_factor(args, now)?,
        AdminCommand::Session(args) => session(args, now)?,
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
    let unknown = || fail("no account with that username or identifier");
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

fn policy(args: &PolicyArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        PolicyCommand::Show { data } => {
            let store = open(data, true)?;
            let policy = store
                .read(registration::policy)
                .map_err(|error| fail(format!("cannot read the policy: {error}")))?;
            println!("registration: {}", registration_name(policy.registration));
            println!(
                "tenant creation: {}",
                tenant_creation_name(policy.tenant_creation)
            );
            println!(
                "installation binding: {}",
                installation_binding_name(policy.installation_binding)
            );
        }
        PolicyCommand::Set {
            data,
            registration: wanted,
            tenant_creation,
            installation_binding,
        } => {
            let store = open(data, true)?;
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
                .write(move |tx| registration::set_policy(tx, Authority::HostLocal, policy, now))
                .map_err(|error| fail(format!("cannot change the policy: {error}")))?;
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

fn invite(args: &InviteArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        InviteCommand::Create {
            data,
            tenant,
            role: wanted,
            identity,
            expires_in,
        } => {
            let store = open(data, true)?;
            let lifetime_ms = lifetime_ms(expires_in)?;
            let (tenant, _) = resolve_target(&store, tenant.as_ref(), None)?;
            let wanted = wanted.as_deref().map(role).transpose()?;
            if tenant.is_some() != wanted.is_some() {
                return Err(fail("--tenant and --role are given together or not at all"));
            }
            // Owned, so the writer closure can borrow it for the whole write.
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
            // The secret alone on stdout, as with credentials: deliver the link
            // out of band. There is no way to show it again.
            println!("{}", sentinel_auth::token::format(&invitation.secret));
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
                println!(
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

fn account(args: &AccountArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
        AccountCommand::Pending { data } => {
            let store = open(data, true)?;
            let applications = store
                .read(|conn| registration::pending(conn, Authority::HostLocal, 100))
                .map_err(|error| fail(format!("cannot list applications: {error}")))?;
            for application in applications {
                println!(
                    "{} applied={} {}",
                    application.user, application.applied.0, application.display_name
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
    }
    Ok(())
}

fn key(args: &KeyArgs) -> Result<(), Error> {
    match &args.command {
        KeyCommand::Create { data, key_file } => {
            if !data.data_dir.is_absolute() {
                return Err(fail("data_dir must be an absolute path"));
            }
            let path = key_file
                .clone()
                .unwrap_or_else(|| data.data_dir.join(MASTER_KEY_FILE));
            sentinel_auth::sealed::Key::create(&path)
                .map_err(|error| fail(format!("cannot create the key: {error:?}")))?;
            eprintln!(
                "wrote {}; keep it out of database backups and losing it loses every sealed value",
                path.display()
            );
        }
    }
    Ok(())
}

/// Enrollment needs the person and their device, so it has no host-local form.
/// Removal does: it is the recovery path for a lost device, and is audited.
fn second_factor(args: &MfaArgs, now: UnixMillis) -> Result<(), Error> {
    match &args.command {
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
            println!("enrolled: {enrolled}");
            println!("recovery codes remaining: {remaining}");
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
                println!(
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
        Event::RegistrationAdmitted => "registration-admitted",
        Event::RegistrationPending => "registration-pending",
        Event::RegistrationRefused => "registration-refused",
        Event::AccountApproved => "account-approved",
        Event::AccountRejected => "account-rejected",
        Event::InvitationCreated => "invitation-created",
        Event::InvitationRedeemed => "invitation-redeemed",
        Event::InvitationRevoked => "invitation-revoked",
        Event::PolicyChanged => "policy-changed",
        Event::InstallationBound => "installation-bound",
        Event::InstallationUnbound => "installation-unbound",
        Event::MfaEnrolled => "mfa-enrolled",
        Event::MfaDisabled => "mfa-disabled",
        Event::SteppedUp => "stepped-up",
        Event::StepUpFailed => "step-up-failed",
        Event::RecoveryCodeUsed => "recovery-code-used",
        Event::RecoveryCodesIssued => "recovery-codes-issued",
        Event::SessionRevoked => "session-revoked",
    }
}
