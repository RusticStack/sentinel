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

use sentinel_store::{
    Durability, METADATA_FILE, Store,
    local_auth::{self, Event},
};

use crate::cli::{AdminArgs, AdminCommand, DataDir};

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
    }
}
