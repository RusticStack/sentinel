//! Exact-revision checkout into a fresh workspace.
//!
//! The commit is what the run pinned, never a branch: `git fetch` asks for
//! the SHA itself (depth 1, no tags) and the result is verified with
//! `rev-parse` before anything runs. Nothing from the host's Git
//! configuration is consulted (`GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_CONFIG_NOSYSTEM=1`) and Git can never prompt.
//!
//! Credentials, when there are any, reach Git through `GIT_ASKPASS` — an
//! owner-only helper that prints a value taken from the helper's own
//! environment — so a token never appears in a URL, in the repository's
//! configuration, in the job's environment or in a log line. The controller
//! does not issue checkout tokens yet (GitHub App installations are G-tasks);
//! the mechanism is here so that day changes one call site.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_pipeline::PinnedSource;

use crate::{Error, Result, process};

/// A whole checkout — every Git invocation together — must finish in this.
pub const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Short-lived, repository-scoped credential for the fetch.
pub struct Credential {
    pub username: String,
    pub secret: String,
}

/// What was checked out: the verified revision.
#[derive(Debug, PartialEq, Eq)]
pub struct Checkout {
    pub sha: String,
}

fn git(workspace: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .current_dir(workspace);
    cmd
}

fn step(cmd: Command, deadline: Instant, what: &'static str) -> Result<process::Output> {
    let output = process::run(cmd, deadline, what)?;
    if output.success() {
        Ok(output)
    } else {
        Err(Error::Preparation(format!(
            "{what}: {}",
            output.stderr_excerpt()
        )))
    }
}

/// Check out `source.sha` from `source.repo` into `workspace` (which must be
/// empty), within `timeout`. `credential` is presented through the askpass
/// helper for the fetch only.
pub fn checkout(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    timeout: Duration,
) -> Result<Checkout> {
    let deadline = Instant::now() + timeout;
    if source.repo.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut init = git(workspace);
    init.args(["init", "-q", "--initial-branch=main", "."]);
    step(init, deadline, "git init")?;

    let mut fetch = git(workspace);
    fetch.args([
        "fetch",
        "-q",
        "--no-tags",
        "--depth",
        "1",
        "--",
        &source.repo,
        &source.sha,
    ]);
    let askpass = match credential {
        Some(credential) => Some(Askpass::install(workspace, credential)?),
        None => None,
    };
    if let Some(askpass) = &askpass {
        fetch
            .env("GIT_ASKPASS", &askpass.path)
            .env("SENTINEL_GIT_USERNAME", &askpass.username)
            .env("SENTINEL_GIT_SECRET", &askpass.secret);
    }
    let fetched = step(fetch, deadline, "git fetch");
    drop(askpass);
    fetched?;

    let mut detach = git(workspace);
    detach.args(["checkout", "-q", "--detach", "FETCH_HEAD"]);
    step(detach, deadline, "git checkout")?;

    let mut head = git(workspace);
    head.args(["rev-parse", "HEAD"]);
    let output = step(head, deadline, "git rev-parse")?;
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if sha != source.sha {
        return Err(Error::Preparation(format!(
            "checkout produced {sha}, not the pinned revision"
        )));
    }
    Ok(Checkout { sha })
}

/// The askpass helper: an owner-only script beside the workspace that
/// answers Git's username/password prompts from its own environment and is
/// removed as soon as the fetch has finished.
struct Askpass {
    path: std::path::PathBuf,
    username: String,
    secret: String,
}

impl Askpass {
    fn install(workspace: &Path, credential: &Credential) -> Result<Askpass> {
        let dir = workspace.with_extension("askpass");
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join("askpass.sh");
        fs::write(
            &path,
            "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s' \"$SENTINEL_GIT_USERNAME\" ;;\n  *) printf '%s' \"$SENTINEL_GIT_SECRET\" ;;\nesac\n",
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Askpass {
            path,
            username: credential.username.clone(),
            secret: credential.secret.clone(),
        })
    }
}

impl Drop for Askpass {
    fn drop(&mut self) {
        if let Some(dir) = self.path.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}
