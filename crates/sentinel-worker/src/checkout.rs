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
//! issues source access under the attempt's live lease (G01).

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::{Access, Credential as SourceCredential};

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

fn step(
    cmd: Command,
    deadline: Instant,
    what: &'static str,
    secrets: &[String],
) -> Result<process::Output> {
    let output = process::run(cmd, deadline, what)?;
    if output.success() {
        Ok(output)
    } else {
        // Git/SSH servers may reflect a credential in stderr. Take one bounded
        // line and strip anything this checkout installed as a secret.
        let mut excerpt = output.stderr_excerpt();
        for secret in secrets {
            excerpt = excerpt.replace(secret, "[redacted]");
        }
        Err(Error::Preparation(format!("{what} failed: {excerpt}")))
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
    checkout_inner(workspace, source, credential, None, timeout)
}

pub fn checkout_authorized(
    workspace: &Path,
    source: &PinnedSource,
    access: &Access,
    timeout: Duration,
) -> Result<Checkout> {
    if !access.validate(sentinel_core::UnixMillis::now().0)
        || source.repo != access.binding.remote
        || source
            .ref_name
            .as_ref()
            .is_some_and(|r| !access.binding.allows(r))
    {
        return Err(Error::Preparation("source access refused".into()));
    }
    checkout_inner(workspace, source, None, Some(access), timeout)
}

fn checkout_inner(
    workspace: &Path,
    source: &PinnedSource,
    credential: Option<&Credential>,
    access: Option<&Access>,
    timeout: Duration,
) -> Result<Checkout> {
    let deadline = Instant::now() + timeout;
    if source.repo.starts_with('-') {
        return Err(Error::Preparation("repository looks like an option".into()));
    }
    let mut init = git(workspace);
    init.args(["init", "-q", "--initial-branch=main", "."]);
    step(init, deadline, "git init", &[])?;

    let mut fetch = git(workspace);
    let private = access.map(|a| Private::install(workspace, a)).transpose()?;
    let secrets = private.as_ref().map(Private::secrets).unwrap_or_default();
    if let Some(private) = &private {
        private.configure(&mut fetch);
    }
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
    let fetched = step(fetch, deadline, "git fetch", &secrets);
    drop(askpass);
    drop(private);
    fetched?;

    let mut detach = git(workspace);
    detach.args(["checkout", "-q", "--detach", "FETCH_HEAD"]);
    step(detach, deadline, "git checkout", &[])?;

    let mut head = git(workspace);
    head.args(["rev-parse", "HEAD"]);
    let output = step(head, deadline, "git rev-parse", &[])?;
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if sha != source.sha {
        return Err(Error::Preparation(format!(
            "checkout produced {sha}, not the pinned revision"
        )));
    }
    Ok(Checkout { sha })
}

/// Checkout-only files are siblings of the workspace, never mounted in a job.
/// Mode is set at creation, including on every partial-failure path.
struct Private {
    dir: std::path::PathBuf,
    ssh: bool,
    ca: bool,
    username: Option<String>,
    secret: Option<String>,
}

impl Private {
    fn install(workspace: &Path, access: &Access) -> Result<Self> {
        let dir = workspace.with_extension("askpass");
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let mut private = Self {
            dir,
            ssh: false,
            ca: false,
            username: None,
            secret: None,
        };
        if !access.binding.trust.is_empty() {
            private.write("trust", access.binding.trust.as_bytes(), 0o600)?;
            private.ca = true;
        }
        match &access.credential {
            SourceCredential::Public => {}
            SourceCredential::Https { username, secret } => {
                private.write("askpass",b"#!/bin/sh\ncase \"$1\" in\nUsername*) printf '%s' \"$SENTINEL_GIT_USERNAME\";;\n*) printf '%s' \"$SENTINEL_GIT_SECRET\";;\nesac\n",0o700)?;
                private.username = Some(username.clone());
                private.secret = Some(secret.clone());
            }
            SourceCredential::Ssh { private_key } => {
                private.ssh = true;
                private.write("key", private_key.as_bytes(), 0o600)?;
                private.write("ssh", b"#!/bin/sh\nexec ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=\"$SENTINEL_GIT_TRUST\" -o UpdateHostKeys=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -i \"$SENTINEL_GIT_KEY\" \"$@\"\n",0o700)?;
            }
        }
        Ok(private)
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(self.dir.join(name))?
            .write_all(bytes)?;
        Ok(())
    }

    fn secrets(&self) -> Vec<String> {
        self.secret.iter().cloned().collect()
    }

    fn configure(&self, cmd: &mut Command) {
        cmd.args([
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-c",
            if self.ssh {
                "protocol.ssh.allow=always"
            } else {
                "protocol.https.allow=always"
            },
        ]);
        if self.ssh {
            cmd.env("GIT_SSH", self.dir.join("ssh"))
                .env("GIT_SSH_VARIANT", "ssh")
                .env("SENTINEL_GIT_TRUST", self.dir.join("trust"))
                .env("SENTINEL_GIT_KEY", self.dir.join("key"));
        } else {
            if self.ca {
                cmd.env("GIT_SSL_CAINFO", self.dir.join("trust"));
            }
            if let (Some(username), Some(secret)) = (&self.username, &self.secret) {
                cmd.env("GIT_ASKPASS", self.dir.join("askpass"))
                    .env("SENTINEL_GIT_USERNAME", username)
                    .env("SENTINEL_GIT_SECRET", secret);
            }
        }
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
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
