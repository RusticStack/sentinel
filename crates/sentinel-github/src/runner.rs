//! Runner mode's GitHub calls (AR02): the just-in-time configuration of one ephemeral runner, the
//! removal of the registration it made, and the queue a reconciliation pass reads when a delivery
//! never arrived.
//!
//! The encoded configuration is a credential GitHub issues for one runner and one job. It leaves
//! here as bytes the caller seals before anything durable sees it, and nothing in this module
//! writes it, logs it or puts it in an error.

use serde_json::json;

use crate::{
    Error, Result,
    app::{App, Token},
};

/// Where a tenant's runners are registered: the organization that owns the installation, or — for a
/// personal namespace, which has no organization — the repository itself. Which one applies is the
/// installation's account kind, decided once and stored beside the installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope<'a> {
    Organization(&'a str),
    Repository { owner: &'a str, repo: &'a str },
}

impl Scope<'_> {
    /// The API path below `/actions/runners`.
    fn path(&self) -> String {
        match self {
            Self::Organization(org) => format!("/orgs/{org}"),
            Self::Repository { owner, repo } => format!("/repos/{owner}/{repo}"),
        }
    }
}

/// The permission an installation token needs to register a runner of this scope: personal
/// namespaces ask for repository administration write, organizations for their self-hosted runners.
pub const fn scope_permission(scope: &Scope<'_>) -> (&'static str, &'static str) {
    match scope {
        Scope::Organization(_) => ("organization_self_hosted_runners", "write"),
        Scope::Repository { .. } => ("administration", "write"),
    }
}

/// A runner registered at GitHub for one job: its id (what removal names) and the configuration the
/// runner application starts with. The bytes are the caller's to seal and wipe; nothing here keeps
/// them.
pub struct JitConfig {
    pub runner_id: u64,
    pub encoded: Vec<u8>,
}

impl std::fmt::Debug for JitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JitConfig")
            .field("runner_id", &self.runner_id)
            .field("encoded", &"<redacted>")
            .finish()
    }
}

/// A queued job GitHub states, read by the reconciliation pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub job: u64,
    pub run: u64,
    pub labels: Vec<String>,
}

/// The largest encoded configuration this module accepts. GitHub's is a few kilobytes; the bound
/// stops a broken answer from becoming a frame or a row nobody could hold.
pub const MAX_JIT_BYTES: usize = 65_536;

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A login or repository name as GitHub spells it, refused when it could change the path.
fn valid_path_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 100
        && part != "."
        && part != ".."
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Labels a runner registers with: the class it serves, and nothing else. A job whose `runs-on:`
/// names that label matches it; a label Sentinel does not define is never sent.
fn labels_for(labels: &[String]) -> Result<Vec<&str>> {
    if labels.is_empty() || labels.len() > 8 {
        return Err(Error::Config("runner labels"));
    }
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        if label.is_empty()
            || label.len() > 64
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(Error::Config("runner label"));
        }
        out.push(label.as_str());
    }
    Ok(out)
}

impl App {
    /// An installation token that may register a runner of `scope` for one repository. A repository
    /// scope also verifies the repository is still the one the binding names, exactly as the source
    /// and checks tokens do; an organization scope cannot verify a repository it is not scoped to.
    pub fn runner_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        scope: &Scope<'_>,
        now_ms: i64,
    ) -> Result<Token> {
        match scope {
            Scope::Repository { .. } => self.repository_token(
                installation,
                account,
                repo,
                remote,
                now_ms,
                &[scope_permission(scope)],
            ),
            Scope::Organization(_) => self.scoped_token(
                installation,
                account,
                None,
                now_ms,
                &[scope_permission(scope)],
            ),
        }
    }

    /// Register one ephemeral runner and return the configuration it starts with. GitHub answers
    /// the runner object and the encoded configuration in one body.
    pub fn generate_jitconfig(
        &self,
        token: &Token,
        scope: &Scope<'_>,
        name: &str,
        group: u64,
        labels: &[String],
    ) -> Result<JitConfig> {
        if !valid_name(name) {
            return Err(Error::Config("runner name"));
        }
        let labels = labels_for(labels)?;
        let mut body = json!({"name": name, "labels": labels});
        // An organization's runners live in a runner group; a repository's have none.
        if matches!(scope, Scope::Organization(_)) {
            if group == 0 {
                return Err(Error::Config("runner group"));
            }
            body["runner_group_id"] = json!(group);
        }
        let reply = self.http.send_json(
            "POST",
            &format!(
                "{}{}/actions/runners/generate-jitconfig",
                self.endpoint,
                scope.path()
            ),
            &token.secret,
            Some(&body),
        )?;
        match reply.status {
            201 | 200 => {
                let runner_id = reply.body["runner"]["id"]
                    .as_u64()
                    .filter(|id| *id > 0)
                    .ok_or(Error::Response("runner id"))?;
                let encoded = reply.body["encoded_jit_config"]
                    .as_str()
                    .filter(|text| !text.is_empty() && text.len() <= MAX_JIT_BYTES)
                    .ok_or(Error::Response("runner configuration"))?;
                Ok(JitConfig {
                    runner_id,
                    encoded: encoded.as_bytes().to_vec(),
                })
            }
            403 | 404 => Err(Error::Response("runner registration refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// Remove a registration. `Ok(false)` when GitHub no longer has it, which is the state we
    /// wanted: an ephemeral runner de-registers itself when its job ends.
    pub fn remove_runner(&self, token: &Token, scope: &Scope<'_>, runner_id: u64) -> Result<bool> {
        if runner_id == 0 {
            return Err(Error::Config("runner id"));
        }
        let reply = self.http.send_json(
            "DELETE",
            &format!(
                "{}{}/actions/runners/{runner_id}",
                self.endpoint,
                scope.path()
            ),
            &token.secret,
            None,
        )?;
        match reply.status {
            204 | 200 => Ok(true),
            404 => Ok(false),
            403 => Err(Error::Response("runner removal refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// The queued jobs of one repository, at most `runs` runs and `per_run` jobs of each: what a
    /// reconciliation pass compares with the jobs its deliveries announced.
    pub fn queued_jobs(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        runs: usize,
        per_run: usize,
    ) -> Result<Vec<QueuedJob>> {
        if !valid_path_part(owner) || !valid_path_part(repo) {
            return Err(Error::Config("repository"));
        }
        let runs = runs.clamp(1, 20);
        let per_run = per_run.clamp(1, 100);
        let listing = self.http.send_json(
            "GET",
            &format!(
                "{}/repos/{owner}/{repo}/actions/runs?status=queued&per_page={runs}",
                self.endpoint
            ),
            &token.secret,
            None,
        )?;
        if listing.status != 200 {
            return Err(Error::Transport(format!("status {}", listing.status)));
        }
        let mut out = Vec::new();
        for run in listing.body["workflow_runs"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(run_id) = run["id"].as_u64().filter(|id| *id > 0) else {
                continue;
            };
            let jobs = self.http.send_json(
                "GET",
                &format!(
                    "{}/repos/{owner}/{repo}/actions/runs/{run_id}/jobs?filter=queued&per_page={per_run}",
                    self.endpoint
                ),
                &token.secret,
                None,
            )?;
            if jobs.status != 200 {
                return Err(Error::Transport(format!("status {}", jobs.status)));
            }
            for job in jobs.body["jobs"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let Some(job_id) = job["id"].as_u64().filter(|id| *id > 0) else {
                    continue;
                };
                let labels: Vec<String> = job["labels"]
                    .as_array()
                    .map(|list| {
                        list.iter()
                            .filter_map(|l| l.as_str())
                            .filter(|l| l.len() <= 64 && !l.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(QueuedJob {
                    job: job_id,
                    run: job["run_id"]
                        .as_u64()
                        .filter(|id| *id > 0)
                        .unwrap_or(run_id),
                    labels,
                });
            }
        }
        Ok(out)
    }
}
