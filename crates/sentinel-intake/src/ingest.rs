use sentinel_core::{DeliveryId, Labelled, RepoId, RunnerClass, UnixMillis};
use sentinel_protocol::intake::{RefUpdate, valid_delivery_id, valid_ref, valid_sha};
use sentinel_store::{Store, intake, runner};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unauthenticated,
    InvalidRequest(&'static str),
    NotFound,
    Forbidden(&'static str),
    Conflict,
    RateLimited,
    Internal,
}

impl From<sentinel_store::Error> for Error {
    fn from(error: sentinel_store::Error) -> Self {
        match error {
            sentinel_store::Error::NotFound => Self::NotFound,
            sentinel_store::Error::Forbidden => Self::Forbidden("source binding"),
            sentinel_store::Error::InvalidInput(what) => Self::InvalidRequest(what),
            sentinel_store::Error::Conflict => Self::Conflict,
            sentinel_store::Error::Overloaded
            | sentinel_store::Error::WriterUnavailable
            | sentinel_store::Error::WriteAmbiguous => Self::RateLimited,
            _ => Self::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ingested {
    pub id: DeliveryId,
    pub duplicate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Github {
    Pong,
    Ingested(Ingested),
    Controlled {
        outcome: String,
        duplicate: bool,
    },
    /// Acknowledged as accepted, not an error: GitHub must not retry it.
    Ignored(&'static str),
}

pub fn generic(
    store: &Store,
    presented: &str,
    repo: RepoId,
    body: &[u8],
    now: UnixMillis,
) -> Result<Ingested, Error> {
    // Authenticate before parsing: an unauthenticated caller must not reach the JSON validator.
    let secret = intake::hook_token_parse(presented).ok_or(Error::Unauthenticated)?;
    let target = store
        .read(|c| intake::authenticate(c, &secret))
        .map_err(Error::from)?;
    match target {
        Some((_, token_repo)) if token_repo == repo => {}
        // Unknown and cross-repository secrets get one indistinguishable refusal.
        _ => return Err(Error::Unauthenticated),
    }
    let update: RefUpdate =
        serde_json::from_slice(body).map_err(|_| Error::InvalidRequest("body"))?;
    update.validate().map_err(Error::InvalidRequest)?;
    accept(
        store,
        repo,
        intake::NewDelivery {
            authentication: intake::Authentication::HookToken,
            provider: "generic",
            external_id: &update.delivery_id,
            event: "ref_update",
            ref_name: &update.ref_name,
            old_sha: &update.old_sha,
            new_sha: &update.new_sha,
        },
        None,
        None,
        now,
    )
}

pub fn github(
    store: &Store,
    secret: &[u8],
    event: &str,
    delivery_id: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
    now: UnixMillis,
) -> Result<Github, Error> {
    let signature = signature.ok_or(Error::Unauthenticated)?;
    if !sentinel_github::webhook::verify_signature(secret, body, signature) {
        return Err(Error::Unauthenticated);
    }
    if event == "ping" {
        return Ok(Github::Pong);
    }
    let delivery_id = delivery_id.ok_or(Error::InvalidRequest("delivery header"))?;
    if !valid_delivery_id(delivery_id) {
        return Err(Error::InvalidRequest("delivery header"));
    }
    match event {
        "check_run"
        | "check_suite"
        | "installation"
        | "installation_repositories"
        | "repository"
        | "organization"
        | "membership"
        | "member"
        | "team" => return control(store, event, delivery_id, body, now),
        "push" => {}
        "pull_request" => return pull_request(store, delivery_id, body, now),
        "merge_group" => return merge_group(store, delivery_id, body, now),
        "workflow_job" => return workflow_job(store, delivery_id, body, now),
        _ => return Ok(Github::Ignored("unsupported_event")),
    }
    let push =
        sentinel_github::webhook::parse_push(body).map_err(|_| Error::InvalidRequest("payload"))?;
    if !valid_ref(&push.ref_name) {
        return Err(Error::InvalidRequest("payload ref"));
    }
    if !valid_sha(&push.before) || !valid_sha(&push.after) {
        return Err(Error::InvalidRequest("payload object id"));
    }
    let repository =
        i64::try_from(push.repository).map_err(|_| Error::InvalidRequest("payload"))?;
    let installation = push.installation.to_string();
    let target = match store.read(|c| intake::github_target(c, &installation, repository)) {
        Ok(target) => target,
        Err(sentinel_store::Error::NotFound) => {
            return Ok(Github::Ignored("unbound_repository"));
        }
        Err(e) => return Err(Error::from(e)),
    };
    accept(
        store,
        target.1,
        intake::NewDelivery {
            authentication: intake::Authentication::SignedWebhook,
            provider: "github",
            external_id: delivery_id,
            event: "push",
            ref_name: &push.ref_name,
            old_sha: &push.before,
            new_sha: &push.after,
        },
        None,
        None,
        now,
    )
    .map(Github::Ingested)
}

fn control(
    store: &Store,
    event: &str,
    delivery: &str,
    body: &[u8],
    now: UnixMillis,
) -> Result<Github, Error> {
    use sentinel_github::webhook::{self, Control as C};
    use sentinel_store::github_events::{self, Event as E};
    let Some(control) = webhook::parse_control(event, body)
        .map_err(|_| Error::InvalidRequest("control payload"))?
    else {
        return Ok(Github::Ignored("control_action"));
    };
    let control = match control {
        C::Rerequest {
            installation,
            repository,
            head,
            check,
            suite,
        } => E::Rerequest {
            installation,
            repository,
            head,
            check,
            suite,
        },
        C::Installation {
            installation,
            disable,
        } => E::Installation {
            installation,
            disable,
        },
        C::Repositories {
            installation,
            removed,
        } => E::Repositories {
            installation,
            removed,
        },
        C::Repository {
            installation,
            repository,
        } => E::Repository {
            installation,
            repository,
        },
        C::Members {
            installation,
            user,
            removed,
        } => E::Members {
            installation,
            user,
            removed,
        },
    };
    let digest = webhook::control_digest(event, body);
    let delivery = delivery.to_owned();
    let (outcome, duplicate) = store
        .writer()
        .write(move |tx| github_events::accept(tx, &delivery, &digest, &control, now))?;
    Ok(Github::Controlled { outcome, duplicate })
}
fn pull_request(
    store: &Store,
    delivery_id: &str,
    body: &[u8],
    now: UnixMillis,
) -> Result<Github, Error> {
    let pr = sentinel_github::webhook::parse_pull_request(body)
        .map_err(|_| Error::InvalidRequest("payload"))?;
    if !matches!(pr.action.as_str(), "opened" | "synchronize" | "reopened") {
        return Ok(Github::Ignored("pr_action"));
    }
    if !valid_sha(&pr.head_sha) || !valid_sha(&pr.base_sha) {
        return Err(Error::InvalidRequest("payload object id"));
    }
    if pr.merge_sha.as_deref().is_some_and(|s| !valid_sha(s)) {
        return Err(Error::InvalidRequest("payload object id"));
    }
    let repository = i64::try_from(pr.repository).map_err(|_| Error::InvalidRequest("payload"))?;
    let installation = pr.installation.to_string();
    let target = match store.read(|c| intake::github_target(c, &installation, repository)) {
        Ok(target) => target,
        Err(sentinel_store::Error::NotFound) => {
            return Ok(Github::Ignored("unbound_repository"));
        }
        Err(e) => return Err(Error::from(e)),
    };
    let base_ref = format!("refs/heads/{}", pr.base_ref);
    let terms = intake::PrTerms {
        number: pr.number,
        action: &pr.action,
        draft: pr.draft,
        head_ref: &pr.head_ref,
        head_sha: &pr.head_sha,
        head_repo: pr.head_repo,
        base_ref: &pr.base_ref,
        base_sha: &pr.base_sha,
        merge_sha: pr.merge_sha.as_deref(),
    };
    accept(
        store,
        target.1,
        intake::NewDelivery {
            authentication: intake::Authentication::SignedWebhook,
            provider: "github",
            external_id: delivery_id,
            event: "pull_request",
            ref_name: &base_ref,
            old_sha: &pr.base_sha,
            new_sha: pr.merge_sha.as_deref().unwrap_or(&pr.head_sha),
        },
        Some(terms),
        None,
        now,
    )
    .map(Github::Ingested)
}

/// A merge-queue group. Its checks are the base branch's required checks, so the
/// delivery is attributed to the base branch (ref name, policy and check
/// identity) while the queue branch and head commit are kept as its own terms;
/// `destroyed` is accepted too, because that action is what cancels the run.
fn merge_group(
    store: &Store,
    delivery_id: &str,
    body: &[u8],
    now: UnixMillis,
) -> Result<Github, Error> {
    let group = sentinel_github::webhook::parse_merge_group(body)
        .map_err(|_| Error::InvalidRequest("payload"))?;
    if !matches!(group.action.as_str(), "checks_requested" | "destroyed") {
        return Ok(Github::Ignored("merge_group_action"));
    }
    if !valid_sha(&group.head_sha) || !valid_sha(&group.base_sha) {
        return Err(Error::InvalidRequest("payload object id"));
    }
    if !valid_ref(&group.head_ref) || !group.head_ref.starts_with("refs/heads/") {
        return Err(Error::InvalidRequest("payload ref"));
    }
    // GitHub states the base branch as a full ref name here, where a pull request
    // states a short one; either form names the same branch.
    let base = group
        .base_ref
        .strip_prefix("refs/heads/")
        .unwrap_or(&group.base_ref);
    let base_ref = format!("refs/heads/{base}");
    if !valid_ref(&base_ref) || base.is_empty() || base.contains("refs/") {
        return Err(Error::InvalidRequest("payload ref"));
    }
    let repository =
        i64::try_from(group.repository).map_err(|_| Error::InvalidRequest("payload"))?;
    let installation = group.installation.to_string();
    let target = match store.read(|c| intake::github_target(c, &installation, repository)) {
        Ok(target) => target,
        Err(sentinel_store::Error::NotFound) => {
            return Ok(Github::Ignored("unbound_repository"));
        }
        Err(e) => return Err(Error::from(e)),
    };
    let terms = intake::MergeTerms {
        action: &group.action,
        head_ref: &group.head_ref,
        head_sha: &group.head_sha,
        base_ref: base,
        base_sha: &group.base_sha,
        head_repo: group.repository,
        reason: group.reason.as_deref(),
    };
    accept(
        store,
        target.1,
        intake::NewDelivery {
            authentication: intake::Authentication::SignedWebhook,
            provider: "github",
            external_id: delivery_id,
            event: "merge_group",
            ref_name: &base_ref,
            old_sha: &group.base_sha,
            new_sha: &group.head_sha,
        },
        None,
        Some(terms),
        now,
    )
    .map(Github::Ingested)
}

/// A GitHub-orchestrated job. Only a job whose `runs-on:` names one of Sentinel's labels is
/// ours at all: another runner's labels are acknowledged and never stored. The delivery is
/// stored with the job facts and resolved later, where the tenant's switch and the
/// installation's permissions decide whether Sentinel provisions it.
fn workflow_job(
    store: &Store,
    delivery_id: &str,
    body: &[u8],
    now: UnixMillis,
) -> Result<Github, Error> {
    let job = sentinel_github::webhook::parse_workflow_job(body)
        .map_err(|_| Error::InvalidRequest("payload"))?;
    if !runner::action_known(&job.action) {
        return Ok(Github::Ignored("runner_action"));
    }
    if matches!(
        RunnerClass::of_labels(job.labels.iter().map(String::as_str)),
        Labelled::None
    ) {
        return Ok(Github::Ignored("runner_label"));
    }
    let repository = i64::try_from(job.repository).map_err(|_| Error::InvalidRequest("payload"))?;
    let installation = job.installation.to_string();
    let target = match store.read(|c| intake::github_target(c, &installation, repository)) {
        Ok(target) => target,
        Err(sentinel_store::Error::NotFound) => {
            return Ok(Github::Ignored("unbound_repository"));
        }
        Err(e) => return Err(Error::from(e)),
    };
    accept_runner(store, target.1, delivery_id, &job, now).map(Github::Ingested)
}

fn accept_runner(
    store: &Store,
    repo: RepoId,
    delivery_id: &str,
    job: &sentinel_github::webhook::WorkflowJob,
    now: UnixMillis,
) -> Result<Ingested, Error> {
    let labels = job.labels.join(",");
    let delivery_id = delivery_id.to_owned();
    let action = job.action.clone();
    let runner_name = job.runner.clone();
    let conclusion = job.conclusion.clone();
    let (job_id, run_id) = (job.job, job.run);
    let accepted = store.writer().write(move |tx| {
        runner::accept(
            tx,
            repo,
            &runner::NewRunner {
                authentication: intake::Authentication::SignedWebhook,
                provider: "github",
                external_id: &delivery_id,
                action: &action,
                job: job_id,
                run: run_id,
                labels: &labels,
                runner: runner_name.as_deref(),
                conclusion: conclusion.as_deref(),
            },
            now,
        )
    })?;
    Ok(Ingested {
        id: accepted.id(),
        duplicate: accepted.duplicate(),
    })
}

fn accept(
    store: &Store,
    repo: RepoId,
    delivery: intake::NewDelivery<'_>,
    pr: Option<intake::PrTerms<'_>>,
    merge: Option<intake::MergeTerms<'_>>,
    now: UnixMillis,
) -> Result<Ingested, Error> {
    let delivery = OwnedDelivery {
        authentication: delivery.authentication,
        provider: delivery.provider.to_owned(),
        external_id: delivery.external_id.to_owned(),
        event: delivery.event.to_owned(),
        ref_name: delivery.ref_name.to_owned(),
        old_sha: delivery.old_sha.to_owned(),
        new_sha: delivery.new_sha.to_owned(),
    };
    let merge = merge.map(|merge| OwnedMerge {
        action: merge.action.to_owned(),
        head_ref: merge.head_ref.to_owned(),
        head_sha: merge.head_sha.to_owned(),
        base_ref: merge.base_ref.to_owned(),
        base_sha: merge.base_sha.to_owned(),
        head_repo: merge.head_repo,
        reason: merge.reason.map(str::to_owned),
    });
    let pr = pr.map(|pr| OwnedPr {
        number: pr.number,
        action: pr.action.to_owned(),
        draft: pr.draft,
        head_ref: pr.head_ref.to_owned(),
        head_sha: pr.head_sha.to_owned(),
        head_repo: pr.head_repo,
        base_ref: pr.base_ref.to_owned(),
        base_sha: pr.base_sha.to_owned(),
        merge_sha: pr.merge_sha.map(str::to_owned),
    });
    let accepted = store.writer().write(move |tx| {
        let merge_terms = merge.as_ref().map(|merge| intake::MergeTerms {
            action: &merge.action,
            head_ref: &merge.head_ref,
            head_sha: &merge.head_sha,
            base_ref: &merge.base_ref,
            base_sha: &merge.base_sha,
            head_repo: merge.head_repo,
            reason: merge.reason.as_deref(),
        });
        let terms = pr.as_ref().map(|pr| intake::PrTerms {
            number: pr.number,
            action: &pr.action,
            draft: pr.draft,
            head_ref: &pr.head_ref,
            head_sha: &pr.head_sha,
            head_repo: pr.head_repo,
            base_ref: &pr.base_ref,
            base_sha: &pr.base_sha,
            merge_sha: pr.merge_sha.as_deref(),
        });
        let delivery = intake::NewDelivery {
            authentication: delivery.authentication,
            provider: &delivery.provider,
            external_id: &delivery.external_id,
            event: &delivery.event,
            ref_name: &delivery.ref_name,
            old_sha: &delivery.old_sha,
            new_sha: &delivery.new_sha,
        };
        intake::accept_with_terms(
            tx,
            repo,
            &delivery,
            terms.as_ref(),
            merge_terms.as_ref(),
            now,
        )
    })?;
    Ok(Ingested {
        id: accepted.id(),
        duplicate: accepted.duplicate(),
    })
}

struct OwnedPr {
    number: u64,
    action: String,
    draft: bool,
    head_ref: String,
    head_sha: String,
    head_repo: u64,
    base_ref: String,
    base_sha: String,
    merge_sha: Option<String>,
}

struct OwnedMerge {
    action: String,
    head_ref: String,
    head_sha: String,
    base_ref: String,
    base_sha: String,
    head_repo: u64,
    reason: Option<String>,
}

struct OwnedDelivery {
    authentication: intake::Authentication,
    provider: String,
    external_id: String,
    event: String,
    ref_name: String,
    old_sha: String,
    new_sha: String,
}
