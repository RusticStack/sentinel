//! The two authenticated ingest paths, shared by the HTTP API and any future
//! transport. Both end in one store transaction: accept, or refuse explicitly.

use sentinel_core::{DeliveryId, RepoId, UnixMillis};
use sentinel_protocol::intake::{RefUpdate, valid_delivery_id, valid_ref, valid_sha};
use sentinel_store::{Store, intake};

/// Why an ingest was refused. Every variant maps to one HTTP status and never
/// echoes the body or a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing, malformed or unknown credential (hook secret or signature).
    Unauthenticated,
    /// The request is not the contract: malformed body or headers.
    InvalidRequest(&'static str),
    /// No such repository or delivery target for this credential.
    NotFound,
    /// The target exists but cannot accept events (revoked binding, ...).
    Forbidden(&'static str),
    /// The same delivery identity arrived with different content.
    Conflict,
    /// Admission bound reached: retry with back-off.
    RateLimited,
    /// Unexpected controller fault.
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

/// One accepted delivery: its record id and whether the identity was already
/// stored. A duplicate is an acknowledgement, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ingested {
    pub id: DeliveryId,
    pub duplicate: bool,
}

/// What a GitHub delivery produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Github {
    /// The App's webhook setup probe; nothing is stored.
    Pong,
    Ingested(Ingested),
    /// A valid delivery that cannot be a trigger here. Reported to GitHub as
    /// accepted — it must not retry — and recorded as a counter, not a row.
    Ignored(&'static str),
}

/// A generic relay submission: bearer-style hook secret over the raw body.
/// The secret is scoped to one repository, so presenting it for another is a
/// failed authentication rather than a forbidden repository.
pub fn generic(
    store: &Store,
    presented: &str,
    repo: RepoId,
    body: &[u8],
    now: UnixMillis,
) -> Result<Ingested, Error> {
    let update: RefUpdate =
        serde_json::from_slice(body).map_err(|_| Error::InvalidRequest("body"))?;
    update.validate().map_err(Error::InvalidRequest)?;
    let secret = intake::hook_token_parse(presented).ok_or(Error::Unauthenticated)?;
    let target = store
        .read(|c| intake::authenticate(c, &secret))
        .map_err(Error::from)?;
    match target {
        Some((_, token_repo)) if token_repo == repo => {}
        // Unknown secret, or a valid secret for another repository: one
        // indistinguishable refusal.
        _ => return Err(Error::Unauthenticated),
    }
    accept(
        store,
        repo,
        intake::NewDelivery {
            provider: "generic",
            external_id: &update.delivery_id,
            event: "ref_update",
            ref_name: &update.ref_name,
            old_sha: &update.old_sha,
            new_sha: &update.new_sha,
        },
        None,
        now,
    )
}

/// A GitHub webhook: the App webhook secret, the raw body, and the headers
/// that say what it is and which delivery it is.
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
        "push" => {}
        // Pull requests arrive only through a bound App installation, and only
        // the actions that mean "there is something new to test" are intake;
        // every other action is acknowledged and ignored so GitHub does not
        // retry it.
        "pull_request" => return pull_request(store, delivery_id, body, now),
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
        // A GitHub installation covers repositories this deployment has not
        // bound; that is a normal state, not a failure to report to GitHub.
        Err(sentinel_store::Error::NotFound) => {
            return Ok(Github::Ignored("unbound_repository"));
        }
        Err(e) => return Err(Error::from(e)),
    };
    accept(
        store,
        target.1,
        intake::NewDelivery {
            provider: "github",
            external_id: delivery_id,
            event: "push",
            ref_name: &push.ref_name,
            old_sha: &push.before,
            new_sha: &push.after,
        },
        None,
        now,
    )
    .map(Github::Ingested)
}
/// A pull request: known actions only, the base branch as the policy ref, the
/// tested merge (or the head tip when GitHub computed none) as the revision.
/// The head repository is stored, so a fork is a fact the resolver can refuse
/// explicitly rather than an inference.
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
            provider: "github",
            external_id: delivery_id,
            event: "pull_request",
            ref_name: &base_ref,
            old_sha: &pr.base_sha,
            new_sha: pr.merge_sha.as_deref().unwrap_or(&pr.head_sha),
        },
        Some(terms),
        now,
    )
    .map(Github::Ingested)
}

fn accept(
    store: &Store,
    repo: RepoId,
    delivery: intake::NewDelivery<'_>,
    pr: Option<intake::PrTerms<'_>>,
    now: UnixMillis,
) -> Result<Ingested, Error> {
    // Own the borrowed terms so the writer closure can be `'static`.
    let delivery = OwnedDelivery {
        provider: delivery.provider.to_owned(),
        external_id: delivery.external_id.to_owned(),
        event: delivery.event.to_owned(),
        ref_name: delivery.ref_name.to_owned(),
        old_sha: delivery.old_sha.to_owned(),
        new_sha: delivery.new_sha.to_owned(),
    };
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
        intake::accept(
            tx,
            repo,
            &intake::NewDelivery {
                provider: &delivery.provider,
                external_id: &delivery.external_id,
                event: &delivery.event,
                ref_name: &delivery.ref_name,
                old_sha: &delivery.old_sha,
                new_sha: &delivery.new_sha,
            },
            terms.as_ref(),
            now,
        )
    })?;
    Ok(Ingested {
        id: accepted.id(),
        duplicate: accepted.duplicate(),
    })
}

/// Owned pull-request terms for the writer closure.
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

struct OwnedDelivery {
    provider: String,
    external_id: String,
    event: String,
    ref_name: String,
    old_sha: String,
    new_sha: String,
}
