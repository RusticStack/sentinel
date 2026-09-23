//! Dispatch resolution: a ready delivery becomes one immutable run, or an
//! explicit outcome (G03).
//!
//! Everything remote happens here, never inside a writer transaction: the
//! source access is minted, the pipeline file is read from the
//! policy-selected revision through Git, the compiled pipeline is asked
//! whether it admits the event, and only then does one short transaction
//! create the run, its jobs, its image pins, its provenance and the
//! delivery's terminal state. A transient failure (a fetch, a GitHub outage)
//! retries under the same attempt budget G02 uses; a permanent one settles
//! with a short reason an operator can read.
//!
//! Trust is decided before any of that: a pull request whose head lives in
//! another repository is refused (`fork_pr`) because Git refs alone do not
//! prove fork trust, and a delivery only ever fetches through its own bound
//! remote and credential.

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{RunId, UnixMillis};
use sentinel_github::app::App;
use sentinel_pipeline::{Event, EventKind, PinnedSource, RunSpec};
use sentinel_store::{
    Error as StoreError, Store,
    intake::{self, Delivery, PrDelivery},
    provenance::Provenance,
    runs,
};

use crate::source;

/// Bounds for one resolution. The Git budget covers every Git invocation of
/// the fetch together; the pipeline read is capped before it is read.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub budget: Duration,
    pub max_pipeline_bytes: usize,
    /// How many generations behind the newest dispatched tip an out-of-order
    /// push is still recognised as stale. Only commits are fetched for it.
    pub ancestry_depth: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(120),
            max_pipeline_bytes: sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES,
            ancestry_depth: 1024,
        }
    }
}

/// What resolving one delivery decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Dispatched {
        run: RunId,
    },
    Ignored(&'static str),
    Failed {
        reason: &'static str,
        detail: Option<String>,
    },
    /// A transient fault: the delivery stays open and is retried later.
    Retried {
        reason: &'static str,
        detail: Option<String>,
    },
    /// Nothing was settled: the delivery changed under us.
    Skipped,
}

impl Outcome {
    /// One bounded line for logs and for the delivery's outcome.
    pub fn describe(&self) -> String {
        match self {
            Self::Dispatched { run } => format!("dispatched:{run}"),
            Self::Ignored(reason) => format!("ignored:{reason}"),
            Self::Failed { reason, .. } => format!("failed:{reason}"),
            Self::Retried { reason, .. } => format!("retried:{reason}"),
            Self::Skipped => "skipped".into(),
        }
    }
}

/// One bounded file-at-revision read: `work` is an empty scratch directory the
/// caller owns and removes, and `max_bytes`/`budget` are hard limits.
pub struct FileRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    pub sha: &'a str,
    pub path: &'a str,
    pub max_bytes: usize,
    pub budget: Duration,
}

/// One bounded merge-ref read (pull requests): the forge's tested-merge ref is
/// resolved live, and the commit it names must list `head` among its parents.
/// A payload's claimed merge can be stale — GitHub computes the merge
/// asynchronously — so the ref and its parents are the authority.
pub struct MergeRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    /// The merge ref, e.g. `refs/pull/7/merge`.
    pub merge_ref: &'a str,
    /// The delivered pull-request head the merge must name as a parent.
    pub head: &'a str,
    pub path: &'a str,
    pub max_bytes: usize,
    pub budget: Duration,
}

/// One bounded ancestry question (the reordered-push rule): is `ancestor` in
/// the history of `tip`, at most `depth` generations back?
pub struct AncestryRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    pub ancestor: &'a str,
    pub tip: &'a str,
    pub depth: u32,
    pub budget: Duration,
}

/// Where the pipeline file comes from. Production uses bounded Git
/// ([`GitFetch`]); a test can supply a fake because a GitHub-App-bound remote
/// is not reachable offline.
pub trait Fetch: Send + Sync {
    fn file_at(
        &self,
        request: FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error>;
    fn merge_at(
        &self,
        request: MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error>;
    /// `Ok(false)` means "not proven" — the push is then treated as new.
    fn is_ancestor(&self, request: AncestryRequest<'_>) -> Result<bool, sentinel_git::Error>;
}

/// The production fetcher: `sentinel-git`'s bounded file-at-revision reads.
pub struct GitFetch;

impl Fetch for GitFetch {
    fn file_at(
        &self,
        request: FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        sentinel_git::file_at(
            request.work,
            request.remote,
            request.access,
            request.sha,
            request.path,
            request.max_bytes,
            request.budget,
        )
    }

    fn merge_at(
        &self,
        request: MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        sentinel_git::file_at_merge(
            request.work,
            request.remote,
            request.access,
            sentinel_git::Merge {
                r#ref: request.merge_ref,
                head: request.head,
            },
            request.path,
            request.max_bytes,
            request.budget,
        )
    }

    fn is_ancestor(&self, request: AncestryRequest<'_>) -> Result<bool, sentinel_git::Error> {
        sentinel_git::is_ancestor(
            request.work,
            request.remote,
            request.access,
            request.ancestor,
            request.tip,
            request.depth,
            request.budget,
        )
    }
}

pub struct Resolver {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Option<Arc<App>>,
    /// The deployment's approved source authorities, rechecked on every
    /// resolution: a narrowed policy stops fetches, not just new bindings.
    destinations: Arc<[String]>,
    fetch: Arc<dyn Fetch>,
    work_root: PathBuf,
    config: Config,
}

impl Resolver {
    /// Prepare a resolver whose scratch space is `work_root`. Anything a
    /// previous process left there is discarded: a half-fetched repository is
    /// never reused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store>,
        key: Option<Arc<Key>>,
        app: Option<Arc<App>>,
        destinations: Arc<[String]>,
        fetch: Arc<dyn Fetch>,
        work_root: PathBuf,
        config: Config,
    ) -> std::io::Result<Resolver> {
        fs::create_dir_all(&work_root)?;
        if let Ok(entries) = fs::read_dir(&work_root) {
            for entry in entries.flatten() {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        Ok(Resolver {
            store,
            key,
            app,
            destinations,
            fetch,
            work_root,
            config,
        })
    }

    /// Resolve one ready delivery. Bounded, idempotent and safe to retry: the
    /// run is created only while the delivery is still ready.
    pub fn resolve(&self, delivery: &Delivery, now: UnixMillis) -> Result<Outcome, StoreError> {
        if delivery.state != intake::State::Ready {
            return Ok(Outcome::Skipped);
        }
        // What the binding authorizes right now. A binding that authorizes
        // nothing settles this delivery with its reason; it never fails the
        // lane's pass for everybody else.
        let binding = match source::classify(&self.store, delivery.repo)? {
            source::Lookup::Bound(binding) => binding,
            source::Lookup::Unbound => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "binding_revoked",
                        detail: None,
                    },
                    now,
                );
            }
            source::Lookup::Unusable(reason) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason,
                        detail: None,
                    },
                    now,
                );
            }
        };
        // The deployment's egress policy, as it is now.
        if !source::destination_allowed(&self.destinations, &binding.metadata.binding.remote) {
            return self.settle(
                delivery,
                Outcome::Failed {
                    reason: "destination_refused",
                    detail: None,
                },
                now,
            );
        }

        // What event this is, which ref the policy is judged against, and
        // which revision the pipeline is read from.
        let pr: Option<PrDelivery> = self.store.read(|c| intake::pr_for(c, delivery.id))?;
        let plan = match self.plan(delivery, pr.as_ref(), &binding) {
            Ok(plan) => plan,
            Err(outcome) => return self.settle(delivery, outcome, now),
        };

        // Duplicate and reordered events, judged against the newest
        // dispatched transition of the same stream (see `order`).
        let stream = plan.policy_ref.clone();
        let is_pr = plan.kind == EventKind::PullRequest;
        let (tenant, repo) = (delivery.tenant, delivery.repo);
        let previous = self
            .store
            .read(move |c| intake::last_dispatched(c, tenant, repo, &stream, is_pr))?;
        let prove_stale = match order(delivery, previous.as_ref(), plan.kind) {
            Order::Settle(outcome) => return self.settle(delivery, outcome, now),
            Order::New => None,
            Order::Prove { tip } => Some(tip),
        };

        // The only network step: mint the access (sealed credential, or App
        // token with a lifecycle recheck).
        let access = match source::issue(
            &self.store,
            self.key.as_deref(),
            self.app.as_ref(),
            &binding,
            now,
        ) {
            Ok(access) => access,
            Err(source::Error::Refused(why)) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: why,
                        detail: None,
                    },
                    now,
                );
            }
            Err(source::Error::Unavailable(why)) => {
                return self.retry(
                    delivery,
                    why,
                    None,
                    intake::Resolution::Failed("resolution_attempts"),
                    now,
                );
            }
        };

        // An out-of-order push: the newest dispatched tip may already contain
        // this revision, in which case the repository moved past it and a
        // run for it would test (and, under `cancel_in_progress`, cancel the
        // tip's run in favour of) an older commit. Only commits are fetched.
        if let (Some(tip), Some(new_sha)) = (prove_stale, delivery.new_sha.as_deref()) {
            let work = self.work_root.join(format!("{}-ancestry", delivery.id));
            let _scratch = Scratch(work.clone());
            fs::create_dir(&work)?;
            match self.fetch.is_ancestor(AncestryRequest {
                work: &work,
                remote: &binding.metadata.binding.remote,
                access: Some(&access),
                ancestor: new_sha,
                tip: &tip,
                depth: self.config.ancestry_depth,
                budget: self.config.budget,
            }) {
                Ok(true) => return self.settle(delivery, Outcome::Ignored("superseded"), now),
                Ok(false) => {}
                Err(sentinel_git::Error::UnsupportedPlatform) => {
                    return self.settle(
                        delivery,
                        Outcome::Failed {
                            reason: "source_unavailable",
                            detail: None,
                        },
                        now,
                    );
                }
                Err(e) => {
                    return self.retry(
                        delivery,
                        "source_unreachable",
                        Some(e.to_string()),
                        intake::Resolution::Failed("resolution_attempts"),
                        now,
                    );
                }
            }
        }

        // The pipeline file, read from the policy-selected revision; a tag
        // object is peeled to its commit. A pull request reads it at the
        // forge's *verified* tested merge: the payload's `merge_commit_sha`
        // can name a merge computed for an older head, so the merge ref and
        // its parents are the authority. A merge the forge has not recomputed
        // yet is retried, then settles `merge_unavailable`.
        let work = self.work_root.join(delivery.id.to_string());
        let _scratch = Scratch(work.clone());
        fs::create_dir(&work)?;
        let fetched = match &plan.source {
            Revision::Commit(sha) => self.fetch.file_at(FileRequest {
                work: &work,
                remote: &binding.metadata.binding.remote,
                access: Some(&access),
                sha,
                path: &binding.metadata.binding.pipeline_path,
                max_bytes: self.config.max_pipeline_bytes,
                budget: self.config.budget,
            }),
            Revision::Merge { merge_ref, head } => match self.fetch.merge_at(MergeRequest {
                work: &work,
                remote: &binding.metadata.binding.remote,
                access: Some(&access),
                merge_ref,
                head,
                path: &binding.metadata.binding.pipeline_path,
                max_bytes: self.config.max_pipeline_bytes,
                budget: self.config.budget,
            }) {
                Err(sentinel_git::Error::Merge) => {
                    return self.retry(
                        delivery,
                        "merge_pending",
                        None,
                        intake::Resolution::Ignored("merge_unavailable"),
                        now,
                    );
                }
                other => other,
            },
        };
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(sentinel_git::Error::Missing) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "no_pipeline",
                        detail: None,
                    },
                    now,
                );
            }
            Err(sentinel_git::Error::TooLarge(_)) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "pipeline_too_large",
                        detail: None,
                    },
                    now,
                );
            }
            Err(sentinel_git::Error::UnsupportedPlatform) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "source_unavailable",
                        detail: None,
                    },
                    now,
                );
            }
            Err(e) => {
                return self.retry(
                    delivery,
                    "source_unreachable",
                    Some(e.to_string()),
                    intake::Resolution::Failed("resolution_attempts"),
                    now,
                );
            }
        };

        // Compile and ask the policy: the pipeline decides which events run it.
        let Ok(text) = String::from_utf8(fetched.bytes) else {
            return self.settle(
                delivery,
                Outcome::Failed {
                    reason: "pipeline_invalid",
                    detail: None,
                },
                now,
            );
        };
        let compiled = match sentinel_pipeline::compile_str(&text) {
            Ok(compiled) => compiled,
            Err(e) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "pipeline_invalid",
                        detail: Some(e.to_string().chars().take(200).collect()),
                    },
                    now,
                );
            }
        };
        if !compiled.on.admits(&plan.event()) {
            return self.settle(delivery, Outcome::Ignored("no_trigger"), now);
        }

        // The immutable spec: the checked-out revision is the peeled event
        // commit (or the tested merge), which may differ from the revision
        // the pipeline was read at.
        let source = match PinnedSource::new(
            &binding.metadata.binding.remote,
            &fetched.commit,
            Some(&plan.checkout_ref),
        ) {
            Ok(source) => source,
            Err(_) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "pipeline_invalid",
                        detail: None,
                    },
                    now,
                );
            }
        };
        let spec = match RunSpec::new(source, compiled) {
            Ok(spec) => spec,
            Err(_) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "pipeline_invalid",
                        detail: None,
                    },
                    now,
                );
            }
        };
        let images = match runs::pinned_images(&spec) {
            Ok(images) => images,
            Err(_) => {
                return self.settle(
                    delivery,
                    Outcome::Failed {
                        reason: "image_unpinned",
                        detail: None,
                    },
                    now,
                );
            }
        };

        // One short transaction: the run, its jobs, its image pins, its
        // provenance and the delivery's terminal state. The pipeline revision
        // recorded is the peeled commit the file was actually read at.
        let provenance = plan.provenance(delivery, &binding, &spec, &fetched.commit);
        let dispatched = delivery.clone();
        let run =
            match self.store.writer().write(move |tx| {
                intake::dispatch(tx, &dispatched, &spec, &images, &provenance, now)
            }) {
                Ok(run) => run,
                Err(StoreError::Conflict) => return Ok(Outcome::Skipped),
                Err(e) => return Err(e),
            };
        Ok(Outcome::Dispatched { run })
    }

    /// Decide what the delivery means, before any remote work. This is where
    /// trust is decided: only the bound remote is fetched, and a pull request
    /// whose head lives elsewhere is refused rather than guessed at.
    fn plan(
        &self,
        delivery: &Delivery,
        pr: Option<&PrDelivery>,
        binding: &source::Binding,
    ) -> Result<Plan, Outcome> {
        let (Some(ref_name), Some(new_sha)) = (&delivery.ref_name, &delivery.new_sha) else {
            return Err(Outcome::Ignored("no_ref"));
        };
        if sentinel_protocol::intake::is_zero_sha(new_sha) {
            return Err(Outcome::Ignored("ref_deleted"));
        }
        match delivery.event.as_str() {
            "push" | "ref_update" => {
                let kind = if ref_name.starts_with("refs/tags/") {
                    EventKind::Tag
                } else {
                    EventKind::Push
                };
                Ok(Plan {
                    kind,
                    policy_ref: ref_name.clone(),
                    source: Revision::Commit(new_sha.clone()),
                    checkout_ref: ref_name.clone(),
                    head_sha: None,
                    base_sha: None,
                    pr_number: None,
                })
            }
            "pull_request" => {
                let Some(pr) = pr else {
                    return Err(Outcome::Failed {
                        reason: "pr_metadata",
                        detail: None,
                    });
                };
                // Fork trust: v1 runs only a head that lives in the bound
                // repository. Hostile fork execution is a later feature, not
                // an implicit default.
                let Some(bound_repo) = binding.forge.as_ref().map(|f| f.repo) else {
                    // A pull request without an App association is an internal
                    // inconsistency: only the adapter can prove PR metadata.
                    return Err(Outcome::Failed {
                        reason: "no_forge_association",
                        detail: None,
                    });
                };
                if pr.head_repo != bound_repo {
                    return Err(Outcome::Ignored("fork_pr"));
                }
                // The tested merge is resolved from the live merge ref, not
                // the payload's `merge_commit_sha`: GitHub computes it
                // asynchronously, so the payload value can be absent (opened)
                // or name a merge computed for an older head.
                Ok(Plan {
                    kind: EventKind::PullRequest,
                    policy_ref: format!("refs/heads/{}", pr.base_ref),
                    source: Revision::Merge {
                        merge_ref: format!("refs/pull/{}/merge", pr.number),
                        head: pr.head_sha.clone(),
                    },
                    // The spec names the ref the run is accountable to: the
                    // authorized base. The head branch is provenance only —
                    // allowing it would mean approving every feature branch.
                    checkout_ref: format!("refs/heads/{}", pr.base_ref),
                    head_sha: Some(pr.head_sha.clone()),
                    base_sha: Some(pr.base_sha.clone()),
                    pr_number: Some(pr.number),
                })
            }
            _ => Err(Outcome::Failed {
                reason: "unsupported_event",
                detail: Some(delivery.event.clone()),
            }),
        }
    }

    /// Persist a terminal outcome. A delivery that changed under us is
    /// skipped, not overwritten.
    fn settle(
        &self,
        delivery: &Delivery,
        outcome: Outcome,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let resolution = match &outcome {
            Outcome::Ignored(reason) => intake::Resolution::Ignored(reason),
            Outcome::Failed { reason, .. } => intake::Resolution::Failed(reason),
            // The rest never come through here.
            Outcome::Dispatched { .. } | Outcome::Retried { .. } | Outcome::Skipped => {
                return Ok(outcome);
            }
        };
        let id = delivery.id;
        match self
            .store
            .writer()
            .write(move |tx| intake::settle(tx, id, resolution, now))
        {
            Ok(()) => Ok(outcome),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }

    /// Schedule another attempt under the shared budget; the last attempt
    /// settles the delivery with `exhausted`.
    fn retry(
        &self,
        delivery: &Delivery,
        reason: &'static str,
        detail: Option<String>,
        exhausted: intake::Resolution,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let id = delivery.id;
        match self
            .store
            .writer()
            .write(move |tx| intake::retry(tx, id, now, exhausted))
        {
            Ok(intake::Retry::Scheduled { .. }) => Ok(Outcome::Retried { reason, detail }),
            Ok(intake::Retry::Exhausted) => Ok(match exhausted {
                intake::Resolution::Ignored(reason) => Outcome::Ignored(reason),
                intake::Resolution::Failed(reason) => Outcome::Failed {
                    reason,
                    detail: None,
                },
                // `intake::retry` refuses it too; keep the outcome honest.
                intake::Resolution::Ready => Outcome::Failed {
                    reason: "resolution_attempts",
                    detail,
                },
            }),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }
}

/// What the ordering rule decided before any remote work.
#[derive(Debug, PartialEq, Eq)]
enum Order {
    /// Nothing on record contradicts this transition: it is new work.
    New,
    /// Decided from stored facts alone.
    Settle(Outcome),
    /// A push that neither continues the newest dispatched transition nor
    /// ends where it began: stale exactly when its revision is already in
    /// the history of `tip`, the newest dispatched revision.
    Prove { tip: String },
}

/// The duplicate/reordered-event rule. Arrival order is not push order — a
/// relay replays its spool, GitHub documents out-of-order delivery — so the
/// rule is anchored on the newest **dispatched** transition of the stream
/// and on commit history, never on which event happened to arrive last:
///
/// 1. the identical transition is a duplicate;
/// 2. a transition starting where the newest one ended continues the stream
///    and runs — including a forced rewind and a repeat of an older
///    transition (`A→B`, `B→A`, `A→B` builds `B` again);
/// 3. a transition ending where the newest one began is its predecessor and
///    is superseded;
/// 4. any other branch push is superseded when its revision is an ancestor
///    of the newest dispatched revision (proved through Git), so an older
///    push can never dispatch after — or cancel the run of — the tip.
///
/// Tags and pull requests stop at rule 3: a retagged tag is not history,
/// and one base branch's stream holds unrelated pull requests.
fn order(delivery: &Delivery, previous: Option<&Delivery>, kind: EventKind) -> Order {
    let Some(previous) = previous else {
        return Order::New;
    };
    let (old, new) = (delivery.old_sha.as_deref(), delivery.new_sha.as_deref());
    if previous.old_sha.as_deref() == old && previous.new_sha.as_deref() == new {
        return Order::Settle(Outcome::Ignored("duplicate"));
    }
    if old.is_some() && old == previous.new_sha.as_deref() {
        return Order::New;
    }
    if new.is_some() && new == previous.old_sha.as_deref() {
        return Order::Settle(Outcome::Ignored("superseded"));
    }
    match previous.new_sha.as_deref() {
        Some(tip) if kind == EventKind::Push && !sentinel_protocol::intake::is_zero_sha(tip) => {
            Order::Prove {
                tip: tip.to_owned(),
            }
        }
        _ => Order::New,
    }
}

/// Where the pipeline file is read from.
enum Revision {
    /// The peeled event commit (push, tag).
    Commit(String),
    /// The pull request's tested-merge ref, verified live: the commit it
    /// names must list `head` among its parents before it is trusted.
    Merge { merge_ref: String, head: String },
}

/// A dispatchable event, fully planned from stored facts.
struct Plan {
    kind: EventKind,
    /// The ref the policy and the duplicate stream are judged against: the
    /// pushed ref, the tag ref, or the pull-request base branch.
    policy_ref: String,
    /// The revision the pipeline file is read from.
    source: Revision,
    /// The ref recorded as provenance and rechecked against the binding: the
    /// pushed ref, the tag, or the pull-request base branch.
    checkout_ref: String,
    head_sha: Option<String>,
    base_sha: Option<String>,
    pr_number: Option<u64>,
}

impl Plan {
    fn event(&self) -> Event<'_> {
        match self.kind {
            EventKind::Push => Event::push(&self.policy_ref),
            EventKind::Tag => Event::tag(&self.policy_ref),
            EventKind::PullRequest => Event::pull_request(&self.policy_ref),
            EventKind::Manual => Event::manual(),
        }
    }

    fn provenance(
        &self,
        delivery: &Delivery,
        binding: &source::Binding,
        spec: &RunSpec,
        commit: &str,
    ) -> Provenance {
        Provenance {
            tenant: delivery.tenant,
            repo: delivery.repo,
            trigger: self.kind.as_str().to_owned(),
            delivery: Some(delivery.id),
            provider: Some(delivery.provider.clone()),
            ref_name: delivery.ref_name.clone(),
            old_sha: delivery.old_sha.clone(),
            new_sha: delivery.new_sha.clone(),
            head_sha: self.head_sha.clone(),
            base_sha: self.base_sha.clone(),
            // For a pull request the merge recorded is the verified commit the
            // merge ref named — what was actually tested — not the payload's
            // possibly-stale claim.
            merge_sha: match &self.source {
                Revision::Merge { .. } => Some(commit.to_owned()),
                Revision::Commit(_) => None,
            },
            // The peeled commit the pipeline was read at: for a tag that is
            // not the tag object the event named.
            pipeline_sha: commit.to_owned(),
            pipeline_path: Some(binding.metadata.binding.pipeline_path.clone()),
            pipeline_digest: spec.pipeline.digest.to_le_bytes(),
            pr_number: self.pr_number,
        }
    }
}

/// A scratch directory removed on every path.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{DeliveryId, RepoId, TenantId};

    fn sha(c: char) -> String {
        c.to_string().repeat(40)
    }

    fn transition(old: char, new: char) -> Delivery {
        Delivery {
            id: DeliveryId::new(),
            tenant: TenantId::new(),
            repo: RepoId::new(),
            provider: "generic".into(),
            external_id: "x".into(),
            event: "ref_update".into(),
            ref_name: Some("refs/heads/main".into()),
            old_sha: Some(sha(old)),
            new_sha: Some(sha(new)),
            state: intake::State::Ready,
            reason: None,
            attempts: 0,
            received: UnixMillis(1),
            settled: None,
            run: None,
        }
    }

    #[test]
    fn the_first_transition_of_a_stream_is_new_work() {
        assert_eq!(
            order(&transition('a', 'b'), None, EventKind::Push),
            Order::New
        );
    }

    #[test]
    fn identical_successor_and_predecessor_transitions_are_decided_without_git() {
        let tip = transition('c', 'd');
        assert_eq!(
            order(&transition('c', 'd'), Some(&tip), EventKind::Push),
            Order::Settle(Outcome::Ignored("duplicate"))
        );
        assert_eq!(
            order(&transition('d', 'e'), Some(&tip), EventKind::Push),
            Order::New
        );
        assert_eq!(
            order(&transition('b', 'c'), Some(&tip), EventKind::Push),
            Order::Settle(Outcome::Ignored("superseded"))
        );
    }

    #[test]
    fn a_rewind_and_a_repeated_transition_continue_the_stream() {
        // A→B built, then a forced rewind B→A, then A→B pushed again: each
        // starts where the newest dispatched one ended, so each runs.
        let built = transition('a', 'b');
        let rewind = transition('b', 'a');
        assert_eq!(order(&rewind, Some(&built), EventKind::Push), Order::New);
        assert_eq!(
            order(&transition('a', 'b'), Some(&rewind), EventKind::Push),
            Order::New
        );
    }

    #[test]
    fn a_non_adjacent_push_must_be_proved_against_the_tip_and_only_for_branches() {
        // C→D is the tip; A→B arrives late. Nothing adjacent decides it, so
        // the tip's history does.
        let tip = transition('c', 'd');
        assert_eq!(
            order(&transition('a', 'b'), Some(&tip), EventKind::Push),
            Order::Prove { tip: sha('d') }
        );
        // A retagged tag and an unrelated pull request on the same base are
        // not history questions.
        assert_eq!(
            order(&transition('a', 'b'), Some(&tip), EventKind::Tag),
            Order::New
        );
        assert_eq!(
            order(&transition('a', 'b'), Some(&tip), EventKind::PullRequest),
            Order::New
        );
    }
}
