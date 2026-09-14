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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(120),
            max_pipeline_bytes: sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES,
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

/// Where the pipeline file comes from. Production uses bounded Git
/// ([`GitFetch`]); a test can supply a fake because a GitHub-App-bound remote
/// is not reachable offline.
pub trait Fetch: Send + Sync {
    fn file_at(
        &self,
        request: FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error>;
}

/// The production fetcher: `sentinel-git`'s bounded file-at-revision read.
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
}

pub struct Resolver {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Option<Arc<App>>,
    fetch: Arc<dyn Fetch>,
    work_root: PathBuf,
    config: Config,
}

impl Resolver {
    /// Prepare a resolver whose scratch space is `work_root`. Anything a
    /// previous process left there is discarded: a half-fetched repository is
    /// never reused.
    pub fn new(
        store: Arc<Store>,
        key: Option<Arc<Key>>,
        app: Option<Arc<App>>,
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
        // What the binding authorizes right now.
        let Some(binding) = source::lookup(&self.store, delivery.repo)? else {
            return self.settle(
                delivery,
                Outcome::Failed {
                    reason: "binding_revoked",
                    detail: None,
                },
                now,
            );
        };
        if binding.metadata.revoked {
            return self.settle(
                delivery,
                Outcome::Failed {
                    reason: "binding_revoked",
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

        // Duplicate and reordered events: a transition already dispatched is
        // acknowledged, and a predecessor of the newest dispatched transition
        // for the same ref is superseded.
        let stream = plan.policy_ref.clone();
        let is_pr = plan.kind == EventKind::PullRequest;
        let (tenant, repo) = (delivery.tenant, delivery.repo);
        let previous = self
            .store
            .read(move |c| intake::last_dispatched(c, tenant, repo, &stream, is_pr))?;
        if let Some(previous) = previous {
            if previous.old_sha.as_deref() == delivery.old_sha.as_deref()
                && previous.new_sha.as_deref() == delivery.new_sha.as_deref()
            {
                return self.settle(delivery, Outcome::Ignored("duplicate"), now);
            }
            if previous.old_sha.as_deref() == delivery.new_sha.as_deref() {
                return self.settle(delivery, Outcome::Ignored("superseded"), now);
            }
        }

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
                return self.retry(delivery, why, None, now);
            }
        };

        // The pipeline file, read from the policy-selected revision; a tag
        // object is peeled to its commit.
        let work = self.work_root.join(delivery.id.to_string());
        let _scratch = Scratch(work.clone());
        fs::create_dir(&work)?;
        let fetched = match self.fetch.file_at(FileRequest {
            work: &work,
            remote: &binding.metadata.binding.remote,
            access: Some(&access),
            sha: &plan.pipeline_sha,
            path: &binding.metadata.binding.pipeline_path,
            max_bytes: self.config.max_pipeline_bytes,
            budget: self.config.budget,
        }) {
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
                return self.retry(delivery, "source_unreachable", Some(e.to_string()), now);
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
                    pipeline_sha: new_sha.clone(),
                    checkout_ref: ref_name.clone(),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
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
                let Some(merge) = pr.merge_sha.clone() else {
                    // No tested merge (conflicts, or GitHub could not compute
                    // one): there is nothing truthful to check out.
                    return Err(Outcome::Ignored("merge_unavailable"));
                };
                Ok(Plan {
                    kind: EventKind::PullRequest,
                    policy_ref: format!("refs/heads/{}", pr.base_ref),
                    pipeline_sha: merge.clone(),
                    checkout_ref: format!("refs/heads/{}", pr.head_ref),
                    head_sha: Some(pr.head_sha.clone()),
                    base_sha: Some(pr.base_sha.clone()),
                    merge_sha: Some(merge),
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
    /// settles the delivery as failed.
    fn retry(
        &self,
        delivery: &Delivery,
        reason: &'static str,
        detail: Option<String>,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let id = delivery.id;
        match self
            .store
            .writer()
            .write(move |tx| intake::retry(tx, id, now))
        {
            Ok(intake::Retry::Scheduled { .. }) => Ok(Outcome::Retried { reason, detail }),
            Ok(intake::Retry::Exhausted) => Ok(Outcome::Failed {
                reason: "resolution_attempts",
                detail,
            }),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }
}

/// A dispatchable event, fully planned from stored facts.
struct Plan {
    kind: EventKind,
    /// The ref the policy and the duplicate stream are judged against: the
    /// pushed ref, the tag ref, or the pull-request base branch.
    policy_ref: String,
    /// The revision the pipeline file is read from.
    pipeline_sha: String,
    /// The ref recorded as provenance (the pushed ref, the tag, or the PR head
    /// branch).
    checkout_ref: String,
    head_sha: Option<String>,
    base_sha: Option<String>,
    merge_sha: Option<String>,
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
            merge_sha: self.merge_sha.clone(),
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
