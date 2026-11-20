//! Remote work never runs inside a writer transaction, so the writer is never held over the network.
//! A pull request whose head lives in another repository is refused: Git refs alone do not prove fork trust.

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{Labelled, RunId, RunnerClass, UnixMillis};
use sentinel_github::app::Current;
use sentinel_pipeline::{Event, EventKind, PinnedSource, RunSpec};
use sentinel_store::{
    Error as StoreError, Store,
    intake::{self, Delivery, MergeDelivery, PrDelivery},
    provenance::Provenance,
    runner, runs,
};

use crate::{
    poll::{Lister, TipRequest},
    source,
};

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub budget: Duration,
    pub max_pipeline_bytes: usize,
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
    Retried {
        reason: &'static str,
        detail: Option<String>,
    },
    Skipped,
}

impl Outcome {
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

pub struct FileRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    pub sha: &'a str,
    pub path: &'a str,
    pub max_bytes: usize,
    pub budget: Duration,
}

pub struct MergeRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    pub merge_ref: &'a str,
    pub head: &'a str,
    pub path: &'a str,
    pub max_bytes: usize,
    pub budget: Duration,
}

pub struct AncestryRequest<'a> {
    pub work: &'a std::path::Path,
    pub remote: &'a str,
    pub access: Option<&'a sentinel_protocol::source::Access>,
    pub ancestor: &'a str,
    pub tip: &'a str,
    pub depth: u32,
    pub budget: Duration,
}

pub trait Fetch: Send + Sync {
    fn file_at(
        &self,
        request: FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error>;
    fn merge_at(
        &self,
        request: MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error>;
    fn is_ancestor(&self, request: AncestryRequest<'_>) -> Result<bool, sentinel_git::Error>;
}

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

/// A compiled pipeline pinned at one revision and ready to create a run from — or the outcome that
/// says why this revision cannot run.
/// Every pipeline of one document the event matched, with its images resolved.
type Pinned = std::result::Result<Vec<(RunSpec, Vec<(String, String)>)>, Outcome>;

/// A pinned pipeline with the provenance its run records, ready to create.
type Part = (RunSpec, Vec<(String, String)>, Provenance);

pub struct Resolver {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Current,
    destinations: Arc<[String]>,
    /// The resource classes this deployment serves, from its own configuration. A label
    /// naming any other class is refused visibly, never silently run elsewhere.
    runner_classes: Arc<[RunnerClass]>,
    fetch: Arc<dyn Fetch>,
    lister: Arc<dyn Lister>,
    work_root: PathBuf,
    config: Config,
}

impl Resolver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store>,
        key: Option<Arc<Key>>,
        app: impl Into<Current>,
        destinations: Arc<[String]>,
        runner_classes: Arc<[RunnerClass]>,
        fetch: Arc<dyn Fetch>,
        lister: Arc<dyn Lister>,
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
            app: app.into(),
            destinations,
            runner_classes,
            fetch,
            lister,
            work_root,
            config,
        })
    }

    pub fn resolve(&self, delivery: &Delivery, now: UnixMillis) -> Result<Outcome, StoreError> {
        if delivery.state != intake::State::Ready {
            return Ok(Outcome::Skipped);
        }
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

        // A GitHub-orchestrated job: no pipeline, no fetch, no lease of this build's own.
        if delivery.event == runner::EVENT {
            return self.runner_job(delivery, now);
        }

        // One point read, and only for the event class that has terms to read.
        let (pr, merge): (Option<PrDelivery>, Option<MergeDelivery>) = match delivery.event.as_str()
        {
            "pull_request" => (self.store.read(|c| intake::pr_for(c, delivery.id))?, None),
            "merge_group" => (
                None,
                self.store.read(|c| intake::merge_for(c, delivery.id))?,
            ),
            _ => (None, None),
        };
        if let Some(merge) = merge.as_ref()
            && let Some(outcome) = self.merge_group(delivery, merge, now)?
        {
            return Ok(outcome);
        }
        let plan = match self.plan(delivery, pr.as_ref(), merge.as_ref(), &binding) {
            Ok(plan) => plan,
            Err(outcome) => return self.settle(delivery, outcome, now),
        };

        // A merge group is its own stream: its ordering and duplication are the
        // group's (above), never the base branch push stream's — the queue branch
        // commit is not history of the base branch and must not be judged by it.
        let prove_stale = if plan.kind == EventKind::MergeGroup {
            None
        } else {
            let stream = plan.policy_ref.clone();
            let is_pr = plan.kind == EventKind::PullRequest;
            let (tenant, repo) = (delivery.tenant, delivery.repo);
            let previous = self
                .store
                .read(move |c| intake::last_dispatched(c, tenant, repo, &stream, is_pr))?;
            match order(delivery, previous.as_ref(), plan.kind) {
                Order::Settle(outcome) => return self.settle(delivery, outcome, now),
                Order::New => None,
                Order::Prove { tip } => Some(tip),
            }
        };

        let access = match source::issue(
            &self.store,
            self.key.as_deref(),
            self.app.get(),
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

        // A run for a commit behind the newest dispatched tip would cancel that tip's run under cancel_in_progress.
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
        let ready = match self.pinned_runs(
            &binding,
            &text,
            &fetched.commit,
            &plan.checkout_ref,
            &plan.event(),
        )? {
            Ok(ready) => ready,
            Err(outcome) => return self.settle(delivery, outcome, now),
        };
        let parts: Vec<Part> = ready
            .into_iter()
            .map(|(spec, images)| {
                let provenance = plan.provenance(delivery, &binding, &spec, &fetched.commit);
                (spec, images, provenance)
            })
            .collect();
        let dispatched = delivery.clone();
        // `now` predates the pipeline fetch: stamping jobs with it would count the fetch as queue time.
        let run = match self.store.writer().write(move |tx| {
            let parts: Vec<intake::Part<'_>> = parts
                .iter()
                .map(|(spec, images, provenance)| intake::Part {
                    spec,
                    images,
                    provenance,
                })
                .collect();
            intake::dispatch_all(tx, &dispatched, &parts, UnixMillis::steady())
        }) {
            Ok(run) => run,
            Err(StoreError::Conflict) => return Ok(Outcome::Skipped),
            Err(e) => return Err(e),
        };
        Ok(Outcome::Dispatched { run })
    }

    /// Compile the pipeline document fetched at `commit` and pin every pipeline it declares that
    /// matches the event, or say why none of them can run.
    ///
    /// Each pipeline is independent: its own triggers decide whether it runs, its own jobs are
    /// pinned, and its own checks are published, so one pipeline refusing an artifact class or an
    /// unpinned image never decides another's fate — everything here is resolved before any run
    /// exists, so a refusal that touches one pipeline fails the delivery alone.
    fn pinned_runs(
        &self,
        binding: &source::Binding,
        text: &str,
        commit: &str,
        checkout_ref: &str,
        event: &Event<'_>,
    ) -> Result<Pinned, StoreError> {
        let compiled = match sentinel_pipeline::compile_document(text) {
            Ok(compiled) => compiled,
            Err(e) => {
                return Ok(Err(Outcome::Failed {
                    reason: "pipeline_invalid",
                    detail: Some(e.to_string().chars().take(200).collect()),
                }));
            }
        };
        let admitted: Vec<_> = compiled
            .into_iter()
            .filter(|pipeline| pipeline.on.admits(event))
            .collect();
        if admitted.is_empty() {
            return Ok(Err(Outcome::Ignored("no_trigger")));
        }
        let classes = self
            .store
            .read(sentinel_store::retention::artifact_classes)?;
        let declared = admitted
            .iter()
            .flat_map(|pipeline| pipeline.jobs.iter())
            .flat_map(|job| job.spec.artifacts.iter())
            .filter_map(|a| a.class.as_deref());
        if sentinel_store::retention::unknown_class(&classes, declared).is_some() {
            return Ok(Err(Outcome::Failed {
                reason: "artifact_class_unknown",
                detail: None,
            }));
        }
        let Ok(source) =
            PinnedSource::new(&binding.metadata.binding.remote, commit, Some(checkout_ref))
        else {
            return Ok(Err(Outcome::Failed {
                reason: "pipeline_invalid",
                detail: None,
            }));
        };
        let mut ready = Vec::with_capacity(admitted.len());
        for pipeline in admitted {
            let source = source.clone();
            let Ok(spec) = RunSpec::new(source, pipeline) else {
                return Ok(Err(Outcome::Failed {
                    reason: "pipeline_invalid",
                    detail: None,
                }));
            };
            let Ok(images) = runs::pinned_images(&spec) else {
                return Ok(Err(Outcome::Failed {
                    reason: "image_unpinned",
                    detail: None,
                }));
            };
            ready.push((spec, images));
        }
        Ok(Ok(ready))
    }

    /// One occurrence of a stored schedule: read the ref the schedule names, pin the commit it holds
    /// right now, and dispatch the pipeline from it.
    ///
    /// Two occurrences of one schedule therefore may run different commits, and each run carries the
    /// revision its own occurrence resolved. Everything that is not a dispatch settles the occurrence
    /// with its reason, so a pass over a repository that cannot be read costs one recorded row, never
    /// an occurrence that disappears.
    pub fn resolve_scheduled(
        &self,
        claim: &sentinel_store::schedule::Claim,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let (tenant, repo) = (claim.schedule.tenant, claim.schedule.repo);
        let binding = match source::classify(&self.store, repo)? {
            source::Lookup::Bound(binding) if binding.tenant == tenant => binding,
            source::Lookup::Bound(_) => return self.settle_scheduled(claim, "tenant_changed", now),
            source::Lookup::Unbound => return self.settle_scheduled(claim, "binding_revoked", now),
            source::Lookup::Unusable(reason) => return self.settle_scheduled(claim, reason, now),
        };
        if !source::destination_allowed(&self.destinations, &binding.metadata.binding.remote) {
            return self.settle_scheduled(claim, "destination_refused", now);
        }
        let access = match source::issue(
            &self.store,
            self.key.as_deref(),
            self.app.get(),
            &binding,
            now,
        ) {
            Ok(access) => access,
            Err(source::Error::Refused(why)) => return self.settle_scheduled(claim, why, now),
            Err(source::Error::Unavailable(why)) => {
                return self.settle_scheduled(claim, why, now);
            }
        };
        // A ref the binding narrowed itself out of since the schedule was configured is refused
        // before the fetch, as every other read of the binding is.
        if !binding
            .metadata
            .binding
            .allowed_refs
            .iter()
            .any(|p| sentinel_protocol::source::ref_matches(p, &claim.schedule.ref_name))
        {
            return self.settle_scheduled(claim, "ref_not_allowed", now);
        }

        let work = self
            .work_root
            .join(format!("{}-{}", repo, claim.at_ms.div_euclid(60_000)));
        let _scratch = Scratch(work.clone());
        fs::create_dir(&work)?;
        let tip = match self.lister.tip(&TipRequest {
            dir: &work,
            remote: &binding.metadata.binding.remote,
            access: Some(&access),
            ref_name: &claim.schedule.ref_name,
            budget: self.config.budget,
        }) {
            Ok(Some(tip)) => tip.peeled.unwrap_or(tip.oid),
            Ok(None) => return self.settle_scheduled(claim, "ref_missing", now),
            Err(sentinel_git::Error::UnsupportedPlatform) => {
                return self.settle_scheduled(claim, "source_unavailable", now);
            }
            Err(_) => return self.settle_scheduled(claim, "source_unreachable", now),
        };
        let fetched = match self.fetch.file_at(FileRequest {
            work: &work,
            remote: &binding.metadata.binding.remote,
            access: Some(&access),
            sha: &tip,
            path: &binding.metadata.binding.pipeline_path,
            max_bytes: self.config.max_pipeline_bytes,
            budget: self.config.budget,
        }) {
            Ok(fetched) => fetched,
            Err(sentinel_git::Error::Missing) => {
                return self.settle_scheduled(claim, "no_pipeline", now);
            }
            Err(sentinel_git::Error::TooLarge(_)) => {
                return self.settle_scheduled(claim, "pipeline_too_large", now);
            }
            Err(sentinel_git::Error::UnsupportedPlatform) => {
                return self.settle_scheduled(claim, "source_unavailable", now);
            }
            Err(_) => return self.settle_scheduled(claim, "source_unreachable", now),
        };
        let Ok(text) = String::from_utf8(fetched.bytes) else {
            return self.settle_scheduled(claim, "pipeline_invalid", now);
        };
        let event = Event::schedule(&claim.schedule.ref_name);
        let ready = match self.pinned_runs(
            &binding,
            &text,
            &fetched.commit,
            &claim.schedule.ref_name,
            &event,
        )? {
            Ok(ready) => ready,
            Err(Outcome::Ignored(reason)) => return self.settle_scheduled(claim, reason, now),
            Err(Outcome::Failed { reason, .. }) => {
                return self.settle_scheduled(claim, reason, now);
            }
            Err(_) => return self.settle_scheduled(claim, "pipeline_invalid", now),
        };
        let parts: Vec<Part> = ready
            .into_iter()
            .map(|(spec, images)| {
                let provenance = Provenance {
                    tenant,
                    repo,
                    trigger: "schedule".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some(claim.schedule.ref_name.clone()),
                    old_sha: None,
                    new_sha: Some(fetched.commit.clone()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: fetched.commit.clone(),
                    pipeline_path: Some(binding.metadata.binding.pipeline_path.clone()),
                    pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                    pr_number: None,
                    group_ref: None,
                };
                (spec, images, provenance)
            })
            .collect();
        let dispatched = claim.clone();
        // `now` predates the resolution: stamping jobs with it would count the fetch as queue time.
        match self.store.writer().write(move |tx| {
            let parts: Vec<intake::Part<'_>> = parts
                .iter()
                .map(|(spec, images, provenance)| intake::Part {
                    spec,
                    images,
                    provenance,
                })
                .collect();
            sentinel_store::schedule::dispatch_all(tx, &dispatched, &parts, UnixMillis::steady())
        }) {
            Ok(run) => Ok(Outcome::Dispatched { run }),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }

    /// Record what became of a scheduled occurrence that dispatched no run.
    fn settle_scheduled(
        &self,
        claim: &sentinel_store::schedule::Claim,
        reason: &'static str,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let claim = claim.clone();
        self.store.writer().write(move |tx| {
            sentinel_store::schedule::settle(
                tx,
                claim.schedule.repo,
                claim.at_ms,
                sentinel_store::schedule::State::Failed,
                Some(reason),
                now,
            )
        })?;
        Ok(Outcome::Failed {
            reason,
            detail: None,
        })
    }

    /// One `workflow_job` delivery. Only a queued job is demand: it becomes one durable job of
    /// the class its labels name, and the tenant's switch and the installation's permissions
    /// decide whether Sentinel offers to serve it. The later activities record what GitHub did
    /// with the job it already has. Every refusal is settled with its reason and an audit row,
    /// never retried, because no later attempt can change any of those facts.
    fn runner_job(&self, delivery: &Delivery, now: UnixMillis) -> Result<Outcome, StoreError> {
        let (tenant, repo) = (delivery.tenant, delivery.repo);
        let access = match self.store.read(move |c| runner::access(c, tenant, repo)) {
            Ok(access) => access,
            Err(StoreError::NotFound) => {
                return self.refuse(delivery, "runner_no_installation", now);
            }
            Err(e) => return Err(e),
        };
        let Some(terms) = self
            .store
            .read(move |c| runner::terms_for(c, delivery.id))?
        else {
            return self.refuse(delivery, "runner_terms", now);
        };
        // Ingest stores only a job whose labels name a Sentinel class; one class must survive
        // to here, and a set naming two of them is a class no one runner can satisfy.
        let class = match terms.class() {
            Labelled::Class(class) => class,
            Labelled::None => return self.refuse(delivery, "runner_label", now),
            Labelled::Conflict => return self.refuse(delivery, "runner_labels_conflict", now),
        };
        if terms.action == runner::QUEUED {
            if !access.enabled {
                return self.refuse(delivery, "runner_mode_off", now);
            }
            // A fork pull request's commit is code the tenant has not merged, so it is served only
            // by the hostile-fork pool and only when the tenant asked for it; otherwise the job is
            // refused and stays queued at GitHub, which is where a runner someone else provides
            // would take it. Placement is what confines an opted-in job to that pool (AR09).
            if terms.fork_pr && !access.fork_prs {
                return self.refuse(delivery, "runner_fork_pr", now);
            }
            if !access.permissions.missing(access.personal).is_empty() {
                return self.refuse(delivery, "runner_permissions", now);
            }
            if !self.runner_classes.contains(&class) {
                return self.refuse(delivery, "runner_class_unavailable", now);
            }
        }
        let dispatched = delivery.clone();
        match self
            .store
            .writer()
            .write(move |tx| runner::record(tx, &dispatched, &terms, class, now))
        {
            // Recorded, not dispatched: the job row is the work; GitHub runs that job itself.
            Ok(()) => Ok(Outcome::Ignored("runner_job")),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }

    /// Settle a delivery with its reason and its audit row in one transaction.
    fn refuse(
        &self,
        delivery: &Delivery,
        reason: &'static str,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let settled = delivery.clone();
        match self
            .store
            .writer()
            .write(move |tx| runner::refuse(tx, &settled, reason, now))
        {
            Ok(()) => Ok(Outcome::Failed {
                reason,
                detail: None,
            }),
            Err(StoreError::Conflict) => Ok(Outcome::Skipped),
            Err(e) => Err(e),
        }
    }

    fn plan(
        &self,
        delivery: &Delivery,
        pr: Option<&PrDelivery>,
        merge: Option<&MergeDelivery>,
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
                    group_ref: None,
                })
            }
            "pull_request" => {
                let Some(pr) = pr else {
                    return Err(Outcome::Failed {
                        reason: "pr_metadata",
                        detail: None,
                    });
                };
                let Some(bound_repo) = binding.forge.as_ref().map(|f| f.repo) else {
                    return Err(Outcome::Failed {
                        reason: "no_forge_association",
                        detail: None,
                    });
                };
                if pr.head_repo != bound_repo {
                    return Err(Outcome::Ignored("fork_pr"));
                }
                Ok(Plan {
                    kind: EventKind::PullRequest,
                    policy_ref: format!("refs/heads/{}", pr.base_ref),
                    source: Revision::Merge {
                        merge_ref: format!("refs/pull/{}/merge", pr.number),
                        head: pr.head_sha.clone(),
                    },
                    checkout_ref: format!("refs/heads/{}", pr.base_ref),
                    head_sha: Some(pr.head_sha.clone()),
                    base_sha: Some(pr.base_sha.clone()),
                    pr_number: Some(pr.number),
                    group_ref: None,
                })
            }
            "merge_group" => {
                let Some(merge) = merge else {
                    return Err(Outcome::Failed {
                        reason: "merge_group_terms",
                        detail: None,
                    });
                };
                let Some(bound_repo) = binding.forge.as_ref().map(|f| f.repo) else {
                    return Err(Outcome::Failed {
                        reason: "no_forge_association",
                        detail: None,
                    });
                };
                // The group's commits are merged into this repository's own queue
                // branch; a binding that now points at another repository cannot
                // read them.
                if merge.head_repo != bound_repo {
                    return Err(Outcome::Ignored("merge_group_repository"));
                }
                Ok(Plan {
                    kind: EventKind::MergeGroup,
                    policy_ref: format!("refs/heads/{}", merge.base_ref),
                    // GitHub states the head commit; it is read by that object id,
                    // never by a branch name that may have moved since.
                    source: Revision::Commit(merge.head_sha.clone()),
                    checkout_ref: merge.head_ref.clone(),
                    head_sha: Some(merge.head_sha.clone()),
                    base_sha: Some(merge.base_sha.clone()),
                    pr_number: None,
                    group_ref: Some(merge.head_ref.clone()),
                })
            }
            _ => Err(Outcome::Failed {
                reason: "unsupported_event",
                detail: Some(delivery.event.clone()),
            }),
        }
    }

    /// The decisions a merge group's own record makes before any remote work, so a
    /// redelivery, a group that already went away and a destroyed group are all
    /// settled without a fetch: `None` means the delivery should be resolved.
    fn merge_group(
        &self,
        delivery: &Delivery,
        merge: &MergeDelivery,
        now: UnixMillis,
    ) -> Result<Option<Outcome>, StoreError> {
        if merge.action == "destroyed" {
            let closed = delivery.clone();
            let (head_ref, base_sha) = (merge.head_ref.clone(), merge.base_sha.clone());
            let reason = match self.store.writer().write(move |tx| {
                intake::destroy_merge_group(tx, &closed, &head_ref, &base_sha, now)
            }) {
                Ok(reason) => reason,
                Err(StoreError::Conflict) => return Ok(Some(Outcome::Skipped)),
                Err(e) => return Err(e),
            };
            return Ok(Some(Outcome::Ignored(reason)));
        }
        let state = self
            .store
            .read(|c| intake::merge_group_state(c, delivery, &merge.head_ref, &merge.base_sha))?;
        let outcome = if state.run.is_some() || state.earlier_open {
            Outcome::Ignored("merge_group_duplicate")
        } else if state.gone {
            Outcome::Ignored("merge_group_merged")
        } else {
            return Ok(None);
        };
        self.settle(delivery, outcome, now).map(Some)
    }

    fn settle(
        &self,
        delivery: &Delivery,
        outcome: Outcome,
        now: UnixMillis,
    ) -> Result<Outcome, StoreError> {
        let resolution = match &outcome {
            Outcome::Ignored(reason) => intake::Resolution::Ignored(reason),
            Outcome::Failed { reason, .. } => intake::Resolution::Failed(reason),
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

#[derive(Debug, PartialEq, Eq)]
enum Order {
    New,
    Settle(Outcome),
    Prove { tip: String },
}

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

enum Revision {
    Commit(String),
    Merge { merge_ref: String, head: String },
}

struct Plan {
    kind: EventKind,
    policy_ref: String,
    source: Revision,
    checkout_ref: String,
    head_sha: Option<String>,
    base_sha: Option<String>,
    pr_number: Option<u64>,
    group_ref: Option<String>,
}

impl Plan {
    fn event(&self) -> Event<'_> {
        match self.kind {
            EventKind::Push => Event::push(&self.policy_ref),
            EventKind::Tag => Event::tag(&self.policy_ref),
            EventKind::PullRequest => Event::pull_request(&self.policy_ref),
            EventKind::MergeGroup => Event::merge_group(&self.policy_ref),
            EventKind::Manual => Event::manual(),
            // A delivery never carries this kind: a schedule resolves its occurrence directly.
            EventKind::Schedule => Event::schedule(&self.policy_ref),
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
            merge_sha: match &self.source {
                Revision::Merge { .. } => Some(commit.to_owned()),
                Revision::Commit(_) => None,
            },
            pipeline_sha: commit.to_owned(),
            pipeline_path: Some(binding.metadata.binding.pipeline_path.clone()),
            pipeline_digest: spec.pipeline.digest.to_le_bytes(),
            pr_number: self.pr_number,
            // The queue branch a merge group was read from; no other event has one.
            group_ref: self.group_ref.clone(),
        }
    }
}

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
        let tip = transition('c', 'd');
        assert_eq!(
            order(&transition('a', 'b'), Some(&tip), EventKind::Push),
            Order::Prove { tip: sha('d') }
        );
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
