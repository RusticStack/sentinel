//! Remote work never runs inside a writer transaction, so the writer is never held over the network.
//! A pull request whose head lives in another repository is refused: Git refs alone do not prove fork trust.

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{RunId, UnixMillis};
use sentinel_github::app::Current;
use sentinel_pipeline::{Event, EventKind, PinnedSource, RunSpec};
use sentinel_store::{
    Error as StoreError, Store,
    intake::{self, Delivery, PrDelivery},
    provenance::Provenance,
    runs,
};

use crate::source;

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

pub struct Resolver {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Current,
    destinations: Arc<[String]>,
    fetch: Arc<dyn Fetch>,
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
            app: app.into(),
            destinations,
            fetch,
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

        let pr: Option<PrDelivery> = self.store.read(|c| intake::pr_for(c, delivery.id))?;
        let plan = match self.plan(delivery, pr.as_ref(), &binding) {
            Ok(plan) => plan,
            Err(outcome) => return self.settle(delivery, outcome, now),
        };

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

        let provenance = plan.provenance(delivery, &binding, &spec, &fetched.commit);
        let dispatched = delivery.clone();
        // `now` predates the pipeline fetch: stamping jobs with it would count the fetch as queue time.
        let run = match self.store.writer().write(move |tx| {
            intake::dispatch(
                tx,
                &dispatched,
                &spec,
                &images,
                &provenance,
                UnixMillis::steady(),
            )
        }) {
            Ok(run) => run,
            Err(StoreError::Conflict) => return Ok(Outcome::Skipped),
            Err(e) => return Err(e),
        };
        Ok(Outcome::Dispatched { run })
    }

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
                })
            }
            _ => Err(Outcome::Failed {
                reason: "unsupported_event",
                detail: Some(delivery.event.clone()),
            }),
        }
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
            merge_sha: match &self.source {
                Revision::Merge { .. } => Some(commit.to_owned()),
                Revision::Commit(_) => None,
            },
            pipeline_sha: commit.to_owned(),
            pipeline_path: Some(binding.metadata.binding.pipeline_path.clone()),
            pipeline_digest: spec.pipeline.digest.to_le_bytes(),
            pr_number: self.pr_number,
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
