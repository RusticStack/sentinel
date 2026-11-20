//! Runner mode end to end over a real store: a signed `workflow_job` enters the durable intake,
//! resolution turns a queued job into one durable job of the label's class, and every refusal —
//! an unbound repository, the switch off, a withdrawn permission, a class this deployment does
//! not serve — is decided without a retry and visible in the intake's own record.

use std::{sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, RepoId, RunnerClass, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Github, Outcome, Resolver,
    ingest::{self, Error as IngestError},
    resolve::{AncestryRequest, Config, Fetch, FileRequest, MergeRequest},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, State},
    registration::{self, Authority},
    runner::{self, JobState},
    sources::{self, Update},
    sources_forge,
};

const SECRET: &[u8] = b"a-webhook-secret-value";
const INSTALLATION: u64 = 42;
const GITHUB_REPO_ID: i64 = 91;
const CLASS: &str = "sentinel-2vcpu-ubuntu-2404";
/// Text that must never reach a stored row, an answer or a log line: runner mode's
/// registration configuration is a credential and Sentinel never stores it.
const CANARY: &str = "jit-canary-1f4c0b7e-do-not-store";

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    resolver: Resolver,
    tenant: TenantId,
    repo: RepoId,
}

/// Nothing in runner mode fetches a repository: a job that reached the fetch path is a bug.
struct NoFetch;

impl Fetch for NoFetch {
    fn file_at(
        &self,
        _: FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        panic!("a runner-mode delivery never fetches a pipeline")
    }
    fn merge_at(
        &self,
        _: MergeRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        panic!("a runner-mode delivery never fetches a merge")
    }
    fn is_ancestor(&self, _: AncestryRequest<'_>) -> Result<bool, sentinel_git::Error> {
        panic!("a runner-mode delivery never reads ancestry")
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let root = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let now = UnixMillis::now();
    let sealing = Arc::clone(&key);
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root.user, "root", true, now)?;
            auth::create_namespace(
                tx,
                root,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, root, tenant, repo, "widget", now)?;
            let installation = sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: INSTALLATION,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: sentinel_core::RunnerPermissions::ALL,
                    migration: sentinel_core::MigrationPermissions::ALL,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            let binding = Binding {
                remote: "https://github.com/account/widget.git".into(),
                allowed_refs: vec!["refs/heads/main".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root.user),
                Update {
                    repo,
                    expected: 0,
                    binding: &binding,
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID as u64)),
                },
                &["https://github.com".into()],
                &sealing,
                now,
            )?;
            Ok(())
        })
        .unwrap();
    let classes: Arc<[RunnerClass]> = vec![
        RunnerClass::parse(CLASS).unwrap(),
        RunnerClass::parse("sentinel-4vcpu-windows-2025").unwrap(),
    ]
    .into();
    let resolver = Resolver::new(
        Arc::clone(&store),
        Some(key),
        None,
        Arc::from(vec!["https://github.com".to_owned()]),
        classes,
        Arc::new(NoFetch),
        Arc::new(sentinel_intake::GitLister),
        dir.path().join("work"),
        Config {
            budget: Duration::from_secs(5),
            ..Config::default()
        },
    )
    .unwrap();
    Fixture {
        dir,
        store,
        resolver,
        tenant,
        repo,
    }
}

impl Fixture {
    fn payload(
        &self,
        action: &str,
        job: u64,
        run: u64,
        labels: &[&str],
        runner_name: Option<&str>,
        conclusion: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "action": action,
            "workflow_job": {
                "id": job,
                "run_id": run,
                "labels": labels,
                "runner_name": runner_name,
                "conclusion": conclusion,
                // A field this build never reads: GitHub does not send it, and a sender that
                // did must not get it stored.
                "encoded_jit_config": CANARY,
            },
            "installation": {"id": INSTALLATION},
            "repository": {"id": GITHUB_REPO_ID, "full_name": "account/widget"},
        })
    }

    fn deliver(&self, delivery: &str, payload: &serde_json::Value) -> Result<Github, IngestError> {
        let body = serde_json::to_vec(payload).unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET);
        let tag = ring::hmac::sign(&key, &body);
        let mut signature = String::from("sha256=");
        for byte in tag.as_ref() {
            signature.push_str(&format!("{byte:02x}"));
        }
        ingest::github(
            &self.store,
            SECRET,
            "workflow_job",
            Some(delivery),
            Some(&signature),
            &body,
            UnixMillis::now(),
        )
    }

    fn accept(
        &self,
        delivery: &str,
        action: &str,
        job: u64,
        run: u64,
        labels: &[&str],
    ) -> DeliveryId {
        let payload = self.payload(action, job, run, labels, None, None);
        match self.deliver(delivery, &payload).unwrap() {
            Github::Ingested(accepted) => accepted.id,
            other => panic!("a signed sentinel-labelled job must be ingested, got {other:?}"),
        }
    }

    /// The same job, but its commit belongs to a pull request from a fork of the repository.
    fn accept_fork(
        &self,
        delivery: &str,
        action: &str,
        job: u64,
        run: u64,
        labels: &[&str],
    ) -> DeliveryId {
        let mut payload = self.payload(action, job, run, labels, None, None);
        payload["workflow_job"]["pull_requests"] = serde_json::json!([
            {"number": 7, "head": {"repo": {"id": GITHUB_REPO_ID + 1}}, "base": {"repo": {"id": GITHUB_REPO_ID}}}
        ]);
        match self.deliver(delivery, &payload).unwrap() {
            Github::Ingested(accepted) => accepted.id,
            other => panic!("a signed sentinel-labelled job must be ingested, got {other:?}"),
        }
    }

    fn offer_fork_prs(&self) {
        let tenant = self.tenant;
        self.store
            .writer()
            .write(move |tx| {
                runner::set_fork_prs(tx, Authority::HostLocal, tenant, true)?;
                Ok(())
            })
            .unwrap();
    }

    fn validate(&self, id: DeliveryId) -> intake::Delivery {
        self.store
            .writer()
            .write(|tx| intake::resolve_due(tx, UnixMillis::now(), 64))
            .unwrap();
        self.store.read(move |c| intake::get(c, id)).unwrap()
    }

    fn resolve(&self, id: DeliveryId) -> (Outcome, intake::Delivery) {
        let delivery = self.store.read(move |c| intake::get(c, id)).unwrap();
        let outcome = self.resolver.resolve(&delivery, UnixMillis::now()).unwrap();
        let row = self.store.read(move |c| intake::get(c, id)).unwrap();
        (outcome, row)
    }

    fn run(&self, id: DeliveryId) -> (Outcome, intake::Delivery) {
        self.validate(id);
        self.resolve(id)
    }

    fn job(&self, job: u64) -> Option<runner::RunnerJob> {
        let (tenant, repo) = (self.tenant, self.repo);
        self.store
            .read(move |c| runner::job(c, tenant, repo, job))
            .unwrap()
    }

    fn jobs(&self) -> i64 {
        self.store
            .read(|c| Ok(c.query_row("SELECT count(*) FROM runner_jobs", [], |r| r.get(0))?))
            .unwrap()
    }

    fn audited(&self, action: &str) -> i64 {
        let (tenant, repo) = (self.tenant, self.repo);
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM source_audit
                     WHERE tenant_id = ?1 AND repo_id = ?2 AND action = ?3",
                    (
                        tenant.as_bytes().as_slice(),
                        repo.as_bytes().as_slice(),
                        action,
                    ),
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .unwrap()
    }

    fn enable_runner_mode(&self) {
        let tenant = self.tenant;
        self.store
            .writer()
            .write(move |tx| {
                runner::set_mode(tx, Authority::HostLocal, tenant, true)?;
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn an_unbound_repository_and_another_installations_repository_are_refused() {
    let f = fixture();
    // A repository no binding names, and one bound through another installation: both are
    // answered so GitHub stops retrying, and neither reaches a stored row.
    for (delivery, repository, installation) in [
        ("job-1", 92, INSTALLATION),
        ("job-2", GITHUB_REPO_ID as u64, INSTALLATION + 1),
    ] {
        let payload = serde_json::json!({
            "action": "queued",
            "workflow_job": {"id": 400, "run_id": 300, "labels": [CLASS]},
            "installation": {"id": installation},
            "repository": {"id": repository},
        });
        let signed = f.deliver(delivery, &payload).unwrap();
        assert_eq!(signed, Github::Ignored("unbound_repository"), "{delivery}");
    }
    let stored: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM webhook_deliveries", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(stored, 0);
    assert_eq!(f.jobs(), 0);
}

#[test]
fn another_runners_labels_and_unhandled_activities_are_acknowledged_unstored() {
    let f = fixture();
    for (delivery, action, labels) in [
        ("job-1", "queued", vec!["ubuntu-latest"]),
        ("job-2", "queued", vec!["self-hosted", "linux"]),
        ("job-3", "waiting", vec![CLASS]),
    ] {
        let payload = f.payload(action, 400, 300, &labels, None, None);
        let signed = f.deliver(delivery, &payload).unwrap();
        let expected = if action == "queued" {
            "runner_label"
        } else {
            "runner_action"
        };
        assert_eq!(signed, Github::Ignored(expected), "{delivery}");
    }
    assert_eq!(
        f.store
            .read(|c| Ok(
                c.query_row("SELECT count(*) FROM webhook_deliveries", [], |r| r
                    .get::<_, i64>(0))?
            ))
            .unwrap(),
        0
    );
    assert_eq!(f.jobs(), 0);
}

#[test]
fn a_queued_job_becomes_one_located_job_of_its_class_and_the_later_activities_update_it() {
    let f = fixture();
    f.enable_runner_mode();

    let queued = f.accept("job-queued", "queued", 4001, 3002, &["self-hosted", CLASS]);
    // A duplicate of the same delivery, and a second delivery of the same job, are no new work.
    assert_eq!(
        f.deliver(
            "job-queued",
            &f.payload("queued", 4001, 3002, &["self-hosted", CLASS], None, None)
        )
        .unwrap(),
        Github::Ingested(sentinel_intake::Ingested {
            duplicate: true,
            id: queued
        })
    );
    let (outcome, row) = f.run(queued);
    assert_eq!(outcome, Outcome::Ignored("runner_job"), "{row:?}");
    assert_eq!(row.state, State::Ignored);
    assert_eq!(row.reason.as_deref(), Some("runner_job"));
    let job = f.job(4001).unwrap();
    assert_eq!(job.class, CLASS);
    assert_eq!(job.state, JobState::Queued);
    assert_eq!((job.job, job.run), (4001, 3002));
    assert_eq!(job.started, None);
    assert_eq!(job.completed, None);

    // The same job delivered again under another delivery id is the same row, not a second job.
    let again = f.accept(
        "job-queued-2",
        "queued",
        4001,
        3002,
        &["self-hosted", CLASS],
    );
    assert_eq!(f.run(again).0, Outcome::Ignored("runner_job"));
    assert_eq!(f.jobs(), 1);

    let starting = f.payload(
        "in_progress",
        4001,
        3002,
        &["self-hosted", CLASS],
        Some("sentinel-runner-7"),
        None,
    );
    let Github::Ingested(started) = f.deliver("job-started", &starting).unwrap() else {
        panic!("in_progress is ingested");
    };
    // An identical replay is the same delivery, never a second fact.
    assert_eq!(
        f.deliver("job-started", &starting).unwrap(),
        Github::Ingested(sentinel_intake::Ingested {
            duplicate: true,
            id: started.id
        })
    );
    assert_eq!(f.run(started.id).0, Outcome::Ignored("runner_job"));
    let job = f.job(4001).unwrap();
    assert_eq!(job.state, JobState::InProgress);
    assert_eq!(job.runner.as_deref(), Some("sentinel-runner-7"));
    assert!(job.started.is_some() && job.completed.is_none());

    let finishing = f.payload(
        "completed",
        4001,
        3002,
        &["self-hosted", CLASS],
        None,
        Some("success"),
    );
    let Github::Ingested(completed) = f.deliver("job-completed", &finishing).unwrap() else {
        panic!("completed is ingested");
    };
    assert_eq!(f.run(completed.id).0, Outcome::Ignored("runner_job"));
    let job = f.job(4001).unwrap();
    assert_eq!(job.state, JobState::Completed);
    assert_eq!(job.conclusion.as_deref(), Some("success"));
    assert_eq!(
        job.runner.as_deref(),
        Some("sentinel-runner-7"),
        "a later activity that names no runner keeps the one it has"
    );

    // A late queued delivery of a completed job never rewinds it.
    let late = f.accept(
        "job-late-queued",
        "queued",
        4001,
        3002,
        &["self-hosted", CLASS],
    );
    assert_eq!(f.run(late).0, Outcome::Ignored("runner_job"));
    let job = f.job(4001).unwrap();
    assert_eq!(job.state, JobState::Completed);
    assert_eq!(f.jobs(), 1);
    // The class is decided once, by the first delivery, and no later one rewrites it.
    assert_eq!(job.class, CLASS);
}

#[test]
fn a_completed_delivery_for_a_job_never_seen_leaves_the_stamps_it_has_no_evidence_for() {
    let f = fixture();
    f.enable_runner_mode();
    let completed = f.accept("job-only-completed", "completed", 4009, 3008, &[CLASS]);
    assert_eq!(f.run(completed).0, Outcome::Ignored("runner_job"));
    let job = f.job(4009).unwrap();
    assert_eq!(job.state, JobState::Completed);
    assert_eq!(
        job.started, None,
        "an unmeasured start is absent, never zero"
    );
    assert!(job.completed.is_some());
}

#[test]
fn runner_mode_off_refuses_a_queued_job_with_an_audit_row_and_no_job() {
    let f = fixture();
    let queued = f.accept("job-off", "queued", 4100, 3100, &[CLASS]);
    let (outcome, row) = f.run(queued);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "runner_mode_off",
            detail: None
        }
    );
    assert_eq!(row.state, State::Failed);
    assert_eq!(row.reason.as_deref(), Some("runner_mode_off"));
    assert_eq!(row.attempts, 0, "a refusal is a decision, never retried");
    assert_eq!(f.audited("runner_mode_off"), 1);
    assert_eq!(f.jobs(), 0);
    // The intrusion is settled: no open delivery is left for the lane to keep trying.
    let open: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM webhook_deliveries WHERE state IN (0, 1)",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(open, 0);
}

#[test]
fn a_fork_pull_requests_job_is_refused_until_the_tenant_offers_them_and_then_waits_for_a_fork_pool()
{
    let f = fixture();
    f.enable_runner_mode();
    let refused = f.accept_fork("job-fork", "queued", 4300, 3300, &[CLASS]);
    let (outcome, row) = f.run(refused);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "runner_fork_pr",
            detail: None
        }
    );
    assert_eq!(row.state, State::Failed);
    assert_eq!(f.audited("runner_fork_pr"), 1);
    assert_eq!(f.jobs(), 0, "a refused fork job is never demand");

    // With the opt-in the job is recorded as demand, carrying the provenance placement reads.
    f.offer_fork_prs();
    let served = f.accept_fork("job-fork-2", "queued", 4301, 3301, &[CLASS]);
    assert_eq!(f.run(served).0, Outcome::Ignored("runner_job"));
    let job = f.job(4301).expect("the opted-in job is demand");
    assert!(job.fork_pr);
    assert!(f.job(4300).is_none(), "the refused job stayed refused");
}

#[test]
fn a_withdrawn_permission_or_a_removed_app_refuses_the_next_queued_job() {
    let f = fixture();
    f.enable_runner_mode();
    // GitHub reports the installation again without the registration grant.
    f.store
        .writer()
        .write(move |tx| {
            sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: INSTALLATION,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: sentinel_core::RunnerPermissions::grants(true, false),
                    migration: sentinel_core::MigrationPermissions::ALL,
                    expected: 1,
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let queued = f.accept("job-withdrawn", "queued", 4200, 3200, &[CLASS]);
    let (outcome, row) = f.run(queued);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "runner_permissions",
            detail: None
        }
    );
    assert_eq!(row.reason.as_deref(), Some("runner_permissions"));
    assert_eq!(f.jobs(), 0);

    // Removing the App suspends the installation, so the binding it authorized is no longer
    // a target at all: the delivery is answered before it is stored, which is the flow
    // stopping at its first step rather than at any later decision.
    let id: [u8; 16] = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT id FROM installations WHERE external_id = ?1",
                [INSTALLATION.to_string()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    let id = sentinel_core::InstallationId::from_bytes(id).unwrap();
    f.store
        .writer()
        .write(move |tx| sources_forge::remove(tx, id))
        .unwrap();
    let payload = f.payload("queued", 4201, 3201, &[CLASS], None, None);
    assert_eq!(
        f.deliver("job-removed", &payload).unwrap(),
        Github::Ignored("unbound_repository")
    );
    assert_eq!(f.jobs(), 0);
}

#[test]
fn a_class_this_deployment_does_not_serve_is_refused_visibly() {
    let f = fixture();
    f.enable_runner_mode();
    // A class Sentinel defines, which this deployment's configuration does not serve.
    let queued = f.accept(
        "job-unserved",
        "queued",
        4300,
        3300,
        &["sentinel-32vcpu-ubuntu-2404"],
    );
    let (outcome, row) = f.run(queued);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "runner_class_unavailable",
            detail: None
        }
    );
    assert_eq!(f.audited("runner_class_unavailable"), 1);
    assert!(row.reason.is_some());
    assert_eq!(f.jobs(), 0);

    // A label set naming two of Sentinel's classes satisfies no one runner.
    let conflict = f.accept(
        "job-conflict",
        "queued",
        4301,
        3301,
        &[CLASS, "sentinel-4vcpu-windows-2025"],
    );
    let (outcome, _) = f.run(conflict);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "runner_labels_conflict",
            detail: None
        }
    );
    assert_eq!(f.audited("runner_labels_conflict"), 1);
    assert_eq!(f.jobs(), 0);
}

#[test]
fn no_credential_or_registration_text_reaches_a_row_an_answer_or_the_database() {
    let f = fixture();
    f.enable_runner_mode();
    let outcomes = [
        f.accept("job-canary-1", "queued", 4400, 3400, &[CLASS]),
        f.accept(
            "job-canary-2",
            "queued",
            4401,
            3401,
            &["sentinel-32vcpu-ubuntu-2404"],
        ),
        {
            // A payload whose own signature is wrong must be refused without echoing it.
            let payload = f.payload("queued", 4402, 3402, &[CLASS], None, None);
            let body = serde_json::to_vec(&payload).unwrap();
            assert_eq!(
                ingest::github(
                    &f.store,
                    SECRET,
                    "workflow_job",
                    Some("job-canary-3"),
                    Some("sha256=00"),
                    &body,
                    UnixMillis::now()
                ),
                Err(IngestError::Unauthenticated)
            );
            f.accept("job-canary-3", "queued", 4402, 3402, &[CLASS])
        },
    ];
    for id in outcomes {
        let (outcome, row) = f.run(id);
        assert!(!format!("{outcome:?}").contains(CANARY), "{outcome:?}");
        assert!(!format!("{row:?}").contains(CANARY), "{row:?}");
    }
    // Every stored row, in the database file as GitHub delivered it minus what is never kept.
    let delivery = f
        .store
        .read(|c| {
            Ok(
                c.prepare("SELECT provider, external_id, event, reason FROM webhook_deliveries")?
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
        })
        .unwrap();
    for row in &delivery {
        assert!(!format!("{row:?}").contains(CANARY), "{row:?}");
    }
    let terms = f
        .store
        .read(|c| {
            Ok(
                c.prepare("SELECT action, labels, runner, conclusion FROM runner_deliveries")?
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
        })
        .unwrap();
    for row in &terms {
        assert!(!format!("{row:?}").contains(CANARY), "{row:?}");
    }
    let job = f.job(4400).unwrap();
    assert!(!format!("{job:?}").contains(CANARY));
    let bytes = std::fs::read(f.dir.path().join("metadata.sqlite")).unwrap();
    assert!(
        !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
        "a credential-shaped field reached the database file"
    );
}

#[test]
fn a_replayed_delivery_with_different_terms_is_a_conflict() {
    let f = fixture();
    f.enable_runner_mode();
    let first = f.accept("job-conflict-id", "queued", 4500, 3500, &[CLASS]);
    let other = f.payload("in_progress", 4500, 3500, &[CLASS], None, None);
    assert_eq!(
        f.deliver("job-conflict-id", &other),
        Err(IngestError::Conflict)
    );
    assert_eq!(f.run(first).0, Outcome::Ignored("runner_job"));
}

#[test]
fn the_runner_mode_delivery_carries_no_ref_and_publishes_no_sentinel_check() {
    let f = fixture();
    f.enable_runner_mode();
    let queued = f.accept("job-no-ref", "queued", 4600, 3600, &[CLASS]);
    let (_, row) = f.run(queued);
    assert_eq!(row.ref_name, None);
    assert_eq!(row.old_sha, None);
    assert_eq!(row.new_sha, None);
    assert_eq!(row.event, runner::EVENT);
    let checks: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM check_publications", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(
        checks, 0,
        "GitHub reports runner-mode jobs under its own names"
    );
}

#[test]
fn the_intake_keeps_the_job_terms_for_its_delivery() {
    let f = fixture();
    f.enable_runner_mode();
    let queued = f.accept("job-terms", "queued", 4700, 3700, &["self-hosted", CLASS]);
    let terms = f
        .store
        .read(move |c| runner::terms_for(c, queued))
        .unwrap()
        .unwrap();
    assert_eq!(terms.action, "queued");
    assert_eq!((terms.job, terms.run), (4700, 3700));
    assert_eq!(terms.labels, format!("self-hosted,{CLASS}"));
    assert_eq!(
        terms.class(),
        sentinel_core::Labelled::Class(RunnerClass::parse(CLASS).unwrap())
    );
    // Duplicate acceptance of the same terms is the same row, never a second one.
    let row = f.store.read(move |c| intake::get(c, queued)).unwrap();
    assert_eq!(row.state, State::Pending);
    let (_, settled) = f.run(queued);
    assert_eq!(settled.state, State::Ignored);
    assert_eq!(settled.reason.as_deref(), Some("runner_job"));
    let terms: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM runner_deliveries WHERE delivery_id = ?1",
                [queued.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(terms, 1);
}
