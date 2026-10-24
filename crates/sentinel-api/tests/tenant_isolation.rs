//! A refusal for another camp's resource must match a guessed identifier's answer byte for byte.

use std::{
    sync::{Arc, Barrier},
    thread,
};

use sentinel_core::{
    ArtifactId, AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UploadId, UserId,
    WorkerId,
    auth::{Namespace, Permissions as P, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::{
    logs::{Frame, Stream},
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
};
use sentinel_store::{
    Durability, Store, artifacts,
    auth::{self, Authority, NamespaceKind},
    dispatch::{self, Capacity},
    local_auth,
    logs::LogStore,
    objects::{Entry, Expect, Kind, Objects},
    registration::{self, Admission, Applicant, Terms},
    tenancy::{self, PoolKind},
    tokens::{self, Grant},
    workers::{self, Presentation},
};
use serde_json::{Value, json};

const PASSWORD: &str = "an acceptable member password";
const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps: [{ id: s, run: 'true' }]
  test:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    needs: [build]
    steps: [{ id: s, run: 'true' }]
";

enum Body {
    None,
    Json(Value),
    Raw(&'static [u8]),
}

fn send(
    base: &str,
    method: &str,
    path: &str,
    body: &Body,
    credential: Option<&str>,
    headers: &[(&str, &str)],
) -> (u16, Value) {
    let url = format!("{base}{path}");
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let mut request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "POST" => agent.post(&url),
        "PUT" => agent.put(&url),
        "DELETE" => agent.delete(&url).force_send_body(),
        other => unreachable!("{other}"),
    };
    if let Some(credential) = credential {
        request = request.header("authorization", credential);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = match body {
        Body::None => request.send_empty(),
        Body::Json(value) => request
            .header("content-type", "application/json")
            .send(value.to_string().as_bytes()),
        Body::Raw(bytes) => request
            .header("content-type", "application/octet-stream")
            .send(*bytes),
    }
    .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

#[derive(Clone)]
struct Target {
    org: String,
    home: String,
    repo: String,
    home_repo: String,
    run: String,
    job: String,
    attempt: String,
    artifact: String,
    digest: String,
    upload: String,
    user: String,
    worker: String,
    pool: String,
}

impl Target {
    fn strings(&self) -> Vec<&str> {
        vec![
            &self.org,
            &self.home,
            &self.repo,
            &self.home_repo,
            &self.run,
            &self.job,
            &self.attempt,
            &self.artifact,
            &self.digest,
            &self.upload,
            &self.user,
            &self.worker,
            &self.pool,
        ]
    }

    fn guess() -> Target {
        Target {
            org: "no-such-organization".into(),
            home: "no-such-person".into(),
            repo: "no-such-repo".into(),
            home_repo: "no-such-notes".into(),
            run: RunId::new().to_string(),
            job: JobId::new().to_string(),
            attempt: AttemptId::new().to_string(),
            artifact: ArtifactId::new().to_string(),
            digest: "0".repeat(64),
            upload: UploadId::new().to_string(),
            user: UserId::new().to_string(),
            worker: WorkerId::new().to_string(),
            pool: PoolId::new().to_string(),
        }
    }
}

struct Camp {
    user: UserId,
    username: &'static str,
    bearer: String,
    org: TenantId,
    home: TenantId,
    target: Target,
}

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    _logs: Arc<LogStore>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    root_bearer: String,
    owner: Camp,
    colleague: Camp,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn local_user(store: &Store, username: &'static str) -> UserId {
    let invitation = store
        .writer()
        .write(|tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms::default(),
                UnixMillis::now(),
            )
        })
        .unwrap()
        .secret;
    match registration::register(
        store,
        Applicant::Local {
            display_name: username,
            username,
            password: PASSWORD.as_bytes(),
        },
        Some(&invitation),
        UnixMillis::now(),
    )
    .unwrap()
    {
        Admission::Admitted(user) => user,
        other => panic!("{other:?}"),
    }
}

fn bearer_of(store: &Store, user: UserId, permissions: P) -> String {
    let granted = tokens::provision(
        store,
        Grant {
            user,
            name: "isolation",
            permissions,
            tenant: None,
            repo: None,
            lifetime_ms: 600_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    format!("Bearer {}", sentinel_auth::token::format(&granted.secret))
}

fn camp(
    store: &Store,
    root: UserId,
    username: &'static str,
    (org_slug, home_slug): (&'static str, &'static str),
    (repo, home_repo): (&'static str, &'static str),
) -> Camp {
    let user = local_user(store, username);
    let (org, home) = (TenantId::new(), TenantId::new());
    let (pool, worker) = (PoolId::new(), WorkerId::new());
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            let admin = sentinel_core::auth::Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                org,
                Namespace::parse(org_slug).unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_namespace(
                tx,
                admin,
                home,
                Namespace::parse(home_slug).unwrap(),
                NamespaceKind::Personal(user),
                now,
            )?;
            auth::set_membership(tx, admin, org, user, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, org, RepoId::new(), repo, now)?;
            auth::create_repo(tx, admin, home, RepoId::new(), home_repo, now)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                &format!("{org_slug}-builders"),
                PoolKind::Dedicated(org),
                now,
            )?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &sentinel_auth::secret::Secret::parse(&text).unwrap(),
                Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "builder",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                now,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 8 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    Camp {
        user,
        username,
        bearer: bearer_of(store, user, P::REPOSITORY.union(P::TENANT_ADMIN)),
        org,
        home,
        target: Target {
            org: org_slug.into(),
            home: home_slug.into(),
            repo: repo.into(),
            home_repo: home_repo.into(),
            run: String::new(),
            job: String::new(),
            attempt: String::new(),
            artifact: String::new(),
            digest: String::new(),
            upload: String::new(),
            user: user.to_string(),
            worker: worker.to_string(),
            pool: pool.to_string(),
        },
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"an operator password, long enough",
        UnixMillis::now(),
    )
    .unwrap();
    let mut owner = camp(
        &store,
        root,
        "olivia",
        ("alpha", "olivia-home"),
        ("app", "notes"),
    );
    let mut colleague = camp(
        &store,
        root,
        "carlos",
        ("beta", "carlos-home"),
        ("site", "dotfiles"),
    );
    let root_bearer = bearer_of(&store, root, P::ALL);
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs: Arc::clone(&logs),
        objects,
        controller: controller.handle(),
        secret_key: Some(key),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let mut d = Deployment {
        dir,
        store,
        _logs: logs,
        _controller: controller,
        server: Some(server),
        base,
        root_bearer,
        owner: Camp {
            user: owner.user,
            username: owner.username,
            bearer: std::mem::take(&mut owner.bearer),
            org: owner.org,
            home: owner.home,
            target: owner.target.clone(),
        },
        colleague: Camp {
            user: colleague.user,
            username: colleague.username,
            bearer: std::mem::take(&mut colleague.bearer),
            org: colleague.org,
            home: colleague.home,
            target: colleague.target.clone(),
        },
    };
    seed(&mut d, true);
    seed(&mut d, false);
    d
}

fn seed(d: &mut Deployment, owner: bool) {
    let camp = if owner { &d.owner } else { &d.colleague };
    let mut target = camp.target.clone();
    let (org, bearer) = (camp.org, camp.bearer.clone());
    let (status, run) = send(
        &d.base,
        "POST",
        &format!("/api/v1/tenants/{}/repos/{}/runs", target.org, target.repo),
        &Body::Json(json!({
            "pipeline": PIPELINE,
            "source": { "repo": "https://github.com/o/r.git",
                        "sha": "0123456789abcdef0123456789abcdef01234567", "ref": "main" }
        })),
        Some(&bearer),
        &[],
    );
    assert_eq!(status, 201, "{run}");
    target.run = run["id"].as_str().unwrap().to_owned();
    target.job = run["jobs"][0]["id"].as_str().unwrap().to_owned();
    let (run_id, job_id): (RunId, JobId) =
        (target.run.parse().unwrap(), target.job.parse().unwrap());
    let worker: WorkerId = target.worker.parse().unwrap();
    let pool: PoolId = target.pool.parse().unwrap();
    let now = UnixMillis::now();
    let offer = d
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("the queued job was placed");
    assert_eq!((offer.run, offer.job), (run_id, job_id));
    target.attempt = offer.attempt.to_string();
    for (seq, text) in [(1, "hello from the build\n"), (2, "second line\n")] {
        d._logs
            .append(
                run_id,
                job_id,
                offer.attempt,
                &Frame {
                    seq,
                    step: 0,
                    stream: Stream::Stdout,
                    bytes: text.as_bytes().to_vec(),
                },
            )
            .unwrap();
    }
    let objects = Objects::open(d.dir.path()).unwrap();
    let staged = objects
        .stage(org, &b"report-bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    target.digest = staged.digest().to_string();
    let attempt = offer.attempt;
    let artifact = d
        .store
        .writer()
        .write(move |tx| {
            objects.commit(tx, &staged)?;
            let version = objects.commit_manifest(
                tx,
                org,
                Kind::Artifact,
                &artifacts::manifest_name(job_id, "report"),
                &[Entry {
                    path: "out/report.txt".into(),
                    digest: staged.digest(),
                    len: staged.len(),
                    mode: 0o644,
                }],
            )?;
            artifacts::record(
                tx,
                org,
                run_id,
                job_id,
                attempt,
                "report",
                artifacts::State::Captured,
                Some(version),
                1,
                staged.len(),
                UnixMillis(now.0 + 7 * 86_400_000),
                now,
            )
        })
        .unwrap();
    target.artifact = artifact.to_string();
    for (path, name) in [
        (format!("?repo={}", target.repo), "TOKEN"),
        (String::new(), "SHARED"),
    ] {
        let (status, body) = send(
            &d.base,
            "PUT",
            &format!("/api/v1/tenants/{}/secrets/{name}{path}", target.org),
            &Body::Raw(b"a-secret-value"),
            Some(&bearer),
            &[("if-match", "0"), ("idempotency-key", name)],
        );
        assert_eq!(status, 200, "{body}");
    }
    let (status, upload) = send(
        &d.base,
        "POST",
        &format!("/api/v1/tenants/{}/uploads", target.org),
        &Body::Json(json!({ "len": 4 })),
        Some(&bearer),
        &[],
    );
    assert_eq!(status, 201, "{upload}");
    target.upload = upload["upload"].as_str().unwrap().to_owned();
    if owner {
        d.owner.target = target;
    } else {
        d.colleague.target = target;
    }
}

struct Probe {
    method: &'static str,
    path: String,
    body: Body,
    headers: Vec<(&'static str, &'static str)>,
    /// Also require the owner to read this path, so a typo cannot make every refusal look right.
    owner_reads: bool,
}

fn get(path: String) -> Probe {
    Probe {
        method: "GET",
        path,
        body: Body::None,
        headers: vec![],
        owner_reads: true,
    }
}

fn change(method: &'static str, path: String, body: Body) -> Probe {
    Probe {
        method,
        path,
        body,
        headers: vec![],
        owner_reads: false,
    }
}

fn probes(t: &Target) -> Vec<Probe> {
    let (org, repo) = (&t.org, &t.repo);
    let v1 = |rest: &str| format!("/api/v1{rest}");
    let mut list = vec![
        get(v1(&format!("/tenants/{org}/settings"))),
        get(v1(&format!("/tenants/{org}/repos"))),
        get(v1(&format!("/tenants/{org}/repos/{repo}/runs"))),
        get(v1(&format!("/tenants/{org}/repos/{repo}/source"))),
        get(v1(&format!("/tenants/{org}/sync"))),
        get(v1(&format!("/tenants/{org}/members"))),
        get(v1(&format!("/tenants/{org}/audit"))),
        get(v1(&format!("/tenants/{org}/invitations"))),
        get(v1(&format!("/tenants/{org}/storage"))),
        get(v1(&format!("/tenants/{org}/secrets?repo={repo}"))),
        get(v1(&format!("/tenants/{org}/secrets/TOKEN?repo={repo}"))),
        get(v1(&format!("/tenants/{org}/secrets"))),
        get(v1(&format!("/tenants/{org}/secrets/SHARED"))),
        get(v1(&format!("/tenants/{org}/secret-bindings?repo={repo}"))),
        get(v1(&format!("/tenants/{org}/objects/{}", t.digest))),
        get(v1(&format!("/tenants/{}/settings", t.home))),
        get(v1(&format!("/tenants/{}/repos", t.home))),
        get(v1(&format!(
            "/tenants/{}/repos/{}/runs",
            t.home, t.home_repo
        ))),
        get(v1(&format!("/runs/{}", t.run))),
        get(v1(&format!("/runs/{}/pipeline", t.run))),
        get(v1(&format!("/runs/{}/wait?timeout_ms=1", t.run))),
        get(v1(&format!("/runs/{}/artifacts", t.run))),
        get(v1(&format!("/runs/{}/artifacts/{}", t.run, t.artifact))),
        get(v1(&format!("/attempts/{}/logs", t.attempt))),
        get(v1(&format!("/attempts/{}/logs?limit=1", t.attempt))),
        get(v1(&format!("/attempts/{}/logs/search?q=hello", t.attempt))),
        get(v1(&format!("/attempts/{}/steps", t.attempt))),
        get(v1(&format!("/attempts/{}/summary", t.attempt))),
        get(v1(&format!("/workers?tenant={org}"))),
        get(v1(&format!("/queue?tenant={org}"))),
        get(v1(&format!("/uploads/{}", t.upload))),
    ];
    let mut failure = get(v1(&format!("/attempts/{}/failure", t.attempt)));
    failure.owner_reads = false;
    list.push(failure);
    let mut secret_headers = vec![("if-match", "1"), ("idempotency-key", "isolation")];
    let mut put = change(
        "PUT",
        v1(&format!("/tenants/{org}/secrets/TOKEN?repo={repo}")),
        Body::Raw(b"planted"),
    );
    put.headers.append(&mut secret_headers);
    list.push(put);
    list.push({
        let mut p = change(
            "DELETE",
            v1(&format!("/tenants/{org}/secrets/TOKEN?repo={repo}")),
            Body::None,
        );
        p.headers = vec![("if-match", "1"), ("idempotency-key", "isolation-delete")];
        p
    });
    list.push(change(
        "POST",
        v1(&format!("/tenants/{org}/repos/{repo}/runs")),
        Body::Json(json!({
            "pipeline": PIPELINE,
            "source": { "repo": "https://github.com/o/r.git",
                        "sha": "0123456789abcdef0123456789abcdef01234567", "ref": "main" }
        })),
    ));
    list.push(change(
        "POST",
        v1(&format!("/runs/{}/cancel", t.run)),
        Body::Json(json!({})),
    ));
    list.push(change(
        "POST",
        v1(&format!("/jobs/{}/cancel", t.job)),
        Body::Json(json!({})),
    ));
    list.push(change(
        "POST",
        v1(&format!("/jobs/{}/rerun", t.job)),
        Body::Json(json!({})),
    ));
    list.push(change(
        "POST",
        v1(&format!("/tenants/{org}/uploads")),
        Body::Json(json!({ "len": 4 })),
    ));
    list.push(change(
        "PUT",
        v1(&format!("/uploads/{}?offset=0", t.upload)),
        Body::Raw(b"abcd"),
    ));
    list.push(change(
        "POST",
        v1(&format!("/uploads/{}/commit", t.upload)),
        Body::Json(json!({})),
    ));
    list.push(change(
        "DELETE",
        v1(&format!("/uploads/{}", t.upload)),
        Body::None,
    ));
    list.push(change(
        "PUT",
        v1(&format!("/tenants/{org}/members/{}", t.user)),
        Body::Json(json!({ "role": "admin" })),
    ));
    list.push(change(
        "DELETE",
        v1(&format!("/tenants/{org}/members/{}", t.user)),
        Body::Json(json!({})),
    ));
    list.push(change(
        "PUT",
        v1(&format!("/tenants/{org}/repos/{repo}/grants/{}", t.user)),
        Body::Json(json!({ "access": ["read", "run", "secrets"] })),
    ));
    list.push(change(
        "POST",
        v1(&format!("/tenants/{org}/repos")),
        Body::Json(json!({ "name": "planted" })),
    ));
    list.push(change(
        "POST",
        v1(&format!("/tenants/{org}/invitations")),
        Body::Json(json!({ "email": "planted@example.com" })),
    ));
    list.push(change(
        "DELETE",
        v1(&format!(
            "/tenants/{org}/invitations/{}",
            sentinel_core::InvitationId::new()
        )),
        Body::Json(json!({})),
    ));
    list.push(change(
        "PUT",
        v1(&format!("/tenants/{org}/repos/{repo}/storage")),
        Body::Json(json!({ "log_retention_secs": 3600 })),
    ));
    list.push(change(
        "PUT",
        v1(&format!(
            "/tenants/{org}/secret-bindings/TOKEN?repo={repo}&job=build&step=s"
        )),
        Body::Json(json!({})),
    ));
    list.push(change(
        "PUT",
        v1(&format!("/tenants/{org}/secrets/SHARED/allow?repo={repo}")),
        Body::Json(json!({})),
    ));
    list.push(change(
        "POST",
        v1(&format!("/tenants/{org}/service-accounts")),
        Body::Json(json!({ "name": "planted-bot" })),
    ));
    list
}

fn normalized(body: &Value, real: &Target, guess: &Target) -> String {
    let mut text = body.to_string();
    for (a, b) in real.strings().into_iter().zip(guess.strings()) {
        for needle in [a, b] {
            if !needle.is_empty() {
                text = text.replace(needle, "_");
            }
        }
    }
    text
}

fn sweep(d: &Deployment, attacker: &Camp, victim: &Camp) {
    let guess = Target::guess();
    let real = probes(&victim.target);
    let guessed = probes(&guess);
    assert_eq!(real.len(), guessed.len());
    for (probe, decoy) in real.iter().zip(&guessed) {
        let label = format!("{} {}", probe.method, probe.path);
        let refused = send(
            &d.base,
            probe.method,
            &probe.path,
            &probe.body,
            Some(&attacker.bearer),
            &probe.headers,
        );
        let missing = send(
            &d.base,
            decoy.method,
            &decoy.path,
            &decoy.body,
            Some(&attacker.bearer),
            &decoy.headers,
        );
        assert_eq!(refused.0, missing.0, "{label}: {refused:?} vs {missing:?}");
        assert!(
            matches!(refused.0, 403 | 404),
            "{label}: the other camp got {refused:?}"
        );
        assert_eq!(
            normalized(&refused.1, &victim.target, &guess),
            normalized(&missing.1, &victim.target, &guess),
            "{label}"
        );
        let body = refused.1.to_string();
        for secret in victim.target.strings() {
            assert!(
                secret.is_empty() || label.contains(secret) || !body.contains(secret),
                "{label}: the refusal leaks {secret}"
            );
        }
        let anonymous = send(
            &d.base,
            probe.method,
            &probe.path,
            &probe.body,
            None,
            &probe.headers,
        );
        assert_eq!(anonymous.0, 401, "{label}");
    }
}

#[test]
fn the_other_camp_is_refused_on_every_route_exactly_as_a_guess_is() {
    let d = deployment();
    sweep(&d, &d.colleague, &d.owner);
    sweep(&d, &d.owner, &d.colleague);
}

#[test]
fn the_routes_in_the_sweep_do_work_for_their_owners() {
    let d = deployment();
    for camp in [&d.owner, &d.colleague] {
        for probe in probes(&camp.target).iter().filter(|p| p.owner_reads) {
            let (status, body) = send(
                &d.base,
                probe.method,
                &probe.path,
                &probe.body,
                Some(&camp.bearer),
                &probe.headers,
            );
            assert!(
                status < 300,
                "{} {} for its owner: {status} {body}",
                probe.method,
                probe.path
            );
        }
    }
}

#[test]
fn nothing_the_other_camp_tried_changed_anything() {
    let d = deployment();
    sweep(&d, &d.colleague, &d.owner);
    sweep(&d, &d.owner, &d.colleague);
    for (camp, other) in [(&d.owner, &d.colleague), (&d.colleague, &d.owner)] {
        let t = &camp.target;
        let get = |path: String| send(&d.base, "GET", &path, &Body::None, Some(&camp.bearer), &[]);
        let (_, run) = get(format!("/api/v1/runs/{}", t.run));
        assert!(!run["cancel_requested"].as_bool().unwrap_or(false), "{run}");
        assert_ne!(run["state"], "canceled", "{run}");
        let (_, runs) = get(format!("/api/v1/tenants/{}/repos/{}/runs", t.org, t.repo));
        assert_eq!(runs["runs"].as_array().unwrap().len(), 1, "{runs}");
        let (_, secret) = get(format!(
            "/api/v1/tenants/{}/secrets/TOKEN?repo={}",
            t.org, t.repo
        ));
        assert_eq!(
            (
                secret["secret"]["version"].as_u64(),
                secret["secret"]["active"].as_bool()
            ),
            (Some(1), Some(true)),
            "{secret}"
        );
        let (_, members) = get(format!("/api/v1/tenants/{}/members", t.org));
        let members = members["members"].as_array().unwrap();
        assert_eq!(members.len(), 1, "{members:?}");
        assert_eq!(members[0]["user"], t.user);
        assert_eq!(members[0]["role"], "admin");
        let (_, invitations) = get(format!("/api/v1/tenants/{}/invitations", t.org));
        assert!(invitations["invitations"].as_array().unwrap().is_empty());
        let (_, repos) = get(format!("/api/v1/tenants/{}/repos", t.org));
        assert_eq!(repos["repos"].as_array().unwrap().len(), 1, "{repos:?}");
        let (_, upload) = get(format!("/api/v1/uploads/{}", t.upload));
        assert_eq!(upload["received"].as_u64().unwrap_or(0), 0, "{upload}");
        assert!(members.iter().all(|m| m["user"] != other.target.user));
    }
}

#[test]
fn a_caller_lists_only_the_tenants_it_belongs_to_and_the_platform_stays_closed() {
    let d = deployment();
    for (camp, other) in [(&d.owner, &d.colleague), (&d.colleague, &d.owner)] {
        let (status, body) = send(
            &d.base,
            "GET",
            "/api/v1/tenants",
            &Body::None,
            Some(&camp.bearer),
            &[],
        );
        assert_eq!(status, 200, "{body}");
        let mut slugs: Vec<(String, String)> = body["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["slug"].as_str().unwrap().to_owned(),
                    t["role"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        slugs.sort();
        let mut expected = vec![
            (camp.target.org.clone(), "admin".to_owned()),
            (camp.target.home.clone(), "admin".to_owned()),
        ];
        expected.sort();
        assert_eq!(slugs, expected);
        assert_eq!(body["super_admin"], false);
        let text = body.to_string();
        for foreign in [&other.target.org, &other.target.home] {
            assert!(!text.contains(foreign.as_str()), "{text}");
        }
        for path in [
            "/api/v1/admin/tenants",
            "/api/v1/admin/audit",
            "/api/v1/admin/pools",
            "/api/v1/admin/policy",
            "/api/v1/admin/registrations",
            "/api/v1/admin/storage",
            "/api/v1/admin/diagnostics",
            "/api/v1/admin/backups",
            "/api/v1/metrics",
        ] {
            let (status, body) = send(&d.base, "GET", path, &Body::None, Some(&camp.bearer), &[]);
            let (peer_status, peer_body) =
                send(&d.base, "GET", path, &Body::None, Some(&other.bearer), &[]);
            assert!(matches!(status, 403 | 404), "{path}: {status} {body}");
            assert_eq!((status, &body), (peer_status, &peer_body), "{path}");
        }
        for (method, path) in [
            (
                "POST",
                format!("/api/v1/workers/{}/drain", other.target.worker),
            ),
            (
                "POST",
                format!("/api/v1/workers/{}/drain", camp.target.worker),
            ),
            (
                "POST",
                format!("/api/v1/workers/{}/undrain", WorkerId::new()),
            ),
        ] {
            let (status, _) = send(
                &d.base,
                method,
                &path,
                &Body::Json(json!({})),
                Some(&camp.bearer),
                &[],
            );
            assert!(matches!(status, 403 | 404), "{path}: {status}");
        }
    }
    let (status, body) = send(
        &d.base,
        "GET",
        "/api/v1/admin/tenants",
        &Body::None,
        Some(&d.root_bearer),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenants"].as_array().unwrap().len(), 4, "{body}");
    for camp in [&d.owner, &d.colleague] {
        for path in [
            format!("/api/v1/runs/{}", camp.target.run),
            format!("/api/v1/attempts/{}/logs", camp.target.attempt),
            format!(
                "/api/v1/tenants/{}/objects/{}",
                camp.target.org, camp.target.digest
            ),
        ] {
            let (status, _) = send(
                &d.base,
                "GET",
                &path,
                &Body::None,
                Some(&d.root_bearer),
                &[],
            );
            assert_eq!(status, 404, "{path}");
        }
    }
}

#[test]
fn a_credential_narrowed_to_one_tenant_cannot_reach_the_same_peoples_other_tenant() {
    let d = deployment();
    for (tenant, other_slug, other_repo) in [
        (d.owner.org, &d.owner.target.home, &d.owner.target.home_repo),
        (d.owner.home, &d.owner.target.org, &d.owner.target.repo),
    ] {
        let granted = tokens::provision(
            &d.store,
            Grant {
                user: d.owner.user,
                name: "narrow",
                permissions: P::REPOSITORY.union(P::TENANT_ADMIN),
                tenant: Some(tenant),
                repo: None,
                lifetime_ms: 600_000,
            },
            UnixMillis::now(),
        )
        .unwrap();
        let narrow = format!("Bearer {}", sentinel_auth::token::format(&granted.secret));
        for path in [
            format!("/api/v1/tenants/{other_slug}/repos"),
            format!("/api/v1/tenants/{other_slug}/repos/{other_repo}/runs"),
            format!("/api/v1/tenants/{other_slug}/settings"),
        ] {
            let (status, body) = send(&d.base, "GET", &path, &Body::None, Some(&narrow), &[]);
            assert_eq!(status, 404, "{path}: {body}");
        }
        let (status, body) = send(
            &d.base,
            "GET",
            "/api/v1/tenants",
            &Body::None,
            Some(&narrow),
            &[],
        );
        assert_eq!(status, 200);
        assert_eq!(body["tenants"].as_array().unwrap().len(), 1, "{body}");
    }
}

#[test]
fn a_log_cursor_belongs_to_its_tenant_and_authorization_is_asked_first() {
    let d = deployment();
    let (olivia, carlos) = (&d.owner, &d.colleague);
    let logs = |camp: &Camp, attempt: &str, query: &str| {
        send(
            &d.base,
            "GET",
            &format!("/api/v1/attempts/{attempt}/logs{query}"),
            &Body::None,
            Some(&camp.bearer),
            &[],
        )
    };
    let (status, page) = logs(olivia, &olivia.target.attempt, "?limit=1");
    assert_eq!(status, 200, "{page}");
    let cursor = page["next"]
        .as_str()
        .expect("a cursor for the rest")
        .to_owned();
    let (status, resumed) = logs(olivia, &olivia.target.attempt, &format!("?cursor={cursor}"));
    assert_eq!(status, 200, "{resumed}");
    let (foreign, body) = logs(carlos, &olivia.target.attempt, &format!("?cursor={cursor}"));
    let (guessed, guess_body) = logs(
        carlos,
        &AttemptId::new().to_string(),
        &format!("?cursor={cursor}"),
    );
    assert_eq!((foreign, guessed), (404, 404), "{body} / {guess_body}");
    assert_eq!(body["code"], guess_body["code"]);
    let (status, body) = logs(carlos, &carlos.target.attempt, &format!("?cursor={cursor}"));
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_cursor"))
    );
    let (status, runs) = send(
        &d.base,
        "GET",
        &format!(
            "/api/v1/tenants/{}/repos/{}/runs?before={}",
            carlos.target.org, carlos.target.repo, olivia.target.run
        ),
        &Body::None,
        Some(&carlos.bearer),
        &[],
    );
    let (guess_status, guess_runs) = send(
        &d.base,
        "GET",
        &format!(
            "/api/v1/tenants/{}/repos/{}/runs?before={}",
            carlos.target.org,
            carlos.target.repo,
            RunId::new()
        ),
        &Body::None,
        Some(&carlos.bearer),
        &[],
    );
    assert_eq!(status, guess_status, "{runs} / {guess_runs}");
    assert_eq!(runs["code"], guess_runs["code"]);
}

#[test]
fn a_sign_in_name_is_never_resolved_outside_the_tenant() {
    let d = deployment();
    for name in [d.owner.username, "nobody-by-that-name"] {
        let (status, body) = send(
            &d.base,
            "PUT",
            &format!("/api/v1/tenants/{}/members/{name}", d.colleague.target.org),
            &Body::Json(json!({ "role": "reader" })),
            Some(&d.colleague.bearer),
            &[],
        );
        assert_eq!(status, 404, "{name}: {body}");
        assert_eq!(body["code"], "not_found");
        let (status, body) = send(
            &d.base,
            "PUT",
            &format!(
                "/api/v1/tenants/{}/repos/{}/grants/{name}",
                d.colleague.target.org, d.colleague.target.repo
            ),
            &Body::Json(json!({ "access": ["read"] })),
            Some(&d.colleague.bearer),
            &[],
        );
        assert_eq!(status, 404, "{name}: {body}");
    }
    let (_, members) = send(
        &d.base,
        "GET",
        &format!("/api/v1/tenants/{}/members", d.colleague.target.org),
        &Body::None,
        Some(&d.colleague.bearer),
        &[],
    );
    assert_eq!(members["members"].as_array().unwrap().len(), 1, "{members}");
    let (status, body) = send(
        &d.base,
        "PUT",
        &format!(
            "/api/v1/tenants/{}/members/{}",
            d.colleague.target.org, d.colleague.username
        ),
        &Body::Json(json!({ "role": "admin" })),
        Some(&d.colleague.bearer),
        &[],
    );
    assert_eq!(status, 200, "{body}");
}

fn session(d: &Deployment, username: &str) -> (String, String) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let response = agent
        .post(&format!("{}/api/v1/login", d.base))
        .header("content-type", "application/json")
        .send(
            json!({ "username": username, "password": PASSWORD })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .next()
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap().to_owned())
        .unwrap();
    let body: Value =
        serde_json::from_str(&response.into_body().read_to_string().unwrap()).unwrap();
    (cookie, body["csrf"].as_str().unwrap().to_owned())
}

#[test]
fn an_invitation_link_presented_by_two_people_at_once_joins_exactly_one() {
    let d = deployment();
    let (status, invited) = send(
        &d.base,
        "POST",
        &format!("/api/v1/tenants/{}/invitations", d.owner.target.org),
        &Body::Json(json!({ "email": "someone@example.com", "role": "operator" })),
        Some(&d.owner.bearer),
        &[],
    );
    assert_eq!(status, 201, "{invited}");
    assert_eq!(invited["delivery"], "link");
    let token = invited["token"].as_str().unwrap().to_owned();
    let dana = local_user(&d.store, "dana");
    let erin = local_user(&d.store, "erin");
    let sessions = [(dana, session(&d, "dana")), (erin, session(&d, "erin"))];
    let barrier = Barrier::new(2);
    let answers: Vec<(u16, Value)> = thread::scope(|scope| {
        let handles: Vec<_> = sessions
            .iter()
            .map(|(_, (cookie, csrf))| {
                let (base, token, barrier) = (&d.base, &token, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    send(
                        base,
                        "POST",
                        "/api/v1/invitations/accept",
                        &Body::Json(json!({ "token": token })),
                        None,
                        &[("cookie", cookie), ("x-sentinel-csrf", csrf)],
                    )
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (status, body) in &answers {
        assert!(matches!(status, 202 | 404), "{status} {body}");
    }
    let members = |user: UserId| {
        d.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM memberships WHERE user_id = ?1",
                    [user.as_bytes()],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .unwrap()
    };
    assert_eq!((members(dana), members(erin)), (0, 0));

    let org = d.owner.org;
    let link = d
        .store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms {
                    tenant: Some(org),
                    role: Some(Role::Reader),
                    ..Terms::default()
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let token = sentinel_auth::token::format(&link.secret);
    let barrier = Barrier::new(2);
    let answers: Vec<(u16, Value)> = thread::scope(|scope| {
        let handles: Vec<_> = sessions
            .iter()
            .map(|(_, (cookie, csrf))| {
                let (base, token, barrier) = (&d.base, &token, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    send(
                        base,
                        "POST",
                        "/api/v1/invitations/accept",
                        &Body::Json(json!({ "token": token })),
                        None,
                        &[("cookie", cookie), ("x-sentinel-csrf", csrf)],
                    )
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let joined = answers.iter().filter(|(s, _)| *s == 200).count();
    let refused: Vec<_> = answers.iter().filter(|(s, _)| *s == 404).collect();
    assert_eq!((joined, refused.len()), (1, 1), "{answers:?}");
    assert_eq!(refused[0].1["code"], "not_found");
    assert_eq!(members(dana) + members(erin), 1);
    let winner = sessions
        .iter()
        .find(|(user, _)| members(*user) == 1)
        .unwrap();
    let (_, listed) = send(
        &d.base,
        "GET",
        "/api/v1/tenants",
        &Body::None,
        Some(&bearer_of(&d.store, winner.0, P::READ)),
        &[],
    );
    let slugs: Vec<&str> = listed["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, [d.owner.target.org.as_str()], "{listed}");
    let (status, _) = send(
        &d.base,
        "GET",
        &format!("/api/v1/tenants/{}/invitations", d.owner.target.org),
        &Body::None,
        Some(&d.colleague.bearer),
        &[],
    );
    assert_eq!(status, 404);
}

#[test]
fn setup_and_registration_say_the_same_thing_to_everyone() {
    let d = deployment();
    let (status, body) = send(&d.base, "GET", "/api/v1/setup", &Body::None, None, &[]);
    assert_eq!(status, 200);
    assert_eq!(body, json!({ "open": false, "mail_configured": false }));
    let mut well_formed_token = String::new();
    sentinel_auth::secret::Secret::generate().expose(&mut well_formed_token);
    let (status, _) = send(
        &d.base,
        "POST",
        "/api/v1/setup",
        &Body::Json(json!({
            "token": well_formed_token, "email": "intruder@example.com",
            "password": PASSWORD, "registration": "closed", "instance_name": "x"
        })),
        None,
        &[],
    );
    assert_eq!(
        status, 404,
        "a closed setup is not found, whatever the token"
    );
    d.store
        .writer()
        .write(|tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                registration::DeploymentPolicy {
                    registration: registration::Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let signup = |address: &str| {
        send(
            &d.base,
            "POST",
            "/api/v1/register",
            &Body::Json(json!({ "email": address, "password": PASSWORD })),
            None,
            &[],
        )
    };
    let first = signup("dup@example.com");
    assert_eq!(first.0, 202, "{first:?}");
    let again = signup("dup@example.com");
    let fresh = signup("never-seen@example.com");
    assert_eq!(first, again);
    assert_eq!(first, fresh);
}
