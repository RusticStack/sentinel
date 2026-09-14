//! G03 resolution over a real repository served on loopback HTTPS: policy,
//! exact provenance, duplicate/reordered events, the explicit outcomes, tag
//! peeling, and the pull-request trust rules. The pull-request happy path
//! uses an injected fetcher because a GitHub-App-bound remote is not
//! reachable offline; the merge choice and provenance it exercises are the
//! same code path a real App delivery takes.
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::BufRead,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_intake::{
    Outcome, Resolver,
    resolve::{Config, Fetch},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    intake::{self, NewDelivery, PrTerms, State},
    provenance, registration, runs,
    sources::{self, Update},
    sources_forge, status,
};

const REF: &str = "refs/heads/main";
const GITHUB_REPO_ID: u64 = 91;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn pipeline(on: &str) -> String {
    format!(
        "schema: 1\non: {on}\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
    )
}

struct Repo {
    git: std::path::PathBuf,
}

impl Repo {
    fn commit(&self, name: &str, files: &[(&str, &str)]) -> String {
        for (path, contents) in files {
            let full = self.git.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full, contents).unwrap();
        }
        run(Command::new("git")
            .args(["add", "-A"])
            .current_dir(&self.git));
        run(Command::new("git")
            .args(["commit", "-qm", name])
            .current_dir(&self.git)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com"));
        self.rev("HEAD")
    }

    fn rev(&self, spec: &str) -> String {
        let output = Command::new("git")
            .args(["rev-parse", spec])
            .current_dir(&self.git)
            .output()
            .unwrap();
        assert!(output.status.success(), "{spec}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The loopback HTTPS server from the shared fixture.
struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    resolver: Resolver,
    tenant: TenantId,
    repo: RepoId,
    github_repo: RepoId,
    remote: String,
    /// one, two (main), dev, unpinned, broken, no-pipeline
    commits: Vec<String>,
    tag_object: String,
    tag_commit: String,
    server: Server,
}

fn prerequisites() -> bool {
    for tool in ["git", "python3", "openssl"] {
        let ok = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("resolution verification requires {tool}; skipping");
            return false;
        }
    }
    true
}

/// The binding's authority: transport, host and port, as the destination
/// policy is written.
fn authority(remote: &str) -> String {
    sentinel_protocol::source::remote(remote)
        .unwrap()
        .to_owned()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());

    // The repository the fixture serves: one commit per interesting case.
    let git = dir.path().join("repo");
    fs::create_dir(&git).unwrap();
    let repo_git = Repo { git };
    run(Command::new("git")
        .args(["init", "-q", "--initial-branch=main"])
        .current_dir(&repo_git.git));
    let first = repo_git.commit(
        "one",
        &[
            (
                ".sentinel.yml",
                &pipeline("{push: {branches: [main, \"release/*\"]}, tag: {}, pull_request: {branches: [main]}, manual: true}"),
            ),
            ("src/lib.txt", "one\n"),
        ],
    );
    run(Command::new("git")
        .args(["tag", "-a", "v1", "-m", "release one"])
        .current_dir(&repo_git.git));
    let tag_object = repo_git.rev("refs/tags/v1");
    let tag_commit = repo_git.rev("refs/tags/v1^{commit}");
    let second = repo_git.commit("two", &[("src/lib.txt", "two\n")]);
    // A branch the pipeline's push filter excludes.
    run(Command::new("git")
        .args(["checkout", "-qb", "dev"])
        .current_dir(&repo_git.git));
    let dev = repo_git.commit("dev", &[("src/lib.txt", "dev\n")]);
    run(Command::new("git")
        .args(["checkout", "-q", "main"])
        .current_dir(&repo_git.git));
    let unpinned = repo_git.commit(
        "unpinned",
        &[(
            ".sentinel.yml",
            "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox:latest\n    steps: [{ id: s, run: 'true' }]\n",
        )],
    );
    let broken = repo_git.commit("broken", &[(".sentinel.yml", "schema: 1\njobs: []\n")]);
    // The bound pipeline path removed: the commit itself is valid, the source
    // has nothing to compile.
    run(Command::new("git")
        .args(["rm", "-q", ".sentinel.yml"])
        .current_dir(&repo_git.git));
    let no_pipeline = repo_git.commit("no-pipeline", &[("src/other.txt", "other\n")]);
    // Real servers need to be told to serve an arbitrary pinned revision.
    run(Command::new("git")
        .args(["config", "uploadpack.allowAnySHA1InWant", "true"])
        .current_dir(&repo_git.git));

    // Serve it over loopback HTTPS with a generated CA.
    let cert = dir.path().join("ca.pem");
    let tls_key = dir.path().join("tls.key");
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&tls_key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(generated.success());
    let password = dir.path().join("password");
    fs::write(&password, "private-source-token").unwrap();
    let mut server = Server(
        Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/git_https.py"
            ))
            // The project root is the directory *containing* the repository;
            // the URL below names it.
            .arg(dir.path())
            .arg(&cert)
            .arg(&tls_key)
            .env("FIXTURE_PASSWORD", &password)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut port = String::new();
    BufRead::read_line(
        &mut std::io::BufReader::new(server.0.stdout.take().unwrap()),
        &mut port,
    )
    .unwrap();
    let port: u16 = port.trim().parse().unwrap();
    let remote = format!("https://127.0.0.1:{port}/repo");

    let (owner, tenant, repo, github_repo) =
        (UserId::new(), TenantId::new(), RepoId::new(), RepoId::new());
    let principal = Principal::new(owner, Permissions::ALL, None, None);
    let trust = fs::read_to_string(&cert).unwrap();
    let sealing = Arc::clone(&key);
    store
        .writer()
        .write({
            let (remote, trust) = (remote.clone(), trust.clone());
            move |tx| {
                provisioning::insert_human(tx, owner, "root", true, UnixMillis::now())?;
                auth::create_namespace(
                    tx,
                    principal,
                    tenant,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    UnixMillis::now(),
                )?;
                auth::create_repo(tx, principal, tenant, repo, "app", UnixMillis::now())?;
                auth::create_repo(
                    tx,
                    principal,
                    tenant,
                    github_repo,
                    "widget",
                    UnixMillis::now(),
                )?;
                let binding = Binding {
                    remote: remote.clone(),
                    allowed_refs: vec!["refs/heads/*".into(), "refs/tags/*".into()],
                    pipeline_path: ".sentinel.yml".into(),
                    trust,
                };
                sources::bind(
                    tx,
                    sentinel_store::registration::Authority::HostLocal,
                    Some(owner),
                    Update {
                        repo,
                        expected: 0,
                        binding: &binding,
                        credential: &Credential::Https {
                            username: "deploy".into(),
                            secret: "private-source-token".into(),
                        },
                        forge: None,
                    },
                    &[authority(&remote)],
                    &sealing,
                    UnixMillis::now(),
                )?;
                // An App association for the trust rules; a happy PR path is
                // exercised with an injected fetcher, since the App-bound
                // remote is not reachable offline.
                let installation = sources_forge::refresh(
                    tx,
                    sources_forge::Snapshot {
                        external_id: 42,
                        account_id: 73,
                        login: "account",
                        personal: false,
                        suspended: false,
                        permissions_valid: true,
                        expected: 0,
                    },
                    UnixMillis::now(),
                )?;
                registration::bind_installation_trusted(
                    tx,
                    installation,
                    tenant,
                    UnixMillis::now(),
                )?;
                let mut forge_binding = binding;
                forge_binding.remote = "https://github.com/account/widget.git".into();
                sources::bind(
                    tx,
                    sentinel_store::registration::Authority::HostLocal,
                    Some(owner),
                    Update {
                        repo: github_repo,
                        expected: 0,
                        binding: &forge_binding,
                        credential: &Credential::Public,
                        forge: Some((installation, GITHUB_REPO_ID)),
                    },
                    &["https://github.com".into()],
                    &sealing,
                    UnixMillis::now(),
                )?;
                Ok(())
            }
        })
        .unwrap();
    let resolver = Resolver::new(
        Arc::clone(&store),
        Some(Arc::clone(&key)),
        None,
        Arc::new(sentinel_intake::resolve::GitFetch),
        dir.path().join("work"),
        Config {
            budget: Duration::from_secs(30),
            max_pipeline_bytes: 64 * 1024,
        },
    )
    .unwrap();
    Fixture {
        dir,
        store,
        resolver,
        tenant,
        repo,
        github_repo,
        remote,
        commits: vec![first, second, dev, unpinned, broken, no_pipeline],
        tag_object,
        tag_commit,
        server,
    }
}

impl Fixture {
    fn accept_push(&self, id: &str, ref_name: &str, old: &str, new: &str) -> DeliveryId {
        let repo = self.repo;
        let (ref_name, old, new, id) = (
            ref_name.to_owned(),
            old.to_owned(),
            new.to_owned(),
            id.to_owned(),
        );
        self.store
            .writer()
            .write(move |tx| {
                intake::accept(
                    tx,
                    repo,
                    &NewDelivery {
                        provider: "generic",
                        external_id: &id,
                        event: "ref_update",
                        ref_name: &ref_name,
                        old_sha: &old,
                        new_sha: &new,
                    },
                    None,
                    UnixMillis::now(),
                )
                .map(|accepted| accepted.id())
            })
            .unwrap()
    }

    fn accept_pr(&self, id: &str, head_repo: u64, merge: Option<&str>) -> DeliveryId {
        let (id, merge) = (id.to_owned(), merge.map(str::to_owned));
        let head_sha = "c".repeat(40);
        let base_sha = "d".repeat(40);
        let (repo, head_sha, base_sha) = (self.github_repo, head_sha, base_sha);
        self.store
            .writer()
            .write(move |tx| {
                let terms = PrTerms {
                    number: 7,
                    action: "opened",
                    draft: false,
                    head_ref: "feature",
                    head_sha: &head_sha,
                    head_repo,
                    base_ref: "main",
                    base_sha: &base_sha,
                    merge_sha: merge.as_deref(),
                };
                intake::accept(
                    tx,
                    repo,
                    &NewDelivery {
                        provider: "github",
                        external_id: &id,
                        event: "pull_request",
                        ref_name: "refs/heads/main",
                        old_sha: &base_sha,
                        new_sha: merge.as_deref().unwrap_or(&head_sha),
                    },
                    Some(&terms),
                    UnixMillis::now(),
                )
                .map(|accepted| accepted.id())
            })
            .unwrap()
    }

    /// Validate a delivery (lane phase one) and return its current row.
    fn validate(&self, id: DeliveryId) -> intake::Delivery {
        self.store
            .writer()
            .write(|tx| intake::resolve_due(tx, UnixMillis::now(), 64))
            .unwrap();
        self.store.read(move |c| intake::get(c, id)).unwrap()
    }

    /// Resolve a delivery (lane phase two) and return its current row.
    fn resolve(&self, id: DeliveryId) -> (Outcome, intake::Delivery) {
        self.resolve_with(&self.resolver, id)
    }

    fn resolve_with(&self, resolver: &Resolver, id: DeliveryId) -> (Outcome, intake::Delivery) {
        let delivery = self.store.read(move |c| intake::get(c, id)).unwrap();
        let outcome = resolver.resolve(&delivery, UnixMillis::now()).unwrap();
        let row = self.store.read(move |c| intake::get(c, id)).unwrap();
        (outcome, row)
    }

    fn spec_of(&self, run: sentinel_core::RunId) -> sentinel_pipeline::RunSpec {
        self.store
            .read(move |c| runs::get_run_spec(c, self.tenant, run))
            .unwrap()
    }

    fn provenance_of(&self, run: sentinel_core::RunId) -> provenance::RunProvenance {
        self.store
            .read(move |c| provenance::of_run(c, run))
            .unwrap()
            .unwrap()
    }
}

#[test]
fn a_push_resolves_through_the_policy_and_dispatches_with_exact_provenance() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    let head = f.commits[1].clone();
    let accepted = f.accept_push("push-1", REF, &f.commits[0], &head);
    let delivery = f.validate(accepted);
    assert_eq!(delivery.state, State::Ready);
    let (outcome, delivery) = f.resolve(accepted);
    let Outcome::Dispatched { run } = outcome else {
        panic!("expected a dispatch, got {outcome:?}");
    };
    assert_eq!(delivery.state, State::Dispatched);
    assert_eq!(delivery.run, Some(run));
    // The run stores the immutable spec at the pushed revision.
    let spec = f.spec_of(run);
    assert_eq!(spec.source.sha, head);
    assert_eq!(spec.source.repo, f.remote);
    assert_eq!(spec.source.ref_name.as_deref(), Some(REF));
    assert_eq!(spec.pipeline.jobs.len(), 1);
    // Provenance is exactly the event: push, the ref transition, the
    // pipeline revision.
    let recorded = f.provenance_of(run);
    assert_eq!(recorded.trigger, "push");
    assert_eq!(recorded.provider.as_deref(), Some("generic"));
    assert_eq!(recorded.delivery, Some(accepted));
    assert_eq!(recorded.ref_name.as_deref(), Some(REF));
    assert_eq!(recorded.old_sha.as_deref(), Some(f.commits[0].as_str()));
    assert_eq!(recorded.new_sha.as_deref(), Some(head.as_str()));
    assert_eq!(recorded.pipeline_sha, head);
    assert_eq!(recorded.pipeline_path.as_deref(), Some(".sentinel.yml"));
    assert!(recorded.head_sha.is_none() && recorded.pr_number.is_none());
    // The status view names the trigger.
    let view = f
        .store
        .read(move |c| status::run(c, f.tenant, run))
        .unwrap();
    assert_eq!(view.trigger.as_deref(), Some("push"));

    // A redelivery of the same transition under a new ID is a duplicate and
    // creates no second run; a predecessor is superseded.
    let again = f.accept_push("push-2", REF, &f.commits[0], &head);
    let _ = f.validate(again);
    let (outcome, row) = f.resolve(again);
    assert_eq!(outcome, Outcome::Ignored("duplicate"));
    assert_eq!(row.reason.as_deref(), Some("duplicate"));
    let earlier = f.accept_push("push-0", REF, &"9".repeat(40), &f.commits[0]);
    let _ = f.validate(earlier);
    let (outcome, row) = f.resolve(earlier);
    assert_eq!(outcome, Outcome::Ignored("superseded"));
    assert_eq!(row.reason.as_deref(), Some("superseded"));
    let runs: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM runs", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(runs, 1);
}

#[test]
fn the_policy_refuses_branches_it_does_not_declare() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    // `dev` exists and the binding allows it, but the pipeline's push filter
    // names main and release/* only.
    let accepted = f.accept_push("dev-1", "refs/heads/dev", &f.commits[1], &f.commits[2]);
    let _ = f.validate(accepted);
    let (outcome, row) = f.resolve(accepted);
    assert_eq!(outcome, Outcome::Ignored("no_trigger"));
    assert_eq!(row.reason.as_deref(), Some("no_trigger"));
}

#[test]
fn tags_are_peeled_to_their_commit_for_checkout() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    let accepted = f.accept_push("tag-1", "refs/tags/v1", &"0".repeat(40), &f.tag_object);
    let _ = f.validate(accepted);
    let (outcome, _) = f.resolve(accepted);
    let Outcome::Dispatched { run } = outcome else {
        panic!("expected a tag dispatch, got {outcome:?}");
    };
    // The tag object is not checked out: its commit is.
    let spec = f.spec_of(run);
    assert_eq!(spec.source.sha, f.tag_commit);
    assert_ne!(spec.source.sha, f.tag_object);
    assert_eq!(spec.source.ref_name.as_deref(), Some("refs/tags/v1"));
    let recorded = f.provenance_of(run);
    assert_eq!(recorded.trigger, "tag");
    assert_eq!(recorded.new_sha.as_deref(), Some(f.tag_object.as_str()));
    assert_eq!(recorded.pipeline_sha, f.tag_commit);
}

#[test]
fn missing_invalid_and_unpinned_sources_settle_explicitly() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    for (id, commit, reason) in [
        ("missing-1", &f.commits[5], "no_pipeline"),
        ("broken-1", &f.commits[4], "pipeline_invalid"),
        ("unpinned-1", &f.commits[3], "image_unpinned"),
    ] {
        let accepted = f.accept_push(id, REF, &f.commits[0], commit);
        let _ = f.validate(accepted);
        let (outcome, row) = f.resolve(accepted);
        assert!(
            matches!(
                outcome,
                Outcome::Failed {
                    reason: got,
                    ..
                } if got == reason
            ),
            "{id}: {outcome:?}"
        );
        assert_eq!(row.state, State::Failed);
        assert_eq!(row.reason.as_deref(), Some(reason));
        let runs: i64 = f
            .store
            .read(|c| Ok(c.query_row("SELECT count(*) FROM runs", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(runs, 0, "{id} must not leave a run");
    }
}

#[test]
fn an_unreachable_remote_retries_within_the_attempt_budget() {
    if !prerequisites() {
        return;
    }
    let mut f = fixture();
    let _ = f.server.0.kill();
    let accepted = f.accept_push("offline-1", REF, &f.commits[0], &f.commits[1]);
    let _ = f.validate(accepted);
    let (outcome, row) = f.resolve(accepted);
    assert!(matches!(outcome, Outcome::Retried { .. }), "{outcome:?}");
    assert_eq!(row.state, State::Ready, "an open delivery is retried later");
    let mut attempts = 1;
    loop {
        let (outcome, row) = f.resolve(accepted);
        attempts += 1;
        if matches!(outcome, Outcome::Failed { .. }) {
            assert_eq!(row.reason.as_deref(), Some("resolution_attempts"));
            assert_eq!(row.state, State::Failed);
            break;
        }
        assert!(attempts <= 10, "the budget must be bounded");
    }
    assert!(attempts >= 3, "it retried rather than failing at once");
}

/// A fetcher that serves one pipeline at one revision, for the pull request
/// path a GitHub-App-bound remote cannot reach offline.
struct FakeFetch {
    pipeline: String,
    commit: String,
}

impl Fetch for FakeFetch {
    fn file_at(
        &self,
        request: sentinel_intake::resolve::FileRequest<'_>,
    ) -> Result<sentinel_git::FetchedFile, sentinel_git::Error> {
        assert_eq!(request.sha, self.commit, "the pipeline revision asked for");
        Ok(sentinel_git::FetchedFile {
            commit: self.commit.clone(),
            bytes: self.pipeline.as_bytes().to_vec(),
        })
    }
}

/// A stub GitHub API for the App token path: token minting and the
/// repository check the App makes before any credential is issued.
struct GithubStub {
    addr: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl GithubStub {
    fn start() -> GithubStub {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => serve_github(stream),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        GithubStub {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for GithubStub {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_github(mut stream: std::net::TcpStream) {
    use std::io::{Read, Write};
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    let mut bearer = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap_or(0),
                "authorization" => bearer = value.trim().to_owned(),
                _ => {}
            }
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    // App-authenticated requests carry a JWT; the token-authenticated
    // repository check carries the minted installation token. Another
    // credential shape is a contract violation.
    if request.contains("/app/installations") {
        assert!(bearer.starts_with("Bearer ey"), "{request} {bearer}");
    } else {
        assert!(bearer.starts_with("Bearer "), "{request} {bearer}");
    }
    let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let expires = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (status, body) = if request.starts_with("GET ") && request.contains("/app/installations/42")
    {
        (
            200,
            "{\"id\":42,\"app_id\":1234,\"account\":{\"id\":73,\"login\":\"account\",\"type\":\"Organization\"},\"suspended_at\":null,\"permissions\":{\"contents\":\"read\",\"checks\":\"write\"}}"
                .to_owned(),
        )
    } else if request.starts_with("POST ") && request.contains("/access_tokens") {
        (
            201,
            format!(
                "{{\"token\":\"ghs_stub_token\",\"expires_at\":\"{expires}\",\"permissions\":{{\"contents\":\"read\",\"metadata\":\"read\"}}}}"
            ),
        )
    } else if request.starts_with("GET ") && request.contains("/repositories/91") {
        (
            200,
            "{\"id\":91,\"owner\":{\"id\":73},\"clone_url\":\"https://github.com/account/widget.git\"}"
                .to_owned(),
        )
    } else {
        (404, "{}".to_owned())
    };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} Ok\r\ncontent-length: {}\r\nconnection: close\r\ncontent-type: application/json\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

#[test]
fn a_same_repository_pull_request_dispatches_at_the_tested_merge() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    let merge = "e".repeat(40);
    let head = "c".repeat(40);
    let base = "d".repeat(40);
    // An App whose API is a loopback stub: the token path a real installation
    // takes, without github.com.
    let key_file = f.dir.path().join("app.pem");
    run(Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&key_file));
    let pem = fs::read_to_string(&key_file).unwrap();
    let stub = GithubStub::start();
    let app = Arc::new(
        sentinel_github::app::App::new(1234, &pem)
            .unwrap()
            .with_endpoint(&stub.endpoint()),
    );
    let resolver = Resolver::new(
        Arc::clone(&f.store),
        None,
        Some(Arc::clone(&app)),
        Arc::new(FakeFetch {
            pipeline: pipeline("[pull_request, push]"),
            commit: merge.clone(),
        }),
        f.dir.path().join("work-fake"),
        Config {
            budget: Duration::from_secs(5),
            max_pipeline_bytes: 64 * 1024,
        },
    )
    .unwrap();
    let accepted = f.accept_pr("pr-1", GITHUB_REPO_ID, Some(&merge));
    let _ = f.validate(accepted);
    let (outcome, _) = f.resolve_with(&resolver, accepted);
    let Outcome::Dispatched { run } = outcome else {
        panic!("expected a pull-request dispatch, got {outcome:?}");
    };
    // The tested merge is what runs; the head branch is provenance.
    let spec = f.spec_of(run);
    assert_eq!(spec.source.sha, merge);
    assert_eq!(spec.source.ref_name.as_deref(), Some("refs/heads/feature"));
    let recorded = f.provenance_of(run);
    assert_eq!(recorded.trigger, "pull_request");
    assert_eq!(recorded.provider.as_deref(), Some("github"));
    assert_eq!(recorded.head_sha.as_deref(), Some(head.as_str()));
    assert_eq!(recorded.base_sha.as_deref(), Some(base.as_str()));
    assert_eq!(recorded.merge_sha.as_deref(), Some(merge.as_str()));
    assert_eq!(recorded.pr_number, Some(7));
    let facts = f
        .store
        .read(move |c| provenance::event_facts(c, run))
        .unwrap();
    assert_eq!(facts.name, "pull_request");
    assert_eq!(facts.ref_name, "refs/pull/7/merge");
    assert_eq!(facts.base_ref.as_deref(), Some("main"));
    assert_eq!(facts.key, "pr-7");
}

#[test]
fn a_fork_or_unmergeable_pull_request_is_refused_before_any_fetch() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    // A head that lives in another repository is refused: Git refs do not
    // prove fork trust, and hostile fork execution is not a default.
    let accepted = f.accept_pr("pr-fork", 999, Some(&"e".repeat(40)));
    let _ = f.validate(accepted);
    let (outcome, row) = f.resolve(accepted);
    assert_eq!(outcome, Outcome::Ignored("fork_pr"));
    assert_eq!(row.reason.as_deref(), Some("fork_pr"));
    // A pull request without a tested merge has nothing truthful to check out.
    let accepted = f.accept_pr("pr-unmergeable", GITHUB_REPO_ID, None);
    let _ = f.validate(accepted);
    let (outcome, row) = f.resolve(accepted);
    assert_eq!(outcome, Outcome::Ignored("merge_unavailable"));
    assert_eq!(row.reason.as_deref(), Some("merge_unavailable"));
    let runs: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM runs", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(runs, 0);
}

#[test]
fn a_generic_binding_without_an_app_association_cannot_claim_a_pull_request() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    // A PR delivery for the *generic* repository: the adapter would never
    // produce one, and the resolver refuses it explicitly rather than treating
    // the base branch as a trusted pull-request target.
    let merge = "e".repeat(40);
    let head_sha = "c".repeat(40);
    let base_sha = "d".repeat(40);
    let repo = f.repo;
    let accepted = f
        .store
        .writer()
        .write(move |tx| {
            let terms = PrTerms {
                number: 8,
                action: "opened",
                draft: false,
                head_ref: "feature",
                head_sha: &head_sha,
                head_repo: GITHUB_REPO_ID,
                base_ref: "main",
                base_sha: &base_sha,
                merge_sha: Some(&merge),
            };
            intake::accept(
                tx,
                repo,
                &NewDelivery {
                    provider: "github",
                    external_id: "pr-generic",
                    event: "pull_request",
                    ref_name: "refs/heads/main",
                    old_sha: &base_sha,
                    new_sha: &merge,
                },
                Some(&terms),
                UnixMillis::now(),
            )
            .map(|accepted| accepted.id())
        })
        .unwrap();
    let _ = f.validate(accepted);
    let (outcome, row) = f.resolve(accepted);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "no_forge_association",
            detail: None
        }
    );
    assert_eq!(row.reason.as_deref(), Some("no_forge_association"));
}

#[test]
fn a_revoked_binding_settles_with_a_reason() {
    if !prerequisites() {
        return;
    }
    let f = fixture();
    let accepted = f.accept_push("gone-1", REF, &f.commits[0], &f.commits[1]);
    let _ = f.validate(accepted);
    let owner = f
        .store
        .read(|c| {
            Ok(c.query_row("SELECT id FROM users LIMIT 1", [], |r| {
                r.get::<_, [u8; 16]>(0)
            })?)
        })
        .map(|b| UserId::from_bytes(b).unwrap())
        .unwrap();
    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| {
            sources::revoke(
                tx,
                sentinel_store::registration::Authority::HostLocal,
                Some(owner),
                repo,
                1,
                UnixMillis::now(),
            )
        })
        .unwrap();
    let (outcome, row) = f.resolve(accepted);
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "binding_revoked",
            detail: None
        }
    );
    assert_eq!(row.reason.as_deref(), Some("binding_revoked"));
}
