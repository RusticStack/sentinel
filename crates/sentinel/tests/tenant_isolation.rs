//! The CLI as one camp's member sees the other camp: an owner administering
//! `rusticstack` and a colleague administering `mutualismo`, each with only
//! their own `sntl_` credential. Everything of the owner's the colleague
//! names (run, job, attempt, queue, workers, dispatch) exits `not_found`
//! (4) with the very message and JSON document a guessed identifier gets;
//! the same commands work for the owner (so the refusals are not typos).

use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::Arc,
};

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    objects::Objects,
    runs,
    tokens::{self, Grant},
};
use serde_json::Value;

const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

struct Camp {
    token: PathBuf,
    org: &'static str,
    run: RunId,
    job: JobId,
}

struct Deployment {
    dir: tempfile::TempDir,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
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

fn camp(
    store: &Store,
    dir: &tempfile::TempDir,
    root: UserId,
    (org, name, token): (&'static str, &'static str, &str),
) -> Camp {
    let (user, tenant, repo, run) = (UserId::new(), TenantId::new(), RepoId::new(), RunId::new());
    let now = UnixMillis::now();
    let spec = RunSpec::new(
        PinnedSource::new(
            "https://github.com/o/r.git",
            "0123456789abcdef0123456789abcdef01234567",
            Some("refs/heads/main"),
        )
        .unwrap(),
        compile_str(&format!(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: docker.io/library/busybox@{DIGEST}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ))
        .unwrap(),
    )
    .unwrap();
    let job = store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            provisioning::insert_human(tx, user, name, false, now)?;
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse(org).unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, user, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)?;
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids[0])
        })
        .unwrap();
    let issued = tokens::provision(
        store,
        Grant::new(user, "cli", P::REPOSITORY.union(P::TENANT_ADMIN)),
        UnixMillis::now(),
    )
    .unwrap();
    let path = dir.path().join(token);
    std::fs::write(&path, sentinel_auth::token::format(&issued.secret)).unwrap();
    Camp {
        token: path,
        org,
        run,
        job,
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery",
        UnixMillis::now(),
    )
    .unwrap();
    let owner = camp(
        &store,
        &dir,
        root,
        ("rusticstack", "Olivia", "olivia.token"),
    );
    let colleague = camp(&store, &dir, root, ("mutualismo", "Carlos", "carlos.token"));
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
        logs,
        objects,
        controller: controller.handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        secret_key: None,
    })
    .unwrap();
    Deployment {
        base: format!("http://{}", server.local_addr()),
        dir,
        _controller: controller,
        server: Some(server),
        owner,
        colleague,
    }
}

fn api(d: &Deployment, token: &PathBuf, args: &[&str]) -> Output {
    // `--json` belongs to `sentinel api`, before the subcommand.
    let (json, args) = match args.split_last() {
        Some((&"--json", rest)) => (true, rest),
        _ => (false, args),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel"));
    command.arg("api");
    if json {
        command.arg("--json");
    }
    command
        .arg("--server")
        .arg(&d.base)
        .arg("--token-file")
        .arg(token)
        .args(args)
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", d.dir.path().join("config"))
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The commands that name something of a camp, with `names` standing for
/// its tenant slug, run, job and attempt.
fn commands(org: &str, run: &str, job: &str, attempt: &str) -> Vec<Vec<String>> {
    let own = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    vec![
        own(&["status", run, "--json"]),
        own(&["logs", attempt, "--json"]),
        own(&["cancel", "--run", run, "--json"]),
        own(&["rerun", job, "--json"]),
        own(&["queue", "--tenant", org, "--json"]),
        own(&["workers", "--tenant", org, "--json"]),
    ]
}

#[test]
fn the_other_camp_gets_not_found_with_the_same_document_a_guess_gets() {
    let d = deployment();
    for (attacker, victim) in [(&d.colleague, &d.owner), (&d.owner, &d.colleague)] {
        let (run, job) = (victim.run.to_string(), victim.job.to_string());
        let attempt = AttemptId::new().to_string();
        let real = commands(victim.org, &run, &job, &attempt);
        let (guess_run, guess_job) = (RunId::new().to_string(), JobId::new().to_string());
        let guessed = commands("no-such-organization", &guess_run, &guess_job, &attempt);
        for (real, guess) in real.iter().zip(&guessed) {
            let args: Vec<&str> = real.iter().map(String::as_str).collect();
            let refused = api(&d, &attacker.token, &args);
            let args: Vec<&str> = guess.iter().map(String::as_str).collect();
            let missing = api(&d, &attacker.token, &args);
            assert_eq!(code(&refused), 4, "{real:?}: {}", text(&refused.stderr));
            assert_eq!(code(&missing), 4, "{guess:?}");
            assert!(refused.stdout.is_empty(), "{real:?}");
            let normalize = |output: &Output, names: &[&str]| {
                let mut body = text(&output.stderr);
                for name in names {
                    body = body.replace(name, "_");
                }
                body
            };
            assert_eq!(
                normalize(
                    &refused,
                    &[
                        victim.org,
                        &run,
                        &job,
                        &guess_run,
                        &guess_job,
                        "no-such-organization"
                    ]
                ),
                normalize(
                    &missing,
                    &[
                        victim.org,
                        &run,
                        &job,
                        &guess_run,
                        &guess_job,
                        "no-such-organization"
                    ]
                ),
                "{real:?}"
            );
            let document: Value = serde_json::from_str(text(&refused.stderr).trim()).unwrap();
            assert_eq!(document["code"], "not_found");
        }
        // Dispatch into the other camp's repository: refused like a missing one.
        let pipeline = d.dir.path().join(".sentinel.yml");
        std::fs::write(
            &pipeline,
            format!(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: docker.io/library/busybox@{DIGEST}\n    steps: [{{ id: s, run: 'true' }}]\n"
            ),
        )
        .unwrap();
        let pipeline = pipeline.to_string_lossy().into_owned();
        for org in [victim.org, "no-such-organization"] {
            let refused = api(
                &d,
                &attacker.token,
                &[
                    "run",
                    "--tenant",
                    org,
                    "--repo",
                    "app",
                    "--pipeline",
                    &pipeline,
                    "--source",
                    "https://github.com/o/r.git",
                    "--sha",
                    "0123456789abcdef0123456789abcdef01234567",
                    "--ref",
                    "main",
                    "--json",
                ],
            );
            assert_eq!(code(&refused), 4, "{org}: {}", text(&refused.stderr));
        }
    }
}

#[test]
fn the_same_commands_work_for_the_camp_that_owns_the_things() {
    let d = deployment();
    for camp in [&d.owner, &d.colleague] {
        let run = camp.run.to_string();
        for args in [
            vec!["status", run.as_str(), "--json"],
            vec!["queue", "--tenant", camp.org, "--json"],
            vec!["workers", "--tenant", camp.org, "--json"],
        ] {
            let output = api(&d, &camp.token, &args);
            assert_eq!(code(&output), 0, "{args:?}: {}", text(&output.stderr));
            let document: Value = serde_json::from_str(text(&output.stdout).trim()).unwrap();
            assert!(!document.to_string().contains("rusticstack") || camp.org == "rusticstack");
            assert!(!document.to_string().contains("mutualismo") || camp.org == "mutualismo");
        }
        // `me` names the caller and nothing of the other camp.
        let me = api(&d, &camp.token, &["me", "--json"]);
        assert_eq!(code(&me), 0, "{}", text(&me.stderr));
        let other = if camp.org == "rusticstack" {
            "mutualismo"
        } else {
            "rusticstack"
        };
        assert!(!text(&me.stdout).contains(other));
    }
}
