//! S07's gate: one canary value through the real delivery path, end to end.
//!
//! The store binds it, the preparation transaction resolves it and audits its use, the worker stages it as the
//! env file and file mount, a real `/bin/sh` wrapper sources it, the attempt's log pipe redacts every form of it
//! before the spool holds a byte, the failure excerpt is redacted too, and the staging directories are gone
//! afterwards. Every path a value touches is scanned for it: the spool, the worker's data and runtime
//! directories, the sealed database and the audit rows.
//!
//! What this does not run is the sandbox: it needs rootless Podman (or a KVM host), which the verification hosts
//! that run this test may not have. The two mounts are therefore staged at their real paths but bound into this
//! process's file system by substituting [`SECRET_ENV_MOUNT`] and [`SECRET_FILES_MOUNT`] with the directories the
//! container would mount them from — the substitution a container makes, as `env_targets_reach_the_step_exactly_
//! through_the_wrapper` above does for the env file alone. The container leg (`podman exec`, the read-only bind
//! mounts, `Container::clear_strays`) is covered by `tests/secret_isolation.rs` and `tests/end_to_end.rs` under
//! `SENTINEL_PODMAN_TESTS=1`.

use std::{path::Path, sync::Arc};

use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{
    DeliveryId, Fence, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    logs::Stream,
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
    secrets::DeliveryBundle,
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    intake::Authentication,
    provenance::{self, Provenance},
    runs,
    secrets::{self, Binding, Scope},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

use super::{
    Output, SECRET_ENV_MOUNT, SECRET_FILES_MOUNT, SecretDirectory, materialize_step_secrets,
    secret_root, wrap_with_env,
};

const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// At least four bytes so it is redactable, distinctive so a scan can find it, and holding characters that a
// percent-encoded form must escape.
const CANARY: &str = "canary-6f1d/2a9e+0b7c=4d3e8f5a";

fn base64(value: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in value.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |acc, (at, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * at))
        });
        for at in 0..=chunk.len() {
            out.push(TABLE[((bits >> (18 - 6 * at)) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

fn percent(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 15)] as char);
        }
    }
    out
}

fn tree_contains(root: &Path, needle: &[u8]) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if tree_contains(&path, needle)? {
                return Ok(true);
            }
        } else if kind.is_file()
            && std::fs::read(&path)?
                .windows(needle.len())
                .any(|window| window == needle)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

struct Deployment {
    dir: tempfile::TempDir,
    store: Store,
    root: UserId,
    tenant: TenantId,
    repo: RepoId,
    spec: RunSpec,
    bundle: DeliveryBundle,
    attempt: sentinel_core::AttemptId,
}

fn deploy() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool, worker) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        sentinel_core::PoolId::new(),
        WorkerId::new(),
    );
    let admin = Principal::new(root, P::ALL, None, None);
    store
        .writer()
        .write({
            let key = Arc::clone(&key);
            move |tx| {
                provisioning::insert_human(tx, root, "root", true, NOW)?;
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
                auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
                auth::create_repo(tx, admin, tenant, repo, "app", NOW)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    PoolKind::Dedicated(tenant),
                    NOW,
                )?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
                let mut enrollment = String::new();
                issued.secret.expose(&mut enrollment);
                workers::enroll(
                    tx,
                    &Secret::parse(&enrollment).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "canary-worker",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(10),
                            capabilities: Capabilities(
                                Capabilities::REQUIRED.0 | Capabilities::SECRET_DELIVERY.0,
                            ),
                            arch: Arch::X86_64,
                        },
                    },
                    NOW,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    Capacity {
                        cpu_millis: 4_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 1 << 40,
                    },
                )?;
                let token = secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "CANARY_TOKEN",
                        expected: 0,
                        value: CANARY.as_bytes(),
                    },
                    &key,
                    NOW,
                )?;
                secrets::bind(
                    tx,
                    admin,
                    &Binding {
                        repo,
                        job: "use".into(),
                        step: "read".into(),
                        name: "CANARY_TOKEN".into(),
                        secret: token.id,
                        override_tenant: false,
                    },
                    NOW,
                )?;
                Ok(())
            }
        })
        .unwrap();

    // The encodings are produced by the step itself, never written into the pipeline: a script that named them
    // would store them in the run spec, where no redactor has ever been asked to look.
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  use:\n    image: busybox@{DIGEST}\n    \
         resources: {{ cpu: 1, memory: 128MiB }}\n    secrets: [CANARY_TOKEN]\n    steps:\n      \
         - id: read\n        run: 'printf \"env=%s\\n\" \"$CANARY_TOKEN\"; \
         printf \"file=%s\\n\" \"$(cat {SECRET_FILES_MOUNT}/tls/client.pem)\"; \
         printf \"b64=%s\\n\" \"$(printf %s \"$CANARY_TOKEN\" | base64 -w0)\"; \
         printf \"pct=%s\\n\" \"$(printf %s \"$CANARY_TOKEN\" | sed -e s,/,%2F,g -e s,+,%2B,g -e s,=,%3D,g)\"; \
         printf \"fatal: %s\\n\" \"$(printf %s \"$CANARY_TOKEN\" | base64 -w0)\" 1>&2'\n        \
         secrets: [CANARY_TOKEN]\n        secret_files: {{ CANARY_TOKEN: tls/client.pem }}\n"
    );
    let spec = RunSpec::new(
        PinnedSource::new("https://example.test/acme/app.git", SHA, Some("main")).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap();

    let run = RunId::new();
    let (tenant, repo) = (tenant, repo);
    let jobs = store
        .writer()
        .write({
            let spec = spec.clone();
            move |tx| {
                let jobs = runs::create_run(tx, tenant, repo, run, &spec, NOW)?;
                runs::resolve_image(tx, tenant, jobs[0], DIGEST, "linux/amd64")?;
                let delivery = DeliveryId::new();
                tx.execute(
                    "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
                        event, ref_name, old_sha, new_sha, state, received_ms, settled_ms, authentication)
                     VALUES (?1, ?2, ?3, 'github', ?4, 'push', 'refs/heads/main', ?5, ?5, 2, ?6, ?6, ?7)",
                    rusqlite::params![
                        delivery.as_bytes(),
                        tenant.as_bytes(),
                        repo.as_bytes(),
                        delivery.to_string(),
                        SHA,
                        NOW.0,
                        Authentication::SignedWebhook as i64
                    ],
                )?;
                provenance::insert(
                    tx,
                    &Provenance {
                        tenant,
                        repo,
                        trigger: "push".into(),
                        provider: Some("github".into()),
                        delivery: Some(delivery),
                        ref_name: Some("refs/heads/main".into()),
                        old_sha: None,
                        new_sha: Some(SHA.into()),
                        head_sha: None,
                        base_sha: None,
                        merge_sha: None,
                        pipeline_sha: SHA.into(),
                        pipeline_path: Some(".sentinel.yml".into()),
                        pipeline_digest: [0; 16],
                        pr_number: None,
                        group_ref: None,
                    },
                    run,
                    NOW,
                )?;
                Ok(jobs)
            }
        })
        .unwrap();

    let offer = store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW))
        .unwrap()
        .expect("a job to place");
    assert_eq!(offer.job, jobs[0]);
    let (attempt, fence) = (offer.attempt, offer.fence);
    store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, worker, attempt, fence, NOW))
        .unwrap();

    // The controller's own entry point: the writer transaction that resolves the binding and audits the use.
    let prepared = secrets::deliver(&store, key, worker, attempt, NOW).unwrap();
    assert_eq!(prepared.fence, Fence(offer.fence.0));
    let bundle: DeliveryBundle = postcard::from_bytes(prepared.encoded.as_slice()).unwrap();

    Deployment {
        dir,
        store,
        root,
        tenant,
        repo,
        spec,
        bundle,
        attempt,
    }
}

#[test]
fn a_canary_binds_runs_redacts_and_is_cleaned_up_without_a_sandbox() {
    let deployment = deploy();
    let Deployment {
        store,
        repo,
        spec,
        bundle,
        attempt,
        ..
    } = &deployment;
    let (repo, attempt) = (*repo, *attempt);

    // The preparation resolved exactly the declared target, one value, and audited its use.
    assert!(bundle.valid());
    assert_eq!(bundle.values.len(), 1);
    assert_eq!(bundle.values[0].expose(), CANARY.as_bytes());
    assert_eq!(bundle.targets.len(), 2);
    // The worker's own gate accepts what the store delivered for this run spec.
    assert!(crate::executor::valid_delivery(spec, 0, bundle));
    let audit: Vec<(String, String, Option<String>)> = store
        .read(|conn| {
            let mut statement =
                conn.prepare("SELECT action,result,step FROM secret_audit ORDER BY at_ms,rowid")?;
            Ok(statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?)
        })
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|(action, result, step)| action == "create" && result == "ok" && step.is_none()),
        "{audit:?}"
    );
    assert!(
        audit
            .iter()
            .any(|(action, result, _)| action == "bind" && result == "ok"),
        "{audit:?}"
    );
    assert!(
        audit
            .iter()
            .any(|(action, result, step)| action == "use" && result == "ok" && step.is_some()),
        "{audit:?}"
    );

    // The worker registers the delivered value before its log pipe opens, exactly as the executor does.
    let data = deployment.dir.path().join("worker");
    std::fs::create_dir_all(&data).unwrap();
    let mut redactor = crate::redact::Redactor::new();
    for value in &bundle.values {
        assert!(redactor.register(value.expose()));
    }
    let pipe = crate::logpipe::LogPipe::open(&data, attempt, redactor, None).unwrap();

    let directory = SecretDirectory::create(&data, attempt).unwrap();
    let staged = materialize_step_secrets(&directory, bundle, 0).unwrap();

    // The env file and the file mount hold the value, outside the workspace the steps write into.
    let env_file = staged.env_file.clone().expect("an env file");
    assert!(env_file.starts_with(secret_root(&data)));
    assert_eq!(
        std::fs::read(&env_file).unwrap(),
        format!("export CANARY_TOKEN='{CANARY}'\n").as_bytes()
    );
    let cert = directory.files_dir.join("tls/client.pem");
    assert_eq!(std::fs::read(&cert).unwrap(), CANARY.as_bytes());
    assert!(!env_file.starts_with(data.join(crate::workspace::WORKSPACES_DIR)));

    // A real shell sources the wrapper exactly as a step does, with the two mounts substituted the way the
    // container's bind mounts would place them.
    let mut command = spec.step_command(0, 0).expect("the step");
    let argv = wrap_with_env(std::mem::take(&mut command.argv), 0);
    assert!(argv.iter().all(|arg| !arg.contains(CANARY)));
    let argv: Vec<String> = argv
        .iter()
        .map(|arg| {
            arg.replace(SECRET_ENV_MOUNT, &directory.env_dir.display().to_string())
                .replace(
                    SECRET_FILES_MOUNT,
                    &directory.files_dir.display().to_string(),
                )
        })
        .collect();
    let run = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(CANARY),
        "the step never saw its secret"
    );

    // The scan finds the value while it is staged, so an empty result later means something.
    assert!(tree_contains(&data, CANARY.as_bytes()).unwrap());

    // Every form of it, fed in chunks that split the values across reads, is redacted before the spool.
    for chunk in run.stdout.chunks(5) {
        pipe.write(0, Stream::Stdout, chunk);
    }
    for chunk in run.stderr.chunks(7) {
        pipe.write(0, Stream::Stderr, chunk);
    }
    // `step_done` releases the carry, so every byte the step printed is in the spool now.
    pipe.step_done(0);
    // What the log store would receive: the frames the pipe spooled, in order.
    let mut spool = crate::spool::Spool::open(&data, attempt).unwrap();
    let frames = spool.send_next(64).unwrap();
    let stored: Vec<u8> = frames
        .iter()
        .flat_map(|frame| frame.bytes.iter().copied())
        .collect();
    let text = String::from_utf8_lossy(&stored).into_owned();
    assert!(!text.is_empty(), "the pipe stored nothing");
    for expected in ["env=***", "file=***", "b64=***", "pct=***"] {
        assert!(
            text.contains(expected),
            "{expected} missing from {:?}",
            text.escape_debug().to_string()
        );
    }
    for encoded in [
        CANARY.as_bytes(),
        base64(CANARY.as_bytes()).as_bytes(),
        percent(CANARY.as_bytes()).as_bytes(),
    ] {
        assert!(
            !stored
                .windows(encoded.len())
                .any(|window| window == encoded),
            "{} reached the spool",
            String::from_utf8_lossy(encoded)
        );
    }

    // The failure excerpt a diagnostic carries holds no form of the value either, composed the way
    // finalization does: the excerpt from the raw stderr, then the attempt's redactor over the detail.
    let excerpt = pipe.excerpt(&run.stderr);
    let detail = pipe.redact(format!("step 0: {excerpt}"));
    for encoded in [
        CANARY.as_bytes(),
        base64(CANARY.as_bytes()).as_bytes(),
        percent(CANARY.as_bytes()).as_bytes(),
    ] {
        let encoded = String::from_utf8_lossy(encoded).into_owned();
        assert!(!detail.contains(&encoded), "{detail}");
        assert!(!excerpt.contains(&encoded), "{excerpt}");
    }
    assert!(detail.contains("***"), "{detail}");

    // Teardown: the step's staging, then the attempt's directory — what the executor's own drop does on
    // success, on failure and on cancel — and nothing of the value anywhere under the worker's data root.
    drop(staged);
    assert!(!env_file.exists());
    assert!(!cert.exists());
    drop(directory);
    assert!(!secret_root(&data).join(attempt.to_string()).exists());
    assert!(!tree_contains(&data, CANARY.as_bytes()).unwrap());
    assert!(!tree_contains(&data, base64(CANARY.as_bytes()).as_bytes()).unwrap());

    // Nothing in the sealed database, its write-ahead log or the audit trail holds the value either.
    let database = deployment.dir.path().join("metadata.sqlite");
    let mut db_bytes = std::fs::read(&database).unwrap();
    for suffix in ["-wal", "-shm"] {
        if let Ok(bytes) = std::fs::read(format!("{}-{suffix}", database.display())) {
            db_bytes.extend_from_slice(&bytes);
        }
    }
    for encoded in [CANARY.as_bytes(), base64(CANARY.as_bytes()).as_bytes()] {
        assert!(
            !db_bytes
                .windows(encoded.len())
                .any(|window| window == encoded),
            "the database holds {}",
            String::from_utf8_lossy(encoded)
        );
    }
    let admin = Principal::new(deployment.root, P::ALL, None, None);
    let listed = store
        .read(|conn| secrets::describe(conn, admin, Scope::Repo(repo), "CANARY_TOKEN"))
        .unwrap();
    assert_eq!((listed.version, listed.tenant), (1, deployment.tenant));
    assert!(!format!("{listed:?}").contains(CANARY));
}
