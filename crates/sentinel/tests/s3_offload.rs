//! R02/R03 end to end against real S3 services: the controller's
//! replicator over `sentinel_s3`, for every endpoint `$SENTINEL_S3_ENDPOINTS`
//! lists (`crates/sentinel-s3/tests/endpoints.sh`). Without the variable it
//! reports that it was skipped, never a false pass.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::sync::Arc;

use sentinel::offload::S3Bucket;
use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_s3::{Client, Config, Credentials};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    logs::LogStore,
    objects::{self, Digest, Expect, Objects, Remote},
    offload,
    replicate::{Bucket, Replicator, Settings},
    space::{Admission, Watermarks},
};

struct Endpoint {
    name: String,
    endpoint: String,
    region: String,
    bucket: String,
    path_style: bool,
    credentials: std::path::PathBuf,
}

fn endpoints() -> Option<Vec<Endpoint>> {
    let list = std::env::var_os("SENTINEL_S3_ENDPOINTS")?;
    let only = std::env::var("SENTINEL_S3_ONLY").ok();
    let text = std::fs::read_to_string(list).unwrap();
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                Endpoint {
                    name: f[0].into(),
                    endpoint: f[1].into(),
                    region: f[2].into(),
                    bucket: f[3].into(),
                    path_style: f[4] == "true",
                    credentials: f[5].into(),
                }
            })
            .filter(|e| {
                only.as_ref()
                    .is_none_or(|o| o.split(',').any(|n| n == e.name))
            })
            .collect(),
    )
}

fn client(e: &Endpoint, endpoint: &str, prefix: &str) -> Client {
    let (connect, read) = sentinel_s3::client::default_timeouts();
    Client::new(Config {
        endpoint: endpoint.into(),
        region: e.region.clone(),
        bucket: e.bucket.clone(),
        prefix: prefix.into(),
        path_style: e.path_style,
        ca_file: None,
        credentials: Credentials::from_file(&e.credentials).unwrap(),
        connect_timeout: connect,
        read_timeout: read,
    })
    .unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    tenant: TenantId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let (root, tenant) = (UserId::new(), TenantId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )
        })
        .unwrap();
    Fixture {
        dir,
        store,
        objects,
        logs,
        tenant,
    }
}

impl Fixture {
    fn put(&self, body: &[u8]) -> Digest {
        let staged = self
            .objects
            .stage(self.tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        digest
    }
    fn read(&self, digest: Digest) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.store
            .read(|c| self.objects.read(c, self.tenant, digest, &mut out))?;
        Ok(out)
    }
    fn local(&self, digest: Digest) -> bool {
        let hex = digest.to_string();
        self.dir
            .path()
            .join("objects")
            .join(self.tenant.to_string())
            .join(&hex[..2])
            .join(&hex)
            .exists()
    }
    fn replicator(&self, bucket: Arc<S3Bucket>, settings: Settings) -> Replicator {
        Replicator::new(
            Arc::clone(&self.store),
            Arc::clone(&self.objects),
            Arc::clone(&self.logs),
            bucket as Arc<dyn Bucket>,
            settings,
        )
    }
}

const SETTINGS: Settings = Settings {
    part_bytes: 5 << 20,
    local_bytes: 0,
    backlog_bytes: 0,
};

fn scenario(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let f = fixture();
    let bucket = Arc::new(S3Bucket::new(client(e, &e.endpoint, prefix)));
    f.objects.set_remote(Arc::clone(&bucket) as Arc<dyn Remote>);
    let admission = Arc::new(
        Admission::with_probe(
            Watermarks {
                reserve: 1 << 20,
                low: 1 << 20,
                high: 2 << 20,
                floor: 1 << 17,
            },
            || Ok(1 << 40),
        )
        .unwrap(),
    );
    f.objects.set_admission(Arc::clone(&admission));

    // Copied and verified: one request and a multipart upload.
    let small = f.put(b"a small artifact");
    let big: Vec<u8> = (0..(11u32 << 20)).map(|i| (i % 249) as u8).collect();
    let large = f.put(&big);
    let r = f.replicator(Arc::clone(&bucket), SETTINGS);
    let pass = r.pass()?;
    if pass.replicated != 2 {
        return Err(format!("replicated {} of 2", pass.replicated));
    }
    let head = bucket
        .head(&objects::remote_key(f.tenant, &large))
        .map_err(|x| x.message)?;
    if head != Some((big.len() as u64, Some(large.to_string()))) {
        return Err(format!("the multipart copy reads back as {head:?}"));
    }

    // Evicted, then fetched back verified on read.
    let r = f.replicator(
        Arc::clone(&bucket),
        Settings {
            local_bytes: 1,
            ..SETTINGS
        },
    );
    r.pass()?;
    if f.local(small) || f.local(large) {
        return Err("eviction left a local copy".into());
    }
    if f.read(large).map_err(|x| x.to_string())? != big
        || f.read(small).map_err(|x| x.to_string())? != b"a small artifact"
    {
        return Err("a fetched-back object differs".into());
    }
    r.pass()?;
    let totals = f.store.read(offload::totals).map_err(|x| x.to_string())?;
    if totals.local_bytes != 0 {
        // The one-byte budget evicts them again right away.
        return Err(format!("{} bytes still local", totals.local_bytes));
    }

    // A multipart upload a crash interrupted after its first part resumes.
    let body: Vec<u8> = (0..(10u32 << 20) + 3).map(|i| (i % 241) as u8).collect();
    let resumed = f.put(&body);
    let key = objects::remote_key(f.tenant, &resumed);
    let id = bucket
        .create_multipart(&key, Some(&resumed.to_string()))
        .map_err(|x| x.message)?;
    bucket
        .upload_part(&key, &id, 1, &body[..5 << 20])
        .map_err(|x| x.message)?;
    let (k, i) = (key.clone(), id.clone());
    f.store
        .writer()
        .write(move |tx| offload::record_upload(tx, &k, &i, 5 << 20, UnixMillis::now()))
        .map_err(|x| x.to_string())?;
    let r = f.replicator(Arc::clone(&bucket), SETTINGS);
    r.pass()?;
    let head = bucket.head(&key).map_err(|x| x.message)?;
    if head.as_ref().map(|h| h.0) != Some(body.len() as u64) {
        return Err(format!("the resumed upload reads back as {head:?}"));
    }

    // An outage: a replicator pointed at nothing fills the backlog past its
    // budget and closes admission; the real one drains it and reopens.
    let dead = Arc::new(S3Bucket::new(client(e, "http://127.0.0.1:9", prefix)));
    let down = f.replicator(
        dead,
        Settings {
            backlog_bytes: 3 << 20,
            ..SETTINGS
        },
    );
    for i in 0..4u8 {
        f.put(&vec![i; 1 << 20]);
    }
    if down.pass().is_ok() || admission.is_open() || down.status().state() != "degraded" {
        return Err("an unreachable bucket did not degrade and close admission".into());
    }
    let up = f.replicator(
        Arc::clone(&bucket),
        Settings {
            backlog_bytes: 3 << 20,
            ..SETTINGS
        },
    );
    up.pass()?;
    if !admission.is_open()
        || up
            .status()
            .backlog_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0
    {
        return Err("draining the backlog did not reopen admission".into());
    }

    // A reclaimed object's copy is deleted.
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                (tenant.as_bytes().as_slice(), small.as_bytes().as_slice()),
            )?;
            Ok(())
        })
        .map_err(|x| x.to_string())?;
    up.pass()?;
    if bucket
        .head(&objects::remote_key(f.tenant, &small))
        .map_err(|x| x.message)?
        .is_some()
    {
        return Err("a reclaimed object's copy stayed".into());
    }
    // Leave the bucket as found.
    for key in bucket.list("").map_err(|x| x.message)? {
        bucket.delete(&key).map_err(|x| x.message)?;
    }
    Ok(())
}

#[test]
fn the_replicator_against_real_s3_services() {
    let Some(endpoints) = endpoints() else {
        eprintln!(
            "skipped: set SENTINEL_S3_ENDPOINTS (crates/sentinel-s3/tests/endpoints.sh writes it)"
        );
        return;
    };
    let prefix = format!("offload-{}/", std::process::id());
    let mut failures = Vec::new();
    for e in &endpoints {
        match scenario(e, &prefix) {
            Ok(()) => println!("| {} | pass |", e.name),
            Err(why) => {
                println!("| {} | FAIL |", e.name);
                failures.push(format!("{}: {why}", e.name));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
