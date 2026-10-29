use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_cache::{
    attach::{self, Attached, Stats},
    clone::Backend,
    manifest::{Compat, FileEntry, FilesBlob, Manifest},
    outcome::{Miss, Outcome},
    remote::{self, Chunk, Grant, Need, Refusal, Remote, Sink, Upload},
    restore::{self, Context},
    scope::{self, Os, Platform, Scope},
};
use sentinel_core::{AttemptId, RepoId, TenantId, UnixMillis};
use sentinel_pipeline::{expr::Template, schema::Cache};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};

const KEY: &str = "deps-abc123";
const CHUNK: usize = 4096;

fn test_scope(trust: Trust) -> Scope {
    Scope::new(
        TenantId::new(),
        RepoId::new(),
        Class::Dependencies,
        trust,
        Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        },
        Scope::toolchain_digest(b"remote hydration test"),
        "deps",
    )
    .unwrap()
}

fn decl(paths: &[&str]) -> Cache {
    Cache {
        name: "deps".into(),
        class: Class::Dependencies,
        key: Template::parse(KEY).unwrap(),
        paths: paths.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn env<'a>(root: &'a Path, ws: &'a Path) -> Context<'a> {
    Context {
        cache_root: root,
        workspace: ws,
        workspace_mount: "/workspace",
        backend: Backend::Copy,
    }
}

fn entry_of(root: &Path, scope: &Scope) -> PathBuf {
    scope.entry_dir(root, attach::entry_key(scope.class, KEY))
}

fn seal_generation(
    root: &Path,
    scope: &Scope,
    files: &[(&str, &[u8])],
    generation: &str,
) -> String {
    let entry = entry_of(root, scope);
    let dir = entry.join(generation);
    fs::create_dir_all(&dir).unwrap();
    let mut entries = Vec::new();
    for (rel, bytes) in files {
        let path = format!("payload/0/{rel}");
        let file = dir.join(&path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        entries.push(FileEntry {
            path,
            size: bytes.len() as u64,
            digest: *blake3::hash(bytes).as_bytes(),
            mode: 0o644,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let blob = FilesBlob { entries };
    let encoded = blob.encode();
    let mut manifest = Manifest::writing(scope, KEY, compat(scope));
    manifest.bytes = blob.entries.iter().map(|e| e.size).sum();
    manifest.files = blob.entries.len() as u32;
    manifest.files_digest = blob.digest();
    manifest.seal(UnixMillis(1_500_000));
    fs::write(dir.join(scope::FILES_NAME), &encoded).unwrap();
    fs::write(dir.join(scope::MANIFEST_NAME), manifest.encode()).unwrap();
    generation.to_owned()
}

fn compat(scope: &Scope) -> Compat {
    attach::declared_compat(&decl(&["vendor"]), KEY, scope.platform)
}

fn attached_for(scope: &Scope) -> Attached {
    Attached {
        name: scope.name.clone(),
        scope: scope.clone(),
        key: KEY.to_owned(),
        compat: compat(scope),
        generation: None,
        outcome: Outcome::Miss(Miss::Absent),
        targets: Vec::new(),
        lease: None,
        stats: Stats::default(),
    }
}

/// Deadline far past any run, so the wall-clock restore budget never aborts these behavior tests.
fn policy<'a>(source: &'a dyn Remote) -> remote::Policy<'a> {
    remote::Policy {
        source,
        attempt: *AttemptId::new().as_bytes(),
        deadline: Instant::now() + Duration::from_secs(24 * 3600),
        budget_bytes: remote::STORE_BUDGET_BYTES,
    }
}

fn entry_id(repo: [u8; 16], name: &str, key: &str) -> String {
    let mut hex = String::with_capacity(32);
    for byte in repo {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{hex}/{name}/{key}")
}

#[derive(Default)]
struct Fake {
    bundles: Mutex<HashMap<String, Vec<u8>>>,
    interrupt: Mutex<Option<u64>>,
    corrupt: Mutex<Option<usize>>,
    busy: Mutex<bool>,
    fetches: AtomicUsize,
    offers: AtomicUsize,
    transfers: Mutex<Vec<(u64, u64)>>,
    at_end: bool,
    offered: Mutex<Vec<[u8; 32]>>,
    outlast: Mutex<bool>,
}

impl Fake {
    fn stored(&self, scope: &Scope) -> Option<Vec<u8>> {
        let id = entry_id(*scope.repo.as_bytes(), &scope.name, KEY);
        self.bundles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
    }

    fn move_bundle(&self, from: &Scope, to: &Scope) {
        let from = entry_id(*from.repo.as_bytes(), &from.name, KEY);
        let to = entry_id(*to.repo.as_bytes(), &to.name, KEY);
        let mut bundles = self.bundles.lock().unwrap_or_else(|p| p.into_inner());
        let stream = bundles.remove(&from).expect("source bundle");
        bundles.insert(to, stream);
    }

    fn transfer(&self, offset: u64, served: u64) {
        self.transfers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((offset, served));
    }
}

impl Remote for Fake {
    fn fetch(&self, need: &Need, deadline: Instant, sink: &mut dyn Sink) -> Result<(), Refusal> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let outlast = std::mem::take(&mut *self.outlast.lock().unwrap_or_else(|p| p.into_inner()));
        if std::mem::take(&mut *self.busy.lock().unwrap_or_else(|p| p.into_inner())) {
            return Err(Refusal::Busy);
        }
        let id = entry_id(need.repo, &need.name, &need.key);
        let Some(stream) = self
            .bundles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
        else {
            return Err(Refusal::NoBundle);
        };
        let total = stream.len() as u64;
        let requested = need.offset.min(total);
        let prefix = *blake3::hash(&stream[..requested as usize]).as_bytes();
        let offset = if requested == 0 || prefix == need.have {
            requested
        } else {
            0
        };
        sink.plan(&Grant {
            attempt: need.attempt,
            total,
            offset,
            prefix: *blake3::hash(&stream[..offset as usize]).as_bytes(),
            digest: *blake3::hash(&stream).as_bytes(),
        })?;
        let mut pos = offset as usize;
        let mut served = 0u64;
        while pos < stream.len() {
            let end = (pos + CHUNK).min(stream.len());
            let mut bytes = stream[pos..end].to_vec();
            if let Some(at) = self
                .corrupt
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
                && at < bytes.len()
            {
                bytes[at] ^= 0xff;
            }
            let stop = {
                let guard = self.interrupt.lock().unwrap_or_else(|p| p.into_inner());
                guard.is_some_and(|limit| served + bytes.len() as u64 > limit)
            };
            if stop {
                *self.interrupt.lock().unwrap_or_else(|p| p.into_inner()) = None;
                self.transfer(offset, served);
                return Err(Refusal::Store);
            }
            if outlast && served > 0 {
                while Instant::now() < deadline {
                    std::thread::sleep(deadline - Instant::now());
                }
            }
            let outcome = sink.chunk(&Chunk {
                attempt: need.attempt,
                offset: pos as u64,
                bytes,
                prefix: *blake3::hash(&stream[..end]).as_bytes(),
            });
            if let Err(refusal) = outcome {
                self.transfer(offset, served);
                return Err(refusal);
            }
            served += (end - pos) as u64;
            pos = end;
        }
        self.transfer(offset, served);
        Ok(())
    }

    fn offer(
        &self,
        upload: &Upload,
        _deadline: Instant,
        source: &mut dyn Read,
    ) -> Result<[u8; 32], Refusal> {
        self.offers.fetch_add(1, Ordering::SeqCst);
        self.offered.lock().unwrap().push(upload.digest);
        let mut stream = Vec::new();
        source
            .read_to_end(&mut stream)
            .map_err(|_| Refusal::Store)?;
        let digest = *blake3::hash(&stream).as_bytes();
        let stated = if upload.digest == remote::DIGEST_AT_END && self.at_end {
            digest
        } else {
            upload.digest
        };
        if stream.len() as u64 != upload.total || digest != stated {
            return Err(Refusal::Store);
        }
        let id = entry_id(upload.repo, &upload.name, &upload.key);
        self.bundles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, stream);
        Ok(digest)
    }

    fn digest_at_end(&self) -> bool {
        self.at_end
    }
}

struct NeverCalled;

impl Remote for NeverCalled {
    fn fetch(&self, _: &Need, _: Instant, _: &mut dyn Sink) -> Result<(), Refusal> {
        panic!("a local hit must never network");
    }
    fn offer(&self, _: &Upload, _: Instant, _: &mut dyn Read) -> Result<[u8; 32], Refusal> {
        panic!("a local hit must never network");
    }
}

fn offer(fake: &Fake, root: &Path, scope: &Scope, generation: &str) -> [u8; 32] {
    let attached = attached_for(scope);
    remote::offer_generation(
        root,
        &attached,
        generation,
        *AttemptId::new().as_bytes(),
        fake,
        Instant::now() + Duration::from_secs(30),
        &|| false,
    )
    .expect("offer")
}

fn staged_bytes(stage: &Path) -> u64 {
    let prefix = stage.join("prefix.part");
    if prefix.exists() {
        return fs::metadata(prefix).unwrap().len();
    }
    let len = |p: PathBuf| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut total = 40 + len(stage.join(scope::MANIFEST_NAME)) + len(stage.join(scope::FILES_NAME));
    let mut stack = vec![stage.join("payload")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                total += entry.metadata().unwrap().len();
            }
        }
    }
    total
}

fn hydrate(root: &Path, ws: &Path, scope: &Scope, source: &dyn Remote) -> Attached {
    fs::create_dir_all(ws).unwrap();
    restore::restore_remote(
        &env(root, ws),
        &decl(&["vendor"]),
        Some(KEY.to_owned()),
        scope.clone(),
        "attempt-1",
        Some(policy(source)),
    )
}

#[test]
fn cold_hydration_serves_the_job_and_installs_a_local_copy() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let (ws1, ws2) = (temp.path().join("ws1"), temp.path().join("ws2"));
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();

    let generation = seal_generation(
        &root_a,
        &scope,
        &[("lib", b"payload-one"), ("sub/tool", b"tool-bytes")],
        "gen-1500000-0000abcd",
    );
    let fake = Fake::default();
    let digest = offer(&fake, &root_a, &scope, &generation);

    let cold = hydrate(&root_b, &ws1, &scope, &fake);
    let Outcome::Hit(hit) = &cold.outcome else {
        panic!("cold hydrate must serve: {:?}", cold.outcome);
    };
    assert_eq!(hit.bytes, 21);
    let installed = cold
        .generation
        .clone()
        .expect("the served hit names a generation");
    assert!(installed.starts_with("gen-1500000-"), "{installed}");
    assert_eq!(
        cold.stats.remote_from, None,
        "a cold transfer resumes nothing"
    );
    assert!(cold.stats.remote_ns.is_some());
    assert!(cold.stats.remote_bytes > 0);
    assert!(cold.lease.is_some(), "the promoted generation stays pinned");
    assert_eq!(fake.fetches.load(Ordering::SeqCst), 1);

    assert_eq!(fs::read(ws1.join("vendor/lib")).unwrap(), b"payload-one");
    assert_eq!(
        fs::read(ws1.join("vendor/sub/tool")).unwrap(),
        b"tool-bytes"
    );

    let entry = entry_of(&root_b, &scope);
    let current = fs::read_to_string(entry.join(scope::CURRENT_NAME)).unwrap();
    assert_eq!(current.trim(), installed);
    let stored = sentinel_cache::manifest::lookup(
        &entry.join(&installed),
        &sentinel_cache::manifest::Request {
            scope: &scope,
            key: KEY,
            compat: &compat(&scope),
        },
    );
    assert!(matches!(stored, Outcome::Hit(_)), "{stored:?}");

    let warm = hydrate(&root_b, &ws2, &scope, &NeverCalled);
    assert!(
        matches!(warm.outcome, Outcome::Hit(_)),
        "{:?}",
        warm.outcome
    );
    assert_eq!(fs::read(ws2.join("vendor/lib")).unwrap(), b"payload-one");
    assert_eq!(fake.fetches.load(Ordering::SeqCst), 1);
    assert_eq!(fake.offers.load(Ordering::SeqCst), 1);

    let stream = fake.stored(&scope).unwrap();
    assert_eq!(blake3::hash(&stream).as_bytes(), &digest);
    let dir = entry_of(&root_a, &scope).join(&generation);
    let expected = 40
        + fs::read(dir.join(scope::MANIFEST_NAME)).unwrap().len() as u64
        + fs::read(dir.join(scope::FILES_NAME)).unwrap().len() as u64
        + 21;
    assert_eq!(stream.len() as u64, expected);
}

#[test]
fn an_interrupted_transfer_resumes_from_its_partial() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();

    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    let generation = seal_generation(
        &root_a,
        &scope,
        &[("blob", payload.as_slice())],
        "gen-1500000-0000abce",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &scope, &generation);

    *fake.interrupt.lock().unwrap_or_else(|p| p.into_inner()) = Some(16 * 1024);
    let cut = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(
        cut.outcome,
        Outcome::Miss(Miss::Unavailable),
        "{:?}",
        cut.outcome
    );

    let part = entry_of(&root_b, &scope)
        .join(scope::WRITING_NAME)
        .join("remote.stage");
    let partial = staged_bytes(&part);
    let total = fake.stored(&scope).unwrap().len() as u64;
    assert!(partial > 0 && partial < total, "{partial} of {total}");

    let resumed = hydrate(&root_b, &ws, &scope, &fake);
    assert!(
        matches!(resumed.outcome, Outcome::Hit(_)),
        "{:?}",
        resumed.outcome
    );
    assert_eq!(resumed.stats.remote_from, Some(partial));
    let transfers = fake
        .transfers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(transfers.len(), 2);
    assert_eq!(transfers[0].1, partial, "the cut left exactly this prefix");
    assert_eq!(
        transfers[1].0, partial,
        "the resume starts where it stopped"
    );
    assert_eq!(
        transfers[1].1,
        total - partial,
        "the resumed transfer re-sent no prefix"
    );
    assert_eq!(fs::read(ws.join("vendor/blob")).unwrap(), payload);
    assert!(!part.exists(), "a completed hydrate removes its partial");
}

#[test]
fn a_corrupt_chunk_is_a_miss_and_never_serves() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();

    let generation = seal_generation(
        &root_a,
        &scope,
        &[("blob", &[7u8; 8 * 1024])],
        "gen-1500000-0000abcf",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &scope, &generation);

    *fake.corrupt.lock().unwrap_or_else(|p| p.into_inner()) = Some(10);
    let refused = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(
        refused.outcome,
        Outcome::Miss(Miss::Corrupt),
        "{:?}",
        refused.outcome
    );

    assert!(!ws.join("vendor/blob").exists());
    let entry = entry_of(&root_b, &scope);
    assert!(!entry.join(scope::CURRENT_NAME).exists());
    assert!(
        !entry
            .join(scope::WRITING_NAME)
            .join("remote.stage")
            .exists()
    );
    assert!(fake.fetches.load(Ordering::SeqCst) >= 1);
}

#[test]
fn a_bundle_sealed_for_another_scope_never_serves() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    let mut foreign = test_scope(Trust::PullRequest);
    foreign.tenant = scope.tenant;
    foreign.repo = scope.repo;
    fs::create_dir_all(&root_b).unwrap();

    let generation = seal_generation(
        &root_a,
        &foreign,
        &[("blob", b"pull-request bytes")],
        "gen-1500000-0000abd0",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &foreign, &generation);
    fake.move_bundle(&foreign, &scope);

    let refused = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(
        refused.outcome,
        Outcome::Miss(Miss::WrongTrust),
        "{:?}",
        refused.outcome
    );
    assert!(!ws.join("vendor/blob").exists());
    let entry = entry_of(&root_b, &scope);
    assert!(!entry.join(scope::CURRENT_NAME).exists());
    assert!(
        !entry
            .join(scope::WRITING_NAME)
            .join("remote.stage")
            .exists()
    );
}

#[test]
fn a_foreign_head_stops_the_transfer_before_its_payload() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    let mut foreign = test_scope(Trust::PullRequest);
    foreign.tenant = scope.tenant;
    foreign.repo = scope.repo;
    fs::create_dir_all(&root_b).unwrap();
    let payload = vec![3u8; 256 * 1024];
    let generation = seal_generation(
        &root_a,
        &foreign,
        &[("blob", payload.as_slice())],
        "gen-1500000-0000abd3",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &foreign, &generation);
    fake.move_bundle(&foreign, &scope);

    let refused = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(refused.outcome, Outcome::Miss(Miss::WrongTrust));
    let transfers = fake.transfers.lock().unwrap().clone();
    assert_eq!(transfers.len(), 1);
    assert!(
        transfers[0].1 < CHUNK as u64,
        "only the chunk carrying the head was accepted, not {} bytes",
        transfers[0].1
    );
    let entry = entry_of(&root_b, &scope);
    assert!(
        !entry
            .join(scope::WRITING_NAME)
            .join("remote.stage")
            .exists()
    );
    assert!(!ws.join("vendor/blob").exists());
}

#[test]
fn a_controller_without_the_bundle_leaves_the_local_miss() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();

    let other = test_scope(Trust::Protected);
    let generation = seal_generation(
        &root_a,
        &other,
        &[("blob", b"somewhere else")],
        "gen-1500000-0000abd1",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &other, &generation);
    let missed = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(
        missed.outcome,
        Outcome::Miss(Miss::Absent),
        "{:?}",
        missed.outcome
    );
    assert!(
        ws.join("vendor").is_dir(),
        "the declared path stays writable"
    );
    assert!(
        !entry_of(&root_b, &scope)
            .join(scope::WRITING_NAME)
            .join("remote.stage")
            .exists()
    );
}

#[test]
fn a_busy_answer_keeps_a_valid_partial() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 249) as u8).collect();
    let generation = seal_generation(
        &root_a,
        &scope,
        &[("blob", payload.as_slice())],
        "gen-1500000-0000abd2",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &scope, &generation);
    *fake.interrupt.lock().unwrap() = Some(16 * 1024);
    let _ = hydrate(&root_b, &ws, &scope, &fake);
    let part = entry_of(&root_b, &scope)
        .join(scope::WRITING_NAME)
        .join("remote.stage");
    let partial = staged_bytes(&part);
    assert!(partial > 0);
    *fake.busy.lock().unwrap() = true;
    let busy = hydrate(&root_b, &ws, &scope, &fake);
    assert_eq!(busy.outcome, Outcome::Miss(Miss::Absent));
    assert_eq!(staged_bytes(&part), partial, "kept whole");
    let resumed = hydrate(&root_b, &ws, &scope, &fake);
    assert!(resumed.outcome.is_hit(), "{:?}", resumed.outcome);
    assert_eq!(resumed.stats.remote_from, Some(partial));
}

#[test]
fn a_transfer_past_its_deadline_keeps_its_partial_for_the_next_attempt() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();
    fs::create_dir_all(&ws).unwrap();
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 241) as u8).collect();
    let generation = seal_generation(
        &root_a,
        &scope,
        &[("blob", payload.as_slice())],
        "gen-1500000-0000abd3",
    );
    let fake = Fake::default();
    offer(&fake, &root_a, &scope, &generation);
    *fake.outlast.lock().unwrap() = true;
    let short = remote::Policy {
        source: &fake,
        attempt: *AttemptId::new().as_bytes(),
        deadline: Instant::now() + Duration::from_millis(200),
        budget_bytes: remote::STORE_BUDGET_BYTES,
    };
    let late = restore::restore_remote(
        &env(&root_b, &ws),
        &decl(&["vendor"]),
        Some(KEY.to_owned()),
        scope.clone(),
        "attempt-1",
        Some(short),
    );
    assert_eq!(late.outcome, Outcome::Miss(Miss::Unavailable));
    let part = entry_of(&root_b, &scope)
        .join(scope::WRITING_NAME)
        .join("remote.stage");
    let partial = staged_bytes(&part);
    assert!(partial > 0, "the staged prefix is kept");
    let resumed = hydrate(&root_b, &ws, &scope, &fake);
    assert!(resumed.outcome.is_hit(), "{:?}", resumed.outcome);
    assert_eq!(resumed.stats.remote_from, Some(partial));
}

#[test]
fn a_spent_job_deadline_never_networks() {
    let temp = tempfile::tempdir().unwrap();
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&ws).unwrap();
    let spent = remote::Policy {
        source: &NeverCalled,
        attempt: *AttemptId::new().as_bytes(),
        deadline: Instant::now(),
        budget_bytes: remote::STORE_BUDGET_BYTES,
    };
    let missed = restore::restore_remote(
        &env(&temp.path().join("cache"), &ws),
        &decl(&["vendor"]),
        Some(KEY.to_owned()),
        scope,
        "attempt-1",
        Some(spent),
    );
    assert_eq!(missed.outcome, Outcome::Miss(Miss::Absent));
    assert_eq!(
        remote::Policy::budget(Duration::from_secs(8)),
        Duration::from_secs(2)
    );
    assert_eq!(
        remote::Policy::budget(Duration::from_secs(3600)),
        remote::BUDGET_MAX
    );
}

fn upload_for(scope: &Scope, stream: &[u8]) -> Upload {
    Upload::of(
        *AttemptId::new().as_bytes(),
        scope,
        KEY,
        stream.len() as u64,
        *blake3::hash(stream).as_bytes(),
    )
}

fn receive(store: &Path, scope: &Scope, stream: &[u8]) {
    let upload = upload_for(scope, stream);
    let mut receiving = remote::Receiving::begin(store, &upload, remote::STORE_BUDGET_BYTES)
        .unwrap()
        .expect("not stored yet");
    for (i, piece) in stream.chunks(1000).enumerate() {
        receiving.push((i * 1000) as u64, piece).unwrap();
    }
    receiving.end(upload.digest).unwrap();
}

fn bundles(entry: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(entry)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".bundle"))
        .collect();
    names.sort();
    names
}

#[test]
fn the_controller_store_keeps_one_bundle_per_entry_and_a_byte_budget() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("remote-cache");
    let scope = test_scope(Trust::Protected);
    let entry = entry_of(&store, &scope);
    receive(&store, &scope, &[1u8; 3000]);
    receive(&store, &scope, &[2u8; 3000]);
    assert_eq!(bundles(&entry).len(), 1, "the superseded bundle is gone");
    let served = remote::Serving::open(&store, &Need::of([9; 16], &scope, KEY, 0, [0; 32]))
        .unwrap()
        .plan();
    assert_eq!(served.digest, *blake3::hash(&[2u8; 3000]).as_bytes());

    let other = test_scope(Trust::Protected);
    receive(&store, &other, &[3u8; 5000]);
    let past = std::time::SystemTime::now() - Duration::from_secs(3600);
    fs::OpenOptions::new()
        .write(true)
        .open(entry.join(scope::CURRENT_NAME))
        .unwrap()
        .set_modified(past)
        .unwrap();
    fs::create_dir_all(entry.join(scope::WRITING_NAME)).unwrap();
    let stale = entry.join(scope::WRITING_NAME).join("dead.part");
    fs::write(&stale, b"half").unwrap();

    let later = UnixMillis::now().0 + remote::STALE_UPLOAD.as_millis() as i64 + 1000;
    let swept = remote::sweep_store(&store, 6000, 1000, later);
    assert_eq!(swept.parts_removed, 1);
    assert!(!stale.exists());
    assert_eq!(swept.entries_evicted, 1, "{swept:?}");
    assert!(!entry.exists(), "the least recently served entry went");
    assert!(entry_of(&store, &other).exists());
    assert_eq!(swept.bytes, 5000);
}

#[test]
fn an_abandoned_upload_leaves_nothing_behind() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("remote-cache");
    let scope = test_scope(Trust::Protected);
    let stream = vec![4u8; 4000];
    let upload = upload_for(&scope, &stream);
    let mut receiving = remote::Receiving::begin(&store, &upload, remote::STORE_BUDGET_BYTES)
        .unwrap()
        .unwrap();
    receiving.push(0, &stream[..1000]).unwrap();
    let writing = entry_of(&store, &scope).join(scope::WRITING_NAME);
    assert!(fs::read_dir(&writing).unwrap().count() > 0);
    drop(receiving);
    assert!(
        fs::read_dir(&writing)
            .map(|d| d.count() == 0)
            .unwrap_or(true),
        "no staging file or lock survives"
    );
    receive(&store, &scope, &stream);
    assert_eq!(bundles(&entry_of(&store, &scope)).len(), 1);
}

#[test]
fn uploads_verify_as_they_land_and_serves_resume_only_proven_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("remote-cache");
    let scope = test_scope(Trust::Protected);
    let stream: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    let upload = upload_for(&scope, &stream);
    let mut lying = remote::Receiving::begin(&store, &upload, remote::STORE_BUDGET_BYTES)
        .unwrap()
        .unwrap();
    let mut forged = stream.clone();
    forged[100] ^= 1;
    lying.push(0, &forged[..100_000]).unwrap();
    lying.push(100_000, &forged[100_000..]).unwrap();
    assert_eq!(lying.end(upload.digest), Err(Refusal::Store));
    drop(lying);
    assert!(bundles(&entry_of(&store, &scope)).is_empty());

    receive(&store, &scope, &stream);
    let have = *blake3::hash(&stream[..70_000]).as_bytes();
    for (offset, have, want_from) in [(70_000, have, 70_000), (70_000, [0; 32], 0)] {
        let mut serving =
            remote::Serving::open(&store, &Need::of([9; 16], &scope, KEY, offset, have)).unwrap();
        assert_eq!(serving.plan().offset, want_from);
        let mut chunk = Chunk {
            attempt: [0; 16],
            offset: 0,
            bytes: Vec::new(),
            prefix: [0; 32],
        };
        let mut got = stream[..want_from as usize].to_vec();
        while serving.next_chunk_into(&mut chunk).unwrap() {
            assert_eq!(chunk.offset, got.len() as u64);
            got.extend_from_slice(&chunk.bytes);
            assert_eq!(chunk.prefix, *blake3::hash(&got).as_bytes());
        }
        assert_eq!(got, stream);
    }
}

#[test]
fn an_offer_to_a_protocol_9_controller_states_its_digest_at_the_end() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    let ws = temp.path().join("ws");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root_b).unwrap();
    let generation = seal_generation(
        &root_a,
        &scope,
        &[("lib", b"payload-one"), ("sub/tool", b"tool-bytes")],
        "gen-1500000-0000abd4",
    );
    let first = Fake::default();
    let up_front = offer(&first, &root_a, &scope, &generation);
    let at_end = Fake {
        at_end: true,
        ..Fake::default()
    };
    let stated = offer(&at_end, &root_a, &scope, &generation);
    assert_eq!(stated, up_front);
    assert_eq!(*first.offered.lock().unwrap(), vec![up_front]);
    assert_eq!(*at_end.offered.lock().unwrap(), vec![remote::DIGEST_AT_END]);
    assert_eq!(at_end.stored(&scope), first.stored(&scope));
    let served = hydrate(&root_b, &ws, &scope, &at_end);
    assert!(served.outcome.is_hit(), "{:?}", served.outcome);
    assert_eq!(fs::read(ws.join("vendor/lib")).unwrap(), b"payload-one");
}

#[test]
fn the_store_takes_a_digest_at_the_end_only_when_the_bytes_prove_it() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("remote-cache");
    let scope = test_scope(Trust::Protected);
    let stream: Vec<u8> = (0..150_000u32).map(|i| (i % 241) as u8).collect();
    let digest = *blake3::hash(&stream).as_bytes();
    let late = Upload::of(
        *AttemptId::new().as_bytes(),
        &scope,
        KEY,
        stream.len() as u64,
        remote::DIGEST_AT_END,
    );
    for wrong in [remote::DIGEST_AT_END, *blake3::hash(b"other").as_bytes()] {
        let mut receiving = remote::Receiving::begin(&store, &late, remote::STORE_BUDGET_BYTES)
            .unwrap()
            .unwrap();
        receiving.push(0, &stream).unwrap();
        assert_eq!(receiving.end(wrong), Err(Refusal::Store));
        drop(receiving);
        assert!(bundles(&entry_of(&store, &scope)).is_empty());
    }
    let mut receiving = remote::Receiving::begin(&store, &late, remote::STORE_BUDGET_BYTES)
        .unwrap()
        .unwrap();
    for (i, piece) in stream.chunks(40_000).enumerate() {
        receiving.push((i * 40_000) as u64, piece).unwrap();
    }
    receiving.end(digest).unwrap();
    let served = remote::Serving::open(&store, &Need::of([9; 16], &scope, KEY, 0, [0; 32]))
        .unwrap()
        .plan();
    assert_eq!(served.digest, digest);
    assert_eq!(bundles(&entry_of(&store, &scope)).len(), 1);
}

/// Grants a total and moves no byte, so only the size gate in front of the transfer is under test.
struct Granting(u64);

impl Remote for Granting {
    fn fetch(&self, need: &Need, _: Instant, sink: &mut dyn Sink) -> Result<(), Refusal> {
        sink.plan(&Grant {
            attempt: need.attempt,
            total: self.0,
            offset: 0,
            prefix: [0; 32],
            digest: [1; 32],
        })
    }
    fn offer(&self, _: &Upload, _: Instant, _: &mut dyn Read) -> Result<[u8; 32], Refusal> {
        Err(Refusal::Store)
    }
}

fn hydrate_with_budget(
    root: &Path,
    ws: &Path,
    scope: &Scope,
    source: &dyn Remote,
    budget_bytes: u64,
) -> Attached {
    fs::create_dir_all(ws).unwrap();
    restore::restore_remote(
        &env(root, ws),
        &decl(&["vendor"]),
        Some(KEY.to_owned()),
        scope.clone(),
        "attempt-1",
        Some(remote::Policy {
            budget_bytes,
            ..policy(source)
        }),
    )
}

fn nothing_staged_or_promoted(root: &Path, scope: &Scope) {
    let entry = entry_of(root, scope);
    assert!(
        !entry
            .join(scope::WRITING_NAME)
            .join("remote.stage")
            .exists(),
        "a refused bundle leaves no staging"
    );
    assert!(!entry.join(scope::CURRENT_NAME).exists());
    let promoted = fs::read_dir(&entry)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("gen-"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(promoted, 0, "a refused bundle installs no generation");
}

#[test]
fn a_grant_past_the_workers_bundle_cap_is_refused_before_anything_is_staged() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let scope = test_scope(Trust::Protected);
    fs::create_dir_all(&root).unwrap();
    let budget = 64 << 20;
    let cap = remote::max_bundle_bytes(budget);
    assert!(
        cap < remote::MAX_BUNDLE_BYTES,
        "a small budget caps below the wire bound"
    );

    let over = hydrate_with_budget(
        &root,
        &temp.path().join("ws"),
        &scope,
        &Granting(cap + 1),
        budget,
    );
    assert_eq!(over.outcome, Outcome::Miss(Miss::Invalid));
    nothing_staged_or_promoted(&root, &scope);

    // At the cap the size gate lets the grant through; this fake then moves nothing, so the bundle never
    // verifies, which is a different miss from a size refusal.
    let at = hydrate_with_budget(
        &root,
        &temp.path().join("ws"),
        &scope,
        &Granting(cap),
        budget,
    );
    assert_eq!(at.outcome, Outcome::Miss(Miss::Corrupt));

    // The same grant is within a worker whose budget is large enough: the cap follows the budget.
    let roomy = hydrate_with_budget(
        &root,
        &temp.path().join("ws"),
        &scope,
        &Granting(cap + 1),
        remote::STORE_BUDGET_BYTES,
    );
    assert_eq!(roomy.outcome, Outcome::Miss(Miss::Corrupt));
}

#[test]
fn the_payload_cap_is_a_quarter_of_the_budget_and_inclusive() {
    let temp = tempfile::tempdir().unwrap();
    let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
    fs::create_dir_all(&root_b).unwrap();
    let scope = test_scope(Trust::Protected);
    let fake = Fake::default();
    let generation = seal_generation(
        &root_a,
        &scope,
        &[("lib", b"payload-one"), ("sub/tool", b"tool-bytes!")],
        "gen-1500000-0000abe0",
    );
    offer(&fake, &root_a, &scope, &generation);
    // 22 payload bytes: a budget of 88 allows exactly 22, a budget of 87 allows 21.
    let refused = hydrate_with_budget(&root_b, &temp.path().join("ws1"), &scope, &fake, 87);
    assert_eq!(refused.outcome, Outcome::Miss(Miss::Invalid));
    nothing_staged_or_promoted(&root_b, &scope);
    let taken = hydrate_with_budget(&root_b, &temp.path().join("ws2"), &scope, &fake, 88);
    assert!(taken.outcome.is_hit(), "{:?}", taken.outcome);
}

fn tamper_manifest(root: &Path, scope: &Scope, generation: &str, edit: impl FnOnce(&mut Manifest)) {
    let path = entry_of(root, scope)
        .join(generation)
        .join(scope::MANIFEST_NAME);
    let mut manifest = Manifest::decode(&fs::read(&path).unwrap()).unwrap();
    edit(&mut manifest);
    fs::write(&path, manifest.encode()).unwrap();
}

#[test]
fn a_manifest_that_misstates_its_bytes_or_seal_time_never_hydrates() {
    type Edit = fn(&mut Manifest);
    let lies: [(&str, Edit, Miss); 4] = [
        ("huge bytes", |m| m.bytes = u64::MAX, Miss::Corrupt),
        ("zero bytes", |m| m.bytes = 0, Miss::Corrupt),
        ("one byte over", |m| m.bytes += 1, Miss::Corrupt),
        (
            "a seal time past i64",
            |m| m.sealed_ms = u64::MAX,
            Miss::Invalid,
        ),
    ];
    for (what, lie, miss) in lies {
        let temp = tempfile::tempdir().unwrap();
        let (root_a, root_b) = (temp.path().join("a"), temp.path().join("b"));
        fs::create_dir_all(&root_b).unwrap();
        let scope = test_scope(Trust::Protected);
        let generation = seal_generation(
            &root_a,
            &scope,
            &[("lib", b"payload-one"), ("sub/tool", b"tool-bytes")],
            "gen-1500000-0000abe1",
        );
        tamper_manifest(&root_a, &scope, &generation, lie);
        let fake = Fake::default();
        offer(&fake, &root_a, &scope, &generation);
        let served = hydrate(&root_b, &temp.path().join("ws"), &scope, &fake);
        assert_eq!(served.outcome, Outcome::Miss(miss), "{what}");
        nothing_staged_or_promoted(&root_b, &scope);
    }
}

#[test]
fn the_store_refuses_a_bundle_past_its_budget_cap_and_sweeps_an_oversize_one_first() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("remote-cache");
    let scope = test_scope(Trust::Protected);
    let budget = 64 << 20;
    let cap = remote::max_bundle_bytes(budget);

    let too_big = Upload::of(
        *AttemptId::new().as_bytes(),
        &scope,
        KEY,
        cap + 1,
        *blake3::hash(b"never sent").as_bytes(),
    );
    assert_eq!(
        remote::Receiving::begin(&store, &too_big, budget).err(),
        Some(Refusal::TooLarge)
    );
    let at_end = Upload::of(
        *AttemptId::new().as_bytes(),
        &scope,
        KEY,
        cap + 1,
        remote::DIGEST_AT_END,
    );
    assert_eq!(
        remote::Receiving::begin(&store, &at_end, budget).err(),
        Some(Refusal::TooLarge),
        "a digest stated at the end changes nothing about the size bound"
    );
    let at_cap = Upload::of(
        *AttemptId::new().as_bytes(),
        &scope,
        KEY,
        cap,
        *blake3::hash(b"never sent").as_bytes(),
    );
    assert!(
        remote::Receiving::begin(&store, &at_cap, budget)
            .unwrap()
            .is_some(),
        "the cap itself is allowed"
    );
    assert!(
        remote::Receiving::begin(&store, &too_big, remote::STORE_BUDGET_BYTES).is_ok(),
        "the bound follows the store's budget"
    );

    // A bundle bigger than the whole budget is dropped before the entries that fit, whoever was served last.
    let small_a = test_scope(Trust::Protected);
    let small_b = test_scope(Trust::Protected);
    let big = test_scope(Trust::Protected);
    receive(&store, &small_a, &[1u8; 3000]);
    receive(&store, &small_b, &[2u8; 3000]);
    receive(&store, &big, &[3u8; 9000]);
    let past = std::time::SystemTime::now() - Duration::from_secs(3600);
    for older in [&small_a, &small_b] {
        fs::OpenOptions::new()
            .write(true)
            .open(entry_of(&store, older).join(scope::CURRENT_NAME))
            .unwrap()
            .set_modified(past)
            .unwrap();
    }
    let swept = remote::sweep_store(&store, 7000, 1000, UnixMillis::now().0);
    assert_eq!(swept.entries_evicted, 1, "{swept:?}");
    assert!(!entry_of(&store, &big).exists());
    assert!(entry_of(&store, &small_a).exists());
    assert!(entry_of(&store, &small_b).exists());
    assert_eq!(swept.bytes, 6000);
}
