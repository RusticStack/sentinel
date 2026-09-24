//! Measurement, not a check (P08-C8): what the worker side of one remote
//! cache transfer costs — wall time and the bytes it moves through
//! `read`/`write` syscalls (`/proc/self/io` `rchar`/`wchar`) — for a
//! hydration (fetch, install, materialize into the job's view) and for an
//! offer (hash and stream a sealed generation). The controller here is an
//! in-memory stand-in that serves 48 KiB chunks with their running digest
//! and hashes what it receives, so the counters are the worker's own.
//! Ignored by default:
//!
//! ```sh
//! SENTINEL_REMOTE_COST_DIR=/root/bench cargo test --release -p sentinel-cache \
//!     --test remote_cost -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `SENTINEL_REMOTE_COST_FILES` × `SENTINEL_REMOTE_COST_FILE_BYTES` size the
//! payload (default 64 × 4 MiB = 256 MiB of pseudo-random bytes).
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
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

const KEY: &str = "deps-cost";
const CHUNK: usize = 48 << 10;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// `(rchar, wchar)` of this process so far.
fn io_counters() -> (u64, u64) {
    let text = fs::read_to_string("/proc/self/io").unwrap();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse().ok())
            .unwrap()
    };
    (field("rchar:"), field("wchar:"))
}

fn test_scope() -> Scope {
    Scope::new(
        TenantId::new(),
        RepoId::new(),
        Class::Dependencies,
        Trust::Protected,
        Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        },
        Scope::toolchain_digest(b"remote cost"),
        "deps",
    )
    .unwrap()
}

fn decl() -> Cache {
    Cache {
        name: "deps".into(),
        class: Class::Dependencies,
        key: Template::parse(KEY).unwrap(),
        paths: vec!["vendor".to_owned()],
    }
}

fn compat(scope: &Scope) -> Compat {
    attach::declared_compat(&decl(), KEY, scope.platform)
}

/// One sealed generation of `files` pseudo-random files.
fn seal(root: &Path, scope: &Scope, files: u64, bytes: u64) -> String {
    let entry = scope.entry_dir(root, attach::entry_key(scope.class, KEY));
    let generation = "gen-00000000000001500000-00000001".to_owned();
    let dir = entry.join(&generation);
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut buf = vec![0u8; bytes as usize];
    let mut entries = Vec::new();
    for i in 0..files {
        for chunk in buf.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        let path = format!("payload/0/f{i:04}");
        let file = dir.join(&path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, &buf).unwrap();
        entries.push(FileEntry {
            path,
            size: bytes,
            digest: *blake3::hash(&buf).as_bytes(),
            mode: 0o644,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let blob = FilesBlob { entries };
    let mut manifest = Manifest::writing(scope, KEY, compat(scope));
    manifest.bytes = blob.entries.iter().map(|e| e.size).sum();
    manifest.files = blob.entries.len() as u32;
    manifest.files_digest = blob.digest();
    manifest.seal(UnixMillis(1_500_000));
    fs::write(dir.join(scope::FILES_NAME), blob.encode()).unwrap();
    fs::write(dir.join(scope::MANIFEST_NAME), manifest.encode()).unwrap();
    generation
}

/// The in-memory controller: one stored stream, served in 48 KiB chunks
/// with the running digest, as `Serving` does; offers are hashed as they
/// arrive, as `Receiving` does, and kept.
#[derive(Default)]
struct Store {
    stream: Mutex<Vec<u8>>,
}

impl Remote for Store {
    fn fetch(&self, need: &Need, _: Instant, sink: &mut dyn Sink) -> Result<(), Refusal> {
        let stream = self.stream.lock().unwrap();
        sink.plan(&Grant {
            attempt: need.attempt,
            total: stream.len() as u64,
            offset: 0,
            prefix: *blake3::Hasher::new().finalize().as_bytes(),
            digest: *blake3::hash(&stream).as_bytes(),
        })?;
        let mut hasher = blake3::Hasher::new();
        let mut chunk = Chunk {
            attempt: need.attempt,
            offset: 0,
            bytes: Vec::with_capacity(CHUNK),
            prefix: [0; 32],
        };
        for (i, piece) in stream.chunks(CHUNK).enumerate() {
            hasher.update(piece);
            chunk.offset = (i * CHUNK) as u64;
            chunk.bytes.clear();
            chunk.bytes.extend_from_slice(piece);
            chunk.prefix = *hasher.clone().finalize().as_bytes();
            sink.chunk(&chunk)?;
        }
        Ok(())
    }

    fn offer(
        &self,
        upload: &Upload,
        _: Instant,
        source: &mut dyn Read,
    ) -> Result<[u8; 32], Refusal> {
        let mut stream = Vec::with_capacity(upload.total as usize);
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = source.read(&mut buf).map_err(|_| Refusal::Store)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            stream.extend_from_slice(&buf[..n]);
        }
        let digest = *hasher.finalize().as_bytes();
        if upload.digest != remote::DIGEST_AT_END && digest != upload.digest {
            return Err(Refusal::Store);
        }
        *self.stream.lock().unwrap() = stream;
        Ok(digest)
    }

    /// Like a protocol-9 controller, unless the run asks for the
    /// digest-first path an older one needs.
    fn digest_at_end(&self) -> bool {
        std::env::var_os("SENTINEL_REMOTE_COST_DIGEST_FIRST").is_none()
    }
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

#[test]
#[ignore = "measurement; run explicitly in release"]
fn transfer_cost() {
    let base = std::env::var_os("SENTINEL_REMOTE_COST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&base).unwrap();
    let files = env_u64("SENTINEL_REMOTE_COST_FILES", 64);
    let bytes = env_u64("SENTINEL_REMOTE_COST_FILE_BYTES", 4 << 20);
    let runs = env_u64("SENTINEL_REMOTE_COST_RUNS", 5);
    let payload = files * bytes;
    let backend = if std::env::var_os("SENTINEL_REMOTE_COST_REFLINK").is_some() {
        Backend::Reflink
    } else {
        Backend::Copy
    };
    eprintln!("payload {files} x {bytes} B = {payload} B, backend {backend:?}");
    for run in 0..runs {
        let temp = tempfile::tempdir_in(&base).unwrap();
        let publisher = temp.path().join("publisher");
        let scope = test_scope();
        let generation = seal(&publisher, &scope, files, bytes);
        // The publisher's own writes are flushed first, so no run pays for
        // the setup's write-back.
        assert!(
            std::process::Command::new("sync")
                .arg("-f")
                .arg(temp.path())
                .status()
                .unwrap()
                .success()
        );
        let store = Store::default();

        let (r0, w0) = io_counters();
        let started = Instant::now();
        remote::offer_generation(
            &publisher,
            &attached_for(&scope),
            &generation,
            *AttemptId::new().as_bytes(),
            &store,
            Instant::now() + Duration::from_secs(600),
            &|| false,
        )
        .expect("offer");
        let offer_ns = started.elapsed().as_nanos();
        let (r1, w1) = io_counters();

        let root = temp.path().join("hydrator");
        let ws = temp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        let env = Context {
            cache_root: &root,
            workspace: &ws,
            workspace_mount: "/workspace",
            backend,
        };
        let started = Instant::now();
        let attached = restore::restore_remote(
            &env,
            &decl(),
            Some(KEY.to_owned()),
            scope.clone(),
            "attempt-cost",
            Some(remote::Policy {
                source: &store,
                attempt: *AttemptId::new().as_bytes(),
                deadline: Instant::now() + Duration::from_secs(600),
            }),
        );
        let hydrate_ns = started.elapsed().as_nanos();
        let (r2, w2) = io_counters();
        assert!(attached.outcome.is_hit(), "hydration missed");
        // What the hydration left dirty still has to reach the disk.
        let synced = Instant::now();
        assert!(
            std::process::Command::new("sync")
                .arg("-f")
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let sync_ns = synced.elapsed().as_nanos();
        eprintln!(
            "run {run}: offer {:.1} ms read {:.2}x write {:.2}x | hydrate {:.1} ms (+syncfs {:.1} ms) read {:.2}x write {:.2}x (x = payload bytes)",
            offer_ns as f64 / 1e6,
            (r1 - r0) as f64 / payload as f64,
            (w1 - w0) as f64 / payload as f64,
            hydrate_ns as f64 / 1e6,
            (hydrate_ns + sync_ns) as f64 / 1e6,
            (r2 - r1) as f64 / payload as f64,
            (w2 - w1) as f64 / payload as f64,
        );
        drop(attached);
    }
}
