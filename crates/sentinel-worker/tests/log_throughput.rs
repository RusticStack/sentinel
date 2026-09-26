//! Measurements for the worker's log path and helper waits (P04-19), not
//! pass/fail tests: run with `--ignored --nocapture` and read the numbers.
//!
//! * `log_path_throughput`: 64 MiB of step output in 8 KiB chunks through
//!   `LogPipe::write` — redaction, spool, send — over a real loopback TLS
//!   session to a stand-in controller that acknowledges every frame at once
//!   (no controller disk in the way), until the last frame is acknowledged;
//!   then the same volume with no session (spool only).
//! * `helper_wait_latency`: 100 helper runs (`podman rm -f` answered by an
//!   `exit 0` shim), the cost a real attempt pays per podman/git call.

#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, Fence, PoolId, UnixMillis, WorkerId};
use sentinel_link::{
    identity::Identity,
    session::{
        self, Accepted, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict,
        Offer, Rejection, Reporter, SessionHandler,
    },
    tls,
};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion, negotiate};
use sentinel_worker::{attempt::Output, logpipe::LogPipe, podman, redact::Redactor};

const TOTAL: usize = 64 << 20;
const CHUNK: usize = 8 << 10;

struct AnyAdmission;
impl Admission for AnyAdmission {
    fn admit(
        &self,
        _: &sentinel_auth::secret::Digest,
        worker: WorkerId,
        _: &str,
        hello: &Hello,
        _: Option<&sentinel_auth::secret::Secret>,
        _: Capacity,
    ) -> Result<Admitted, Rejection> {
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated: negotiate(hello).map_err(Rejection::from)?,
        })
    }
}

struct AckAll;
impl SessionHandler for AckAll {
    fn ping(&self, _: WorkerId, _: &[AttemptId]) -> sentinel_link::Result<Beat> {
        Ok(Beat {
            lease_until: UnixMillis(UnixMillis::now().0 + 30_000),
            stop: Vec::new(),
            cancel: Vec::new(),
        })
    }
    fn acknowledged(&self, _: WorkerId, _: AttemptId, _: Fence) {}
    fn declined(&self, _: WorkerId, _: AttemptId, _: Fence) {}
    fn reported(&self, _: WorkerId, _: AttemptId, _: Fence, _: Event, _: Option<Vec<u8>>) {}
    fn spec(&self, _: WorkerId, _: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }
    fn log(&self, _: WorkerId, _: AttemptId, frame: Frame) -> LogVerdict {
        LogVerdict::Acked(frame.seq)
    }
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

#[derive(Default)]
struct Forward {
    reporter: Mutex<Option<Reporter>>,
    pipe: Mutex<Option<Arc<LogPipe>>>,
    acked: AtomicU64,
}

impl Executor for Forward {
    fn offered(&self, _: &Offer) -> bool {
        false
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, reporter: Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, through: u64) {
        if let Some(pipe) = self.pipe.lock().unwrap().clone() {
            pipe.acked(through);
        }
        self.acked.fetch_max(through, Ordering::SeqCst);
    }
    fn log_refused(&self, _: AttemptId) {}
}

fn chunk() -> Vec<u8> {
    (0..CHUNK)
        .map(|i| {
            if i % 80 == 79 {
                b'\n'
            } else {
                b'a' + (i % 26) as u8
            }
        })
        .collect()
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn log_path_throughput() {
    let controller = Identity::generate("bench-controller").unwrap();
    let pin = controller.fingerprint();
    let server = tls::server_config(controller).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        if let Ok(Accepted::Control(mut control)) = session::accept(socket, server, &AnyAdmission) {
            let _ = control.serve(&AckAll);
        }
    });
    let client = tls::client_config(Identity::generate("bench-worker").unwrap(), pin).unwrap();
    let mut link = session::connect(
        addr,
        client,
        WorkerId::new(),
        "bench",
        Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: ProtocolVersion(6),
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "bench".into(),
        },
        None,
        Capacity {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
        },
    )
    .unwrap();
    let executor = Arc::new(Forward::default());
    let running = {
        let executor = Arc::clone(&executor);
        thread::spawn(move || {
            let _ = link.run(&*executor, || false);
        })
    };
    while executor.reporter.lock().unwrap().is_none() {
        thread::sleep(Duration::from_millis(5));
    }
    let root = tempfile::tempdir().unwrap();
    let reporter = executor.reporter.lock().unwrap().clone();
    let pipe =
        Arc::new(LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), reporter).unwrap());
    *executor.pipe.lock().unwrap() = Some(Arc::clone(&pipe));
    let bytes = chunk();
    let frames = (TOTAL / CHUNK) as u64;
    let started = Instant::now();
    for _ in 0..frames {
        pipe.write(0, Stream::Stdout, &bytes);
    }
    while executor.acked.load(Ordering::SeqCst) < frames {
        thread::sleep(Duration::from_micros(200));
    }
    let linked = started.elapsed();
    drop(running);

    let root = tempfile::tempdir().unwrap();
    let spool_only = LogPipe::open(root.path(), AttemptId::new(), Redactor::new(), None).unwrap();
    let started = Instant::now();
    for _ in 0..frames {
        spool_only.write(0, Stream::Stdout, &bytes);
    }
    let local = started.elapsed();
    let mib = (TOTAL >> 20) as f64;
    println!(
        "log path, 64 MiB in 8 KiB chunks: linked and acknowledged {:.1} ms ({:.0} MiB/s); spool only {:.1} ms ({:.0} MiB/s)",
        linked.as_secs_f64() * 1e3,
        mib / linked.as_secs_f64(),
        local.as_secs_f64() * 1e3,
        mib / local.as_secs_f64(),
    );
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn helper_wait_latency() {
    let dir = tempfile::tempdir().unwrap();
    let shim = dir.path().join("podman");
    fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    // SAFETY: the only test of this binary that runs helpers sets it before
    // it starts any.
    unsafe {
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}",
                dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    }
    const N: u32 = 100;
    let started = Instant::now();
    for _ in 0..N {
        podman::remove_named("sentinel-bench", &podman::Store::Shared).unwrap();
    }
    let per = started.elapsed() / N;
    let started = Instant::now();
    for _ in 0..N {
        assert!(
            std::process::Command::new(&shim)
                .status()
                .unwrap()
                .success()
        );
    }
    let blocking = started.elapsed() / N;
    println!("helper run: {per:?} per call; the same process with a blocking wait: {blocking:?}");
}
