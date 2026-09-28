//! The worker's optional metrics listener (R06): `metrics_listen` in the
//! worker's configuration names a loopback address, and `GET /metrics` there
//! answers the Prometheus text format. Loopback only, so a node exporter or
//! an agent on the same machine scrapes it; the figures name no tenant,
//! repository, attempt or secret.
//!
//! What it counts comes from the executor's notices (attempts, spool
//! refusals, cache and image reclamation, availability) and the link's
//! events, plus the process's own figures and the data directory's disk.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The counters the executor's notices and the link's events feed.
#[derive(Default)]
pub struct Metrics {
    pub connected: AtomicBool,
    pub connects: AtomicU64,
    pub disconnects: AtomicU64,
    pub attempts_started: AtomicU64,
    pub attempts_finished: AtomicU64,
    pub attempts_canceled: AtomicU64,
    pub attempts_handed_back: AtomicU64,
    pub attempts_abandoned: AtomicU64,
    pub leases_lost: AtomicU64,
    pub spool_refusals: AtomicU64,
    pub cache_sweeps: AtomicU64,
    pub images_reclaimed: AtomicU64,
    pub cache_bytes: AtomicU64,
    pub cache_entries: AtomicU64,
    pub images_held: AtomicU64,
    pub images_in_flight: AtomicU64,
    /// The running executor, once it started (none without a runtime).
    pub executor: OnceLock<sentinel_worker::executor::Executor>,
}

impl Metrics {
    /// Count one executor notice.
    pub fn count(&self, notice: &sentinel_worker::executor::Notice) {
        use sentinel_worker::executor::Notice;
        let add = |a: &AtomicU64| {
            a.fetch_add(1, Relaxed);
        };
        match notice {
            Notice::Started(_) => add(&self.attempts_started),
            Notice::Finished(..) => add(&self.attempts_finished),
            Notice::Canceled { .. } => add(&self.attempts_canceled),
            Notice::HandedBack(_) => add(&self.attempts_handed_back),
            Notice::Abandoned { .. } => add(&self.attempts_abandoned),
            Notice::LeaseLost(_) => add(&self.leases_lost),
            Notice::SpoolRefused { .. } => add(&self.spool_refusals),
            Notice::CacheSwept(_) => add(&self.cache_sweeps),
            Notice::ImagesReclaimed(removed) => {
                self.images_reclaimed.fetch_add(*removed as u64, Relaxed);
            }
            Notice::Availability(snapshot) => {
                self.cache_bytes.store(snapshot.cache_bytes, Relaxed);
                self.cache_entries.store(snapshot.cache_entries, Relaxed);
                self.images_held
                    .store(snapshot.images_held.len() as u64, Relaxed);
                self.images_in_flight
                    .store(snapshot.images_in_flight as u64, Relaxed);
            }
            _ => {}
        }
    }

    pub fn render(&self, free: u64) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(4096);
        let _ = writeln!(
            out,
            "# HELP sentinel_worker_build_info This worker's version.\n\
             # TYPE sentinel_worker_build_info gauge\n\
             sentinel_worker_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        let n = |a: &AtomicU64| a.load(Relaxed).to_string();
        let mut one = |name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
            );
        };
        let f = sentinel_core::process::figures();
        if let Some(v) = f.resident_bytes {
            one(
                "sentinel_process_resident_bytes",
                "gauge",
                "Resident memory of this process.",
                v.to_string(),
            );
        }
        if let Some(v) = f.cpu_seconds {
            one(
                "sentinel_process_cpu_seconds_total",
                "counter",
                "CPU time this process used.",
                v.to_string(),
            );
        }
        if let Some(v) = f.open_fds {
            one(
                "sentinel_process_open_fds",
                "gauge",
                "Open file descriptors.",
                v.to_string(),
            );
        }
        if let Some(v) = f.threads {
            one(
                "sentinel_process_threads",
                "gauge",
                "Threads.",
                v.to_string(),
            );
        }
        one(
            "sentinel_worker_connected",
            "gauge",
            "A control session with the controller is up (1).",
            u8::from(self.connected.load(Relaxed)).to_string(),
        );
        one(
            "sentinel_worker_connects_total",
            "counter",
            "Control sessions established.",
            n(&self.connects),
        );
        one(
            "sentinel_worker_disconnects_total",
            "counter",
            "Control sessions lost.",
            n(&self.disconnects),
        );
        if let Some(executor) = self.executor.get() {
            one(
                "sentinel_worker_attempts_live",
                "gauge",
                "Attempts running or waiting for their spec.",
                executor.attempts_live().to_string(),
            );
            one(
                "sentinel_worker_spool_bytes",
                "gauge",
                "Bytes the attempts' log spools hold.",
                executor.spool_used().to_string(),
            );
            one(
                "sentinel_worker_reports_pending",
                "gauge",
                "Attempt reports waiting for a session.",
                executor.pending_reports().to_string(),
            );
        }
        one(
            "sentinel_worker_attempts_started_total",
            "counter",
            "Attempts started.",
            n(&self.attempts_started),
        );
        one(
            "sentinel_worker_attempts_finished_total",
            "counter",
            "Attempts finished with a verdict.",
            n(&self.attempts_finished),
        );
        one(
            "sentinel_worker_attempts_canceled_total",
            "counter",
            "Attempts canceled.",
            n(&self.attempts_canceled),
        );
        one(
            "sentinel_worker_attempts_handed_back_total",
            "counter",
            "Attempts returned unstarted: the spec never arrived.",
            n(&self.attempts_handed_back),
        );
        one(
            "sentinel_worker_attempts_abandoned_total",
            "counter",
            "Attempts a previous process left, handed to the controller.",
            n(&self.attempts_abandoned),
        );
        one(
            "sentinel_worker_leases_lost_total",
            "counter",
            "Times attempts ended because no renewal came before the deadline.",
            n(&self.leases_lost),
        );
        one(
            "sentinel_worker_spool_refusals_total",
            "counter",
            "Attempts whose output the spool could not hold in full.",
            n(&self.spool_refusals),
        );
        one(
            "sentinel_worker_cache_bytes",
            "gauge",
            "Bytes the local cache holds.",
            n(&self.cache_bytes),
        );
        one(
            "sentinel_worker_cache_entries",
            "gauge",
            "Cache entries the last sweep saw.",
            n(&self.cache_entries),
        );
        one(
            "sentinel_worker_cache_sweeps_total",
            "counter",
            "Cache reclamation passes.",
            n(&self.cache_sweeps),
        );
        one(
            "sentinel_worker_images_held",
            "gauge",
            "Images the local store holds.",
            n(&self.images_held),
        );
        one(
            "sentinel_worker_images_in_flight",
            "gauge",
            "Image pulls in flight.",
            n(&self.images_in_flight),
        );
        one(
            "sentinel_worker_images_reclaimed_total",
            "counter",
            "Images removed by reclamation.",
            n(&self.images_reclaimed),
        );
        one(
            "sentinel_worker_disk_free_bytes",
            "gauge",
            "Free bytes on the data directory's file system.",
            free.to_string(),
        );

        out
    }
}

/// Serve `metrics` on `listen` from a thread of its own until the process
/// exits. One connection at a time, each bounded to two seconds and 4 KiB of
/// request: a scrape is small and rare.
pub fn serve(
    listen: SocketAddr,
    metrics: Arc<Metrics>,
    data_dir: PathBuf,
    free: fn(&std::path::Path) -> u64,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(listen)?;
    let bound = listener.local_addr()?;
    std::thread::Builder::new()
        .name("sentinel-worker-metrics".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream, &metrics, &data_dir, free);
            }
        })?;
    Ok(bound)
}

fn answer(
    mut stream: TcpStream,
    metrics: &Metrics,
    data_dir: &std::path::Path,
    free: fn(&std::path::Path) -> u64,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        if request.len() > 4096 {
            return Ok(());
        }
        let got = stream.read(&mut buf)?;
        if got == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..got]);
    }
    let line = request.split(|b| *b == b'\r').next().unwrap_or_default();
    let (status, body) = match line {
        b"GET /metrics HTTP/1.1" | b"GET /metrics HTTP/1.0" => {
            ("200 OK", metrics.render(free(data_dir)))
        }
        _ => ("404 Not Found", "not found\n".to_owned()),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listener_answers_metrics_and_nothing_else() {
        let metrics = Arc::new(Metrics::default());
        metrics.attempts_started.store(3, Relaxed);
        metrics.connected.store(true, Relaxed);
        let bound = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&metrics),
            std::env::temp_dir(),
            |_| 42,
        )
        .unwrap();
        let get = |path: &str| {
            let mut s = TcpStream::connect(bound).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        let page = get("/metrics");
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert!(
            page.contains("sentinel_worker_attempts_started_total 3\n"),
            "{page}"
        );
        assert!(page.contains("sentinel_worker_connected 1\n"), "{page}");
        assert!(
            page.contains("sentinel_worker_disk_free_bytes 42\n"),
            "{page}"
        );
        assert!(page.contains(&format!(
            "sentinel_worker_build_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(page.contains("sentinel_process_resident_bytes "), "{page}");
        assert!(get("/other").starts_with("HTTP/1.1 404"));
    }
}
