//! Loopback only: the figures name no tenant, repository, attempt or secret.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_costly_hits: AtomicU64,
    pub cache_lock_wait_ns: AtomicU64,
    pub cache_clone_ns: AtomicU64,
    pub cache_first_touch_ns: AtomicU64,
    pub cache_commit_ns: AtomicU64,
    pub cache_restored_bytes: AtomicU64,
    pub cache_copied_bytes: AtomicU64,
    pub cache_dirty_bytes: AtomicU64,
    /// Settled per-class estimates in nanoseconds, indexed by class code; zero is not yet settled.
    pub cache_restore_ns: [AtomicU64; sentinel_protocol::cache::Class::ALL.len()],
    pub cache_rebuild_ns: [AtomicU64; sentinel_protocol::cache::Class::ALL.len()],
    pub executor: OnceLock<sentinel_worker::executor::Executor>,
}

impl Metrics {
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
            Notice::CacheFigures(t) => {
                let sum = |a: &AtomicU64, v: u64| {
                    a.fetch_add(v, Relaxed);
                };
                sum(&self.cache_hits, t.hits);
                sum(&self.cache_misses, t.misses);
                sum(&self.cache_costly_hits, t.costly_hits);
                sum(&self.cache_lock_wait_ns, t.lock_wait_ns);
                sum(&self.cache_clone_ns, t.clone_ns);
                sum(&self.cache_first_touch_ns, t.first_touch_ns);
                sum(&self.cache_commit_ns, t.commit_ns);
                sum(&self.cache_restored_bytes, t.restored_bytes);
                sum(&self.cache_copied_bytes, t.copied_bytes);
                sum(&self.cache_dirty_bytes, t.dirty_bytes);
            }
            Notice::Availability(snapshot) => {
                for f in &snapshot.cache_costs {
                    let at = usize::from(f.class.to_u8());
                    self.cache_restore_ns[at].store(f.restore.map_or(0, |e| e.ns), Relaxed);
                    self.cache_rebuild_ns[at].store(f.rebuild.map_or(0, |e| e.ns), Relaxed);
                }
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

        {
            let mut counter = |name: &str, help: &str, value: String| {
                let _ = writeln!(
                    out,
                    "# HELP {name} {help}
# TYPE {name} counter
{name} {value}"
                );
            };
            let seconds = |a: &AtomicU64| format!("{:.9}", a.load(Relaxed) as f64 / 1e9);
            counter(
                "sentinel_worker_cache_hits_total",
                "Cache entries restored from a local generation.",
                n(&self.cache_hits),
            );
            counter(
                "sentinel_worker_cache_misses_total",
                "Cache entries that restored nothing.",
                n(&self.cache_misses),
            );
            counter(
                "sentinel_worker_cache_costly_hits_total",
                "Hits whose restore cost more than rebuilding what they held (docs/cache.md).",
                n(&self.cache_costly_hits),
            );
            counter(
                "sentinel_worker_cache_lock_wait_seconds_total",
                "Time attempts waited for a cache entry before restoring it.",
                seconds(&self.cache_lock_wait_ns),
            );
            counter(
                "sentinel_worker_cache_restore_seconds_total",
                "Time spent cloning hit generations into attempt views.",
                seconds(&self.cache_clone_ns),
            );
            counter(
                "sentinel_worker_cache_first_touch_seconds_total",
                "Time the first read of restored cache files took.",
                seconds(&self.cache_first_touch_ns),
            );
            counter(
                "sentinel_worker_cache_commit_seconds_total",
                "Time spent publishing cache generations.",
                seconds(&self.cache_commit_ns),
            );
            counter(
                "sentinel_worker_cache_restored_bytes_total",
                "Bytes restored by hits.",
                n(&self.cache_restored_bytes),
            );
            counter(
                "sentinel_worker_cache_copied_bytes_total",
                "Bytes a hit copied because a clone was not possible.",
                n(&self.cache_copied_bytes),
            );
            counter(
                "sentinel_worker_cache_dirty_bytes_total",
                "Bytes jobs rewrote relative to the generation they restored.",
                n(&self.cache_dirty_bytes),
            );
        }
        for (name, help, values) in [
            (
                "sentinel_worker_cache_restore_estimate_seconds",
                "Weighted restore time of a hit, per class, once settled.",
                &self.cache_restore_ns,
            ),
            (
                "sentinel_worker_cache_rebuild_estimate_seconds",
                "Weighted time a hit saves over rebuilding, per class, once settled.",
                &self.cache_rebuild_ns,
            ),
        ] {
            let mut rows = String::new();
            for class in sentinel_protocol::cache::Class::ALL {
                let ns = values[usize::from(class.to_u8())].load(Relaxed);
                if ns > 0 {
                    let _ = writeln!(
                        rows,
                        "{name}{{class=\"{}\"}} {:.9}",
                        class.as_str(),
                        ns as f64 / 1e9
                    );
                }
            }
            if !rows.is_empty() {
                let _ = write!(
                    out,
                    "# HELP {name} {help}
# TYPE {name} gauge
{rows}"
                );
            }
        }

        out
    }
}

/// One connection at a time, each capped at two seconds and 4 KiB of request.
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
    fn cache_figures_accumulate_and_settled_costs_are_labelled_by_class() {
        use sentinel_worker::executor::{Availability, CacheTotals, Notice};
        let metrics = Metrics::default();
        let attempt = CacheTotals {
            entries: 2,
            hits: 1,
            misses: 1,
            costly_hits: 1,
            lock_wait_ns: 500_000_000,
            clone_ns: 1_500_000_000,
            first_touch_ns: 250_000_000,
            commit_ns: 2_000_000_000,
            restored_bytes: 4096,
            copied_bytes: 1024,
            staged_bytes: 9000,
            dirty_bytes: 512,
        };
        metrics.count(&Notice::CacheFigures(attempt));
        metrics.count(&Notice::CacheFigures(attempt));
        let costs = sentinel_worker::cache::CostBook::new();
        for _ in 0..sentinel_worker::cache::cost::MIN_SAMPLES {
            costs.record_rebuild(sentinel_protocol::cache::Class::Compiler, 2_000_000_000);
        }
        metrics.count(&Notice::Availability(Availability {
            cache_costs: costs.figures(),
            images_held: Vec::new(),
            images_in_flight: 0,
            cache_entries: 0,
            cache_generations: 0,
            cache_bytes: 0,
            truncated: false,
        }));
        let page = metrics.render(1);
        for line in [
            "sentinel_worker_cache_hits_total 2
",
            "sentinel_worker_cache_misses_total 2
",
            "sentinel_worker_cache_costly_hits_total 2
",
            "sentinel_worker_cache_lock_wait_seconds_total 1.000000000
",
            "sentinel_worker_cache_restore_seconds_total 3.000000000
",
            "sentinel_worker_cache_first_touch_seconds_total 0.500000000
",
            "sentinel_worker_cache_commit_seconds_total 4.000000000
",
            "sentinel_worker_cache_restored_bytes_total 8192
",
            "sentinel_worker_cache_copied_bytes_total 2048
",
            "sentinel_worker_cache_dirty_bytes_total 1024
",
            "sentinel_worker_cache_rebuild_estimate_seconds{class=\"compiler\"} 2.000000000
",
        ] {
            assert!(
                page.contains(line),
                "{line}
{page}"
            );
        }
        assert!(
            !page.contains("estimate_seconds{class=\"dependencies\"}")
                && !page.contains("sentinel_worker_cache_restore_estimate_seconds"),
            "an unsettled estimate is absent, never zero"
        );
    }

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
