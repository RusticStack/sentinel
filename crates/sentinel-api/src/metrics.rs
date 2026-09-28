//! Scrapeable metrics (R06): `GET /metrics` in the Prometheus text
//! exposition format, and the request counters the HTTP layer keeps.
//!
//! Everything here is either an atomic the hot paths already bump or an
//! indexed count the store answers from a partial index; a scrape costs a
//! handful of short reads, never a table scan. A value that cannot be
//! measured (a platform without `/proc`, a feature not configured) is
//! absent, never zero.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Duration,
};

use crate::State;

/// Upper bounds of the request-duration histogram, in seconds.
const BUCKETS: [f64; 10] = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// What the HTTP layer counts per request.
#[derive(Default)]
pub(crate) struct Requests {
    /// By status class: 1xx … 5xx.
    by_class: [AtomicU64; 5],
    /// Cumulative-by-construction later: each request lands in the first
    /// bucket whose bound it is within, `+Inf` last.
    buckets: [AtomicU64; BUCKETS.len() + 1],
    micros: AtomicU64,
    /// Refusals worth watching for: a wrong or missing credential, a
    /// credential without the right, the admission budgets.
    pub unauthenticated: AtomicU64,
    pub forbidden: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl Requests {
    pub(crate) fn observe(&self, status: u16, took: Duration) {
        let class = usize::from(status / 100).clamp(1, 5) - 1;
        self.by_class[class].fetch_add(1, Relaxed);
        let secs = took.as_secs_f64();
        let bucket = BUCKETS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS.len());
        self.buckets[bucket].fetch_add(1, Relaxed);
        self.micros
            .fetch_add(u64::try_from(took.as_micros()).unwrap_or(u64::MAX), Relaxed);
        match status {
            401 => {
                self.unauthenticated.fetch_add(1, Relaxed);
            }
            403 => {
                self.forbidden.fetch_add(1, Relaxed);
            }
            429 => {
                self.rate_limited.fetch_add(1, Relaxed);
            }
            _ => {}
        }
    }

    /// The counters as JSON, for the diagnostic bundle.
    pub(crate) fn snapshot(&self) -> serde_json::Value {
        let n = |a: &AtomicU64| a.load(Relaxed);
        let total: u64 = self.by_class.iter().map(n).sum();
        serde_json::json!({
            "requests": total,
            "by_class": {
                "1xx": n(&self.by_class[0]), "2xx": n(&self.by_class[1]),
                "3xx": n(&self.by_class[2]), "4xx": n(&self.by_class[3]),
                "5xx": n(&self.by_class[4]),
            },
            "mean_ms": if total == 0 { 0.0 } else { n(&self.micros) as f64 / total as f64 / 1e3 },
            "unauthenticated": n(&self.unauthenticated),
            "forbidden": n(&self.forbidden),
            "rate_limited": n(&self.rate_limited),
        })
    }
}

/// A metric family being written.
struct Out(String);

impl Out {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }
    fn value(&mut self, name: &str, labels: &str, value: impl std::fmt::Display) {
        if labels.is_empty() {
            let _ = writeln!(self.0, "{name} {value}");
        } else {
            let _ = writeln!(self.0, "{name}{{{labels}}} {value}");
        }
    }
    fn one(&mut self, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
        self.family(name, kind, help);
        self.value(name, "", value);
    }
}

/// Escape a label value.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The process's own figures ([`sentinel_core::process`]).
fn process(out: &mut Out) {
    let f = sentinel_core::process::figures();
    if let Some(v) = f.resident_bytes {
        out.one(
            "sentinel_process_resident_bytes",
            "gauge",
            "Resident memory of this process.",
            v,
        );
    }
    if let Some(v) = f.cpu_seconds {
        out.one(
            "sentinel_process_cpu_seconds_total",
            "counter",
            "CPU time this process used.",
            v,
        );
    }
    if let Some(v) = f.open_fds {
        out.one(
            "sentinel_process_open_fds",
            "gauge",
            "Open file descriptors.",
            v,
        );
    }
    if let Some(v) = f.threads {
        out.one("sentinel_process_threads", "gauge", "Threads.", v);
    }
}

/// Render every metric.
pub(crate) fn render(state: &State) -> String {
    let mut out = Out(String::with_capacity(8 * 1024));
    let schema: i64 = state
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap_or(0);
    out.family(
        "sentinel_build_info",
        "gauge",
        "The running build: version and database schema.",
    );
    out.value(
        "sentinel_build_info",
        &format!(
            "version=\"{}\",schema=\"{schema}\"",
            label(env!("CARGO_PKG_VERSION"))
        ),
        1,
    );
    process(&mut out);

    // HTTP.
    let r = &state.requests;
    out.family(
        "sentinel_http_requests_total",
        "counter",
        "Requests answered, by status class.",
    );
    for (i, class) in ["1xx", "2xx", "3xx", "4xx", "5xx"].iter().enumerate() {
        out.value(
            "sentinel_http_requests_total",
            &format!("class=\"{class}\""),
            r.by_class[i].load(Relaxed),
        );
    }
    out.family(
        "sentinel_http_request_duration_seconds",
        "histogram",
        "Time to answer a request.",
    );
    let mut cumulative = 0u64;
    for (i, bound) in BUCKETS.iter().enumerate() {
        cumulative += r.buckets[i].load(Relaxed);
        out.value(
            "sentinel_http_request_duration_seconds_bucket",
            &format!("le=\"{bound}\""),
            cumulative,
        );
    }
    cumulative += r.buckets[BUCKETS.len()].load(Relaxed);
    out.value(
        "sentinel_http_request_duration_seconds_bucket",
        "le=\"+Inf\"",
        cumulative,
    );
    out.value(
        "sentinel_http_request_duration_seconds_sum",
        "",
        r.micros.load(Relaxed) as f64 / 1e6,
    );
    out.value(
        "sentinel_http_request_duration_seconds_count",
        "",
        cumulative,
    );
    out.family(
        "sentinel_auth_refusals_total",
        "counter",
        "Requests refused for their credential or its rights.",
    );
    out.value(
        "sentinel_auth_refusals_total",
        "reason=\"unauthenticated\"",
        r.unauthenticated.load(Relaxed),
    );
    out.value(
        "sentinel_auth_refusals_total",
        "reason=\"forbidden\"",
        r.forbidden.load(Relaxed),
    );
    out.one(
        "sentinel_http_rate_limited_total",
        "counter",
        "Requests refused by an admission budget.",
        r.rate_limited.load(Relaxed),
    );
    out.one(
        "sentinel_http_parked_polls",
        "gauge",
        "Long polls parked right now.",
        state.subscribers.held(),
    );

    // Queue and fleet, from partial indexes.
    let queue = state.store.read(|c| {
        let count =
            |sql: &str| -> sentinel_store::Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
        Ok((
            count("SELECT COUNT(*) FROM jobs WHERE state_code = 1")?,
            count("SELECT COUNT(*) FROM jobs WHERE state_code = 0")?,
            count("SELECT COUNT(*) FROM attempts WHERE released_ms IS NULL")?,
            c.query_row(
                "SELECT MIN(queued_ms) FROM jobs WHERE state_code = 1",
                [],
                |r| r.get::<_, Option<i64>>(0),
            )?,
            count("SELECT COUNT(*) FROM workers WHERE revoked_ms IS NULL")?,
            count(
                "SELECT COUNT(*) FROM workers WHERE revoked_ms IS NULL AND drain_ms IS NOT NULL",
            )?,
        ))
    });
    if let Ok((queued, blocked, held, oldest, enrolled, draining)) = queue {
        out.family(
            "sentinel_jobs_waiting",
            "gauge",
            "Jobs not yet running: queued (ready) or blocked on dependencies.",
        );
        out.value("sentinel_jobs_waiting", "state=\"queued\"", queued);
        out.value("sentinel_jobs_waiting", "state=\"blocked\"", blocked);
        out.one(
            "sentinel_attempts_held",
            "gauge",
            "Attempts a worker holds (offered through finalizing).",
            held,
        );
        if let Some(oldest) = oldest {
            let age = (sentinel_core::UnixMillis::now().0 - oldest).max(0) as f64 / 1e3;
            out.one(
                "sentinel_jobs_oldest_queued_seconds",
                "gauge",
                "Age of the longest-waiting queued job.",
                age,
            );
        }
        out.family(
            "sentinel_workers",
            "gauge",
            "Enrolled workers: connected now, draining, and all.",
        );
        out.value("sentinel_workers", "state=\"enrolled\"", enrolled);
        out.value(
            "sentinel_workers",
            "state=\"connected\"",
            state.controller.connected().len(),
        );
        out.value("sentinel_workers", "state=\"draining\"", draining);
    }

    // The worker link's own counters.
    let s = state.controller.stats();
    out.family(
        "sentinel_link_events_total",
        "counter",
        "Worker link events since start.",
    );
    for (name, v) in [
        ("admitted", &s.admitted),
        ("rejected", &s.rejected),
        ("offers", &s.offers),
        ("acknowledged", &s.acknowledged),
        ("lapsed", &s.lapsed),
        ("sessions_ended", &s.sessions_ended),
        ("reports", &s.reports),
        ("stale_reports", &s.stale_reports),
        ("log_frames", &s.log_frames),
        ("log_refused", &s.log_refused),
        ("expired", &s.expired),
        ("queue_timeouts", &s.queue_timeouts),
        ("abandoned", &s.abandoned),
        ("artifacts", &s.artifacts),
        ("bulk_attached", &s.bulk_attached),
        ("bulk_refused", &s.bulk_refused),
        ("cache_denied", &s.cache_denied),
        ("shed", &s.shed),
        ("handed_back", &s.handed_back),
        ("placement_errors", &s.placement_errors),
        ("sweep_errors", &s.sweep_errors),
        ("prefetch_hints", &s.prefetch_hints),
        ("revoked_sessions", &s.revoked_sessions),
    ] {
        out.value(
            "sentinel_link_events_total",
            &format!("event=\"{name}\""),
            v.load(Relaxed),
        );
    }
    out.one(
        "sentinel_remote_cache_bytes",
        "gauge",
        "Bytes the controller's remote cache store keeps.",
        s.remote_cache_bytes.load(Relaxed),
    );
    out.one(
        "sentinel_log_writers_open",
        "gauge",
        "Attempt log writers open.",
        state.logs.open_writers(),
    );

    // Disk and storage.
    if let Some(a) = state.objects.admission() {
        out.one(
            "sentinel_storage_free_bytes",
            "gauge",
            "Free bytes on the data file system.",
            a.free(),
        );
        out.one(
            "sentinel_storage_reserve_bytes",
            "gauge",
            "The reserve in force (metadata and log evidence).",
            a.reserve(),
        );
        out.one(
            "sentinel_storage_inflight_bytes",
            "gauge",
            "Bytes admitted but not yet committed.",
            a.total_inflight(),
        );
        out.one(
            "sentinel_storage_admission_open",
            "gauge",
            "Whether new artifacts, uploads and work are admitted (1) or held (0).",
            u8::from(a.is_open()),
        );
    }
    out.one(
        "sentinel_storage_metadata_bytes",
        "gauge",
        "The metadata database on disk.",
        state.store.metadata_bytes(),
    );
    if let Ok(stored) = state
        .store
        .read(sentinel_store::retention::deployment_usage)
    {
        out.one(
            "sentinel_storage_stored_bytes",
            "gauge",
            "Objects, uploads and logs every tenant stores.",
            stored,
        );
    }
    if let Some(r) = state.objects.replication() {
        out.one(
            "sentinel_s3_healthy",
            "gauge",
            "The external copy's last pass succeeded (1) or it is degraded (0).",
            u8::from(r.state() == "healthy"),
        );
        out.one(
            "sentinel_s3_backlog_bytes",
            "gauge",
            "Bytes waiting for the external copy.",
            r.backlog_bytes.load(Relaxed),
        );
        out.one(
            "sentinel_s3_backlog_full",
            "gauge",
            "The backlog is past its budget and holds admission.",
            u8::from(r.backlog_full.load(Relaxed)),
        );
        out.one(
            "sentinel_s3_replicated_bytes_total",
            "counter",
            "Bytes copied to the external copy since start.",
            r.replicated_bytes.load(Relaxed),
        );
        out.one(
            "sentinel_s3_consecutive_failures",
            "gauge",
            "Replicator passes failed in a row.",
            r.consecutive_failures.load(Relaxed),
        );
    }
    if let Some(b) = state.objects.backups() {
        let status = b.status();
        if let Some(at) = status["last_success_ms"].as_i64() {
            out.one(
                "sentinel_backup_last_success_seconds",
                "gauge",
                "Unix time of the last successful backup.",
                at as f64 / 1e3,
            );
        }
        out.one(
            "sentinel_backup_last_failed",
            "gauge",
            "The most recent backup attempt failed (1).",
            u8::from(!status["last_failure"].is_null()),
        );
    }

    // GitHub check publication, from its partial indexes.
    if let Ok((pending, refused, oldest)) = state.store.read(|c| {
        Ok((
            c.query_row(
                "SELECT COUNT(*) FROM check_publications WHERE state = 0",
                [],
                |r| r.get::<_, i64>(0),
            )?,
            c.query_row(
                "SELECT COUNT(*) FROM check_publications WHERE state = 2",
                [],
                |r| r.get::<_, i64>(0),
            )?,
            c.query_row(
                "SELECT MIN(updated_ms) FROM check_publications WHERE state = 0",
                [],
                |r| r.get::<_, Option<i64>>(0),
            )?,
        ))
    }) {
        out.family(
            "sentinel_github_check_publications",
            "gauge",
            "GitHub check publications waiting or refused.",
        );
        out.value(
            "sentinel_github_check_publications",
            "state=\"pending\"",
            pending,
        );
        out.value(
            "sentinel_github_check_publications",
            "state=\"refused\"",
            refused,
        );
        if let Some(oldest) = oldest {
            let age = (sentinel_core::UnixMillis::now().0 - oldest).max(0) as f64 / 1e3;
            out.one(
                "sentinel_github_oldest_pending_seconds",
                "gauge",
                "Age of the oldest waiting check publication.",
                age,
            );
        }
    }
    out.0
}
