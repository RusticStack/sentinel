//! This process's own figures from `/proc/self` (Linux), for the controller's
//! and the worker's metrics and diagnostics (R06). `None` where the platform
//! has no `/proc`.

/// What `/proc/self` says about this process right now.
#[derive(Clone, Copy, Debug, Default)]
pub struct Figures {
    /// Resident memory.
    pub resident_bytes: Option<u64>,
    /// User plus system CPU time since start.
    pub cpu_seconds: Option<f64>,
    /// Open file descriptors.
    pub open_fds: Option<u64>,
    /// Threads.
    pub threads: Option<u64>,
}

/// Read them. A few small `/proc` reads; cheap enough for every scrape.
pub fn figures() -> Figures {
    #[cfg(target_os = "linux")]
    {
        // `statm` counts pages; every Linux target Sentinel builds for uses
        // 4 KiB pages.
        let resident_bytes = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map(|pages| pages * 4096);
        let stat = std::fs::read_to_string("/proc/self/stat").ok();
        // After the parenthesised command, field n of proc(5) is at index
        // n - 3: utime 14, stime 15, num_threads 20. Clock ticks are 100 Hz.
        let fields: Vec<&str> = stat
            .as_deref()
            .and_then(|s| s.rsplit_once(')'))
            .map(|(_, rest)| rest.split_whitespace().collect())
            .unwrap_or_default();
        let at = |n: usize| fields.get(n - 3).and_then(|v| v.parse::<u64>().ok());
        let cpu_seconds = match (at(14), at(15)) {
            (Some(u), Some(s)) => Some((u + s) as f64 / 100.0),
            _ => None,
        };
        let open_fds = std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|d| d.count() as u64);
        Figures {
            resident_bytes,
            cpu_seconds,
            open_fds,
            threads: at(20),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Figures::default()
}
