#[derive(Clone, Copy, Debug, Default)]
pub struct Figures {
    pub resident_bytes: Option<u64>,
    pub cpu_seconds: Option<f64>,
    pub open_fds: Option<u64>,
    pub threads: Option<u64>,
}

pub fn figures() -> Figures {
    #[cfg(target_os = "linux")]
    {
        // statm counts pages; Sentinel's Linux targets all use 4 KiB pages.
        let resident_bytes = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map(|pages| pages * 4096);
        let stat = std::fs::read_to_string("/proc/self/stat").ok();
        // proc(5) field n sits at index n - 3 after the command name; clock ticks are 100 Hz.
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
