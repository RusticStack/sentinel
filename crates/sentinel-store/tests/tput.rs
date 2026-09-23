//! Concurrent log append throughput (P06-8 measurement). `--ignored`.
use std::{sync::Arc, time::Instant};

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::logs::LogStore;

#[test]
#[ignore]
fn concurrent_append_throughput() {
    let attempts: usize = std::env::var("TPUT_ATTEMPTS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let frames: u64 = 250;
    let temp = tempfile::tempdir().unwrap();
    let logs = Arc::new(LogStore::open(temp.path().join("logs")).unwrap());
    let (run, job) = (RunId::new(), JobId::new());
    let started = Instant::now();
    let threads: Vec<_> = (0..attempts)
        .map(|_| {
            let logs = Arc::clone(&logs);
            std::thread::spawn(move || {
                let attempt = AttemptId::new();
                for seq in 1..=frames {
                    logs.append(
                        run,
                        job,
                        attempt,
                        &Frame { seq, step: 0, stream: Stream::Stdout, bytes: vec![b'x'; 512] },
                    )
                    .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let elapsed = started.elapsed();
    let total = attempts as u64 * frames;
    println!(
        "TPUT attempts={attempts} frames={total} secs={:.3} frames_per_sec={:.0}",
        elapsed.as_secs_f64(),
        total as f64 / elapsed.as_secs_f64()
    );
}
