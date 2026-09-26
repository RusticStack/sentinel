//! Helper processes under a deadline, in their own process group, with
//! bounded output capture. `git` and `podman` are both run this way.
//!
//! Waiting costs no polling: the child's exit wakes the wait at once (a
//! pidfd), and the wait only returns early to look at the deadline and the
//! cancel flag. A cancel kills the whole group, so a preparation helper — a
//! large pull, say — never runs on after the attempt was cancelled.

use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};

use sentinel_protocol::logs::Stream;

use crate::{Error, Result};

/// Where a helper's output streams as it is produced (W05). Called from the
/// reader threads with chunks of at most `CHUNK_BYTES`; must not block
/// for long, since the child's pipe fills behind it.
pub type Sink = Arc<dyn Fn(Stream, &[u8]) + Send + Sync>;
/// Bytes read from a pipe per call; well under one log frame.
pub const CHUNK_BYTES: usize = 8192;

/// Bytes of each stream kept for diagnostics; older output is dropped.
pub const OUTPUT_TAIL_BYTES: usize = 64 * 1024;

/// What a helper produced. `code` is `None` when it died from a signal.
#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The last line of stderr, printable characters only, for an error.
    pub fn stderr_excerpt(&self) -> String {
        crate::redact::excerpt(&self.stderr)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
        core::hint::black_box((&mut self.stdout, &mut self.stderr));
    }
}

/// The last [`OUTPUT_TAIL_BYTES`] of a stream: a fixed ring written in
/// place, so keeping the tail of a long stream costs no memmove per chunk.
struct Tail {
    ring: Vec<u8>,
    /// Where the next byte goes once the ring is full.
    head: usize,
}

impl Tail {
    fn new() -> Tail {
        Tail {
            ring: Vec::with_capacity(4096),
            head: 0,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        if bytes.len() >= OUTPUT_TAIL_BYTES {
            bytes = &bytes[bytes.len() - OUTPUT_TAIL_BYTES..];
            self.ring.clear();
            self.ring.extend_from_slice(bytes);
            self.head = 0;
            return;
        }
        let room = OUTPUT_TAIL_BYTES - self.ring.len();
        if room > 0 {
            let fill = room.min(bytes.len());
            self.ring.extend_from_slice(&bytes[..fill]);
            bytes = &bytes[fill..];
        }
        while !bytes.is_empty() {
            let n = (OUTPUT_TAIL_BYTES - self.head).min(bytes.len());
            self.ring[self.head..self.head + n].copy_from_slice(&bytes[..n]);
            self.head = (self.head + n) % OUTPUT_TAIL_BYTES;
            bytes = &bytes[n..];
        }
    }

    /// The tail in order, oldest byte first.
    fn into_bytes(mut self) -> Vec<u8> {
        if self.ring.len() == OUTPUT_TAIL_BYTES {
            self.ring.rotate_left(self.head);
        }
        std::mem::take(&mut self.ring)
    }
}

impl Drop for Tail {
    fn drop(&mut self) {
        self.ring.fill(0);
        core::hint::black_box(&mut self.ring);
    }
}

/// Read a stream to its end, keeping only the last [`OUTPUT_TAIL_BYTES`]
/// and handing every chunk to the sink as it arrives.
fn drain(
    mut stream: impl Read + Send + 'static,
    which: Stream,
    sink: Option<Sink>,
) -> std::io::Result<thread::JoinHandle<Vec<u8>>> {
    thread::Builder::new()
        .name("sentinel-helper-out".into())
        .spawn(move || {
            let mut tail = Tail::new();
            let mut chunk = [0u8; CHUNK_BYTES];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Some(sink) = &sink {
                            sink(which, &chunk[..n]);
                        }
                        tail.push(&chunk[..n]);
                        chunk[..n].fill(0);
                    }
                }
            }
            tail.into_bytes()
        })
}

/// Run `command` as the leader of a new process group, with stdin closed,
/// and wait until it exits or `deadline` passes — then the whole group is
/// killed and `Timeout(what)` returned.
pub fn run(command: Command, deadline: Instant, what: &'static str) -> Result<Output> {
    run_with(command, deadline, what, None)
}

/// [`run`] with the output also streamed to `sink`.
pub fn run_with(
    command: Command,
    deadline: Instant,
    what: &'static str,
    sink: Option<Sink>,
) -> Result<Output> {
    run_canceled(command, deadline, what, sink, None)
}

fn kill_group(child: &mut std::process::Child) {
    let pgid = child.id() as libc::pid_t;
    // SAFETY: a plain syscall on our own child's process group id; a group
    // that already vanished makes kill fail harmlessly.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// [`run_with`] that also ends — killing the whole group — once `cancel`
/// is set, with `Preparation("<what> canceled")`.
pub fn run_canceled(
    mut command: Command,
    deadline: Instant,
    what: &'static str,
    sink: Option<Sink>,
    cancel: Option<&AtomicBool>,
) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let readers = drain(
        child.stdout.take().expect("piped"),
        Stream::Stdout,
        sink.clone(),
    )
    .and_then(|stdout| {
        drain(child.stderr.take().expect("piped"), Stream::Stderr, sink).map(|e| (stdout, e))
    });
    let (stdout, stderr) = match readers {
        Ok(readers) => readers,
        Err(e) => {
            // No thread to read its pipes: the helper must not run on
            // unobserved.
            kill_group(&mut child);
            return Err(e.into());
        }
    };
    let watch = sentinel_git::ExitWatch::of(&child);
    let status = loop {
        if let Some(status) = sentinel_git::wait_step(&mut child, &watch, deadline)? {
            break status;
        }
        let canceled = cancel.is_some_and(|c| c.load(Ordering::Acquire));
        if canceled || Instant::now() >= deadline {
            kill_group(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(if canceled {
                Error::Preparation(format!("{what} canceled"))
            } else {
                Error::Timeout(what)
            });
        }
    };
    Ok(Output {
        code: status.code(),
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn the_tail_keeps_the_last_bytes_in_order() {
        let mut tail = Tail::new();
        let mut all = Vec::new();
        for i in 0..40u32 {
            let chunk: Vec<u8> = (0..5_000).map(|j| ((i * 7 + j) % 251) as u8).collect();
            tail.push(&chunk);
            all.extend_from_slice(&chunk);
        }
        assert_eq!(tail.into_bytes(), all[all.len() - OUTPUT_TAIL_BYTES..]);
        let mut short = Tail::new();
        short.push(b"abc");
        short.push(b"def");
        assert_eq!(short.into_bytes(), b"abcdef");
    }

    /// P04-16: a cancel kills a running helper's whole group at once
    /// instead of letting it run to its deadline.
    #[test]
    fn a_cancel_kills_a_running_helper() {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            flag.store(true, Ordering::Release);
        });
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30"]);
        let started = Instant::now();
        let outcome = run_canceled(
            cmd,
            Instant::now() + Duration::from_secs(30),
            "sleep",
            None,
            Some(&cancel),
        );
        setter.join().unwrap();
        assert!(matches!(outcome, Err(Error::Preparation(_))));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A helper that exits is noticed at once, not at the next poll tick:
    /// running one costs what a blocking `wait` costs, plus the reader
    /// threads — not an extra poll interval (the old 20 ms sleep added
    /// 10 ms on average and at least 20 ms to a helper that outlived the
    /// first check).
    ///
    /// Measured in interleaved pairs (alternating which goes first) and
    /// judged by the median paired difference, so a host whose load drifts
    /// during the test — a full parallel suite — moves both sides alike. A
    /// 2 ms child would cost about 18 ms more under the old poll.
    #[test]
    fn a_quick_helper_is_not_held_by_a_poll_interval() {
        const PAIRS: usize = 21;
        let sleep = || {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "sleep 0.002"]);
            cmd
        };
        let blocking = || {
            let started = Instant::now();
            assert!(sleep().status().unwrap().success());
            started.elapsed()
        };
        let ours = || {
            let started = Instant::now();
            let output = run(sleep(), Instant::now() + Duration::from_secs(10), "sleep").unwrap();
            assert!(output.success());
            started.elapsed()
        };
        let mut extra: Vec<i128> = (0..PAIRS)
            .map(|i| {
                let (b, o) = if i % 2 == 0 {
                    let b = blocking();
                    (b, ours())
                } else {
                    let o = ours();
                    (blocking(), o)
                };
                o.as_micros() as i128 - b.as_micros() as i128
            })
            .collect();
        extra.sort_unstable();
        let median = extra[PAIRS / 2];
        assert!(
            median < 8_000,
            "a helper cost {median} µs more than a blocking wait (median of {PAIRS} pairs: {extra:?})"
        );
    }
}
