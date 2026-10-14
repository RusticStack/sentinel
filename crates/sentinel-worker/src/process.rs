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

pub type Sink = Arc<dyn Fn(Stream, &[u8]) + Send + Sync>;
pub const CHUNK_BYTES: usize = 8192;

pub const OUTPUT_TAIL_BYTES: usize = 64 * 1024;

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

    pub fn stderr_excerpt(&self) -> String {
        crate::redact::excerpt(&self.stderr)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
        // black_box keeps the optimizer from eliding the zeroing.
        core::hint::black_box((&mut self.stdout, &mut self.stderr));
    }
}

struct Tail {
    ring: Vec<u8>,
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

pub fn run(command: Command, deadline: Instant, what: &'static str) -> Result<Output> {
    run_with(command, deadline, what, None)
}

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
    // A worker that dies takes its helpers with it instead of leaving them to run to their deadlines.
    sentinel_git::die_with_parent(&mut command);
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
            kill_group(&mut child);
            return Err(e.into());
        }
    };
    let watch = sentinel_git::ExitWatch::of(&child);
    let status = loop {
        match sentinel_git::wait_step(&mut child, &watch, deadline) {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                // A helper must not keep running unobserved after a failed wait.
                kill_group(&mut child);
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(error.into());
            }
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

    #[test]
    fn a_quick_helper_is_not_held_by_a_poll_interval() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("release");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in a directory this test owns.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let probe = Command::new("sleep").arg("600").spawn().unwrap();
        assert!(sentinel_git::ExitWatch::of(&probe).wakes_on_exit());
        let mut probe = probe;
        probe.kill().unwrap();
        probe.wait().unwrap();

        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let held = fifo.clone();
        let helper = thread::spawn(move || {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg("cat \"$1\" >/dev/null")
                .arg("sh")
                .arg(held);
            let output = run(cmd, Instant::now() + Duration::from_secs(300), "held");
            flag.store(true, Ordering::Release);
            output
        });
        thread::sleep(Duration::from_millis(200));
        assert!(
            !done.load(Ordering::Acquire),
            "returned before the helper exited"
        );
        let released = Instant::now();
        drop(std::fs::OpenOptions::new().write(true).open(&fifo).unwrap());
        let output = helper.join().unwrap().unwrap();
        assert!(output.success());
        assert!(
            released.elapsed() < Duration::from_secs(60),
            "held towards its deadline"
        );
    }
}
