//! Helper processes under a deadline, in their own process group, with
//! bounded output capture. `git` and `podman` are both run this way.

use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{Error, Result};

/// Bytes of each stream kept for diagnostics; older output is dropped.
pub const OUTPUT_TAIL_BYTES: usize = 64 * 1024;
/// How often a running helper is checked against its deadline.
const POLL: Duration = Duration::from_millis(20);

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
        let text = String::from_utf8_lossy(&self.stderr);
        let line = text
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        let mut out: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
        if out.is_empty() {
            out.push_str("no diagnostic output");
        }
        out
    }
}

/// Read a stream to its end, keeping only the last [`OUTPUT_TAIL_BYTES`].
fn drain(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut tail = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tail.extend_from_slice(&chunk[..n]);
                    if tail.len() > OUTPUT_TAIL_BYTES {
                        let excess = tail.len() - OUTPUT_TAIL_BYTES;
                        tail.drain(..excess);
                    }
                }
            }
        }
        tail
    })
}

/// Run `command` as the leader of a new process group, with stdin closed,
/// and wait until it exits or `deadline` passes — then the whole group is
/// killed and `Timeout(what)` returned.
pub fn run(mut command: Command, deadline: Instant, what: &'static str) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = drain(child.stdout.take().expect("piped"));
    let stderr = drain(child.stderr.take().expect("piped"));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let pgid = child.id() as libc::pid_t;
            // SAFETY: a plain syscall on our own child's process group id; a
            // group that already vanished makes kill fail harmlessly.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(Error::Timeout(what));
        }
        thread::sleep(POLL);
    };
    Ok(Output {
        code: status.code(),
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}
