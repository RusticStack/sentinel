use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{self, BufReader, Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use sentinel_protocol::agent::{self, Exec, Reply, Request, Stream};

/// The job's root: the image under the overlay. Steps are chrooted here.
const JOB_ROOT: &str = "/job";
/// How long an exited step's pipes may stay open (a background child holding them) before `Exited` is sent.
const DRAIN: Duration = Duration::from_millis(500);

type Writer = Arc<Mutex<File>>;

/// A started command: the channel its end is reported on.
struct Running {
    done: mpsc::Sender<(Option<i32>, Option<i32>)>,
}

#[derive(Default)]
struct Children {
    by_pid: HashMap<i32, Running>,
    pid_of: HashMap<u32, i32>,
}

pub fn main() {
    if let Err(e) = boot() {
        console(&format!("sentinel-agent: boot failed: {e}"));
        power_off();
    }
    let children = Arc::new(Mutex::new(Children::default()));
    let reaper = Arc::clone(&children);
    thread::spawn(move || reap(&reaper));
    match listen() {
        Ok(listener) => loop {
            match accept(&listener) {
                Ok(conn) => {
                    let children = Arc::clone(&children);
                    thread::spawn(move || {
                        if let Err(e) = serve(conn, &children) {
                            console(&format!("sentinel-agent: connection ended: {e}"));
                        }
                    });
                }
                Err(e) => {
                    console(&format!("sentinel-agent: accept failed: {e}"));
                    thread::sleep(Duration::from_millis(100));
                }
            }
        },
        Err(e) => {
            console(&format!("sentinel-agent: cannot listen on vsock: {e}"));
            power_off();
        }
    }
}

fn console(line: &str) {
    if let Ok(mut c) = File::options().write(true).open("/dev/console") {
        let _ = writeln!(c, "{line}");
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other("NUL in path"))
}

fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    std::fs::create_dir_all(target)?;
    let (source, target, fstype, data) = (cstr(source)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    // SAFETY: every pointer is a NUL-terminated string that outlives the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        Err(io::Error::new(e.kind(), format!("mount {target:?}: {e}")))
    }
}

fn boot() -> io::Result<()> {
    mount("proc", "/proc", "proc", 0, "")?;
    mount("sysfs", "/sys", "sysfs", 0, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", 0, "")?;
    mount("/dev/vda", "/lower", "ext4", libc::MS_RDONLY, "")?;
    mount("/dev/vdb", "/scratch", "ext4", libc::MS_NOATIME, "")?;
    std::fs::create_dir_all("/scratch/upper")?;
    std::fs::create_dir_all("/scratch/work")?;
    mount(
        "overlay",
        JOB_ROOT,
        "overlay",
        0,
        "lowerdir=/lower,upperdir=/scratch/upper,workdir=/scratch/work",
    )?;
    let nodev = libc::MS_NOSUID | libc::MS_NODEV;
    mount("proc", "/job/proc", "proc", nodev | libc::MS_NOEXEC, "")?;
    mount(
        "sysfs",
        "/job/sys",
        "sysfs",
        nodev | libc::MS_NOEXEC | libc::MS_RDONLY,
        "",
    )?;
    mount("/dev", "/job/dev", "", libc::MS_BIND | libc::MS_REC, "")?;
    mount(
        "tmpfs",
        "/job/dev/shm",
        "tmpfs",
        nodev,
        "mode=1777,size=64m",
    )?;
    mount("tmpfs", "/job/tmp", "tmpfs", nodev, "mode=1777,size=1g")?;
    std::fs::create_dir_all("/job/workspace")?;
    loopback_up()?;
    if let Some(dns) = cmdline_value("sentinel.dns") {
        std::fs::create_dir_all("/job/etc")?;
        std::fs::write("/job/etc/resolv.conf", format!("nameserver {dns}\n"))?;
    }
    Ok(())
}

fn cmdline_value(key: &str) -> Option<String> {
    let line = std::fs::read_to_string("/proc/cmdline").ok()?;
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
        .map(str::to_owned)
}

/// Brings `lo` up, as a container's network namespace has it.
fn loopback_up() -> io::Result<()> {
    // SAFETY: a plain socket call; the descriptor is owned below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor this function owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain data; zeroed is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in b"lo".iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    use std::os::fd::AsRawFd;
    // SAFETY: req is a valid ifreq for SIOCSIFFLAGS and lives across the call.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn power_off() -> ! {
    // SAFETY: sync takes no arguments; reboot makes Firecracker end the VM.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn listen() -> io::Result<OwnedFd> {
    // SAFETY: a plain socket call; the descriptor is owned below.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor this function owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_vm is plain data; zeroed is a valid value.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = agent::PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    use std::os::fd::AsRawFd;
    // SAFETY: addr is a valid sockaddr_vm of the given size.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: listening on an owned, bound socket.
    if unsafe { libc::listen(sock.as_raw_fd(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

fn accept(listener: &OwnedFd) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    // SAFETY: accept on an owned listening socket; null address pointers are allowed.
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor the File now owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn send(writer: &Writer, reply: &Reply) -> io::Result<()> {
    let mut w = writer
        .lock()
        .map_err(|_| io::Error::other("writer poisoned"))?;
    agent::write(&mut *w, reply)
}

fn serve(conn: File, children: &Arc<Mutex<Children>>) -> io::Result<()> {
    let writer: Writer = Arc::new(Mutex::new(conn.try_clone()?));
    let mut reader = BufReader::with_capacity(agent::CHUNK, conn);
    match agent::read::<Request>(&mut reader)? {
        Some(Request::Hello { .. }) => {}
        other => return Err(io::Error::other(format!("expected Hello, got {other:?}"))),
    }
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    send(
        &writer,
        &Reply::Ready {
            version: agent::VERSION,
            kernel: kernel.trim().to_owned(),
        },
    )?;
    while let Some(request) = agent::read::<Request>(&mut reader)? {
        match request {
            Request::Put { root } => {
                let reply = match put(&mut reader, &root) {
                    Ok(()) => Reply::Done,
                    Err(e) => Reply::Failed {
                        message: format!("put {root}: {e}"),
                    },
                };
                send(&writer, &reply)?;
            }
            Request::Get { root, paths } => {
                if let Err(e) = get(&writer, &root, &paths) {
                    send(
                        &writer,
                        &Reply::Failed {
                            message: format!("get {root}: {e}"),
                        },
                    )?;
                }
            }
            Request::Exec(exec) => {
                if let Err(e) = start(exec.clone(), &writer, children) {
                    send(
                        &writer,
                        &Reply::Failed {
                            message: format!("exec {}: {e}", exec.id),
                        },
                    )?;
                }
            }
            Request::Signal { id, signal } => {
                let pid = children
                    .lock()
                    .ok()
                    .and_then(|c| c.pid_of.get(&id).copied());
                if let Some(pid) = pid {
                    // SAFETY: signalling the step's process group; it may already be gone.
                    unsafe { libc::kill(-pid, signal) };
                }
            }
            Request::SignalAll { signal } => {
                // From PID 1, kill(-1) reaches every process except the caller.
                // SAFETY: plain syscall.
                unsafe { libc::kill(-1, signal) };
                send(&writer, &Reply::Done)?;
            }
            Request::KillStrays => {
                // SAFETY: as above.
                unsafe { libc::kill(-1, libc::SIGKILL) };
                send(&writer, &Reply::Done)?;
            }
            Request::OomKills => send(&writer, &Reply::OomKills(oom_kills()))?,
            Request::Shutdown => power_off(),
            Request::Hello { .. } | Request::Data(_) | Request::End => {
                return Err(io::Error::other("unexpected frame"));
            }
        }
    }
    Ok(())
}

fn oom_kills() -> u64 {
    std::fs::read_to_string("/proc/vmstat")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("oom_kill ")?.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Reads `Data` frames as one byte stream until `End`.
struct DataIn<'a, R: Read> {
    reader: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
    ended: bool,
}

impl<R: Read> Read for DataIn<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.ended {
                return Ok(0);
            }
            match agent::read::<Request>(self.reader)? {
                Some(Request::Data(bytes)) => {
                    self.buf = bytes;
                    self.pos = 0;
                }
                Some(Request::End) => self.ended = true,
                other => return Err(io::Error::other(format!("expected Data, got {other:?}"))),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: Read> DataIn<'_, R> {
    /// Consumes what the archive left unread, through `End`, so the stream stays in step.
    fn finish(&mut self) -> io::Result<()> {
        let mut sink = [0u8; 8192];
        while self.read(&mut sink)? > 0 {}
        Ok(())
    }
}

fn put(reader: &mut impl Read, root: &str) -> io::Result<()> {
    let mut data = DataIn {
        reader,
        buf: Vec::new(),
        pos: 0,
        ended: false,
    };
    let result = (|| {
        if !root.starts_with('/') {
            return Err(io::Error::other("root must be absolute"));
        }
        std::fs::create_dir_all(root)?;
        let mut archive = tar::Archive::new(&mut data);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_overwrite(true);
        archive.unpack(root)
    })();
    // Read through `End` even after a failure, so the next request starts on a frame boundary.
    data.finish()?;
    result
}

/// Writes a byte stream as `Data` frames of at most [`agent::CHUNK`].
struct DataOut<'a> {
    writer: &'a Writer,
    buf: Vec<u8>,
}

impl Write for DataOut<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let room = agent::CHUNK - self.buf.len();
        let n = bytes.len().min(room);
        self.buf.extend_from_slice(&bytes[..n]);
        if self.buf.len() == agent::CHUNK {
            self.flush()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            send(self.writer, &Reply::Data(std::mem::take(&mut self.buf)))?;
        }
        Ok(())
    }
}

fn get(writer: &Writer, root: &str, paths: &[String]) -> io::Result<()> {
    let root = Path::new(root);
    let mut out = DataOut {
        writer,
        buf: Vec::with_capacity(agent::CHUNK),
    };
    {
        let mut builder = tar::Builder::new(&mut out);
        builder.follow_symlinks(false);
        for rel in paths {
            let rel = rel.trim_start_matches('/');
            if rel.split('/').any(|c| c == "..") {
                return Err(io::Error::other(format!("{rel}: escapes the root")));
            }
            let full = root.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&full) else {
                continue;
            };
            if meta.is_dir() {
                builder.append_dir_all(rel, &full)?;
            } else {
                builder.append_path_with_name(&full, rel)?;
            }
        }
        builder.finish()?;
    }
    out.flush()?;
    send(writer, &Reply::End)
}

/// Resolves `argv[0]` inside the job root, as the shell there would through `PATH`.
fn resolve(program: &str, env: &[(String, String)]) -> io::Result<PathBuf> {
    if program.contains('/') {
        return Ok(PathBuf::from(program));
    }
    let path = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for dir in path.split(':').filter(|d| d.starts_with('/')) {
        let candidate = Path::new(dir).join(program);
        let inside = Path::new(JOB_ROOT).join(candidate.strip_prefix("/").unwrap_or(&candidate));
        if std::fs::metadata(&inside)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{program}: not found in PATH"),
    ))
}

fn start(exec: Exec, writer: &Writer, children: &Arc<Mutex<Children>>) -> io::Result<()> {
    let program = exec
        .argv
        .first()
        .ok_or_else(|| io::Error::other("empty argv"))?;
    let resolved = resolve(program, &exec.env)?;
    let root = cstr(&exec.root)?;
    let workdir = cstr(&exec.workdir)?;
    let mut command = Command::new(&resolved);
    command
        .args(&exec.argv[1..])
        .env_clear()
        .envs(exec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::chroot(root.as_ptr()) != 0 || libc::chdir(workdir.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Hold the table across spawn so the reaper cannot see the pid before it is registered.
    let mut table = children
        .lock()
        .map_err(|_| io::Error::other("children poisoned"))?;
    let mut child = command.spawn()?;
    let pid = child.id() as i32;
    let (done_tx, done_rx) = mpsc::channel();
    table.by_pid.insert(pid, Running { done: done_tx });
    table.pid_of.insert(exec.id, pid);
    drop(table);
    let (eof_tx, eof_rx) = mpsc::channel::<()>();
    let pumps = [
        (
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            Stream::Stdout,
        ),
        (
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            Stream::Stderr,
        ),
    ];
    // The Child is never waited on here: the reaper owns waitpid.
    drop(child);
    for (pipe, stream) in pumps {
        let Some(mut pipe) = pipe else { continue };
        let (writer, eof, id) = (Arc::clone(writer), eof_tx.clone(), exec.id);
        thread::spawn(move || {
            let mut buf = vec![0u8; 64 << 10];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let reply = Reply::Output {
                            id,
                            stream,
                            bytes: buf[..n].to_vec(),
                        };
                        if send(&writer, &reply).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = eof.send(());
        });
    }
    drop(eof_tx);
    let (writer, children, id) = (Arc::clone(writer), Arc::clone(children), exec.id);
    thread::spawn(move || {
        let (code, signal) = done_rx.recv().unwrap_or((None, None));
        // Both pipes, unless a background child keeps one open past the drain.
        let deadline = std::time::Instant::now() + DRAIN;
        for _ in 0..2 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if eof_rx.recv_timeout(left).is_err() {
                break;
            }
        }
        if let Ok(mut c) = children.lock() {
            c.pid_of.remove(&id);
        }
        let _ = send(&writer, &Reply::Exited { id, code, signal });
    });
    Ok(())
}

/// PID 1's reaper: every child and orphan ends here; a step's end goes to its waiter.
fn reap(children: &Arc<Mutex<Children>>) {
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            // ECHILD: nothing to reap yet.
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let running = children.lock().ok().and_then(|mut c| c.by_pid.remove(&pid));
        if let Some(running) = running {
            let ended = if libc::WIFEXITED(status) {
                (Some(libc::WEXITSTATUS(status)), None)
            } else if libc::WIFSIGNALED(status) {
                (None, Some(libc::WTERMSIG(status)))
            } else {
                (None, None)
            };
            let _ = running.done.send(ended);
        }
    }
}
