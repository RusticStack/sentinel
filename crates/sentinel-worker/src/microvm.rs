//! MicroVM jobs (plan 16.8, TODO M03–M05): one Firecracker VM per attempt, steps run by the guest agent.
//!
//! Rootless, like the container executor. Firecracker's jailer needs root, so its sandbox is built from
//! what the worker account has: a user namespace from `podman unshare` (Podman's setuid id-map helpers),
//! a fresh network namespace (empty unless the worker grants egress), a user systemd scope that caps CPU
//! and memory and names the VM for cleanup, and Firecracker's own seccomp filters. The guest boots the
//! pinned kernel with an initramfs whose `/init` is the agent; `/dev/vda` is the job image as a read-only
//! ext4 file built once per image (cached under `microvm/images`) and `/dev/vdb` the attempt's scratch
//! disk, sized to the job's disk reservation. Firecracker has no shared file system, so the workspace and
//! mounts go in as tar streams over vsock and the paths the host reads afterwards (artifacts, writable
//! caches) come back the same way.

use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_pipeline::run::StepCommand;
use sentinel_protocol::agent::{self, Reply, Request};

use crate::{
    Error, Result,
    podman::{Exit, Limits, Mount, Network, Store, Terminated, WORKSPACE_MOUNT},
    process,
};

/// Under the worker's data root.
pub const DIR: &str = "microvm";
/// Guest path of the job image's root (the overlay the agent builds).
const JOB_ROOT: &str = "/job";
/// The guest CID Firecracker gives the VM; the host side is the vsock socket file.
const GUEST_CID: u32 = 3;
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(900);
/// Memory the VMM process needs beyond the guest's RAM, in the scope's cap.
const VMM_OVERHEAD: u64 = 256 << 20;

/// The operator's `[microvm]` setup: Firecracker, the pinned guest kernel and the static agent binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub agent: PathBuf,
}

impl Setup {
    /// Whether this setup can run a VM, as text for `runtime_selected`.
    pub fn check(&self) -> std::result::Result<(), String> {
        let executable = |p: &Path| {
            fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        };
        if !executable(&self.firecracker) {
            return Err(format!(
                "{}: not an executable file",
                self.firecracker.display()
            ));
        }
        if !fs::metadata(&self.kernel).is_ok_and(|m| m.is_file()) {
            return Err(format!("{}: no guest kernel", self.kernel.display()));
        }
        if !executable(&self.agent) {
            return Err(format!("{}: not an executable file", self.agent.display()));
        }
        Ok(())
    }
}

fn vm_dir(root: &Path, attempt: AttemptId) -> PathBuf {
    root.join(DIR).join("vms").join(attempt.to_string())
}

fn unit_name(attempt: AttemptId) -> String {
    format!("sentinel-vm-{attempt}")
}

fn systemctl_user(args: &[&str]) -> io::Result<std::process::Output> {
    Command::new("systemctl").arg("--user").args(args).output()
}

// ---------------------------------------------------------------- initramfs

/// The initramfs with the agent as `/init`, written once per agent binary (named by its digest).
pub fn initramfs(root: &Path, setup: &Setup) -> Result<PathBuf> {
    let agent = fs::read(&setup.agent)?;
    let digest = blake3::hash(&agent).to_hex();
    let dir = root.join(DIR);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("initramfs-{}.cpio", &digest[..16]));
    if path.exists() {
        return Ok(path);
    }
    let mut out = Vec::with_capacity(agent.len() + 4096);
    let mut ino = 1;
    for dir in ["dev", "proc", "sys", "lower", "scratch", "job"] {
        cpio_entry(&mut out, &mut ino, dir, 0o040755, &[]);
    }
    cpio_entry(&mut out, &mut ino, "init", 0o100755, &agent);
    cpio_entry(&mut out, &mut ino, "TRAILER!!!", 0, &[]);
    let tmp = dir.join(format!(
        ".initramfs-{}.{}",
        &digest[..16],
        std::process::id()
    ));
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, &path)?;
    Ok(path)
}

/// One `newc` cpio record (the format the kernel unpacks into the initial root).
fn cpio_entry(out: &mut Vec<u8>, ino: &mut u32, name: &str, mode: u32, data: &[u8]) {
    let fields = [
        *ino,
        mode,
        0,
        0,
        1,
        0,
        data.len() as u32,
        0,
        0,
        0,
        0,
        name.len() as u32 + 1,
        0,
    ];
    *ino += 1;
    out.extend_from_slice(b"070701");
    for f in fields {
        out.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

// ---------------------------------------------------------------- images

/// A job image as the guest sees it: its root file system and the environment `podman exec` would add.
#[derive(Clone, Debug)]
pub struct GuestImage {
    pub rootfs: PathBuf,
    pub env: Vec<(String, String)>,
}

/// The image's root file system as a read-only ext4 file, built once per (store, image) and reused.
pub fn guest_image(root: &Path, image: &str, store: &Store) -> Result<GuestImage> {
    let dir = root.join(DIR).join("images");
    fs::create_dir_all(&dir)?;
    let key = blake3::hash(format!("{store:?}\0{image}").as_bytes()).to_hex();
    let rootfs = dir.join(format!("{}.ext4", &key[..32]));
    let env_file = dir.join(format!("{}.env", &key[..32]));
    if !(rootfs.exists() && env_file.exists()) {
        build_image(image, store, &rootfs, &env_file)?;
    }
    let env = fs::read_to_string(&env_file)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    Ok(GuestImage { rootfs, env })
}

fn build_image(image: &str, store: &Store, rootfs: &Path, env_file: &Path) -> Result<()> {
    let deadline = Instant::now() + IMAGE_BUILD_TIMEOUT;
    let tag = format!("{}.{}", std::process::id(), thread_tag());
    let tmp = rootfs.with_extension(format!("ext4.{tag}"));
    let tmp_env = env_file.with_extension(format!("env.{tag}"));
    let mut inspect = crate::podman::podman_in(store);
    inspect.args([
        "image",
        "inspect",
        "--format",
        "{{range .Config.Env}}{{println .}}{{end}}",
        "--",
        image,
    ]);
    let env = process::run(inspect, deadline, "podman image inspect")?;
    if !env.success() {
        return Err(Error::Preparation(format!(
            "image inspect: {}",
            env.stderr_excerpt()
        )));
    }
    fs::write(&tmp_env, &env.stdout)?;
    // Inside the user namespace the image's files keep their owners, so the ext4 file records them.
    let store_args = store_args(store);
    let script = format!(
        "set -e; m=$(podman {s} image mount -- \"$1\"); trap 'podman {s} image unmount -- \"$1\" >/dev/null' EXIT; \
         size=$(du -sm --apparent-size \"$m\" | cut -f1); \
         truncate -s $(( size * 5 / 4 + 256 ))M \"$2\"; \
         mkfs.ext4 -q -F -m 0 -L sentinel-image -E root_owner=0:0 -d \"$m\" \"$2\"",
        s = store_args
    );
    let mut build = crate::podman::podman_in(store);
    build
        .args(["unshare", "sh", "-c", &script, "sh", image])
        .arg(&tmp);
    let built = process::run(build, deadline, "guest image build")?;
    if !built.success() {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&tmp_env);
        return Err(Error::Preparation(format!(
            "guest image build: {}",
            built.stderr_excerpt()
        )));
    }
    fs::rename(&tmp_env, env_file)?;
    fs::rename(&tmp, rootfs)?;
    Ok(())
}

fn store_args(store: &Store) -> String {
    match store {
        Store::Shared => String::new(),
        Store::Private { graph, run } => {
            format!("--root '{}' --runroot '{}'", graph.display(), run.display())
        }
    }
}

fn thread_tag() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    thread::current().id().hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------- agent client

/// One agent connection: requests go out under a lock, replies come back on a channel fed by a reader.
struct Client {
    writer: Mutex<UnixStream>,
    replies: Mutex<mpsc::Receiver<Reply>>,
}

/// Firecracker's host side of vsock is a Unix socket: `CONNECT <port>` opens a stream to the guest port.
fn connect(socket: &Path, deadline: Instant, alive: &mut dyn FnMut() -> bool) -> Result<Client> {
    loop {
        let attempt = (|| -> io::Result<Client> {
            let mut stream = UnixStream::connect(socket)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(format!("CONNECT {}\n", agent::PORT).as_bytes())?;
            let mut line = String::new();
            BufReader::new(stream.try_clone()?).read_line(&mut line)?;
            if !line.starts_with("OK ") {
                return Err(io::Error::other(format!("vsock: {}", line.trim())));
            }
            agent::write(
                &mut stream,
                &Request::Hello {
                    version: agent::VERSION,
                },
            )?;
            match agent::read::<Reply>(&mut stream)? {
                Some(Reply::Ready { version, .. }) if version == agent::VERSION => {}
                other => return Err(io::Error::other(format!("agent answered {other:?}"))),
            }
            stream.set_read_timeout(None)?;
            let (tx, rx) = mpsc::channel();
            let mut reader = BufReader::with_capacity(agent::CHUNK, stream.try_clone()?);
            thread::Builder::new()
                .name("sentinel-vm-agent".into())
                .spawn(move || {
                    while let Ok(Some(reply)) = agent::read::<Reply>(&mut reader) {
                        if tx.send(reply).is_err() {
                            break;
                        }
                    }
                })?;
            Ok(Client {
                writer: Mutex::new(stream),
                replies: Mutex::new(rx),
            })
        })();
        match attempt {
            Ok(client) => return Ok(client),
            Err(e) => {
                if !alive() {
                    return Err(Error::Preparation(format!("the VM ended during boot: {e}")));
                }
                if Instant::now() >= deadline {
                    return Err(Error::Preparation(format!(
                        "the guest agent did not answer: {e}"
                    )));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

impl Client {
    fn send(&self, request: &Request) -> Result<()> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| Error::Runtime("agent writer".into()))?;
        agent::write(&mut *w, request).map_err(Error::Io)
    }

    /// The next reply that is not output of an earlier command (late output after its `Exited` is dropped).
    fn control(&self, timeout: Duration) -> Result<Reply> {
        let replies = self
            .replies
            .lock()
            .map_err(|_| Error::Runtime("agent reader".into()))?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match replies.recv_timeout(left) {
                Ok(Reply::Output { .. } | Reply::Exited { .. }) => continue,
                Ok(reply) => return Ok(reply),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(Error::Timeout("guest agent"));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::Runtime(
                        "the guest agent closed the connection".into(),
                    ));
                }
            }
        }
    }

    fn expect_done(&self, what: &str) -> Result<()> {
        match self.control(CONTROL_TIMEOUT)? {
            Reply::Done => Ok(()),
            Reply::Failed { message } => Err(Error::Runtime(format!("{what}: {message}"))),
            other => Err(Error::Runtime(format!("{what}: unexpected {other:?}"))),
        }
    }

    /// Streams a host directory into the guest as a tar archive under `guest_root`.
    fn put_dir(&self, host: &Path, guest_root: &str, skip: &[&str]) -> Result<()> {
        self.send(&Request::Put {
            root: guest_root.to_owned(),
        })?;
        let packed = (|| -> io::Result<()> {
            let mut out = DataOut {
                client: self,
                buf: Vec::with_capacity(agent::CHUNK),
            };
            {
                let mut builder = tar::Builder::new(&mut out);
                builder.follow_symlinks(false);
                for entry in fs::read_dir(host)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    let Some(text) = name.to_str() else { continue };
                    if skip.contains(&text) {
                        continue;
                    }
                    if entry.file_type()?.is_dir() {
                        builder.append_dir_all(text, entry.path())?;
                    } else {
                        builder.append_path_with_name(entry.path(), text)?;
                    }
                }
                builder.finish()?;
            }
            out.flush()
        })();
        // End the stream even after a packing error, so the agent's next frame is a request.
        self.send(&Request::End)?;
        packed.map_err(Error::Io)?;
        self.expect_done("put")
    }

    /// Unpacks `paths` (relative to `guest_root`) from the guest into `host`.
    fn get_into(&self, guest_root: &str, paths: Vec<String>, host: &Path) -> Result<()> {
        self.send(&Request::Get {
            root: guest_root.to_owned(),
            paths,
        })?;
        let replies = self
            .replies
            .lock()
            .map_err(|_| Error::Runtime("agent reader".into()))?;
        let mut input = DataIn {
            replies: &replies,
            buf: Vec::new(),
            pos: 0,
            ended: false,
            failed: None,
        };
        let unpacked = {
            let mut archive = tar::Archive::new(&mut input);
            archive.set_preserve_permissions(true);
            archive.set_preserve_mtime(true);
            archive.set_overwrite(true);
            archive.unpack(host)
        };
        let drained = input.finish();
        if let Some(message) = input.failed {
            return Err(Error::Runtime(format!("get {guest_root}: {message}")));
        }
        drained.map_err(Error::Io)?;
        unpacked.map_err(Error::Io)
    }
}

struct DataOut<'a> {
    client: &'a Client,
    buf: Vec<u8>,
}

impl Write for DataOut<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(agent::CHUNK - self.buf.len());
        self.buf.extend_from_slice(&bytes[..n]);
        if self.buf.len() == agent::CHUNK {
            self.flush()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let data = Request::Data(std::mem::take(&mut self.buf));
            self.client
                .send(&data)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(())
    }
}

struct DataIn<'a> {
    replies: &'a mpsc::Receiver<Reply>,
    buf: Vec<u8>,
    pos: usize,
    ended: bool,
    failed: Option<String>,
}

impl Read for DataIn<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.ended {
                return Ok(0);
            }
            match self.replies.recv_timeout(CONTROL_TIMEOUT) {
                Ok(Reply::Data(bytes)) => {
                    self.buf = bytes;
                    self.pos = 0;
                }
                Ok(Reply::End) => self.ended = true,
                Ok(Reply::Failed { message }) => {
                    self.failed = Some(message);
                    self.ended = true;
                }
                Ok(Reply::Output { .. } | Reply::Exited { .. }) => continue,
                Ok(other) => return Err(io::Error::other(format!("expected Data, got {other:?}"))),
                Err(_) => return Err(io::Error::other("the guest agent stopped sending")),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl DataIn<'_> {
    fn finish(&mut self) -> io::Result<()> {
        let mut sink = [0u8; 8192];
        while self.read(&mut sink)? > 0 {}
        Ok(())
    }
}

// ---------------------------------------------------------------- the VM

/// A running job VM; the counterpart of [`crate::podman::Container`].
pub struct Vm {
    attempt: AttemptId,
    dir: PathBuf,
    child: Mutex<Child>,
    client: Client,
    env: Vec<(String, String)>,
    next_id: AtomicU32,
    /// Writable mounts: their guest path and the host directory they come back to.
    writable: Vec<(String, PathBuf)>,
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

impl Vm {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        root: &Path,
        setup: &Setup,
        _worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
        network: Network,
    ) -> Result<Vm> {
        if network != Network::None {
            return Err(Error::Preparation(
                "microVM jobs with egress are not supported yet (TODO M05)".into(),
            ));
        }
        let guest = guest_image(root, image, store)?;
        let initrd = initramfs(root, setup)?;
        let dir = vm_dir(root, attempt);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let scratch = dir.join("scratch.ext4");
        scratch_disk(&scratch, limits.disk_bytes.max(1 << 30))?;
        let vcpus = limits.cpu_millis.div_ceil(1000).max(1);
        let mib = (limits.memory_bytes >> 20).max(128);
        let socket = dir.join("vsock.sock");
        let config = serde_json::json!({
            "boot-source": {
                "kernel_image_path": setup.kernel,
                "initrd_path": initrd,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd quiet",
            },
            "drives": [
                { "drive_id": "image", "path_on_host": guest.rootfs, "is_root_device": false, "is_read_only": true },
                { "drive_id": "scratch", "path_on_host": scratch, "is_root_device": false, "is_read_only": false },
            ],
            "machine-config": { "vcpu_count": vcpus, "mem_size_mib": mib, "smt": false },
            "vsock": { "guest_cid": GUEST_CID, "uds_path": socket },
        });
        fs::write(
            dir.join("vm.json"),
            serde_json::to_vec_pretty(&config).map_err(io::Error::other)?,
        )?;
        let console = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("console.log"))?;
        let mut command = Command::new("systemd-run");
        command
            .args(["--user", "--scope", "--quiet", "--collect", "--unit"])
            .arg(unit_name(attempt))
            .arg(format!("-pCPUQuota={}%", (limits.cpu_millis / 10).max(1)))
            .arg(format!(
                "-pMemoryMax={}",
                limits.memory_bytes.saturating_add(VMM_OVERHEAD)
            ))
            .args([
                "--", "podman", "unshare", "unshare", "--net", "--fork", "--",
            ])
            .arg(&setup.firecracker)
            .arg("--api-sock")
            .arg(dir.join("api.sock"))
            .arg("--config-file")
            .arg(dir.join("vm.json"))
            .stdin(Stdio::null())
            .stdout(console.try_clone()?)
            .stderr(console);
        let mut child = command
            .spawn()
            .map_err(|e| Error::Preparation(format!("firecracker: {e}")))?;
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let client = connect(&socket, deadline, &mut || {
            matches!(child.try_wait(), Ok(None))
        });
        let client = match client {
            Ok(client) => client,
            Err(e) => {
                let tail = console_tail(&dir);
                let _ = child.kill();
                let _ = child.wait();
                stop_unit(attempt);
                let _ = fs::remove_dir_all(&dir);
                return Err(Error::Preparation(format!("{e}; console: {tail}")));
            }
        };
        let mut vm = Vm {
            attempt,
            dir,
            child: Mutex::new(child),
            client,
            env: guest.env,
            next_id: AtomicU32::new(1),
            writable: Vec::new(),
        };
        let prepared = (|| -> Result<()> {
            vm.client.put_dir(
                workspace,
                &guest_path(WORKSPACE_MOUNT),
                &[sentinel_cache::attach::PRIVATE_DIR],
            )?;
            for mount in mounts {
                vm.client
                    .put_dir(&mount.host, &guest_path(&mount.container), &[])?;
                if !mount.read_only {
                    vm.writable
                        .push((guest_path(&mount.container), mount.host.clone()));
                }
            }
            Ok(())
        })();
        if let Err(e) = prepared {
            let _ = vm.destroy_inner();
            return Err(e);
        }
        Ok(vm)
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    pub fn exec(&self, step: &StepCommand, extra: &[(String, String)]) -> Result<Exit> {
        self.exec_streaming(step, extra, None)
    }

    pub fn exec_streaming(
        &self,
        step: &StepCommand,
        extra: &[(String, String)],
        sink: Option<process::Sink>,
    ) -> Result<Exit> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // The image's environment, then the step's, then the worker's, each overriding the one before.
        let mut env: Vec<(String, String)> = Vec::new();
        for (k, v) in self.env.iter().chain(&step.env).chain(extra) {
            match env.iter_mut().find(|(name, _)| name == k) {
                Some(slot) => slot.1 = v.clone(),
                None => env.push((k.clone(), v.clone())),
            }
        }
        let workdir = match &step.workdir {
            Some(dir) => format!("{WORKSPACE_MOUNT}/{dir}"),
            None => WORKSPACE_MOUNT.to_owned(),
        };
        self.client.send(&Request::Exec(agent::Exec {
            id,
            argv: step.argv.clone(),
            env,
            workdir,
            root: JOB_ROOT.to_owned(),
        }))?;
        let deadline = Instant::now() + Duration::from_secs(step.timeout_secs.max(1));
        let (mut stdout, mut stderr) = (process::Tail::new(), process::Tail::new());
        let replies = self
            .client
            .replies
            .lock()
            .map_err(|_| Error::Runtime("agent reader".into()))?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match replies.recv_timeout(left) {
                Ok(Reply::Output {
                    id: of,
                    stream,
                    bytes,
                }) if of == id => {
                    let which = match stream {
                        agent::Stream::Stdout => sentinel_protocol::logs::Stream::Stdout,
                        agent::Stream::Stderr => sentinel_protocol::logs::Stream::Stderr,
                    };
                    if let Some(sink) = &sink {
                        sink(which, &bytes);
                    }
                    match stream {
                        agent::Stream::Stdout => stdout.push(&bytes),
                        agent::Stream::Stderr => stderr.push(&bytes),
                    }
                }
                Ok(Reply::Exited {
                    id: of,
                    code,
                    signal,
                }) if of == id => {
                    return Ok(Exit {
                        code,
                        signal,
                        timed_out: false,
                        stdout: stdout.into_bytes(),
                        stderr: stderr.into_bytes(),
                    });
                }
                Ok(Reply::Failed { message }) => {
                    return Err(Error::Runtime(format!("guest exec: {message}")));
                }
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drop(replies);
                    let _ = self.client.send(&Request::SignalAll {
                        signal: libc::SIGKILL,
                    });
                    return Ok(Exit {
                        code: None,
                        signal: None,
                        timed_out: true,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    });
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::Runtime(
                        "the guest agent closed the connection".into(),
                    ));
                }
            }
        }
    }

    pub fn oom_kills(&self) -> Result<u64> {
        self.client.send(&Request::OomKills)?;
        match self.client.control(CONTROL_TIMEOUT)? {
            Reply::OomKills(n) => Ok(n),
            other => Err(Error::Runtime(format!("oom count: unexpected {other:?}"))),
        }
    }

    /// Every process an earlier step left: the guest has one PID namespace, as a container does.
    pub fn clear_strays(&self) -> Result<usize> {
        self.client.send(&Request::KillStrays)?;
        self.client.expect_done("clear strays")?;
        Ok(0)
    }

    /// Brings back what the host reads after the steps: `workspace_paths` (relative to the workspace, the
    /// artifacts) and every writable mount, whose host directory is replaced by the guest's view.
    pub fn sync_out(&self, workspace: &Path, workspace_paths: &[String]) -> Result<()> {
        if !workspace_paths.is_empty() {
            self.client.get_into(
                &guest_path(WORKSPACE_MOUNT),
                workspace_paths.to_vec(),
                workspace,
            )?;
        }
        for (guest, host) in &self.writable {
            clear_dir(host)?;
            self.client.get_into(guest, vec![".".into()], host)?;
        }
        Ok(())
    }

    pub fn destroy(self) -> Result<()> {
        self.destroy_inner()
    }

    fn destroy_inner(&self) -> Result<()> {
        let _ = self.client.send(&Request::Shutdown);
        let mut child = self
            .child
            .lock()
            .map_err(|_| Error::Runtime("vm child".into()))?;
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until && matches!(child.try_wait(), Ok(None)) {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        stop_unit(self.attempt);
        fs::remove_dir_all(&self.dir).or_else(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        Ok(())
    }
}

fn guest_path(container: &str) -> String {
    format!("{JOB_ROOT}{container}")
}

fn clear_dir(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            crate::workspace::remove_tree(&entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn scratch_disk(path: &Path, bytes: u64) -> Result<()> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?
        .set_len(bytes)?;
    let mut mkfs = Command::new("mkfs.ext4");
    mkfs.args([
        "-q",
        "-F",
        "-m",
        "0",
        "-L",
        "sentinel-scratch",
        "-E",
        "root_owner=0:0",
    ])
    .arg(path);
    let out = process::run(mkfs, Instant::now() + Duration::from_secs(60), "mkfs.ext4")?;
    if !out.success() {
        return Err(Error::Preparation(format!(
            "scratch disk: {}",
            out.stderr_excerpt()
        )));
    }
    Ok(())
}

fn console_tail(dir: &Path) -> String {
    let text = fs::read(dir.join("console.log")).unwrap_or_default();
    let start = text.len().saturating_sub(2048);
    crate::redact::excerpt(&text[start..])
}

fn stop_unit(attempt: AttemptId) {
    let unit = format!("{}.scope", unit_name(attempt));
    let _ = systemctl_user(&["kill", "--signal=SIGKILL", &unit]);
    let _ = systemctl_user(&["stop", &unit]);
}

// ---------------------------------------------------------------- by name, from other threads

/// A cancel: SIGTERM to every guest process, SIGKILL after `grace`, through a connection of its own.
pub fn terminate_named(root: &Path, attempt: AttemptId, grace: Duration) -> Result<Terminated> {
    let dir = vm_dir(root, attempt);
    let socket = dir.join("vsock.sock");
    if !socket.exists() {
        return Ok(Terminated::Gone);
    }
    let client = match connect(
        &socket,
        Instant::now() + Duration::from_secs(2),
        &mut || true,
    ) {
        Ok(client) => client,
        Err(_) => {
            remove_named(root, attempt)?;
            return Ok(Terminated::Forced);
        }
    };
    client.send(&Request::SignalAll {
        signal: libc::SIGTERM,
    })?;
    client.expect_done("terminate")?;
    thread::sleep(grace);
    client.send(&Request::SignalAll {
        signal: libc::SIGKILL,
    })?;
    client.expect_done("terminate")?;
    Ok(Terminated::Forced)
}

/// Stops the VM's scope and removes its directory: shutdown, lease loss and startup recovery.
pub fn remove_named(root: &Path, attempt: AttemptId) -> Result<()> {
    stop_unit(attempt);
    match fs::remove_dir_all(vm_dir(root, attempt)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(e)),
        _ => Ok(()),
    }
}

/// Whether the attempt runs in a VM here (its directory exists from start to destroy).
pub fn exists(root: &Path, attempt: AttemptId) -> bool {
    vm_dir(root, attempt).is_dir()
}

/// The attempts whose VM directories remain, for startup reconciliation.
pub fn owned(root: &Path) -> Vec<AttemptId> {
    let Ok(entries) = fs::read_dir(root.join(DIR).join("vms")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<AttemptId>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpio_records_are_newc_and_four_byte_aligned() {
        let mut out = Vec::new();
        let mut ino = 1;
        cpio_entry(&mut out, &mut ino, "init", 0o100755, b"abc");
        assert!(out.starts_with(b"070701"));
        assert_eq!(out.len() % 4, 0);
        // header 110 bytes, name "init\0" padded to 116, data 3 padded to 4.
        assert_eq!(out.len(), 116 + 4);
        assert_eq!(&out[110..114], b"init");
        assert_eq!(&out[116..119], b"abc");
        assert_eq!(ino, 2);
    }

    #[test]
    fn mounts_land_under_the_job_root() {
        assert_eq!(guest_path("/workspace"), "/job/workspace");
        assert_eq!(guest_path("/cache/gomod"), "/job/cache/gomod");
    }

    #[test]
    fn a_setup_with_missing_files_says_which() {
        let setup = Setup {
            firecracker: "/nonexistent/firecracker".into(),
            kernel: "/nonexistent/vmlinux".into(),
            agent: "/nonexistent/agent".into(),
        };
        assert!(setup.check().unwrap_err().contains("firecracker"));
    }

    #[test]
    fn owned_lists_only_attempt_directories() {
        let dir = std::env::temp_dir().join(format!("sentinel-vm-owned-{}", std::process::id()));
        let vms = dir.join(DIR).join("vms");
        let attempt = AttemptId::new();
        fs::create_dir_all(vms.join(attempt.to_string())).unwrap();
        fs::create_dir_all(vms.join("not-an-attempt")).unwrap();
        assert_eq!(owned(&dir), vec![attempt]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
