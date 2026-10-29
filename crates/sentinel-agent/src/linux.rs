use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{self, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
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

/// The cgroup every step is started in, as the file that takes a pid; absent when the guest kernel has no cgroup
/// v2 with a memory controller.
static JOB_PROCS: OnceLock<File> = OnceLock::new();
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Creates the cgroup the steps run in (`memory.max` stays unlimited until [`Request::MemoryLimit`] sets it). The
/// agent and the kernel threads stay in the root cgroup, so a step that exhausts its memory is killed there and
/// the agent keeps the memory it needs to report it.
fn job_cgroup() {
    let setup = || -> io::Result<File> {
        mount(
            "cgroup2",
            CGROUP_ROOT,
            "cgroup2",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        std::fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+memory")?;
        std::fs::create_dir_all(format!("{CGROUP_ROOT}/job"))?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{CGROUP_ROOT}/job/cgroup.procs"))
    };
    match setup() {
        Ok(procs) => {
            let _ = JOB_PROCS.set(procs);
        }
        Err(e) => console(&format!("sentinel-agent: no job cgroup: {e}")),
    }
}

fn set_memory_limit(bytes: u64) -> io::Result<()> {
    if JOB_PROCS.get().is_none() {
        return Err(io::Error::other("the guest kernel has no memory cgroup"));
    }
    std::fs::write(format!("{CGROUP_ROOT}/job/memory.max"), bytes.to_string())?;
    // No swap exists, but a swap device added later must not let a step outgrow its limit.
    let _ = std::fs::write(format!("{CGROUP_ROOT}/job/memory.swap.max"), "0");
    Ok(())
}

fn boot() -> io::Result<()> {
    mount("proc", "/proc", "proc", 0, "")?;
    mount("sysfs", "/sys", "sysfs", 0, "")?;
    job_cgroup();
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
    // What a step is given as secrets lives in memory only, whatever the image does with /run.
    for dir in agent::SECRET_MOUNTS {
        mount(
            "tmpfs",
            &format!("{JOB_ROOT}{dir}"),
            "tmpfs",
            nodev,
            "mode=0755,size=64m",
        )?;
    }
    std::fs::create_dir_all("/job/workspace")?;
    loopback_up()?;
    if let Some(net) = parse_net(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default()) {
        configure_net(&net)?;
    }
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

/// The guest's one network interface, as the worker states it on the kernel command line
/// (`sentinel.ip=<address>/<prefix> sentinel.gw=<gateway>`); absent for a job without network, whose VM has no
/// interface at all.
#[derive(Debug, PartialEq, Eq)]
struct NetConfig {
    addr: [u8; 4],
    prefix: u8,
    gateway: [u8; 4],
}

fn parse_net(cmdline: &str) -> Option<NetConfig> {
    let value = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
    };
    let (addr, prefix) = value("sentinel.ip")?.split_once('/')?;
    let prefix: u8 = prefix.parse().ok().filter(|p| (1..=30).contains(p))?;
    let addr: std::net::Ipv4Addr = addr.parse().ok()?;
    let gateway: std::net::Ipv4Addr = value("sentinel.gw")?.parse().ok()?;
    Some(NetConfig {
        addr: addr.octets(),
        prefix,
        gateway: gateway.octets(),
    })
}

fn netmask(prefix: u8) -> [u8; 4] {
    (u32::MAX << (32 - u32::from(prefix))).to_be_bytes()
}

fn sockaddr_in(ip: [u8; 4]) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        // The octets in memory order are the address in network byte order.
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        },
        sin_zero: [0; 8],
    }
}

/// The kernel's `struct rtentry` (`SIOCADDRT`), declared here because not every libc target has it.
#[repr(C)]
struct RtEntry {
    pad1: libc::c_ulong,
    dst: libc::sockaddr_in,
    gateway: libc::sockaddr_in,
    genmask: libc::sockaddr_in,
    flags: libc::c_ushort,
    pad2: libc::c_short,
    pad3: libc::c_ulong,
    pad4: *mut libc::c_void,
    metric: libc::c_short,
    dev: *mut libc::c_char,
    mtu: libc::c_ulong,
    window: libc::c_ulong,
    irtt: libc::c_ushort,
}

const RTF_UP: u16 = 0x1;
const RTF_GATEWAY: u16 = 0x2;
const SIOCADDRT: libc::c_ulong = 0x890B;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
/// `RNDADDENTROPY`: `_IOW('R', 0x03, int[2])`.
const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;

fn ifreq(name: &str) -> libc::ifreq {
    // SAFETY: ifreq is plain data; zeroed is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
        req.ifr_name[i] = b as libc::c_char;
    }
    req
}

fn inet_socket() -> io::Result<OwnedFd> {
    // SAFETY: a plain socket call; the descriptor is owned below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor this function owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Gives `eth0` its address, brings it up and routes everything through the gateway. The interface is the
/// one virtio-net device the VMM was given; its driver is built in, so it exists when `/init` starts.
fn configure_net(net: &NetConfig) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let sock = inet_socket()?;
    let fd = sock.as_raw_fd();
    let set_addr = |request: libc::c_ulong, ip: [u8; 4]| -> io::Result<()> {
        let mut req = ifreq("eth0");
        // SAFETY: sockaddr and sockaddr_in are both 16 bytes; ifru_addr is the union member these requests read.
        unsafe {
            std::ptr::write(
                std::ptr::addr_of_mut!(req.ifr_ifru.ifru_addr).cast::<libc::sockaddr_in>(),
                sockaddr_in(ip),
            );
        }
        // SAFETY: req is a valid ifreq for the request and lives across the call.
        if unsafe { libc::ioctl(fd, request as _, &req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    set_addr(SIOCSIFADDR, net.addr)?;
    set_addr(SIOCSIFNETMASK, netmask(net.prefix))?;
    let mut req = ifreq("eth0");
    req.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    // SAFETY: req is a valid ifreq for SIOCSIFFLAGS and lives across the call.
    if unsafe { libc::ioctl(fd, SIOCSIFFLAGS as _, &req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let route = RtEntry {
        pad1: 0,
        dst: sockaddr_in([0; 4]),
        gateway: sockaddr_in(net.gateway),
        genmask: sockaddr_in([0; 4]),
        flags: (RTF_UP | RTF_GATEWAY) as libc::c_ushort,
        pad2: 0,
        pad3: 0,
        pad4: std::ptr::null_mut(),
        metric: 0,
        dev: std::ptr::null_mut(),
        mtu: 0,
        window: 0,
        irtt: 0,
    };
    // SAFETY: route is a valid rtentry for SIOCADDRT and lives across the call.
    if unsafe { libc::ioctl(fd, SIOCADDRT as _, &route) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a restored guest needs before it runs a step (`Request::Resume`): fresh randomness credited to the
/// kernel's pool and the current wall clock.
fn resume(entropy: &[u8], realtime_ns: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if !entropy.is_empty() {
        let n = entropy.len().min(512);
        let mut info = Vec::with_capacity(8 + n);
        info.extend_from_slice(&((n * 8) as i32).to_ne_bytes());
        info.extend_from_slice(&(n as i32).to_ne_bytes());
        info.extend_from_slice(&entropy[..n]);
        let pool = File::options().write(true).open("/dev/urandom")?;
        // SAFETY: info is a rand_pool_info header followed by n bytes, as RNDADDENTROPY reads.
        if unsafe { libc::ioctl(pool.as_raw_fd(), RNDADDENTROPY as _, info.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let at = libc::timespec {
        tv_sec: (realtime_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (realtime_ns % 1_000_000_000) as libc::c_long,
    };
    // SAFETY: at is a valid timespec for the call.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &at) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
            Request::Resume {
                entropy,
                realtime_ns,
            } => {
                let reply = match resume(&entropy, realtime_ns) {
                    Ok(()) => Reply::Done,
                    Err(e) => Reply::Failed {
                        message: format!("resume: {e}"),
                    },
                };
                send(&writer, &reply)?;
            }
            Request::MemoryLimit { bytes } => {
                let reply = match set_memory_limit(bytes) {
                    Ok(()) => Reply::Done,
                    Err(e) => Reply::Failed {
                        message: format!("memory limit: {e}"),
                    },
                };
                send(&writer, &reply)?;
            }
            Request::WaitIdle { timeout_ms } => {
                let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
                let idle = loop {
                    if !children.lock().is_ok_and(|c| !c.by_pid.is_empty()) {
                        break true;
                    }
                    if Instant::now() >= deadline {
                        break false;
                    }
                    thread::sleep(Duration::from_millis(5));
                };
                send(&writer, &Reply::Idle(idle))?;
            }
            Request::Wipe { dirs } => {
                let reply = match wipe(&dirs) {
                    Ok(()) => Reply::Done,
                    Err(e) => Reply::Failed {
                        message: format!("wipe: {e}"),
                    },
                };
                send(&writer, &reply)?;
            }
            Request::Shutdown => power_off(),
            Request::Hello { .. } | Request::Data(_) | Request::End => {
                return Err(io::Error::other("unexpected frame"));
            }
        }
    }
    Ok(())
}

/// Empties each directory (see [`Request::Wipe`]): the job root's own, never the guest's.
fn wipe(dirs: &[String]) -> io::Result<()> {
    for dir in dirs {
        if !dir.starts_with("/job/") || dir.split('/').any(|c| c == "..") {
            return Err(io::Error::other(format!("{dir}: outside the job root")));
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::remove_file(entry.path())?;
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

/// Who a step runs as: the image's `USER`, resolved against the image's own passwd and group files.
struct Identity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

/// Resolves an image `USER` (`name`, `uid`, `name:group` or `uid:gid`) to ids. Empty and root stay root and
/// return `None`; a name the image does not define is an error, as it is for `podman run`.
fn resolve_identity(root: &str, spec: &str) -> io::Result<Option<Identity>> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    let read =
        |name: &str| std::fs::read_to_string(format!("{root}/etc/{name}")).unwrap_or_default();
    let (passwd, group) = (read("passwd"), read("group"));
    let (user, wanted_group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let fail = |what: &str| io::Error::other(format!("image user {spec:?}: {what} not found"));
    // passwd: name:x:uid:gid:...
    let entry = passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || (f[0] != user && f[2] != user) {
            return None;
        }
        Some((
            f[0].to_owned(),
            f[2].parse::<u32>().ok()?,
            f[3].parse::<u32>().ok()?,
        ))
    });
    let (name, uid, primary) = match (entry, user.parse::<u32>()) {
        (Some(e), _) => e,
        (None, Ok(uid)) => (String::new(), uid, 0),
        (None, Err(_)) => return Err(fail("user")),
    };
    let gid = match wanted_group {
        None => primary,
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => group
                .lines()
                .find_map(|line| {
                    let f: Vec<&str> = line.split(':').collect();
                    (f.len() >= 3 && f[0] == g)
                        .then(|| f[2].parse::<u32>().ok())
                        .flatten()
                })
                .ok_or_else(|| fail("group"))?,
        },
    };
    let mut groups = vec![gid];
    if !name.is_empty() {
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4
                && f[3].split(',').any(|m| m == name)
                && let Ok(g) = f[2].parse::<u32>()
                && !groups.contains(&g)
            {
                groups.push(g);
            }
        }
    }
    if uid == 0 && gid == 0 && groups == [0] {
        return Ok(None);
    }
    Ok(Some(Identity { uid, gid, groups }))
}

/// Gives `path` and everything below it (symlinks themselves, never their targets) to the step's user.
fn chown_tree(path: &Path, identity: &Identity) {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    // SAFETY: a valid NUL-terminated path.
    unsafe { libc::lchown(c.as_ptr(), identity.uid, identity.gid) };
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir()
        && let Ok(entries) = std::fs::read_dir(path)
    {
        for entry in entries.flatten() {
            chown_tree(&entry.path(), identity);
        }
    }
}
fn start(exec: Exec, writer: &Writer, children: &Arc<Mutex<Children>>) -> io::Result<()> {
    let program = exec
        .argv
        .first()
        .ok_or_else(|| io::Error::other("empty argv"))?;
    let resolved = resolve(program, &exec.env)?;
    let root = cstr(&exec.root)?;
    let workdir = cstr(&exec.workdir)?;
    let identity = resolve_identity(&exec.root, &exec.user)?;
    if let Some(identity) = &identity {
        // The workspace was unpacked by root; the step's user has to be able to write it.
        chown_tree(
            Path::new(&format!("{}{}", exec.root, exec.workdir)),
            identity,
        );
    }
    let mut command = Command::new(&resolved);
    command
        .args(&exec.argv[1..])
        .env_clear()
        .envs(exec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // No core dump, whatever a step does: its memory may hold secrets (a container runs with the same
    // `core=0:0` limit and with `no-new-privileges`).
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let groups: Vec<libc::gid_t> = identity
        .as_ref()
        .map(|i| i.groups.clone())
        .unwrap_or_default();
    let ids = identity.as_ref().map(|i| (i.uid, i.gid));
    let procs = JOB_PROCS.get().map(AsRawFd::as_raw_fd);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some(fd) = procs {
                // Into the steps' memory cgroup, before the program (or anything it forks) allocates.
                if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::chroot(root.as_ptr()) != 0 || libc::chdir(workdir.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some((uid, gid)) = ids {
                // Groups first, the user last: after setuid the process may no longer change either.
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_network_comes_from_the_command_line_or_is_absent() {
        let line = "console=ttyS0 quiet sentinel.ip=10.211.0.2/30 sentinel.gw=10.211.0.1 sentinel.dns=192.0.2.53";
        assert_eq!(
            parse_net(line),
            Some(NetConfig {
                addr: [10, 211, 0, 2],
                prefix: 30,
                gateway: [10, 211, 0, 1],
            })
        );
        // No interface was given, or the line is not a usable one: nothing is configured.
        assert_eq!(parse_net("console=ttyS0 quiet"), None);
        assert_eq!(parse_net("sentinel.ip=10.211.0.2/30"), None);
        assert_eq!(
            parse_net("sentinel.ip=10.211.0.2 sentinel.gw=10.211.0.1"),
            None
        );
        assert_eq!(
            parse_net("sentinel.ip=10.211.0.2/0 sentinel.gw=10.211.0.1"),
            None
        );
        assert_eq!(
            parse_net("sentinel.ip=10.211.0.2/31 sentinel.gw=10.211.0.1"),
            None
        );
        assert_eq!(
            parse_net("sentinel.ip=nope/30 sentinel.gw=10.211.0.1"),
            None
        );
    }

    #[test]
    fn prefixes_become_masks() {
        assert_eq!(netmask(30), [255, 255, 255, 252]);
        assert_eq!(netmask(24), [255, 255, 255, 0]);
        assert_eq!(netmask(1), [128, 0, 0, 0]);
    }

    #[test]
    fn addresses_are_stored_in_network_order() {
        let sin = sockaddr_in([10, 211, 0, 2]);
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [10, 211, 0, 2]);
        assert_eq!(i32::from(sin.sin_family), libc::AF_INET);
    }
    #[test]
    fn an_image_user_resolves_against_the_images_own_account_files() {
        let root = std::env::temp_dir().join(format!("sentinel-agent-user-{}", std::process::id()));
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nbuild:x:1000:100::/home/build:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/group"),
            "root:x:0:\nusers:x:100:\nci:x:200:build\n",
        )
        .unwrap();
        let root_str = root.to_str().unwrap();
        let ids = |spec: &str| {
            resolve_identity(root_str, spec)
                .unwrap()
                .map(|i| (i.uid, i.gid, i.groups))
        };
        assert_eq!(ids(""), None);
        assert_eq!(ids("root"), None);
        assert_eq!(ids("0:0"), None);
        assert_eq!(ids("build"), Some((1000, 100, vec![100, 200])));
        assert_eq!(ids("1000"), Some((1000, 100, vec![100, 200])));
        assert_eq!(ids("build:ci"), Some((1000, 200, vec![200])));
        // No passwd entry: the numeric id stands on its own, with the given (or root) group.
        assert_eq!(ids("65534:65534"), Some((65534, 65534, vec![65534])));
        assert_eq!(ids("65534"), Some((65534, 0, vec![0])));
        assert!(resolve_identity(root_str, "nobody-here").is_err());
        assert!(resolve_identity(root_str, "build:missing").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
