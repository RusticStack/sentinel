//! MicroVM jobs (plan 16.8, TODO M03–M06): one Firecracker VM per attempt, steps run by the guest agent.
//!
//! Rootless, like the container executor. Firecracker's jailer needs root, so its sandbox is built from
//! what the worker account has: a user namespace from `podman unshare` (Podman's setuid id-map helpers),
//! fresh mount and network namespaces (the network empty unless the worker grants egress, see [`net`]), a user systemd scope that
//! caps CPU and memory and names the VM for cleanup, and Firecracker's own seccomp filters. The guest boots the
//! pinned kernel with an initramfs whose `/init` is the agent; `/dev/vda` is the job image as a read-only
//! ext4 file built once per image (cached under `microvm/images`) and `/dev/vdb` the attempt's scratch
//! disk, sized to the job's disk reservation. Firecracker has no shared file system, so the workspace and
//! mounts go in as tar streams over vsock and the paths the host reads afterwards (artifacts, writable
//! caches) come back the same way.
//!
//! A VM starts warm when it can: the first VM of a shape (image, vCPUs, memory, scratch size, network) builds
//! a snapshot of its booted, idle guest ([`snapshot`]) and every VM of that shape, that one included, is
//! restored from it with a copy-on-write memory mapping and a clone of the snapshot's scratch disk. Anything
//! that goes wrong with a warm start falls back to a cold boot of the same attempt.

mod fcapi;
pub mod net;
mod snapshot;

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_pipeline::run::StepCommand;
use sentinel_protocol::{
    agent::{self, Reply, Request},
    summary::GuestImageRecord,
};

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
/// The paths the VMM sees: it runs in a chroot that is the VM's directory (see `net::NETNS_SCRIPT`), so these are
/// the same in every VM, a snapshot saves them as they are, and it restores wherever the worker's data
/// directory has been moved to.
const JAIL_KERNEL: &str = "/kernel";
const JAIL_INITRD: &str = "/initrd";
const JAIL_IMAGE: &str = "/image.ext4";
const JAIL_SCRATCH: &str = "/scratch.ext4";
const JAIL_VSOCK: &str = "/vsock.sock";
const JAIL_CPU_CONFIG: &str = "/cpu.json";
const JAIL_API: &str = "/api.sock";
const JAIL_CONFIG: &str = "/vm.json";
/// Where a restoring VMM sees the snapshot's directory.
const JAIL_SNAPSHOT: &str = "/snap";
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(900);
/// Memory the VMM process needs beyond the guest's RAM, in the scope's cap.
const VMM_OVERHEAD: u64 = 256 << 20;
/// Memory a guest has beyond its job's reservation: the kernel, the agent and the file system caches they
/// need. The steps share a memory cgroup capped at the reservation itself ([`Request::MemoryLimit`]), so a job
/// that outgrows it is OOM-killed inside the guest and the agent stays able to say so, the way a container
/// is, instead of the whole guest running out of memory with it.
const GUEST_OVERHEAD_MIB: u64 = 64;
/// How long a cancel waits for the guest agent to confirm a signal before it kills the VM instead. A healthy
/// agent answers in milliseconds; the bound keeps cancel to VM gone under 2 s (TODO M04) when it cannot.
const CANCEL_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a cancel waits to reach the agent at all.
const CANCEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// A cached guest image is stamped on use only when its stamp is older than this, so the stamp stays within
/// it of the last use while a hit costs no write; image GC keeps everything used within `images::IMAGE_KEEP`.
const STAMP_AFTER: Duration = Duration::from_secs(60);
/// Files in the image directory that no complete image owns are removed once this old: a build in progress
/// writes at least every few minutes and ends within `IMAGE_BUILD_TIMEOUT`.
const ORPHAN_AGE: Duration = Duration::from_secs(3600);
const SYSTEMCTL: &str = "systemctl";
/// Firecracker's `PUT /snapshot/create` writes the guest's whole memory.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the restored VMM has to bring up its API socket and load a snapshot.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(30);

/// The operator's `[microvm]` setup: Firecracker, the pinned guest kernel and the static agent binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub agent: PathBuf,
    /// Whether VMs start from snapshots of a booted guest (M06). Off, every VM boots cold.
    pub snapshots: bool,
    /// Endpoints of the worker itself that a guest granted egress must not reach (M05).
    pub guard: net::Guard,
}

impl Setup {
    /// Whether this setup can run a VM, as text for `runtime_selected` and `worker --check`.
    /// Names every missing piece at once, so one look at the message finishes the install.
    pub fn check(&self) -> std::result::Result<(), String> {
        let executable = |p: &Path| {
            fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        };
        let mut missing = Vec::new();
        if !executable(&self.firecracker) {
            missing.push(format!(
                "firecracker {}: not an executable file",
                self.firecracker.display()
            ));
        }
        if !fs::metadata(&self.kernel).is_ok_and(|m| m.is_file()) {
            missing.push(format!("{}: no guest kernel", self.kernel.display()));
        }
        if !executable(&self.agent) {
            missing.push(format!(
                "agent {}: not an executable file",
                self.agent.display()
            ));
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} (the x86_64 worker package installs all three: docs/releasing.md#microvm-assets)",
                missing.join("; ")
            ))
        }
    }
}

fn vm_dir(root: &Path, attempt: AttemptId) -> PathBuf {
    root.join(DIR).join("vms").join(attempt.to_string())
}

/// Every VM scope of one worker data root shares this prefix, so reconciliation finds its own scopes and
/// never another worker's on the same account.
fn unit_prefix(root: &Path) -> String {
    let tag = blake3::hash(root.as_os_str().as_encoded_bytes()).to_hex();
    format!("sentinel-vm-{}-", &tag[..8])
}

fn unit_name(root: &Path, attempt: AttemptId) -> String {
    format!("{}{attempt}", unit_prefix(root))
}

/// The name of the systemd scope an attempt's VM runs in.
pub fn scope_name(root: &Path, attempt: AttemptId) -> String {
    format!("{}.scope", unit_name(root, attempt))
}

fn systemctl_user(program: &OsStr, args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(program).arg("--user").args(args).output()
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
    // A name of its own per call: attempts of one worker start together, and two writers sharing a temporary
    // would have the second rename find the file the first already moved.
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".initramfs-{}.{}.{}",
        &digest[..16],
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp, &out)?;
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
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
    /// The image's configured user (`USER`): empty for root.
    pub user: String,
    /// What the attempt's summary records: the pinned digest this root file system carries.
    pub record: GuestImageRecord,
    /// Keeps GC off the image for as long as a VM boots from it (see [`ImageLease`]).
    lease: Arc<ImageLease>,
}

/// A live attempt's claim on a cached image. GC ([`remove_guest_image`]) never removes a leased image, so
/// an attempt's root file system cannot go while the attempt is booting from it or running on it, however
/// old its last-use stamp is. A lease is taken before the cache is consulted and held by the VM until it
/// is destroyed, so a removal either completes first (the next lookup misses and rebuilds) or sees the lease.
#[derive(Debug)]
pub struct ImageLease {
    rootfs: PathBuf,
}

type Leases = Mutex<Vec<(PathBuf, usize)>>;

fn leases() -> MutexGuard<'static, Vec<(PathBuf, usize)>> {
    static LEASES: Leases = Mutex::new(Vec::new());
    LEASES.lock().unwrap_or_else(|p| p.into_inner())
}

impl ImageLease {
    fn take(rootfs: &Path) -> Arc<ImageLease> {
        let mut held = leases();
        match held.iter_mut().find(|(path, _)| path == rootfs) {
            Some((_, count)) => *count += 1,
            None => held.push((rootfs.to_path_buf(), 1)),
        }
        Arc::new(ImageLease {
            rootfs: rootfs.to_path_buf(),
        })
    }
}

impl Drop for ImageLease {
    fn drop(&mut self) {
        let mut held = leases();
        if let Some(at) = held.iter().position(|(path, _)| *path == self.rootfs) {
            held[at].1 -= 1;
            if held[at].1 == 0 {
                held.swap_remove(at);
            }
        }
    }
}

/// What `<key>.json` holds. It is written after the root file system is in place, so its presence marks a
/// complete image, and its modification time is the image's last use for GC.
#[derive(Debug, PartialEq, Eq)]
struct ImageMeta {
    digest: String,
    image_id: String,
    rootfs_bytes: u64,
    env: Vec<(String, String)>,
    user: String,
}

const META_FORMAT: u64 = 2;

impl ImageMeta {
    fn to_json(&self) -> Vec<u8> {
        let env: Vec<String> = self.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        serde_json::to_vec(&serde_json::json!({
            "format": META_FORMAT,
            "digest": self.digest,
            "image_id": self.image_id,
            "rootfs_bytes": self.rootfs_bytes,
            "env": env,
            "user": self.user,
        }))
        .expect("a JSON value serializes")
    }

    fn from_json(bytes: &[u8]) -> Option<ImageMeta> {
        let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        if value.get("format")?.as_u64()? != META_FORMAT {
            return None;
        }
        Some(ImageMeta {
            digest: value.get("digest")?.as_str()?.to_owned(),
            image_id: value.get("image_id")?.as_str()?.to_owned(),
            rootfs_bytes: value.get("rootfs_bytes")?.as_u64()?,
            env: value
                .get("env")?
                .as_array()?
                .iter()
                .filter_map(|line| {
                    let (k, v) = line.as_str()?.split_once('=')?;
                    Some((k.to_owned(), v.to_owned()))
                })
                .collect(),
            user: value.get("user")?.as_str()?.to_owned(),
        })
    }
}

fn images_dir(root: &Path) -> PathBuf {
    root.join(DIR).join("images")
}

/// The name both of an image's files share, one per (store, image): a tenant's private store never shares a
/// root file system with the shared one.
fn image_key(store: &Store, image: &str) -> String {
    blake3::hash(format!("{store:?}\0{image}").as_bytes()).to_hex()[..32].to_owned()
}

fn is_image_key(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The `sha256:` digest of a reference that is pinned by one.
fn pinned_digest(image: &str) -> Result<&str> {
    let digest = image.rsplit_once('@').map(|(_, digest)| digest);
    match digest.and_then(|d| Some((d, d.strip_prefix("sha256:")?))) {
        Some((digest, hex))
            if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            Ok(digest)
        }
        _ => Err(Error::Preparation("image is not pinned by digest".into())),
    }
}

/// The image's root file system as a read-only ext4 file, built once per (store, pinned digest) and reused.
pub fn guest_image(root: &Path, image: &str, store: &Store) -> Result<GuestImage> {
    guest_image_canceled(root, image, store, &AtomicBool::new(false))
}

/// As [`guest_image`]; a build under way ends when `cancel` is set.
pub fn guest_image_canceled(
    root: &Path,
    image: &str,
    store: &Store,
    cancel: &AtomicBool,
) -> Result<GuestImage> {
    ensure_image(root, image, store, cancel, &build_image)
}

/// Builds the image's files: the temporary names it may use are derived from the final ones.
type Builder<'a> = &'a dyn Fn(&str, &str, &Store, &Path, &Path, &AtomicBool) -> Result<ImageMeta>;

fn ensure_image(
    root: &Path,
    image: &str,
    store: &Store,
    cancel: &AtomicBool,
    build: Builder,
) -> Result<GuestImage> {
    let digest = pinned_digest(image)?;
    let dir = images_dir(root);
    fs::create_dir_all(&dir)?;
    let key = image_key(store, image);
    let rootfs = dir.join(format!("{key}.ext4"));
    let meta_path = dir.join(format!("{key}.json"));
    // Taken before the cache is consulted: GC either removed the image already (a miss, so a rebuild) or
    // finds the lease and leaves it.
    let lease = ImageLease::take(&rootfs);
    if let Some(hit) = cached_image(&rootfs, &meta_path, digest, &lease) {
        return Ok(hit);
    }
    // One build per image at a time: a burst of attempts on a new image waits for the first one's result.
    let lock = build_lock(&key);
    let built = (|| -> Result<GuestImage> {
        let _held = acquire_build(&lock, cancel)?;
        if let Some(hit) = cached_image(&rootfs, &meta_path, digest, &lease) {
            return Ok(hit);
        }
        // What is here is not a usable image (a marker that does not parse or names another digest, a root
        // file system of another size): drop the marker so nothing counts or serves it while it is rebuilt.
        let _ = fs::remove_file(&meta_path);
        let started = Instant::now();
        let meta = build(image, digest, store, &rootfs, &meta_path, cancel)?;
        // A rebuilt root file system is a new file: snapshots taken from the old one no longer describe its disk.
        snapshot::remove_for_image(root, &key);
        Ok(GuestImage {
            rootfs: rootfs.clone(),
            record: GuestImageRecord {
                digest: meta.digest,
                rootfs_bytes: meta.rootfs_bytes,
                built: true,
                build_ns: Some(started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)),
            },
            env: meta.env,
            user: meta.user,
            lease: Arc::clone(&lease),
        })
    })();
    drop(lock);
    release_build_lock(&key);
    built
}

/// Waits for the key's build lock, until `cancel` is set or a build's time is up.
fn acquire_build<'a>(lock: &'a Mutex<()>, cancel: &AtomicBool) -> Result<MutexGuard<'a, ()>> {
    let deadline = Instant::now() + IMAGE_BUILD_TIMEOUT;
    loop {
        match lock.try_lock() {
            Ok(held) => return Ok(held),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if cancel.load(Ordering::Acquire) {
                    return Err(Error::Preparation("guest image build canceled".into()));
                }
                if Instant::now() >= deadline {
                    return Err(Error::Timeout("guest image build"));
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// A complete cached image for `digest`: its marker parses, names that digest and the root file system has
/// the recorded size. A hit stamps the marker when its stamp is old, which is what keeps GC off it.
fn cached_image(
    rootfs: &Path,
    meta_path: &Path,
    digest: &str,
    lease: &Arc<ImageLease>,
) -> Option<GuestImage> {
    let mut marker = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(meta_path)
        .ok()?;
    let mut text = Vec::new();
    marker.read_to_end(&mut text).ok()?;
    let meta = ImageMeta::from_json(&text)?;
    if meta.digest != digest || fs::metadata(rootfs).ok()?.len() != meta.rootfs_bytes {
        return None;
    }
    let stamp = marker.metadata().ok()?.modified().ok()?;
    let now = SystemTime::now();
    if now.duration_since(stamp).is_ok_and(|age| age > STAMP_AFTER) {
        let _ = marker.set_modified(now);
    }
    Some(GuestImage {
        rootfs: rootfs.to_path_buf(),
        record: GuestImageRecord {
            digest: meta.digest,
            rootfs_bytes: meta.rootfs_bytes,
            built: false,
            build_ns: None,
        },
        env: meta.env,
        user: meta.user,
        lease: Arc::clone(lease),
    })
}

type BuildLocks = Mutex<Vec<(String, Arc<Mutex<()>>)>>;

fn build_locks() -> &'static BuildLocks {
    static LOCKS: BuildLocks = Mutex::new(Vec::new());
    &LOCKS
}

fn build_lock(key: &str) -> Arc<Mutex<()>> {
    let mut locks = build_locks().lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, lock)) = locks.iter().find(|(k, _)| k == key) {
        return Arc::clone(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.push((key.to_owned(), Arc::clone(&lock)));
    lock
}

/// Forgets a key's lock once nobody holds or waits on it, so the list stays as long as the builds in flight.
fn release_build_lock(key: &str) {
    let mut locks = build_locks().lock().unwrap_or_else(|p| p.into_inner());
    locks.retain(|(k, lock)| k != key || Arc::strong_count(lock) > 1);
}

/// What `podman image inspect` reports for a guest image (see [`INSPECT_FORMAT`]).
#[derive(Debug, PartialEq, Eq)]
struct Inspected {
    id: String,
    digest: String,
    repo_digests: Vec<String>,
    user: String,
    env: Vec<(String, String)>,
}

const ENV_SEPARATOR: &str = "--env--";
const USER_SEPARATOR: &str = "--user--";
/// One value per line: the image ID, its manifest digest, each repo digest, the configured user after a separator, then the environment after another.
/// Plain actions with newlines in the template: Podman 4.9 refuses a field passed to `println`.
const INSPECT_FORMAT: &str = "{{.Id}}\n{{.Digest}}\n{{range .RepoDigests}}{{.}}\n{{end}}--user--\n{{.Config.User}}\n--env--\n{{range .Config.Env}}{{.}}\n{{end}}";

fn parse_inspect(text: &str) -> Option<Inspected> {
    let mut lines = text.lines();
    let id = lines.next()?.trim().to_owned();
    let digest = lines.next()?.trim().to_owned();
    let mut repo_digests = Vec::new();
    let mut user = String::new();
    loop {
        let line = lines.next()?.trim();
        if line == ENV_SEPARATOR {
            break;
        }
        if line == USER_SEPARATOR {
            user = lines.next()?.trim().to_owned();
            if lines.next()?.trim() != ENV_SEPARATOR {
                return None;
            }
            break;
        }
        if !line.is_empty() {
            repo_digests.push(line.to_owned());
        }
    }
    let env = lines
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    (!id.is_empty()).then_some(Inspected {
        id,
        digest,
        repo_digests,
        user,
        env,
    })
}

impl Inspected {
    /// Whether the stored image is the one `pinned` names: its manifest digest, or a repo digest it was
    /// pulled under.
    fn carries(&self, pinned: &str) -> bool {
        self.digest == pinned
            || self
                .repo_digests
                .iter()
                .any(|r| r.rsplit_once('@').is_some_and(|(_, d)| d == pinned))
    }
}

fn build_image(
    image: &str,
    digest: &str,
    store: &Store,
    rootfs: &Path,
    meta_path: &Path,
    cancel: &AtomicBool,
) -> Result<ImageMeta> {
    let deadline = Instant::now() + IMAGE_BUILD_TIMEOUT;
    let tag = format!("{}.{}", std::process::id(), thread_tag());
    let tmp = rootfs.with_extension(format!("ext4.{tag}"));
    let mut inspect = crate::podman::podman_in(store);
    inspect.args(["image", "inspect", "--format", INSPECT_FORMAT, "--", image]);
    let inspected = process::run_canceled(
        inspect,
        deadline,
        "podman image inspect",
        None,
        Some(cancel),
    )?;
    if !inspected.success() {
        return Err(Error::Preparation(format!(
            "image inspect: {}",
            inspected.stderr_excerpt()
        )));
    }
    let inspected = parse_inspect(&String::from_utf8_lossy(&inspected.stdout))
        .ok_or_else(|| Error::Preparation("image inspect: unreadable answer".into()))?;
    // The digest a job ran is the one the controller pinned: never a root file system from another image.
    if !inspected.carries(digest) {
        return Err(Error::Preparation(
            "the stored image does not carry the pinned digest".into(),
        ));
    }
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
    let built = process::run_canceled(build, deadline, "guest image build", None, Some(cancel));
    match built {
        Ok(built) if built.success() => {}
        Ok(built) => {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Preparation(format!(
                "guest image build: {}",
                built.stderr_excerpt()
            )));
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    publish_image(
        &tmp,
        rootfs,
        meta_path,
        digest,
        &inspected.id,
        &inspected.env,
        &inspected.user,
    )
}

/// Puts a built root file system (`tmp`) in place and writes its marker. The marker goes last: an image
/// counts only once both files are in place, and a failure leaves neither behind.
fn publish_image(
    tmp: &Path,
    rootfs: &Path,
    meta_path: &Path,
    digest: &str,
    image_id: &str,
    env: &[(String, String)],
    user: &str,
) -> Result<ImageMeta> {
    let mut tmp_meta = tmp.as_os_str().to_owned();
    tmp_meta.push(".json");
    let tmp_meta = PathBuf::from(tmp_meta);
    let finish = || -> Result<ImageMeta> {
        let meta = ImageMeta {
            digest: digest.to_owned(),
            image_id: image_id.to_owned(),
            rootfs_bytes: fs::metadata(tmp)?.len(),
            env: env.to_vec(),
            user: user.to_owned(),
        };
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_meta)?
            .write_all(&meta.to_json())?;
        fs::rename(tmp, rootfs)?;
        fs::rename(&tmp_meta, meta_path)?;
        Ok(meta)
    };
    finish().inspect_err(|_| {
        let _ = fs::remove_file(tmp);
        let _ = fs::remove_file(&tmp_meta);
    })
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

// ---------------------------------------------------------------- guest image GC

/// A cached guest image, for the image budget (see [`crate::images`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestEntry {
    pub key: String,
    pub digest: String,
    /// The figure the image budget counts: the apparent size of the root file system plus the bytes held by
    /// the image's snapshots (they are reclaimed with it).
    pub bytes: u64,
    /// The last use: the marker's modification time.
    pub used: SystemTime,
    /// A live attempt is booting from or running on this image: GC must leave it, whatever its stamp says.
    pub in_use: bool,
}

/// The complete cached images under `root`.
pub fn guest_images(root: &Path) -> Vec<GuestEntry> {
    let Ok(entries) = fs::read_dir(images_dir(root)) else {
        return Vec::new();
    };
    let snapshots = snapshot::bytes_by_image(root);
    let dir = images_dir(root);
    let leased: Vec<PathBuf> = leases().iter().map(|(path, _)| path.clone()).collect();
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let key = name.to_str()?.strip_suffix(".json")?;
            if !is_image_key(key) {
                return None;
            }
            let used = entry.metadata().ok()?.modified().ok()?;
            let meta = ImageMeta::from_json(&fs::read(entry.path()).ok()?)?;
            Some(GuestEntry {
                key: key.to_owned(),
                digest: meta.digest,
                bytes: meta
                    .rootfs_bytes
                    .saturating_add(snapshots.get(key).copied().unwrap_or(0)),
                used,
                in_use: leased.contains(&dir.join(format!("{key}.ext4"))),
            })
        })
        .collect()
}

/// Removes one cached image, marker first so no attempt can pick it up half gone; false when there is no
/// such image and when a live attempt holds it (an [`ImageLease`]: GC never takes an image out from under a
/// VM, and a lease taken after the check waits on the lease registry this function holds while it removes).
pub fn remove_guest_image(root: &Path, key: &str) -> bool {
    if !is_image_key(key) {
        return false;
    }
    let dir = images_dir(root);
    let held = leases();
    if held
        .iter()
        .any(|(path, _)| *path == dir.join(format!("{key}.ext4")))
    {
        return false;
    }
    let removed = fs::remove_file(dir.join(format!("{key}.json"))).is_ok();
    let _ = fs::remove_file(dir.join(format!("{key}.ext4")));
    // The snapshots were taken from this root file system and are useless without it.
    snapshot::remove_for_image(root, key);
    drop(held);
    removed
}

/// Files in the image directory that no complete image owns and that are old enough not to be a build in
/// progress: temporary files of failed builds, a root file system whose marker never landed, leftovers of
/// an earlier layout.
fn orphans(files: &[(String, Duration)]) -> Vec<&str> {
    let names: HashSet<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    files
        .iter()
        .filter(|(name, age)| {
            if *age < ORPHAN_AGE {
                return false;
            }
            let Some((key, ext)) = name.split_once('.') else {
                return true;
            };
            let complete = is_image_key(key)
                && names.contains(format!("{key}.json").as_str())
                && names.contains(format!("{key}.ext4").as_str());
            !(complete && (ext == "json" || ext == "ext4"))
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// Removes the image directory's orphans; the count removed.
pub fn sweep_guest_orphans(root: &Path) -> usize {
    let dir = images_dir(root);
    let snapshots = snapshot::sweep(
        root,
        |key| is_image_key(key) && dir.join(format!("{key}.json")).is_file(),
        ORPHAN_AGE,
    );
    let Ok(entries) = fs::read_dir(&dir) else {
        return snapshots;
    };
    let now = SystemTime::now();
    let files: Vec<(String, Duration)> = entries
        .flatten()
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let age = now
                .duration_since(metadata.modified().ok()?)
                .unwrap_or(Duration::ZERO);
            Some((entry.file_name().into_string().ok()?, age))
        })
        .collect();
    snapshots
        + orphans(&files)
            .into_iter()
            .filter(|name| fs::remove_file(dir.join(name)).is_ok())
            .count()
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
            // The handshake never outlives the caller's deadline: a cancel to a frozen VMM must not wait out 5 s.
            let left = deadline.saturating_duration_since(Instant::now());
            stream.set_read_timeout(Some(
                left.clamp(Duration::from_millis(50), Duration::from_secs(5)),
            ))?;
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

impl Drop for Client {
    /// A connection the worker is done with ends for the guest agent too, whoever else holds the socket.
    fn drop(&mut self) {
        self.close();
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

    /// Ends the connection from the host side, so the guest agent's end of it ends too.
    fn close(&self) {
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
    }

    fn expect_done(&self, what: &str) -> Result<()> {
        self.expect_done_within(what, CONTROL_TIMEOUT)
    }

    fn expect_done_within(&self, what: &str, timeout: Duration) -> Result<()> {
        match self.control(timeout)? {
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

/// How a VM's guest came up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// Booted from the kernel.
    Cold,
    /// Restored from a snapshot of a booted guest of the same shape.
    Restored,
}

/// What the start of a VM decided and measured, for diagnostics and for the warm-start evidence (M06, M08).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartReport {
    pub mode: Start,
    /// Monotonic time from the start of the VMM until the guest agent was ready for the workspace (for a restore:
    /// clone, load, connect and resume; for the VM that builds the snapshot: the build is in it).
    pub ready_ns: u64,
    /// This start built the snapshot it was restored from.
    pub snapshot_built: bool,
    /// Why a warm start was not used when one was wanted: a snapshot that failed to build or to restore.
    pub fallback: Option<String>,
}

/// A running job VM; the counterpart of [`crate::podman::Container`].
pub struct Vm {
    attempt: AttemptId,
    dir: PathBuf,
    /// The systemd scope the VM runs in (`unit_name`), stopped on destroy.
    unit: String,
    /// The guest image this VM booted, for the attempt's summary.
    guest: GuestImageRecord,
    start: StartReport,
    child: Mutex<Child>,
    client: Client,
    env: Vec<(String, String)>,
    user: String,
    next_id: AtomicU32,
    /// Writable mounts: their guest path and the host directory they come back to.
    writable: Vec<(String, PathBuf)>,
    /// Keeps image GC off this VM's root file system until the VM is gone.
    _image: Arc<ImageLease>,
    /// Set once the scope is confirmed stopped and the directory removed, so dropping the handle is then a no-op.
    gone: AtomicBool,
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

/// The kernel command line of a guest.
fn boot_args(net: bool) -> String {
    let mut args = String::from(
        "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd quiet",
    );
    if net {
        args.push_str(&net::boot_args());
    }
    args
}

/// A VM start in progress: everything the cold boot, the snapshot build and the restore share.
struct Plan<'a> {
    root: &'a Path,
    setup: &'a Setup,
    guest: &'a GuestImage,
    initrd: &'a Path,
    limits: Limits,
    shape: snapshot::Shape,
    /// The attempt's VM directory and the scope its VMM runs in.
    dir: &'a Path,
    unit: &'a str,
    cancel: &'a AtomicBool,
}

impl Plan<'_> {
    /// The nftables rules of a VM granted egress (none for a VM without a network).
    fn rules(&self) -> Result<Option<String>> {
        if !self.shape.net {
            return Ok(None);
        }
        let host = net::host_addresses()
            .map_err(|e| Error::Preparation(format!("the host's addresses: {e}")))?;
        Ok(Some(net::Policy::new(&host, &self.setup.guard).rules()))
    }

    /// Starts the VMM in its scope, in a chroot that is `dir` with the kernel, the initramfs, the guest image and
    /// (for a restore) the directory `snapshot` bound in; `tap` is the rules of a VM with a tap and whether it
    /// also gets an uplink.
    fn spawn(
        &self,
        dir: &Path,
        unit: &str,
        limits: Limits,
        snapshot: Option<&Path>,
        tap: Option<(&str, bool)>,
        args: &[OsString],
    ) -> Result<Child> {
        net::install(
            dir,
            tap.map(|(rules, _)| rules),
            tap.is_some_and(|(_, uplink)| uplink),
        )?;
        let console = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("console.log"))?;
        let mut command = Command::new("systemd-run");
        command
            .args(["--user", "--scope", "--quiet", "--collect", "--unit"])
            .arg(unit)
            .arg(format!("-pCPUQuota={}%", (limits.cpu_millis / 10).max(1)))
            .arg(format!(
                "-pMemoryMax={}",
                limits.memory_bytes.saturating_add(VMM_OVERHEAD)
            ))
            .args(["--", "/bin/sh"])
            .arg(net::launch_script(dir))
            .arg(dir)
            .arg(&self.setup.kernel)
            .arg(self.initrd)
            .arg(&self.guest.rootfs)
            .arg(snapshot.map_or(OsStr::new("-"), Path::as_os_str))
            .arg(&self.setup.firecracker)
            .args(args)
            .stdin(Stdio::null())
            .stdout(console.try_clone()?)
            .stderr(console);
        command
            .spawn()
            .map_err(|e| Error::Preparation(format!("firecracker: {e}")))
    }

    /// Connects to the guest agent of a VMM just started in `dir`; a VMM that ends or a cancel stops the wait
    /// and the VM with it.
    fn await_agent(&self, child: &mut Child, dir: &Path, unit: &str) -> Result<Client> {
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let client = connect(&dir.join("vsock.sock"), deadline, &mut || {
            matches!(child.try_wait(), Ok(None)) && !self.cancel.load(Ordering::Acquire)
        });
        client.map_err(|e| {
            let tail = console_tail(dir);
            kill_vmm(child, unit);
            if self.cancel.load(Ordering::Acquire) {
                return canceled_start();
            }
            Error::Preparation(format!("{e}; console: {tail}"))
        })
    }

    /// The cold boot: the pinned kernel, the initramfs, the image and a fresh scratch disk.
    fn cold(&self) -> Result<(Child, Client)> {
        scratch_disk(&self.dir.join("scratch.ext4"), self.shape.scratch_bytes)?;
        self.write_config(self.dir)?;
        let rules = self.rules()?;
        let mut child = self.spawn(
            self.dir,
            self.unit,
            self.limits,
            None,
            rules.as_deref().map(|r| (r, true)),
            &[
                "--api-sock".into(),
                JAIL_API.into(),
                "--config-file".into(),
                JAIL_CONFIG.into(),
            ],
        )?;
        let client = self.await_agent(&mut child, self.dir, self.unit)?;
        Ok((child, client))
    }

    /// The VMM's configuration and CPU template, as files of the VM directory (the chroot).
    fn write_config(&self, dir: &Path) -> Result<()> {
        fs::write(dir.join("cpu.json"), CPU_CONFIG)?;
        fs::write(
            dir.join("vm.json"),
            serde_json::to_vec_pretty(&vm_config(&self.shape)).map_err(io::Error::other)?,
        )?;
        Ok(())
    }

    /// The warm start. `Ok(None)` when no snapshot is usable right now and the VM should boot cold without
    /// it being a failure (another attempt is building the snapshot, or a build failed lately).
    fn warm(&self, report: &mut StartReport) -> Result<Option<(Child, Client)>> {
        let rootfs_id = snapshot::file_identity(&self.guest.rootfs)?;
        let image_key = self
            .guest
            .rootfs
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let name = snapshot::name(
            image_key,
            &rootfs_id,
            self.initrd,
            &self.setup.kernel,
            &self.setup.firecracker,
            &self.shape,
            &boot_args(self.shape.net),
        )?;
        let snap = match snapshot::open(self.root, &name) {
            Some(snap) => snap,
            None => match self.ensure_snapshot(&name, report)? {
                Some(snap) => snap,
                None => return Ok(None),
            },
        };
        match self.restore(&snap) {
            Ok(started) => Ok(Some(started)),
            Err(e) => {
                // A snapshot that cannot be restored is not tried again: the next attempt builds a new one.
                if !self.cancel.load(Ordering::Acquire) {
                    snapshot::remove(self.root, &name);
                }
                Err(e)
            }
        }
    }

    /// The snapshot `name`, built now when it does not exist, nobody else is building it and a build of it
    /// has not failed lately.
    fn ensure_snapshot(
        &self,
        name: &str,
        report: &mut StartReport,
    ) -> Result<Option<snapshot::Snapshot>> {
        if snapshot::recently_failed(name) {
            report.fallback = Some("building a snapshot of this shape failed lately".into());
            return Ok(None);
        }
        let lock = snapshot::build_lock(name);
        let outcome = match lock.try_lock() {
            Err(TryLockError::WouldBlock) => Ok(None),
            Ok(_held) => self.build_if_missing(name, report),
            Err(TryLockError::Poisoned(held)) => {
                let _held = held.into_inner();
                self.build_if_missing(name, report)
            }
        };
        drop(lock);
        snapshot::release_build_lock(name);
        outcome
    }

    fn build_if_missing(
        &self,
        name: &str,
        report: &mut StartReport,
    ) -> Result<Option<snapshot::Snapshot>> {
        if let Some(snap) = snapshot::open(self.root, name) {
            return Ok(Some(snap));
        }
        match self.build_snapshot(name) {
            Ok(()) => {
                report.snapshot_built = true;
                Ok(snapshot::open(self.root, name))
            }
            Err(_) if self.cancel.load(Ordering::Acquire) => Err(canceled_start()),
            Err(e) => {
                snapshot::note_failure(name);
                report.fallback = Some(format!("building the snapshot failed: {e}"));
                Ok(None)
            }
        }
    }

    /// Boots a template VM of the shape in a VM directory of its own (so a crash leaves it to startup
    /// reconciliation like any VM), waits for its agent, pauses it and saves its state, memory and scratch disk.
    fn build_snapshot(&self, name: &str) -> Result<()> {
        let builder = AttemptId::new();
        let dir = vm_dir(self.root, builder);
        fs::create_dir_all(&dir)?;
        let unit = unit_name(self.root, builder);
        let built = self.build_in(&dir, &unit, name, builder);
        // The template VM never outlives the build; its directory stays while its scope could still be running.
        if stop_unit(OsStr::new(SYSTEMCTL), &unit).is_ok() {
            let _ = fs::remove_dir_all(&dir);
        }
        built
    }

    fn build_in(&self, dir: &Path, unit: &str, name: &str, builder: AttemptId) -> Result<()> {
        scratch_disk(&dir.join("scratch.ext4"), self.shape.scratch_bytes)?;
        self.write_config(dir)?;
        // The template has the tap and the rules a VM of its shape has, but no uplink: it never runs a job.
        let rules = self
            .shape
            .net
            .then(|| net::Policy::new(&[], &net::Guard::default()).rules());
        let limits = Limits {
            cpu_millis: u32::try_from(self.shape.vcpus * 1000).unwrap_or(u32::MAX),
            memory_bytes: self.shape.mib << 20,
            ..self.limits
        };
        let mut child = self.spawn(
            dir,
            unit,
            limits,
            None,
            rules.as_deref().map(|r| (r, false)),
            &[
                "--api-sock".into(),
                JAIL_API.into(),
                "--config-file".into(),
                JAIL_CONFIG.into(),
            ],
        )?;
        let saved = (|| -> Result<()> {
            let client = self.await_agent(&mut child, dir, unit)?;
            // The snapshot holds no connection: the host side closes its own and the guest sees the end.
            client.close();
            thread::sleep(Duration::from_millis(20));
            let api = dir.join("api.sock");
            fcapi::call(
                &api,
                "PATCH",
                "/vm",
                Some(&serde_json::json!({ "state": "Paused" })),
                CONTROL_TIMEOUT,
            )?;
            fcapi::call(
                &api,
                "PUT",
                "/snapshot/create",
                Some(&serde_json::json!({
                    "snapshot_type": "Full",
                    "snapshot_path": "/state",
                    "mem_file_path": "/mem",
                })),
                SNAPSHOT_TIMEOUT,
            )?;
            Ok(())
        })();
        kill_vmm(&mut child, unit);
        saved?;
        stop_unit(OsStr::new(SYSTEMCTL), unit)?;
        let staged = snapshot::staging(self.root, name, &builder.to_string())?;
        let moved = (|| -> Result<()> {
            for file in ["state", "mem", "scratch.ext4"] {
                fs::rename(dir.join(file), staged.join(file))?;
            }
            snapshot::publish(self.root, name, &staged)?;
            Ok(())
        })();
        if moved.is_err() {
            let _ = fs::remove_dir_all(&staged);
        }
        moved
    }

    /// Restores a VM from `snap`: the snapshot's scratch disk cloned for this attempt, the image bound into its chroot, a VMM
    /// with no configuration that loads the snapshot, then the agent told the time and given fresh entropy.
    fn restore(&self, snap: &snapshot::Snapshot) -> Result<(Child, Client)> {
        snapshot::clone_file(&snap.scratch, &self.dir.join("scratch.ext4"))?;
        let rules = self.rules()?;
        let mut child = self.spawn(
            self.dir,
            self.unit,
            self.limits,
            snap.state.parent(),
            rules.as_deref().map(|r| (r, true)),
            &["--api-sock".into(), JAIL_API.into()],
        )?;
        let resumed = (|| -> Result<Client> {
            self.await_api(&mut child)?;
            fcapi::call(
                &self.dir.join("api.sock"),
                "PUT",
                "/snapshot/load",
                Some(&serde_json::json!({
                    "snapshot_path": format!("{JAIL_SNAPSHOT}/state"),
                    "mem_backend": { "backend_path": format!("{JAIL_SNAPSHOT}/mem"), "backend_type": "File" },
                    "resume_vm": true,
                })),
                RESTORE_TIMEOUT,
            )?;
            let client = self.await_agent(&mut child, self.dir, self.unit)?;
            let mut entropy = vec![0u8; 64];
            fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| Error::Runtime("the clock is before the epoch".into()))?;
            client.send(&Request::Resume {
                entropy,
                realtime_ns: u64::try_from(now.as_nanos()).unwrap_or(u64::MAX),
            })?;
            client.expect_done("resume")?;
            Ok(client)
        })();
        match resumed {
            Ok(client) => Ok((child, client)),
            Err(e) => {
                kill_vmm(&mut child, self.unit);
                Err(e)
            }
        }
    }

    /// Waits for the restored VMM's API socket to accept a connection.
    fn await_api(&self, child: &mut Child) -> Result<()> {
        let api = self.dir.join("api.sock");
        let deadline = Instant::now() + RESTORE_TIMEOUT;
        loop {
            if UnixStream::connect(&api).is_ok() {
                return Ok(());
            }
            if self.cancel.load(Ordering::Acquire) {
                return Err(canceled_start());
            }
            if !matches!(child.try_wait(), Ok(None)) {
                return Err(Error::Preparation(format!(
                    "the VMM ended before its API was up; console: {}",
                    console_tail(self.dir)
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout("firecracker API"));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Ends a VMM that failed or finished its work: the process, then its scope.
fn kill_vmm(child: &mut Child, unit: &str) {
    let _ = child.kill();
    let _ = child.wait();
    let _ = stop_unit(OsStr::new(SYSTEMCTL), unit);
}

impl Vm {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        root: &Path,
        setup: &Setup,
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
        network: Network,
    ) -> Result<Vm> {
        Vm::start_canceled(
            root,
            setup,
            worker,
            attempt,
            image,
            limits,
            workspace,
            mounts,
            store,
            network,
            &AtomicBool::new(false),
        )
    }

    /// Starts the VM; `cancel` (set by a cancel, a lease loss or a shutdown) ends an image build or a boot in
    /// progress and removes what the start made, so no VM outlives the attempt that asked for it.
    #[allow(clippy::too_many_arguments)]
    pub fn start_canceled(
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
        cancel: &AtomicBool,
    ) -> Result<Vm> {
        if cancel.load(Ordering::Acquire) {
            return Err(canceled_start());
        }
        // The directory exists from here to destroy, so a cancel or lease loss that arrives during the image
        // build or the boot finds this VM by name and stops it.
        let dir = vm_dir(root, attempt);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let started = Vm::boot(
            root, setup, attempt, image, limits, workspace, mounts, store, network, cancel, &dir,
        );
        if started.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        started
    }

    #[allow(clippy::too_many_arguments)]
    fn boot(
        root: &Path,
        setup: &Setup,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
        network: Network,
        cancel: &AtomicBool,
        dir: &Path,
    ) -> Result<Vm> {
        let guest = guest_image_canceled(root, image, store, cancel)?;
        let initrd = initramfs(root, setup)?;
        if cancel.load(Ordering::Acquire) {
            return Err(canceled_start());
        }
        let unit = unit_name(root, attempt);
        let plan = Plan {
            root,
            setup,
            guest: &guest,
            initrd: &initrd,
            limits,
            shape: snapshot::Shape {
                vcpus: u64::from(limits.cpu_millis.div_ceil(1000).max(1)),
                mib: ((limits.memory_bytes >> 20) + GUEST_OVERHEAD_MIB).max(128),
                scratch_bytes: limits.disk_bytes.max(1 << 30),
                net: network == Network::Egress,
            },
            dir,
            unit: &unit,
            cancel,
        };
        let began = Instant::now();
        let mut report = StartReport {
            mode: Start::Cold,
            ready_ns: 0,
            snapshot_built: false,
            fallback: None,
        };
        let mut launched = None;
        if setup.snapshots && plan.shape.mib <= snapshot::MAX_MEMORY_MIB {
            match plan.warm(&mut report) {
                Ok(Some(started)) => {
                    report.mode = Start::Restored;
                    launched = Some(started);
                }
                Ok(None) => {}
                Err(e) => {
                    if cancel.load(Ordering::Acquire) {
                        return Err(canceled_start());
                    }
                    // The same attempt boots cold in the same directory.
                    report.fallback = Some(format!("restoring the snapshot failed: {e}"));
                    stop_unit(OsStr::new(SYSTEMCTL), &unit)?;
                    clear_dir(dir)?;
                }
            }
        }
        let (child, client) = match launched {
            Some(started) => started,
            None => plan.cold()?,
        };
        report.ready_ns = u64::try_from(began.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut vm = Vm {
            attempt,
            dir: dir.to_path_buf(),
            unit,
            guest: guest.record,
            start: report,
            child: Mutex::new(child),
            client,
            env: guest.env,
            user: guest.user,
            next_id: AtomicU32::new(1),
            writable: Vec::new(),
            _image: guest.lease,
            gone: AtomicBool::new(false),
        };
        let prepared = (|| -> Result<()> {
            vm.client.send(&Request::MemoryLimit {
                bytes: limits.memory_bytes,
            })?;
            vm.client.expect_done("memory limit")?;
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
            if cancel.load(Ordering::Acquire) {
                return Err(canceled_start());
            }
            Ok(())
        })();
        if let Err(e) = prepared {
            let _ = vm.destroy_inner();
            return Err(e);
        }
        Ok(vm)
    }

    /// How this VM's guest came up and how long it took to be ready.
    pub fn start_report(&self) -> &StartReport {
        &self.start
    }

    /// The guest image this VM booted: the pinned digest, for the attempt's provenance.
    pub fn guest_image(&self) -> &GuestImageRecord {
        &self.guest
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
            user: self.user.clone(),
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
                    return Err(Error::Runtime(format!(
                        "the guest agent closed the connection; console: {}",
                        console_tail(&self.dir)
                    )));
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

    /// Every process an earlier step left: the guest has one PID namespace, as a container does. The agent
    /// does not count what it killed, so the number is always 0 here.
    pub fn clear_strays(&self) -> Result<usize> {
        self.client.send(&Request::KillStrays)?;
        self.client.expect_done("clear strays")?;
        Ok(0)
    }

    /// Puts a step's secret directories into the guest, each under its container path (the guest keeps them
    /// in memory: the agent mounts a tmpfs at each [`agent::SECRET_MOUNTS`] path).
    pub fn deliver_secrets(&self, dirs: &[(&Path, &str)]) -> Result<()> {
        for (host, container) in dirs {
            self.client.put_dir(host, &guest_path(container), &[])?;
        }
        Ok(())
    }

    /// Empties the guest's secret directories: nothing a step was given stays for the next one to read.
    pub fn retract_secrets(&self) -> Result<()> {
        self.client.send(&Request::Wipe {
            dirs: agent::SECRET_MOUNTS.iter().map(|d| guest_path(d)).collect(),
        })?;
        self.client.expect_done("retract secrets")
    }

    /// Brings back what the host reads after the steps: `workspace_paths` (relative to the workspace, the
    /// artifacts), the workspace directories in `replaced` (the cache views declared by relative paths), whose
    /// host copy is replaced by the guest's so a file the job deleted is gone, and every writable mount, whose
    /// host directory is replaced the same way.
    pub fn sync_out(
        &self,
        workspace: &Path,
        workspace_paths: &[String],
        replaced: &[String],
    ) -> Result<()> {
        let patterns: Vec<&str> = workspace_paths.iter().map(String::as_str).collect();
        self.pull_workspace(workspace, &patterns)?;
        for rel in replaced {
            let host = workspace.join(rel);
            // Only a real directory is replaced: a path the job's checkout made a link or a file is left to
            // publication, which resolves it without following links.
            if !fs::symlink_metadata(&host).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            clear_dir(&host)?;
            self.client
                .get_into(&guest_path(WORKSPACE_MOUNT), vec![rel.clone()], workspace)?;
        }
        for (guest, host) in &self.writable {
            clear_dir(host)?;
            self.client.get_into(guest, vec![".".into()], host)?;
        }
        Ok(())
    }

    /// Brings the guest workspace's files matching `patterns` (globs, as artifacts and `hash_files` state
    /// them) back over the host copy. The agent returns literal paths, so each pattern is fetched as the
    /// directory it starts from and the host applies the glob to what arrived.
    pub fn pull_workspace(&self, workspace: &Path, patterns: &[&str]) -> Result<()> {
        let roots = fetch_roots(patterns);
        if roots.is_empty() {
            return Ok(());
        }
        self.client
            .get_into(&guest_path(WORKSPACE_MOUNT), roots, workspace)
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
        // A scope that is still running keeps its directory: startup reconciliation finds the VM by it.
        stop_unit(OsStr::new(SYSTEMCTL), &self.unit)?;
        fs::remove_dir_all(&self.dir).or_else(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        self.gone.store(true, Ordering::Release);
        Ok(())
    }
}

/// A handle that goes away without `destroy` (an attempt thread that panics, an early return) must not leave
/// its VM running: the scope is killed and the directory removed, as `destroy` does. A worker that dies
/// without running destructors (`kill -9`, power loss) leaves the VM to startup reconciliation instead.
impl Drop for Vm {
    fn drop(&mut self) {
        if !self.gone.load(Ordering::Acquire) {
            let _ = self.destroy_inner();
        }
    }
}

fn canceled_start() -> Error {
    Error::Preparation("microVM start canceled".into())
}

/// The CPU configuration of every guest (Firecracker's custom CPU template, a file in the VM's directory):
/// the CPUID bits that advertise hardware virtualization, VMX (leaf 1, ECX bit 5) and SVM (leaf 0x8000_0001,
/// ECX bit 2), are cleared, so a guest on a host with nested virtualization enabled sees neither. A bit the
/// host's vendor does not define is reserved and already zero. It is part of a snapshot's name, because the
/// saved vCPU state carries the CPUID the guest booted with.
pub(crate) const CPU_CONFIG: &str = r#"{
  "cpuid_modifiers": [
    {
      "leaf": "0x1",
      "subleaf": "0x0",
      "flags": 0,
      "modifiers": [
        { "register": "ecx", "bitmap": "0bxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxx" }
      ]
    },
    {
      "leaf": "0x80000001",
      "subleaf": "0x0",
      "flags": 0,
      "modifiers": [
        { "register": "ecx", "bitmap": "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx" }
      ]
    }
  ]
}
"#;

/// The Firecracker configuration of one VM. The guest gets the image (read-only), its scratch disk, the vsock
/// the agent speaks on and the CPU configuration above, so it sees no hardware virtualization (`/dev/kvm` and
/// nested KVM stay off). A network interface is attached only to a guest the worker granted egress; nothing
/// else is.
fn vm_config(shape: &snapshot::Shape) -> serde_json::Value {
    let mut config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": JAIL_KERNEL,
            "initrd_path": JAIL_INITRD,
            "boot_args": boot_args(shape.net),
        },
        "drives": [
            { "drive_id": "image", "path_on_host": JAIL_IMAGE, "is_root_device": false, "is_read_only": true },
            { "drive_id": "scratch", "path_on_host": JAIL_SCRATCH, "is_root_device": false, "is_read_only": false },
        ],
        "machine-config": { "vcpu_count": shape.vcpus, "mem_size_mib": shape.mib, "smt": false },
        "cpu-config": JAIL_CPU_CONFIG,
        "vsock": { "guest_cid": GUEST_CID, "uds_path": JAIL_VSOCK },
    });
    if shape.net {
        config["network-interfaces"] = net::interface();
    }
    config
}

/// The literal paths to fetch for glob `patterns`: each pattern's leading components that hold no glob
/// character (the whole pattern when it has none), `.` when it starts with a glob. Paths under another
/// fetched path are dropped, so nothing travels twice.
fn fetch_roots(patterns: &[&str]) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    for pattern in patterns {
        let literal: Vec<&str> = pattern
            .trim_start_matches('/')
            .split('/')
            .take_while(|part| !part.contains(['*', '?', '[', '{']))
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        let root = if literal.is_empty() {
            ".".to_owned()
        } else {
            literal.join("/")
        };
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.iter().any(|r| r == ".") {
        return vec![".".to_owned()];
    }
    let all = roots.clone();
    roots.retain(|r| {
        !all.iter()
            .any(|other| other != r && r.starts_with(&format!("{other}/")))
    });
    roots
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

/// The last lines the VMM and the launch scripts wrote to the VM's console log: one line is rarely enough to
/// say why a VM did not come up (`mount` and `nft` print their reason before their last line).
fn console_tail(dir: &Path) -> String {
    let text = fs::read(dir.join("console.log")).unwrap_or_default();
    let start = text.len().saturating_sub(2048);
    let text = String::from_utf8_lossy(&text[start..]);
    let mut lines: Vec<String> = text
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(4)
        .map(|l| l.chars().filter(|c| !c.is_control()).take(200).collect())
        .collect();
    lines.reverse();
    if lines.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        lines.join(" | ")
    }
}

/// Whether `systemctl is-active` said the unit is up (or coming up or going down).
fn unit_running(output: &std::process::Output) -> bool {
    matches!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "active" | "activating" | "deactivating" | "reloading"
    )
}

/// Kills and stops the VM's scope, then checks it is gone: a VM that may still be running must not have its
/// files removed or its attempt abandoned. A `systemctl` that cannot run at all means no scope can exist.
fn stop_unit(systemctl: &OsStr, unit: &str) -> Result<()> {
    let scope = format!("{unit}.scope");
    let _ = systemctl_user(systemctl, &["kill", "--signal=SIGKILL", &scope]);
    let _ = systemctl_user(systemctl, &["stop", &scope]);
    match systemctl_user(systemctl, &["is-active", &scope]) {
        Ok(status) if unit_running(&status) => {
            Err(Error::Runtime("the VM's scope is still running".into()))
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------- by name, from other threads

/// A cancel: SIGTERM to every guest process, SIGKILL after `grace`, through a connection of its own. A guest
/// that does not confirm in time loses its VM instead.
pub fn terminate_named(root: &Path, attempt: AttemptId, grace: Duration) -> Result<Terminated> {
    terminate_named_with(
        OsStr::new(SYSTEMCTL),
        root,
        attempt,
        grace,
        CANCEL_CONNECT_TIMEOUT,
        CANCEL_REPLY_TIMEOUT,
    )
}

fn terminate_named_with(
    systemctl: &OsStr,
    root: &Path,
    attempt: AttemptId,
    grace: Duration,
    connect_wait: Duration,
    reply_wait: Duration,
) -> Result<Terminated> {
    let dir = vm_dir(root, attempt);
    let socket = dir.join("vsock.sock");
    if !socket.exists() {
        return Ok(Terminated::Gone);
    }
    let client = match connect(&socket, Instant::now() + connect_wait, &mut || true) {
        Ok(client) => client,
        Err(_) => {
            remove_named_with(systemctl, root, attempt)?;
            return Ok(Terminated::Forced);
        }
    };
    let signaled = (|| -> Result<Terminated> {
        client.send(&Request::SignalAll {
            signal: libc::SIGTERM,
        })?;
        client.expect_done_within("terminate", reply_wait)?;
        // The grace period ends as soon as the steps have: a step that stops on SIGTERM is a graceful stop.
        client.send(&Request::WaitIdle {
            timeout_ms: u32::try_from(grace.as_millis()).unwrap_or(u32::MAX),
        })?;
        match client.control(grace + reply_wait)? {
            Reply::Idle(true) => return Ok(Terminated::Graceful),
            Reply::Idle(false) => {}
            Reply::Failed { message } => {
                return Err(Error::Runtime(format!("terminate: {message}")));
            }
            other => return Err(Error::Runtime(format!("terminate: unexpected {other:?}"))),
        }
        client.send(&Request::SignalAll {
            signal: libc::SIGKILL,
        })?;
        client.expect_done_within("terminate", reply_wait)?;
        Ok(Terminated::Forced)
    })();
    match signaled {
        Ok(how) => Ok(how),
        Err(_) => {
            // The guest could not be told: the VM is all that is left to stop, and the step waiting on it ends
            // when its connection closes.
            remove_named_with(systemctl, root, attempt)?;
            Ok(Terminated::Forced)
        }
    }
}

/// Stops the VM's scope and removes its directory: shutdown, lease loss and startup recovery. A scope that
/// does not stop is an error and leaves the directory, so the VM is still found by name.
pub fn remove_named(root: &Path, attempt: AttemptId) -> Result<()> {
    remove_named_with(OsStr::new(SYSTEMCTL), root, attempt)
}

fn remove_named_with(systemctl: &OsStr, root: &Path, attempt: AttemptId) -> Result<()> {
    stop_unit(systemctl, &unit_name(root, attempt))?;
    match fs::remove_dir_all(vm_dir(root, attempt)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(e)),
        _ => Ok(()),
    }
}

/// Whether the attempt runs in a VM here (its directory exists from the start of its start to destroy).
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

/// The attempts named by the VM scopes in a `systemctl list-units` listing, for scopes with `prefix`.
fn parse_units(listing: &str, prefix: &str) -> Vec<AttemptId> {
    listing
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?;
            name.strip_prefix(prefix)?
                .strip_suffix(".scope")?
                .parse::<AttemptId>()
                .ok()
        })
        .collect()
}

/// The attempts whose VM scopes this data root left running or failed, whether or not their directories
/// remain. A `systemctl` that fails is an error, not an empty listing: a scope would go unstopped.
fn listed_units(systemctl: &OsStr, root: &Path) -> Result<Vec<AttemptId>> {
    let prefix = unit_prefix(root);
    let pattern = format!("{prefix}*.scope");
    let listing = systemctl_user(
        systemctl,
        &[
            "list-units",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
            &pattern,
        ],
    )
    .map_err(|e| Error::Runtime(format!("listing microVM scopes: {e}")))?;
    if !listing.status.success() {
        return Err(Error::Runtime(format!(
            "listing microVM scopes: {}",
            crate::redact::excerpt(&listing.stderr)
        )));
    }
    Ok(parse_units(
        &String::from_utf8_lossy(&listing.stdout),
        &prefix,
    ))
}

/// Startup reconciliation: every VM this data root left behind, whether it has a directory, a scope or both,
/// is stopped and its files (scratch disk, console log, sockets) removed. The count of VMs removed. A host that
/// never ran a microVM (no `microvm` directory) is not asked about scopes at all.
pub fn reconcile(root: &Path) -> Result<usize> {
    reconcile_with(OsStr::new(SYSTEMCTL), root)
}

fn reconcile_with(systemctl: &OsStr, root: &Path) -> Result<usize> {
    let mut leftover = owned(root);
    if root.join(DIR).is_dir() {
        for attempt in listed_units(systemctl, root)? {
            if !leftover.contains(&attempt) {
                leftover.push(attempt);
            }
        }
    }
    for attempt in &leftover {
        remove_named_with(systemctl, root, *attempt)?;
    }
    Ok(leftover.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_names_every_missing_piece_and_passes_when_complete() {
        let dir = tempfile::tempdir().unwrap();
        let put = |name: &str, mode: u32| {
            let path = dir.path().join(name);
            fs::write(&path, b"x").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let setup = Setup {
            firecracker: dir.path().join("firecracker"),
            kernel: dir.path().join("vmlinux"),
            agent: dir.path().join("sentinel-agent"),
            snapshots: true,
            guard: net::Guard::default(),
        };
        let error = setup.check().unwrap_err();
        assert!(error.contains("firecracker "), "{error}");
        assert!(error.contains("no guest kernel"), "{error}");
        assert!(error.contains("agent "), "{error}");
        put("firecracker", 0o755);
        put("vmlinux", 0o644);
        put("sentinel-agent", 0o644);
        let error = setup.check().unwrap_err();
        assert!(!error.contains("firecracker "), "{error}");
        assert!(!error.contains("no guest kernel"), "{error}");
        assert!(error.contains("agent "), "{error}");
        put("sentinel-agent", 0o755);
        assert_eq!(setup.check(), Ok(()));
    }

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
    fn attempts_starting_together_share_one_initramfs() {
        let root = tempfile::tempdir().unwrap();
        let agent = root.path().join("agent");
        fs::write(&agent, vec![7u8; 256 << 10]).unwrap();
        let setup = Setup {
            firecracker: "/nonexistent/firecracker".into(),
            kernel: "/nonexistent/vmlinux".into(),
            agent,
            snapshots: true,
            guard: net::Guard::default(),
        };
        for _ in 0..20 {
            let data = tempfile::tempdir().unwrap();
            let paths: Vec<PathBuf> = thread::scope(|scope| {
                let writers: Vec<_> = (0..8)
                    .map(|_| scope.spawn(|| initramfs(data.path(), &setup).unwrap()))
                    .collect();
                writers.into_iter().map(|w| w.join().unwrap()).collect()
            });
            assert!(paths.iter().all(|p| p == &paths[0] && p.is_file()));
            let leftovers: Vec<_> = fs::read_dir(data.path().join(DIR))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".initramfs-"))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
    }

    #[test]
    fn a_setup_with_missing_files_says_which() {
        let setup = Setup {
            firecracker: "/nonexistent/firecracker".into(),
            kernel: "/nonexistent/vmlinux".into(),
            agent: "/nonexistent/agent".into(),
            snapshots: true,
            guard: net::Guard::default(),
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

    // ------------------------------------------------------------ guest images

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const OTHER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000002";

    fn image_ref(digest: &str) -> String {
        format!("example.test/i@{digest}")
    }

    /// A complete cached image, as a finished build leaves it.
    fn plant_image(root: &Path, image: &str, digest: &str, bytes: u64) -> (PathBuf, PathBuf) {
        let dir = images_dir(root);
        fs::create_dir_all(&dir).unwrap();
        let key = image_key(&Store::Shared, image);
        let rootfs = dir.join(format!("{key}.ext4"));
        let marker = dir.join(format!("{key}.json"));
        fs::File::create(&rootfs).unwrap().set_len(bytes).unwrap();
        let meta = ImageMeta {
            digest: digest.into(),
            image_id: "ab".repeat(32),
            rootfs_bytes: bytes,
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            user: String::new(),
        };
        fs::write(&marker, meta.to_json()).unwrap();
        (rootfs, marker)
    }

    fn lease(rootfs: &Path) -> Arc<ImageLease> {
        ImageLease::take(rootfs)
    }

    fn age(path: &Path, by: Duration) {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - by)
            .unwrap();
    }

    #[test]
    fn only_a_digest_pinned_reference_names_a_guest_image() {
        assert_eq!(pinned_digest(&image_ref(DIGEST)).unwrap(), DIGEST);
        for bad in [
            "example.test/i:latest",
            "example.test/i@sha256:abc",
            "example.test/i@sha512:00",
            &format!("example.test/i@sha256:{}", "G".repeat(64)),
            &format!("example.test/i@sha256:{}", "A".repeat(64)),
        ] {
            assert!(
                matches!(pinned_digest(bad), Err(Error::Preparation(ref why)) if why == "image is not pinned by digest"),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_inspect_answer_is_checked_against_the_pinned_digest() {
        let answer = format!(
            "{id}\n{DIGEST}\nexample.test/i@{DIGEST}\nexample.test/i@{OTHER}\n--env--\nPATH=/bin\nA=b=c\nnoequals\n",
            id = "ab".repeat(32)
        );
        let inspected = parse_inspect(&answer).unwrap();
        assert_eq!(inspected.id, "ab".repeat(32));
        assert_eq!(inspected.repo_digests.len(), 2);
        assert_eq!(
            inspected.env,
            vec![
                ("PATH".to_owned(), "/bin".to_owned()),
                ("A".to_owned(), "b=c".to_owned())
            ]
        );
        assert!(inspected.carries(DIGEST));
        assert!(
            inspected.carries(OTHER),
            "a repo digest it was pulled under"
        );
        assert!(!inspected.carries(&format!("sha256:{}", "f".repeat(64))));
        // An image with no repo digests still carries its own manifest digest.
        let local = parse_inspect(&format!("id\n{DIGEST}\n--env--\n")).unwrap();
        assert!(local.carries(DIGEST) && !local.carries(OTHER));
        assert!(parse_inspect("id\n").is_none());
        assert!(parse_inspect(&format!("\n{DIGEST}\n--env--\n")).is_none());
        assert!(parse_inspect("id\ndigest\nno separator\n").is_none());
    }

    #[test]
    fn a_cached_image_is_reused_and_reports_the_digest_it_carries() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 4096);
        let hit = guest_image(root.path(), &image, &Store::Shared).unwrap();
        assert_eq!(hit.rootfs, rootfs);
        assert_eq!(hit.env, vec![("PATH".into(), "/usr/bin:/bin".into())]);
        assert_eq!(
            hit.record,
            GuestImageRecord {
                digest: DIGEST.into(),
                rootfs_bytes: 4096,
                built: false,
                build_ns: None,
            }
        );
        // A stale stamp is refreshed by the use, which is what keeps GC off a busy image.
        age(&marker, Duration::from_secs(3600));
        guest_image(root.path(), &image, &Store::Shared).unwrap();
        let stamp = fs::metadata(&marker).unwrap().modified().unwrap();
        assert!(stamp.elapsed().unwrap() < Duration::from_secs(60));
        // A recent stamp is left alone.
        let recent = SystemTime::now() - Duration::from_secs(10);
        fs::OpenOptions::new()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(recent)
            .unwrap();
        guest_image(root.path(), &image, &Store::Shared).unwrap();
        assert_eq!(fs::metadata(&marker).unwrap().modified().unwrap(), recent);
    }

    #[test]
    fn a_cache_entry_that_is_not_the_pinned_image_is_not_used() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        // The marker names another digest than the reference: never served.
        let (_, marker) = plant_image(root.path(), &image, OTHER, 4096);
        let dir = images_dir(root.path());
        assert!(
            cached_image(
                &dir.join("x.ext4"),
                &marker,
                DIGEST,
                &lease(&dir.join("x.ext4"))
            )
            .is_none()
        );
        let key = image_key(&Store::Shared, &image);
        let rootfs = dir.join(format!("{key}.ext4"));
        assert!(cached_image(&rootfs, &marker, DIGEST, &lease(&rootfs)).is_none());
        // A root file system of another size than the marker records (truncated or replaced).
        let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 4096);
        assert!(cached_image(&rootfs, &marker, DIGEST, &lease(&rootfs)).is_some());
        fs::OpenOptions::new()
            .write(true)
            .open(&rootfs)
            .unwrap()
            .set_len(100)
            .unwrap();
        assert!(cached_image(&rootfs, &marker, DIGEST, &lease(&rootfs)).is_none());
        // A marker that does not parse, or of another format.
        fs::write(&marker, b"{").unwrap();
        assert!(cached_image(&rootfs, &marker, DIGEST, &lease(&rootfs)).is_none());
        fs::write(&marker, br#"{"format":9}"#).unwrap();
        assert!(cached_image(&rootfs, &marker, DIGEST, &lease(&rootfs)).is_none());
        // And a tag is refused before anything runs.
        let tagged = guest_image(root.path(), "example.test/i:latest", &Store::Shared);
        assert!(matches!(tagged, Err(Error::Preparation(_))));
    }

    #[test]
    fn a_canceled_image_build_waits_for_nothing() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(OTHER);
        let canceled = AtomicBool::new(true);
        // Another attempt holds the image's build lock; this one gives up when its cancel is set.
        let key = image_key(&Store::Shared, &image);
        let lock = build_lock(&key);
        let held = lock.lock().unwrap();
        let started = Instant::now();
        let result = guest_image_canceled(root.path(), &image, &Store::Shared, &canceled);
        assert!(matches!(result, Err(Error::Preparation(ref why)) if why.contains("canceled")));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
        drop(lock);
        release_build_lock(&key);
        assert!(
            build_locks().lock().unwrap().iter().all(|(k, _)| *k != key),
            "an unused lock is forgotten"
        );
    }

    #[test]
    fn cached_images_are_listed_and_removed_by_key() {
        let root = tempfile::tempdir().unwrap();
        assert!(guest_images(root.path()).is_empty());
        let (a, b) = (image_ref(DIGEST), image_ref(OTHER));
        plant_image(root.path(), &a, DIGEST, 1000);
        let (rootfs_b, marker_b) = plant_image(root.path(), &b, OTHER, 3000);
        age(&marker_b, Duration::from_secs(7200));
        // Half an image (no marker) is not listed.
        fs::write(
            images_dir(root.path()).join(format!("{}.ext4", "c".repeat(32))),
            b"x",
        )
        .unwrap();
        let mut listed = guest_images(root.path());
        listed.sort_by_key(|g| g.bytes);
        assert_eq!(listed.len(), 2);
        assert_eq!((listed[0].digest.as_str(), listed[0].bytes), (DIGEST, 1000));
        assert_eq!((listed[1].digest.as_str(), listed[1].bytes), (OTHER, 3000));
        assert!(listed[1].used.elapsed().unwrap() >= Duration::from_secs(7000));
        assert!(!remove_guest_image(root.path(), "../escape"));
        assert!(!remove_guest_image(root.path(), "short"));
        assert!(remove_guest_image(root.path(), &listed[1].key));
        assert!(!rootfs_b.exists() && !marker_b.exists());
        assert_eq!(guest_images(root.path()).len(), 1);
        assert!(
            !remove_guest_image(root.path(), &listed[1].key),
            "already gone"
        );
    }

    /// A builder that makes a root file system of `bytes` without Podman and counts its calls.
    fn fake_build(
        calls: &std::sync::atomic::AtomicUsize,
        bytes: u64,
        delay: Duration,
        image: &str,
        digest: &str,
        rootfs: &Path,
        meta_path: &Path,
    ) -> Result<ImageMeta> {
        let n = calls.fetch_add(1, Ordering::SeqCst);
        thread::sleep(delay);
        let tmp = rootfs.with_extension(format!("ext4.test.{n}"));
        fs::File::create(&tmp)?.set_len(bytes)?;
        let _ = image;
        publish_image(
            &tmp,
            rootfs,
            meta_path,
            digest,
            &"cd".repeat(32),
            &[("PATH".into(), "/bin".into())],
            "",
        )
    }

    fn ensure(root: &Path, image: &str, build: Builder) -> Result<GuestImage> {
        ensure_image(root, image, &Store::Shared, &AtomicBool::new(false), build)
    }

    #[test]
    fn a_damaged_or_partial_image_is_rebuilt_and_never_served() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let build =
            |image: &str, digest: &str, _: &Store, rootfs: &Path, meta: &Path, _: &AtomicBool| {
                fake_build(&calls, 8192, Duration::ZERO, image, digest, rootfs, meta)
            };
        type Damage = fn(&Path, &Path);
        let damages: [(&str, Damage); 4] = [
            ("truncated root file system", |rootfs, _| {
                fs::OpenOptions::new()
                    .write(true)
                    .open(rootfs)
                    .unwrap()
                    .set_len(100)
                    .unwrap();
            }),
            ("marker that does not parse", |_, marker| {
                fs::write(marker, b"{\"format\":1,").unwrap();
            }),
            ("marker without a root file system", |rootfs, _| {
                fs::remove_file(rootfs).unwrap();
            }),
            ("root file system without a marker", |_, marker| {
                fs::remove_file(marker).unwrap();
            }),
        ];
        for (what, damage) in damages {
            let root = tempfile::tempdir().unwrap();
            let image = image_ref(DIGEST);
            let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 4096);
            damage(&rootfs, &marker);
            let before = calls.load(Ordering::SeqCst);
            let rebuilt = ensure(root.path(), &image, &build).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), before + 1, "{what}");
            assert!(rebuilt.record.built, "{what}");
            assert_eq!(rebuilt.record.rootfs_bytes, 8192, "{what}");
            assert_eq!(fs::metadata(&rootfs).unwrap().len(), 8192, "{what}");
            drop(rebuilt);
            // The rebuilt image is a complete one: the next attempt is served from the cache.
            let again = ensure(root.path(), &image, &build).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), before + 1, "{what}");
            assert!(!again.record.built, "{what}");
        }
    }

    #[test]
    fn a_failed_rebuild_leaves_no_marker_to_count() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 4096);
        fs::write(&marker, b"garbage").unwrap();
        let refused = ensure(
            root.path(),
            &image,
            &|_: &str, _: &str, _: &Store, _: &Path, _: &Path, _: &AtomicBool| {
                Err(Error::Preparation("guest image build: no space".into()))
            },
        );
        assert!(matches!(refused, Err(Error::Preparation(_))));
        assert!(!marker.exists(), "a damaged marker is not left to count");
        assert!(guest_images(root.path()).is_empty());
        // The root file system without a marker is not an image; the orphan sweep takes it once it is old.
        assert!(rootfs.exists());
    }

    #[test]
    fn concurrent_attempts_on_a_new_image_build_it_once() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(OTHER);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let build =
            |image: &str, digest: &str, _: &Store, rootfs: &Path, meta: &Path, _: &AtomicBool| {
                fake_build(
                    &calls,
                    4096,
                    Duration::from_millis(150),
                    image,
                    digest,
                    rootfs,
                    meta,
                )
            };
        let waiting = std::sync::Barrier::new(8);
        let results: Vec<GuestImage> = thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        waiting.wait();
                        ensure(root.path(), &image, &build).unwrap()
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a stampede builds once");
        assert_eq!(results.iter().filter(|r| r.record.built).count(), 1);
        assert!(results.iter().all(|r| r.rootfs == results[0].rootfs));
        assert!(
            results
                .iter()
                .all(|r| r.record.digest == OTHER && r.record.rootfs_bytes == 4096)
        );
        let key = image_key(&Store::Shared, &image);
        assert!(
            build_locks().lock().unwrap().iter().all(|(k, _)| *k != key),
            "the build lock is forgotten once nobody waits"
        );
        // Every attempt holds the image, so GC leaves it.
        assert!(guest_images(root.path())[0].in_use);
        assert!(!remove_guest_image(root.path(), &key));
        drop(results);
        assert!(!guest_images(root.path())[0].in_use);
    }

    #[test]
    fn an_image_a_live_attempt_holds_is_never_removed() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 4096);
        let key = image_key(&Store::Shared, &image);
        let held = guest_image(root.path(), &image, &Store::Shared).unwrap();
        // The attempt has been running for a day: the stamp is far past any keep window.
        age(&marker, Duration::from_secs(86_400));
        assert!(guest_images(root.path())[0].in_use);
        assert!(!remove_guest_image(root.path(), &key));
        assert!(rootfs.exists() && marker.exists());
        // A second attempt on the same image shares the claim: one releasing leaves it held.
        let second = guest_image(root.path(), &image, &Store::Shared).unwrap();
        drop(held);
        assert!(!remove_guest_image(root.path(), &key));
        drop(second);
        assert!(!guest_images(root.path())[0].in_use);
        assert!(remove_guest_image(root.path(), &key));
        assert!(!rootfs.exists() && !marker.exists());
        // After a removal the next attempt rebuilds, and GC cannot take the image while it is built.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let root_path = root.path().to_path_buf();
        let rebuilt = ensure(
            root.path(),
            &image,
            &|image: &str, digest: &str, _: &Store, rootfs: &Path, meta: &Path, _: &AtomicBool| {
                assert!(
                    !remove_guest_image(&root_path, &key),
                    "GC cannot take an image out from under the attempt that builds it"
                );
                fake_build(&calls, 2048, Duration::ZERO, image, digest, rootfs, meta)
            },
        )
        .unwrap();
        assert!(rebuilt.record.built);
    }

    #[test]
    fn budget_eviction_takes_the_least_recently_used_and_spares_held_images() {
        let root = tempfile::tempdir().unwrap();
        let hour = Duration::from_secs(3_600);
        let digests: Vec<String> = (1..=4).map(|n| format!("sha256:{n:064x}")).collect();
        let shapes = [
            (1000u64, hour * 3),
            (2000, hour * 9),
            (4000, hour * 30),
            (8000, hour),
        ];
        let mut keys = Vec::new();
        for (digest, (bytes, idle)) in digests.iter().zip(shapes) {
            let image = image_ref(digest);
            let (_, marker) = plant_image(root.path(), &image, digest, bytes);
            age(&marker, idle);
            keys.push(image_key(&Store::Shared, &image));
        }
        // The least recently used image (idle 30 h) belongs to a running attempt.
        let held = guest_image(root.path(), &image_ref(&digests[2]), &Store::Shared).unwrap();
        age(
            &images_dir(root.path()).join(format!("{}.json", keys[2])),
            hour * 30,
        );
        let images = crate::images::Images::new(PathBuf::new());
        let guests = guest_images(root.path());
        let total: u64 = guests.iter().map(|g| g.bytes).sum();
        assert_eq!(total, 15_000);
        // A 12 000 byte budget with nothing else in the store: 3 000 bytes must go.
        let over = crate::images::guest_overage(total, 0, 12_000);
        assert_eq!(over, 3_000);
        let victims = images.reclaimable_guests(&guests, over);
        // The held image is skipped; of the rest the 9 h one (2 000 bytes) goes first, then the 3 h one
        // (1 000 bytes), which is enough. The 1 h image is untouched.
        assert_eq!(victims, [keys[1].clone(), keys[0].clone()]);
        for key in &victims {
            assert!(remove_guest_image(root.path(), key));
        }
        let left = guest_images(root.path());
        assert_eq!(left.iter().map(|g| g.bytes).sum::<u64>(), 12_000);
        assert!(left.iter().any(|g| g.key == keys[2] && g.in_use));
        drop(held);
    }

    #[test]
    fn a_glob_is_fetched_as_the_directory_it_starts_from() {
        // The agent returns literal paths: a pattern must name where to look, the host applies the glob.
        assert_eq!(fetch_roots(&["out/**"]), ["out"]);
        assert_eq!(fetch_roots(&["target/release/*.so"]), ["target/release"]);
        assert_eq!(fetch_roots(&["out/app", "missing"]), ["out/app", "missing"]);
        assert_eq!(fetch_roots(&["./reports/{a,b}.xml"]), ["reports"]);
        // A leading glob needs the whole workspace, which swallows the other roots.
        assert_eq!(fetch_roots(&["out/**", "**/*.xml", "x"]), ["."]);
        assert_eq!(fetch_roots(&["*"]), ["."]);
        // A path under another fetched path travels once; a longer name that merely shares a prefix stays.
        assert_eq!(
            fetch_roots(&["out/**", "out/deep/*.txt", "output/**"]),
            ["out", "output"]
        );
        assert!(fetch_roots(&[]).is_empty());
    }

    #[test]
    fn only_old_files_no_complete_image_owns_are_orphans() {
        let key = "a".repeat(32);
        let other = "b".repeat(32);
        let old = ORPHAN_AGE + Duration::from_secs(1);
        let young = Duration::from_secs(5);
        let files = vec![
            (format!("{key}.ext4"), old),
            (format!("{key}.json"), old),
            (format!("{key}.ext4.99.7"), old),
            (format!("{key}.json.99.7"), old),
            (format!("{key}.env"), old),
            (format!("{other}.ext4"), old),
            (format!("{other}.ext4.99.7"), young),
            ("notes".to_owned(), old),
        ];
        let mut found = orphans(&files);
        found.sort_unstable();
        let mut want = [
            format!("{key}.ext4.99.7"),
            format!("{key}.json.99.7"),
            format!("{key}.env"),
            format!("{other}.ext4"),
            "notes".to_owned(),
        ];
        want.sort_unstable();
        assert_eq!(found, want.iter().map(String::as_str).collect::<Vec<_>>());
        // A pair that is still young is kept whole, and so is a half that a build is finishing.
        assert!(orphans(&[(format!("{key}.ext4"), young)]).is_empty());
    }

    #[test]
    fn sweeping_removes_the_orphans_and_keeps_complete_images() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        let (rootfs, marker) = plant_image(root.path(), &image, DIGEST, 2048);
        age(&rootfs, ORPHAN_AGE * 2);
        age(&marker, ORPHAN_AGE * 2);
        let dir = images_dir(root.path());
        let key = image_key(&Store::Shared, &image);
        let failed = dir.join(format!("{key}.ext4.1.2"));
        let leftover = dir.join(format!("{key}.env"));
        let building = dir.join(format!("{}.ext4.3.4", "d".repeat(32)));
        for file in [&failed, &leftover, &building] {
            fs::write(file, b"x").unwrap();
        }
        age(&failed, ORPHAN_AGE * 2);
        age(&leftover, ORPHAN_AGE * 2);
        assert_eq!(sweep_guest_orphans(root.path()), 2);
        assert!(rootfs.exists() && marker.exists() && building.exists());
        assert!(!failed.exists() && !leftover.exists());
        assert_eq!(sweep_guest_orphans(root.path()), 0);
        assert_eq!(sweep_guest_orphans(&root.path().join("nowhere")), 0);
    }

    // ------------------------------------------------------------ snapshots beside the image GC and reconciliation

    /// A complete snapshot of the image `key`, as a finished build publishes it.
    fn plant_snapshot(root: &Path, key: &str, suffix: &str, bytes: usize) -> String {
        let name = format!("{key}-{suffix}");
        let staged = snapshot::staging(root, &name, "t").unwrap();
        for file in ["state", "mem", "scratch.ext4"] {
            fs::write(staged.join(file), vec![9u8; bytes]).unwrap();
        }
        snapshot::publish(root, &name, &staged).unwrap();
        name
    }

    #[test]
    fn an_images_snapshots_count_against_its_budget_and_go_with_it() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        plant_image(root.path(), &image, DIGEST, 1000);
        let key = image_key(&Store::Shared, &image);
        assert_eq!(guest_images(root.path())[0].bytes, 1000);
        let a = plant_snapshot(root.path(), &key, "aaaaaaaaaaaaaaaa", 8192);
        plant_snapshot(root.path(), &key, "bbbbbbbbbbbbbbbb", 8192);
        // Another image's snapshot is neither counted nor removed.
        let other_key = "f".repeat(32);
        let other = plant_snapshot(root.path(), &other_key, "cccccccccccccccc", 8192);
        let counted = guest_images(root.path())[0].bytes;
        assert!(counted >= 1000 + 2 * 3 * 8192, "{counted}");
        assert!(snapshot::open(root.path(), &a).is_some());
        assert!(remove_guest_image(root.path(), &key));
        assert!(
            snapshot::open(root.path(), &a).is_none(),
            "a snapshot is useless without its root file system"
        );
        assert!(snapshot::open(root.path(), &other).is_some());
    }

    #[test]
    fn the_orphan_sweep_takes_old_snapshots_of_missing_images_and_abandoned_builds() {
        let root = tempfile::tempdir().unwrap();
        let image = image_ref(DIGEST);
        plant_image(root.path(), &image, DIGEST, 1000);
        let key = image_key(&Store::Shared, &image);
        let kept = plant_snapshot(root.path(), &key, "aaaaaaaaaaaaaaaa", 16);
        let lost_key = "e".repeat(32);
        let lost = plant_snapshot(root.path(), &lost_key, "bbbbbbbbbbbbbbbb", 16);
        let abandoned = snapshot::staging(root.path(), &kept, "dead").unwrap();
        for path in [
            snapshot::dir(root.path()).join(&lost),
            snapshot::dir(root.path()).join(&kept),
            abandoned.clone(),
        ] {
            fs::File::open(&path)
                .unwrap()
                .set_modified(SystemTime::now() - ORPHAN_AGE - Duration::from_secs(60))
                .unwrap();
        }
        assert_eq!(sweep_guest_orphans(root.path()), 2);
        assert!(snapshot::open(root.path(), &kept).is_some());
        assert!(snapshot::open(root.path(), &lost).is_none());
        assert!(!abandoned.exists());
        // A young orphan is a build that may still be running.
        let young = plant_snapshot(root.path(), &lost_key, "dddddddddddddddd", 16);
        assert_eq!(sweep_guest_orphans(root.path()), 0);
        assert!(snapshot::open(root.path(), &young).is_some());
    }

    #[test]
    fn removing_a_vm_never_follows_its_image_link_into_the_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let image = image_ref(DIGEST);
        let (rootfs, _) = {
            fs::create_dir_all(&root).unwrap();
            plant_image(&root, &image, DIGEST, 1000)
        };
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        // The files a start leaves: a link to the cached image (what older workers made), sockets, the saved state.
        std::os::unix::fs::symlink(&rootfs, dir.join("image.ext4")).unwrap();
        for file in ["state", "mem", "netns.pid", "uplink"] {
            fs::write(dir.join(file), b"x").unwrap();
        }
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        remove_named_with(systemctl.program.as_os_str(), &root, attempt).unwrap();
        assert!(!dir.exists());
        assert!(rootfs.is_file(), "the cached root file system survives");
        // A failed warm start empties the directory the same way, keeping the directory itself.
        let again = vm_files(&root, attempt);
        std::os::unix::fs::symlink(&rootfs, again.join("image.ext4")).unwrap();
        clear_dir(&again).unwrap();
        assert!(again.is_dir() && fs::read_dir(&again).unwrap().next().is_none());
        assert!(rootfs.is_file());
    }

    #[test]
    fn a_template_vm_a_crashed_worker_left_is_reconciled_like_any_vm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let builder = AttemptId::new();
        let dir = vm_files(&root, builder);
        for file in ["state", "mem", "api.sock"] {
            fs::write(dir.join(file), b"x").unwrap();
        }
        let systemctl = FakeSystemctl::new(
            temp.path(),
            "inactive",
            &format!(
                "{}.scope loaded active running x\n",
                unit_name(&root, builder)
            ),
            0,
        );
        assert_eq!(
            reconcile_with(systemctl.program.as_os_str(), &root).unwrap(),
            1
        );
        assert!(!dir.exists() && owned(&root).is_empty());
    }

    // ------------------------------------------------------------ the VM configuration

    #[test]
    fn the_guest_keeps_exactly_the_paths_the_worker_delivers_secrets_to_in_memory() {
        assert_eq!(
            agent::SECRET_MOUNTS,
            [
                crate::attempt::SECRET_FILES_MOUNT,
                crate::attempt::SECRET_ENV_MOUNT
            ]
        );
    }

    #[test]
    fn the_cpu_configuration_clears_the_bits_that_advertise_virtualization() {
        let config: serde_json::Value = serde_json::from_str(CPU_CONFIG).unwrap();
        let cleared = |leaf: &str, register: &str| -> u32 {
            let modifiers = config["cpuid_modifiers"].as_array().unwrap();
            let entry = modifiers.iter().find(|m| m["leaf"] == leaf).unwrap();
            assert_eq!(entry["subleaf"], "0x0");
            let modifier = entry["modifiers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["register"] == register)
                .unwrap();
            let bitmap = modifier["bitmap"]
                .as_str()
                .unwrap()
                .strip_prefix("0b")
                .unwrap();
            assert_eq!(bitmap.len(), 32);
            bitmap
                .chars()
                .rev()
                .enumerate()
                .fold(0, |acc, (bit, c)| match c {
                    '0' => acc | 1 << bit,
                    'x' => acc,
                    other => panic!("bit {bit} is {other}, not a 0 or an x"),
                })
        };
        assert_eq!(cleared("0x1", "ecx"), 1 << 5, "VMX");
        assert_eq!(cleared("0x80000001", "ecx"), 1 << 2, "SVM");
        assert_eq!(config["cpuid_modifiers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_guest_is_given_no_way_to_nest_virtualization() {
        let mut shape = snapshot::Shape {
            vcpus: 2,
            mib: 512,
            scratch_bytes: 1 << 30,
            net: false,
        };
        let config = vm_config(&shape);
        // A new top-level section (a device could carry /dev/kvm) must be reviewed against the isolation
        // contract before this test is changed.
        let mut sections: Vec<&str> = config
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        sections.sort_unstable();
        assert_eq!(
            sections,
            [
                "boot-source",
                "cpu-config",
                "drives",
                "machine-config",
                "vsock"
            ]
        );
        assert_eq!(config["cpu-config"], "/cpu.json");
        // Every path is inside the VMM's chroot: nothing names the worker's data directory, so a snapshot
        // that saves them restores wherever that directory has gone.
        assert_eq!(config["boot-source"]["kernel_image_path"], "/kernel");
        assert_eq!(config["boot-source"]["initrd_path"], "/initrd");
        assert_eq!(config["vsock"]["uds_path"], "/vsock.sock");
        let machine = config["machine-config"].as_object().unwrap();
        assert!(!machine.contains_key("cpu_template"));
        assert!(!config.to_string().to_ascii_lowercase().contains("kvm"));
        let drives = config["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 2);
        assert_eq!(
            drives[0]["is_read_only"], true,
            "the job image is read-only"
        );
        assert_eq!(drives[0]["path_on_host"], "/image.ext4");
        assert_eq!(drives[1]["path_on_host"], "/scratch.ext4");
        assert_eq!(config["machine-config"]["vcpu_count"], 2);
        assert_eq!(config["machine-config"]["mem_size_mib"], 512);
        assert!(
            !config["boot-source"]["boot_args"]
                .as_str()
                .unwrap()
                .contains("sentinel.ip")
        );

        // A guest granted egress gets exactly one more section: its one network interface, backed by the tap.
        shape.net = true;
        let granted = vm_config(&shape);
        let mut sections: Vec<&str> = granted
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        sections.sort_unstable();
        assert_eq!(
            sections,
            [
                "boot-source",
                "cpu-config",
                "drives",
                "machine-config",
                "network-interfaces",
                "vsock"
            ]
        );
        assert_eq!(granted["network-interfaces"].as_array().unwrap().len(), 1);
        assert_eq!(granted["network-interfaces"][0]["host_dev_name"], net::TAP);
        assert!(
            granted["boot-source"]["boot_args"]
                .as_str()
                .unwrap()
                .contains("sentinel.ip=10.211.0.2/30")
        );
        assert!(!granted.to_string().to_ascii_lowercase().contains("kvm"));
    }

    // ------------------------------------------------------------ reconciliation, without a KVM host

    /// A stand-in for `systemctl`: logs every call and answers `is-active` and `list-units` as told.
    struct FakeSystemctl {
        program: PathBuf,
        log: PathBuf,
    }

    impl FakeSystemctl {
        fn new(dir: &Path, is_active: &str, listing: &str, list_exit: i32) -> Self {
            let log = dir.join("systemctl.log");
            let program = dir.join("systemctl");
            let script = format!(
                "#!/bin/sh\necho \"$*\" >> '{log}'\ncase \"$2\" in\n  is-active) echo '{is_active}';;\n  list-units) cat '{list}'; test {list_exit} -eq 0 || {{ echo 'bus unreachable' >&2; exit {list_exit}; }};;\nesac\nexit 0\n",
                log = log.display(),
                list = dir.join("listing.txt").display(),
            );
            fs::write(dir.join("listing.txt"), listing).unwrap();
            fs::write(&program, script).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
            FakeSystemctl { program, log }
        }

        fn calls(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    fn vm_files(root: &Path, attempt: AttemptId) -> PathBuf {
        let dir = vm_dir(root, attempt);
        fs::create_dir_all(&dir).unwrap();
        for file in ["scratch.ext4", "console.log", "vm.json"] {
            fs::write(dir.join(file), b"x").unwrap();
        }
        dir
    }

    #[test]
    fn scopes_are_named_per_data_root() {
        let attempt = AttemptId::new();
        let (a, b) = (Path::new("/data/worker-a"), Path::new("/data/worker-b"));
        assert_ne!(unit_prefix(a), unit_prefix(b));
        assert!(unit_name(a, attempt).starts_with(&unit_prefix(a)));
        assert_eq!(
            scope_name(a, attempt),
            format!("{}.scope", unit_name(a, attempt))
        );
        let listing = format!(
            "{mine}.scope loaded active running Sentinel VM\n{theirs}.scope loaded active running Sentinel VM\nunrelated.service loaded active running x\n{prefix}not-an-attempt.scope loaded failed failed x\n\n",
            mine = unit_name(a, attempt),
            theirs = unit_name(b, AttemptId::new()),
            prefix = unit_prefix(a),
        );
        assert_eq!(parse_units(&listing, &unit_prefix(a)), vec![attempt]);
    }

    #[test]
    fn startup_reconciliation_removes_every_leftover_vm_and_its_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let (with_dir, scope_only) = (AttemptId::new(), AttemptId::new());
        let dir = vm_files(&root, with_dir);
        let stranger = AttemptId::new();
        let listing = format!(
            "{}.scope loaded active running x\n{}.scope loaded failed failed x\n{}.scope loaded active running x\n",
            unit_name(&root, scope_only),
            unit_name(&root, with_dir),
            unit_name(Path::new("/another/worker"), stranger),
        );
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", &listing, 0);
        assert_eq!(
            reconcile_with(systemctl.program.as_os_str(), &root).unwrap(),
            2
        );
        assert!(
            !dir.exists(),
            "the scratch disk and console log go with the VM's directory"
        );
        assert!(owned(&root).is_empty());
        let calls = systemctl.calls();
        for attempt in [with_dir, scope_only] {
            let scope = scope_name(&root, attempt);
            assert!(
                calls.contains(&format!("kill --signal=SIGKILL {scope}")),
                "{calls}"
            );
            assert!(calls.contains(&format!("stop {scope}")), "{calls}");
        }
        assert!(
            !calls.contains(&stranger.to_string()),
            "another worker's VM is not ours"
        );
        // Nothing left: the second pass finds nothing and removes nothing.
        let later = temp.path().join("later");
        fs::create_dir_all(&later).unwrap();
        let systemctl = FakeSystemctl::new(&later, "inactive", "", 0);
        assert_eq!(
            reconcile_with(systemctl.program.as_os_str(), &root).unwrap(),
            0
        );
    }

    #[test]
    fn a_host_that_never_ran_a_microvm_is_not_asked_about_scopes() {
        let temp = tempfile::tempdir().unwrap();
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 1);
        let root = temp.path().join("data");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(
            reconcile_with(systemctl.program.as_os_str(), &root).unwrap(),
            0
        );
        assert_eq!(systemctl.calls(), "");
    }

    #[test]
    fn a_scope_listing_that_fails_is_reported_not_taken_for_none() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir_all(root.join(DIR)).unwrap();
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 1);
        let error = reconcile_with(systemctl.program.as_os_str(), &root).unwrap_err();
        assert!(
            error.to_string().contains("listing microVM scopes")
                && error.to_string().contains("bus unreachable"),
            "{error}"
        );
    }

    #[test]
    fn a_scope_that_will_not_stop_keeps_its_directory_and_fails_the_removal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        let running = FakeSystemctl::new(temp.path(), "active", "", 0);
        assert!(remove_named_with(running.program.as_os_str(), &root, attempt).is_err());
        assert!(dir.exists(), "the VM is still found by name");
        assert!(reconcile_with(running.program.as_os_str(), &root).is_err());
        let stopped = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        remove_named_with(stopped.program.as_os_str(), &root, attempt).unwrap();
        assert!(!dir.exists());
        // Removing what is not there is not an error.
        remove_named_with(stopped.program.as_os_str(), &root, attempt).unwrap();
        // And a host with no systemctl at all has no scopes to be running.
        let dir = vm_files(&root, attempt);
        remove_named_with(OsStr::new("/nonexistent/systemctl"), &root, attempt).unwrap();
        assert!(!dir.exists());
    }

    // ------------------------------------------------------------ cancel and lease loss, without a KVM host

    /// A guest agent that records the signals it is sent, with the time each arrived; `answer` says whether
    /// it confirms them. Serves one connection, then returns once it has seen `expect` signals.
    /// A guest agent that records the signals sent to it. `answer` is whether it confirms them; `idle` whether
    /// the steps have ended by the time it is asked to wait for them.
    fn fake_agent(
        socket: &Path,
        answer: bool,
        idle: bool,
    ) -> thread::JoinHandle<Vec<(i32, Instant)>> {
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert!(line.starts_with(b"CONNECT "));
            stream.write_all(b"OK 1\n").unwrap();
            let hello: Request = agent::read(&mut stream).unwrap().unwrap();
            assert!(matches!(hello, Request::Hello { .. }));
            agent::write(
                &mut stream,
                &Reply::Ready {
                    version: agent::VERSION,
                    kernel: "test".into(),
                },
            )
            .unwrap();
            let mut seen = Vec::new();
            // Until the host hangs up.
            while let Ok(Some(request)) = agent::read::<Request>(&mut stream) {
                match request {
                    Request::SignalAll { signal } => {
                        seen.push((signal, Instant::now()));
                        if answer {
                            agent::write(&mut stream, &Reply::Done).unwrap();
                        }
                    }
                    Request::WaitIdle { timeout_ms } => {
                        if !idle {
                            thread::sleep(Duration::from_millis(u64::from(timeout_ms)));
                        }
                        agent::write(&mut stream, &Reply::Idle(idle)).unwrap();
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            seen
        })
    }

    fn terminate(
        systemctl: &FakeSystemctl,
        root: &Path,
        attempt: AttemptId,
        grace: Duration,
    ) -> Result<Terminated> {
        terminate_named_with(
            systemctl.program.as_os_str(),
            root,
            attempt,
            grace,
            Duration::from_millis(200),
            Duration::from_millis(300),
        )
    }

    #[test]
    fn a_cancel_asks_politely_then_forces_through_the_agent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        let agent = fake_agent(&dir.join("vsock.sock"), true, false);
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        let grace = Duration::from_millis(150);
        let outcome = terminate(&systemctl, &root, attempt, grace).unwrap();
        assert_eq!(outcome, Terminated::Forced);
        let seen = agent.join().unwrap();
        assert_eq!(
            seen.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            [libc::SIGTERM, libc::SIGKILL]
        );
        assert!(
            seen[1].1.duration_since(seen[0].1) >= grace,
            "the step gets its grace"
        );
        assert_eq!(
            systemctl.calls(),
            "",
            "a guest that answers is not killed from outside"
        );
        assert!(
            exists(&root, attempt),
            "the attempt's own teardown removes the VM"
        );
    }

    #[test]
    fn a_step_that_stops_on_the_polite_signal_is_a_graceful_cancel() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        let agent = fake_agent(&dir.join("vsock.sock"), true, true);
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        let started = Instant::now();
        let outcome = terminate(&systemctl, &root, attempt, Duration::from_secs(30)).unwrap();
        assert_eq!(outcome, Terminated::Graceful);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the grace period ends with the steps"
        );
        let seen = agent.join().unwrap();
        assert_eq!(
            seen.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            [libc::SIGTERM],
            "nothing is killed that stopped by itself"
        );
        assert_eq!(systemctl.calls(), "");
    }

    #[test]
    fn a_guest_that_does_not_answer_a_cancel_loses_its_vm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        let agent = fake_agent(&dir.join("vsock.sock"), false, false);
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        let started = Instant::now();
        let outcome = terminate(&systemctl, &root, attempt, Duration::ZERO).unwrap();
        assert_eq!(outcome, Terminated::Forced);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(agent.join().unwrap().len(), 1);
        assert!(!exists(&root, attempt), "the VM and its files are gone");
        assert!(
            systemctl.calls().contains(&format!(
                "kill --signal=SIGKILL {}",
                scope_name(&root, attempt)
            )),
            "{}",
            systemctl.calls()
        );
    }

    #[test]
    fn a_cancel_that_cannot_reach_the_agent_kills_the_vm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let attempt = AttemptId::new();
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        assert_eq!(
            terminate(&systemctl, &root, attempt, Duration::ZERO).unwrap(),
            Terminated::Gone,
            "no VM by that name"
        );
        // A socket file nothing listens on: the guest is gone or never came up.
        let dir = vm_files(&root, attempt);
        drop(std::os::unix::net::UnixListener::bind(dir.join("vsock.sock")).unwrap());
        assert_eq!(
            terminate(&systemctl, &root, attempt, Duration::ZERO).unwrap(),
            Terminated::Forced
        );
        assert!(!exists(&root, attempt));
    }

    #[test]
    fn a_cancel_to_a_frozen_vmm_waits_no_longer_than_its_connect_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let attempt = AttemptId::new();
        let dir = vm_files(&root, attempt);
        // A VMM that is stopped still has its socket accepted by the kernel; it never answers the handshake.
        let listener = std::os::unix::net::UnixListener::bind(dir.join("vsock.sock")).unwrap();
        let systemctl = FakeSystemctl::new(temp.path(), "inactive", "", 0);
        let started = Instant::now();
        assert_eq!(
            terminate(&systemctl, &root, attempt, Duration::ZERO).unwrap(),
            Terminated::Forced
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the handshake read ignored the deadline: {:?}",
            started.elapsed()
        );
        assert!(!exists(&root, attempt));
        drop(listener);
    }

    #[test]
    fn a_start_that_was_canceled_makes_no_vm() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("d");
        let setup = Setup {
            firecracker: "/nonexistent/firecracker".into(),
            kernel: "/nonexistent/vmlinux".into(),
            agent: "/nonexistent/agent".into(),
            snapshots: true,
            guard: net::Guard::default(),
        };
        let limits = Limits {
            cpu_millis: 1000,
            memory_bytes: 256 << 20,
            pids: 100,
            disk_bytes: 1 << 30,
            lifetime_secs: 60,
        };
        let start = |image: &str, cancel: &AtomicBool| {
            let attempt = AttemptId::new();
            let result = Vm::start_canceled(
                &root,
                &setup,
                WorkerId::new(),
                attempt,
                image,
                limits,
                temp.path(),
                &[],
                &Store::Shared,
                Network::None,
                cancel,
            );
            (attempt, result)
        };
        let (attempt, result) = start(&image_ref(DIGEST), &AtomicBool::new(true));
        assert!(
            matches!(result, Err(Error::Preparation(ref why)) if why == "microVM start canceled")
        );
        assert!(!exists(&root, attempt));
        // A start that fails before the VM boots leaves no directory behind either.
        let (attempt, result) = start("example.test/i:latest", &AtomicBool::new(false));
        assert!(
            matches!(result, Err(Error::Preparation(ref why)) if why == "image is not pinned by digest")
        );
        assert!(!exists(&root, attempt));
        assert!(owned(&root).is_empty());
    }
}
