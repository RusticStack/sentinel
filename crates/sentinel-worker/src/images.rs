//! Every pull runs `podman pull` even for a resident digest, to recheck the attempt's registry authority.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use crate::{Error, Result, attempt::Cancel, microvm::GuestEntry, podman};

pub const MAX_HELD: usize = 1024;

/// Recently pulled digests are never reclaimed: an attempt may be about to create its container.
pub const IMAGE_KEEP: Duration = Duration::from_secs(600);
pub const MAX_IMAGE_REMOVALS: usize = 16;

const FOLLOW_POLL: Duration = Duration::from_millis(50);

type Download =
    Arc<dyn Fn(&str, &Path, &podman::Store, Duration, &AtomicBool) -> Result<bool> + Send + Sync>;

#[derive(Clone, Hash, PartialEq, Eq)]
struct PullKey {
    image: Box<str>,
    tenant: Option<[u8; 16]>,
    credential: [u8; 32],
    store: podman::Store,
}

impl PullKey {
    fn anonymous(image: &str) -> Self {
        Self {
            image: image.into(),
            tenant: None,
            credential: [0; 32],
            store: podman::Store::Shared,
        }
    }
}

pub fn prepare_anonymous_authfile(root: &Path) -> Result<PathBuf> {
    use std::io::Write;
    let root_metadata = std::fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(Error::Preparation("worker data directory".into()));
    }
    let dir = root.join("registry-auth");
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&dir)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::Preparation("registry auth directory".into()));
            }
        }
        Err(error) => return Err(error.into()),
    }
    restrict_dir(&dir)?;
    let path = dir.join("anonymous.json");
    const EMPTY: &[u8] = b"{\"auths\":{}}\n";
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            restrict_file(&path)?;
            file.write_all(EMPTY)?;
            file.sync_data()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || std::fs::read(&path)? != EMPTY
            {
                return Err(Error::Preparation("anonymous registry auth file".into()));
            }
            restrict_file(&path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Default)]
struct Pull {
    result: Mutex<Option<std::result::Result<bool, Shared>>>,
    done: Condvar,
    waiters: AtomicUsize,
}

#[derive(Clone, Debug)]
enum Shared {
    Preparation(String),
    Runtime(String),
    Timeout(&'static str),
    Workspace(String),
    Io(std::io::ErrorKind, String),
    Abandoned,
}

impl Shared {
    fn of(error: &Error) -> Shared {
        match error {
            Error::Preparation(what) => Shared::Preparation(what.clone()),
            Error::Runtime(what) => Shared::Runtime(what.clone()),
            Error::Timeout(what) => Shared::Timeout(what),
            Error::Workspace(what) => Shared::Workspace(what.clone()),
            Error::Io(e) => Shared::Io(e.kind(), e.to_string()),
        }
    }

    fn into_error(self) -> Error {
        match self {
            Shared::Preparation(what) => Error::Preparation(what),
            Shared::Runtime(what) => Error::Runtime(what),
            Shared::Timeout(what) => Error::Timeout(what),
            Shared::Workspace(what) => Error::Workspace(what),
            Shared::Io(kind, what) => Error::Io(std::io::Error::new(kind, what)),
            Shared::Abandoned => Error::Preparation("image pull abandoned".into()),
        }
    }
}

struct State {
    pulling: HashMap<PullKey, Arc<Pull>>,
    held: HashSet<Box<str>>,
    order: VecDeque<Box<str>>,
    version: u64,
    prefetching: HashSet<PullKey>,
    used: HashMap<Box<str>, Instant>,
}

struct Inner {
    state: Mutex<State>,
    download: Download,
    anonymous_authfile: PathBuf,
}

#[derive(Clone)]
pub struct Images {
    inner: Arc<Inner>,
}

impl Images {
    pub fn new(anonymous_authfile: PathBuf) -> Self {
        let anonymous = anonymous_authfile.clone();
        Self::with_authfile_and_download(
            anonymous_authfile,
            move |image, authfile, store, timeout, cancel| {
                let recheck = podman::registry_check_needed(authfile == anonymous, store);
                podman::pull_checked(image, authfile, store, timeout, cancel, recheck)
            },
        )
    }

    pub fn for_worker_data_dir(root: &Path) -> Result<Self> {
        Ok(Self::new(prepare_anonymous_authfile(root)?))
    }

    pub fn anonymous_authfile(&self) -> &Path {
        &self.inner.anonymous_authfile
    }

    #[doc(hidden)]
    pub fn with_download(
        download: impl Fn(&str, &Path, &podman::Store, Duration, &AtomicBool) -> Result<bool>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self::with_authfile_and_download(PathBuf::from("unused-anonymous-auth.json"), download)
    }

    fn with_authfile_and_download(
        anonymous_authfile: PathBuf,
        download: impl Fn(&str, &Path, &podman::Store, Duration, &AtomicBool) -> Result<bool>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Images {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    pulling: HashMap::new(),
                    held: HashSet::new(),
                    order: VecDeque::new(),
                    version: 0,
                    prefetching: HashSet::new(),
                    used: HashMap::new(),
                }),
                download: Arc::new(download),
                anonymous_authfile,
            }),
        }
    }

    pub fn pull(&self, image: &str, timeout: Duration, cancel: &Cancel) -> Result<bool> {
        validate_pinned_reference(image)?;
        let key = PullKey::anonymous(image);
        self.pull_keyed(key, image, &self.inner.anonymous_authfile, timeout, cancel)
    }

    /// The key includes tenant, credential and store, so no tenant or rotated credential inherits another's auth check.
    #[allow(clippy::too_many_arguments)]
    pub fn pull_for_tenant(
        &self,
        image: &str,
        tenant: [u8; 16],
        credential: [u8; 32],
        authfile: &Path,
        store: &podman::Store,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<bool> {
        validate_pinned_reference(image)?;
        self.pull_keyed(
            PullKey {
                image: image.into(),
                tenant: Some(tenant),
                credential,
                store: store.clone(),
            },
            image,
            authfile,
            timeout,
            cancel,
        )
    }

    fn pull_keyed(
        &self,
        key: PullKey,
        image: &str,
        authfile: &Path,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<bool> {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Preparation("canceled".into()));
        }
        let (slot, leader) = {
            let mut state = self.state();
            match state.pulling.get(&key) {
                Some(slot) => (Arc::clone(slot), false),
                None => {
                    let slot = Arc::new(Pull::default());
                    state.pulling.insert(key.clone(), Arc::clone(&slot));
                    (slot, true)
                }
            }
        };
        if leader {
            return self.lead(&key, image, authfile, &slot, timeout, cancel);
        }
        slot.waiters.fetch_add(1, Ordering::Relaxed);
        let deadline = Instant::now() + timeout;
        let mut result = slot.result.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(outcome) = result.clone() {
                drop(result);
                if matches!(outcome, Err(Shared::Abandoned)) {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    return self.pull_keyed(key.clone(), image, authfile, remaining, cancel);
                }
                if outcome.is_ok() && key.store == podman::Store::Shared {
                    self.record(image);
                }
                return outcome.map_err(Shared::into_error);
            }
            if cancel.load(Ordering::Acquire) {
                return Err(Error::Preparation("canceled".into()));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let mut state = self.state();
                if state
                    .pulling
                    .get(&key)
                    .is_some_and(|s| Arc::ptr_eq(s, &slot))
                {
                    state.pulling.remove(&key);
                }
                return Err(Error::Timeout("image pull"));
            }
            let (guard, _) = slot
                .done
                .wait_timeout(result, remaining.min(FOLLOW_POLL))
                .unwrap_or_else(|p| p.into_inner());
            result = guard;
        }
    }

    fn lead(
        &self,
        key: &PullKey,
        image: &str,
        authfile: &Path,
        slot: &Pull,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<bool> {
        let outcome = (self.inner.download)(image, authfile, &key.store, timeout, cancel);
        if outcome.is_ok() && key.store == podman::Store::Shared {
            self.record(image);
        }
        // A pull killed by its leader's cancel says nothing about the image: followers pull for themselves.
        let shared = match &outcome {
            Err(_) if cancel.load(Ordering::Acquire) => Err(Shared::Abandoned),
            other => other.as_ref().copied().map_err(Shared::of),
        };
        *slot.result.lock().unwrap_or_else(|p| p.into_inner()) = Some(shared);
        slot.done.notify_all();
        let mut state = self.state();
        state.pulling.remove(key);
        state.prefetching.remove(key);
        outcome
    }

    pub fn prefetch(
        &self,
        image: &str,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Option<Result<bool>> {
        let slot = {
            let mut state = self.state();
            let digest = image.split_once('@')?.1;
            let key = PullKey::anonymous(image);
            if state.held.contains(digest) || state.pulling.contains_key(&key) {
                return None;
            }
            let slot = Arc::new(Pull::default());
            state.pulling.insert(key.clone(), Arc::clone(&slot));
            state.prefetching.insert(key);
            slot
        };
        let key = PullKey::anonymous(image);
        Some(self.lead(
            &key,
            image,
            &self.inner.anonymous_authfile,
            &slot,
            timeout,
            cancel,
        ))
    }

    pub fn attempt_pulls(&self) -> usize {
        let state = self.state();
        state
            .pulling
            .keys()
            .filter(|key| !state.prefetching.contains(*key))
            .count()
    }

    pub fn followers(&self, image: &str) -> usize {
        self.state()
            .pulling
            .iter()
            .filter(|(key, _)| key.image.as_ref() == image)
            .map(|(_, slot)| slot.waiters.load(Ordering::Relaxed))
            .sum()
    }

    pub fn holds(&self, digest: &str) -> bool {
        self.state().held.contains(digest)
    }

    pub fn held(&self) -> Vec<String> {
        let mut held: Vec<String> = self
            .state()
            .held
            .iter()
            .map(|digest| digest.to_string())
            .collect();
        held.sort_unstable();
        held
    }

    pub fn version(&self) -> u64 {
        self.state().version
    }

    pub fn held_keys(&self, max: usize) -> Vec<[u8; 8]> {
        let state = self.state();
        state
            .order
            .iter()
            .rev()
            .filter_map(|digest| {
                let hex = digest.strip_prefix("sha256:")?.as_bytes();
                let mut key = [0u8; 8];
                for (i, slot) in key.iter_mut().enumerate() {
                    let pair = std::str::from_utf8(hex.get(i * 2..i * 2 + 2)?).ok()?;
                    *slot = u8::from_str_radix(pair, 16).ok()?;
                }
                Some(key)
            })
            .take(max)
            .collect()
    }

    pub fn in_flight(&self) -> usize {
        self.state().pulling.len()
    }

    fn record(&self, image: &str) {
        let Some((_, digest)) = image.split_once('@') else {
            return;
        };
        let mut state = self.state();
        let now = Instant::now();
        if let Some(used) = state.used.get_mut(digest) {
            *used = now;
        }
        if state.held.contains(digest) {
            return;
        }
        if state.held.len() >= MAX_HELD
            && let Some(oldest) = state.order.pop_front()
        {
            state.held.remove(&oldest);
            state.used.remove(&oldest);
        }
        let digest: Box<str> = digest.into();
        state.order.push_back(digest.clone());
        state.used.insert(digest.clone(), now);
        state.held.insert(digest);
        state.version += 1;
    }

    pub fn reclaimable(&self, images: &[podman::StoredImage], budget: u64) -> Vec<String> {
        let total: u64 = images.iter().map(|i| i.bytes).sum();
        if total <= budget {
            return Vec::new();
        }
        let state = self.state();
        let now = Instant::now();
        let pulling: HashSet<&str> = state
            .pulling
            .keys()
            .filter_map(|k| k.image.split_once('@').map(|(_, d)| d))
            .collect();
        let mut candidates: Vec<(&podman::StoredImage, Option<Instant>)> = images
            .iter()
            .filter(|i| i.containers == 0 && !pulling.contains(i.digest.as_str()))
            .map(|i| (i, state.used.get(i.digest.as_str()).copied()))
            .filter(|(_, used)| used.is_none_or(|t| now.duration_since(t) >= IMAGE_KEEP))
            .collect();
        candidates.sort_by_key(|(_, used)| *used);
        let mut over = total - budget;
        let mut out = Vec::new();
        for (image, _) in candidates {
            if over == 0 || out.len() >= MAX_IMAGE_REMOVALS {
                break;
            }
            over = over.saturating_sub(image.bytes);
            out.push(image.id.clone());
        }
        out
    }

    /// Cached microVM root file systems to remove to bring the guest images back under their share of the
    /// image budget (`over` bytes, see [`guest_overage`]): least recently used first, never one used within
    /// `IMAGE_KEEP` (an attempt may be about to boot from it) and never one whose digest is being pulled.
    pub fn reclaimable_guests(&self, guests: &[GuestEntry], over: u64) -> Vec<String> {
        let state = self.state();
        let pulling: HashSet<&str> = state
            .pulling
            .keys()
            .filter_map(|k| k.image.split_once('@').map(|(_, d)| d))
            .collect();
        plan_guest_reclaim(guests, &pulling, over, SystemTime::now())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// How many bytes of cached guest images must go so that they and the Podman store together fit `budget`:
/// guest images that still fit alongside what Podman holds are left alone, and never more than all of them.
pub fn guest_overage(guest_total: u64, podman_total: u64, budget: u64) -> u64 {
    guest_total
        .saturating_add(podman_total)
        .saturating_sub(budget)
        .min(guest_total)
}

fn plan_guest_reclaim(
    guests: &[GuestEntry],
    pulling: &HashSet<&str>,
    over: u64,
    now: SystemTime,
) -> Vec<String> {
    if over == 0 {
        return Vec::new();
    }
    let mut candidates: Vec<&GuestEntry> = guests
        .iter()
        .filter(|g| !pulling.contains(g.digest.as_str()))
        .filter(|g| {
            now.duration_since(g.used)
                .is_ok_and(|age| age >= IMAGE_KEEP)
        })
        .collect();
    candidates.sort_by_key(|g| g.used);
    let mut over = over;
    let mut out = Vec::new();
    for guest in candidates {
        if over == 0 || out.len() >= MAX_IMAGE_REMOVALS {
            break;
        }
        over = over.saturating_sub(guest.bytes);
        out.push(guest.key.clone());
    }
    out
}

fn validate_pinned_reference(image: &str) -> Result<()> {
    if image.contains("@sha256:") {
        Ok(())
    } else {
        Err(Error::Preparation("image is not pinned by digest".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Barrier,
            atomic::{AtomicBool, AtomicUsize},
            mpsc,
        },
        thread,
    };

    use super::*;

    const IMAGE: &str = "example.test/image@sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn anonymous_auth_file_is_private_and_refuses_a_symlink_directory() {
        let root = tempfile::tempdir().unwrap();
        let authfile = prepare_anonymous_authfile(root.path()).unwrap();
        assert_eq!(std::fs::read(&authfile).unwrap(), b"{\"auths\":{}}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(authfile.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&authfile).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        #[cfg(unix)]
        {
            let other = tempfile::tempdir().unwrap();
            let linked = other.path().join("worker");
            std::os::unix::fs::symlink(root.path(), &linked).unwrap();
            assert!(prepare_anonymous_authfile(&linked).is_err());
        }
    }

    fn cancel() -> Cancel {
        Arc::new(AtomicBool::new(false))
    }

    fn stored(id: &str, bytes: u64, containers: u32, digest: &str) -> podman::StoredImage {
        podman::StoredImage {
            id: id.into(),
            bytes,
            containers,
            digest: digest.into(),
        }
    }

    #[test]
    fn reclamation_takes_the_least_recently_used_and_spares_what_is_in_use() {
        let images = Images::new(PathBuf::new());
        images.record("r@sha256:recent");
        images.record("r@sha256:old");
        images.state().used.insert(
            "sha256:old".into(),
            Instant::now()
                .checked_sub(Duration::from_secs(3_600))
                .unwrap(),
        );
        let store = [
            stored("aa", 100, 0, "sha256:old"),
            stored("bb", 200, 1, "sha256:used-by-a-container"),
            stored("cc", 300, 0, "sha256:recent"),
            stored("dd", 400, 0, "sha256:unknown"),
        ];
        assert!(images.reclaimable(&store, 1_000).is_empty());
        assert_eq!(images.reclaimable(&store, 300), ["dd", "aa"]);
        assert_eq!(images.reclaimable(&store, 950), ["dd"]);
        images.record("r@sha256:old");
        assert_eq!(images.reclaimable(&store, 300), ["dd"]);
    }

    fn waiters(images: &Images, image: &str) -> usize {
        images
            .state()
            .pulling
            .get(&PullKey::anonymous(image))
            .map(|slot| slot.waiters.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn parked(images: &Images, image: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while waiters(images, image) < n {
            assert!(Instant::now() < deadline, "followers never parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    struct Stub {
        calls: Arc<AtomicUsize>,
        entered: mpsc::Sender<()>,
        release: Arc<Barrier>,
        outcome: std::result::Result<bool, &'static str>,
    }

    impl Stub {
        fn new(outcome: std::result::Result<bool, &'static str>) -> (Stub, mpsc::Receiver<()>) {
            let (entered, rx) = mpsc::channel();
            (
                Stub {
                    calls: Arc::new(AtomicUsize::new(0)),
                    entered,
                    release: Arc::new(Barrier::new(2)),
                    outcome,
                },
                rx,
            )
        }

        fn images(&self) -> Images {
            let (calls, entered, release, outcome) = (
                Arc::clone(&self.calls),
                self.entered.clone(),
                Arc::clone(&self.release),
                self.outcome,
            );
            Images::with_download(move |_, _, _, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                let _ = entered.send(());
                release.wait();
                outcome.map_err(Error::Timeout)
            })
        }
    }

    #[test]
    fn concurrent_pulls_share_one_download() {
        let (stub, entered) = Stub::new(Ok(false));
        let images = stub.images();
        let callers: Vec<_> = (0..5)
            .map(|_| {
                let (images, cancel) = (images.clone(), cancel());
                thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
            })
            .collect();
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        parked(&images, IMAGE, 4);
        stub.release.wait();
        for caller in callers {
            assert!(!caller.join().unwrap().unwrap());
        }
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            1,
            "one download for five"
        );
        assert_eq!(images.in_flight(), 0, "no slot left behind");
        assert!(images.holds(DIGEST));
        assert_eq!(images.held(), vec![DIGEST.to_string()]);
    }

    #[test]
    fn tenant_and_credential_changes_never_share_an_authorized_pull() {
        fn calls_for(tenants: [[u8; 16]; 2], credentials: [[u8; 32]; 2]) -> usize {
            let calls = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(AtomicBool::new(false));
            let (entered_tx, entered_rx) = mpsc::channel();
            let images = Images::with_download({
                let (calls, release, entered_tx) =
                    (Arc::clone(&calls), Arc::clone(&release), entered_tx);
                move |_, authfile, _, _, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(authfile.to_path_buf()).unwrap();
                    while !release.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                    Ok(false)
                }
            });
            let first = {
                let images = images.clone();
                thread::spawn(move || {
                    images.pull_for_tenant(
                        IMAGE,
                        tenants[0],
                        credentials[0],
                        Path::new("auth-first.json"),
                        &podman::Store::Shared,
                        Duration::from_secs(5),
                        &cancel(),
                    )
                })
            };
            assert_eq!(
                entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                PathBuf::from("auth-first.json")
            );
            let second = {
                let images = images.clone();
                thread::spawn(move || {
                    images.pull_for_tenant(
                        IMAGE,
                        tenants[1],
                        credentials[1],
                        Path::new("auth-second.json"),
                        &podman::Store::Shared,
                        Duration::from_secs(5),
                        &cancel(),
                    )
                })
            };
            let second_entered = entered_rx.recv_timeout(Duration::from_secs(2)).ok();
            release.store(true, Ordering::Release);
            assert!(first.join().unwrap().is_ok());
            assert!(second.join().unwrap().is_ok());
            assert_eq!(second_entered, Some(PathBuf::from("auth-second.json")));
            calls.load(Ordering::SeqCst)
        }

        assert_eq!(calls_for([[1; 16], [2; 16]], [[7; 32], [7; 32]]), 2);
        assert_eq!(calls_for([[1; 16], [1; 16]], [[7; 32], [8; 32]]), 2);
    }

    #[test]
    fn followers_get_the_leaders_error_and_the_next_attempt_retries() {
        let (stub, entered) = Stub::new(Err("podman pull"));
        let images = stub.images();
        let callers: Vec<_> = (0..3)
            .map(|_| {
                let (images, cancel) = (images.clone(), cancel());
                thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
            })
            .collect();
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        parked(&images, IMAGE, 2);
        stub.release.wait();
        for caller in callers {
            match caller.join().unwrap() {
                Err(Error::Timeout("podman pull")) => {}
                other => panic!("follower got {other:?}"),
            }
        }
        assert_eq!(images.in_flight(), 0);
        assert!(!images.holds(DIGEST), "a failed pull records nothing");
        let retry = {
            let (images, cancel) = (images.clone(), cancel());
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
        };
        entered
            .recv_timeout(Duration::from_secs(10))
            .expect("a fresh download ran");
        stub.release.wait();
        match retry.join().unwrap() {
            Err(Error::Timeout("podman pull")) => {}
            other => panic!("retry got {other:?}"),
        }
        assert_eq!(stub.calls.load(Ordering::SeqCst), 2, "a fresh download ran");
    }

    #[test]
    fn a_canceled_follower_stops_waiting_without_ending_the_pull() {
        let (stub, entered) = Stub::new(Ok(true));
        let images = stub.images();
        let leader = {
            let (images, cancel) = (images.clone(), cancel());
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &cancel))
        };
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        let flag = cancel();
        let follower = {
            let (images, flag) = (images.clone(), Arc::clone(&flag));
            thread::spawn(move || images.pull(IMAGE, Duration::from_secs(30), &flag))
        };
        parked(&images, IMAGE, 1);
        flag.store(true, Ordering::Release);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(follower.join().unwrap()).unwrap());
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Err(Error::Preparation(ref what)) => assert_eq!(what, "canceled"),
            other => panic!("canceled follower got {other:?}"),
        }
        assert_eq!(images.in_flight(), 1, "the leader's pull goes on");
        stub.release.wait();
        assert!(leader.join().unwrap().unwrap());
        assert_eq!(images.in_flight(), 0);
        assert!(images.holds(DIGEST), "the completed pull still records");
    }

    #[test]
    fn a_pull_after_the_leader_finishes_pulls_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let images = Images::with_download({
            let calls = Arc::clone(&calls);
            move |_, _, _, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        });
        images
            .pull(IMAGE, Duration::from_secs(30), &cancel())
            .unwrap();
        images
            .pull(IMAGE, Duration::from_secs(30), &cancel())
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(images.in_flight(), 0);
        assert_eq!(images.held(), vec![DIGEST.to_string()]);
        assert!(!images.holds("sha256:never-pulled"));
    }

    #[test]
    fn the_held_record_is_bounded_and_evicts_the_oldest() {
        let images = Images::with_download(|_, _, _, _, _| Ok(false));
        let flag = cancel();
        for i in 0..MAX_HELD + 1 {
            let image = format!("example.test/i@sha256:{i:064}");
            images.pull(&image, Duration::from_secs(30), &flag).unwrap();
        }
        let held = images.held();
        assert_eq!(held.len(), MAX_HELD);
        assert!(!images.holds(&format!("sha256:{:064}", 0)));
        assert!(images.holds(&format!("sha256:{:064}", MAX_HELD)));
    }

    #[test]
    fn the_wrapped_pull_still_refuses_an_unpinned_reference() {
        let images = Images::new(PathBuf::new());
        match images.pull(
            "example.test/image:latest",
            Duration::from_secs(1),
            &cancel(),
        ) {
            Err(Error::Preparation(ref what)) => {
                assert_eq!(what, "image is not pinned by digest")
            }
            other => panic!("unpinned reference got {other:?}"),
        }
        assert_eq!(images.in_flight(), 0);
        assert!(images.held().is_empty());
    }

    #[test]
    fn anonymous_and_tenant_pulls_refuse_unpinned_images_before_download() {
        let calls = Arc::new(AtomicUsize::new(0));
        let images = Images::with_download({
            let calls = Arc::clone(&calls);
            move |_, _, _, _, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
        });
        let authfile = tempfile::tempdir().unwrap();
        let image = "example.test/image:latest";
        let cancel = cancel();

        for result in [
            images.pull(image, Duration::from_secs(1), &cancel),
            images.pull_for_tenant(
                image,
                [0; 16],
                [0; 32],
                authfile.path(),
                &podman::Store::Shared,
                Duration::from_secs(1),
                &cancel,
            ),
        ] {
            assert!(matches!(
                result,
                Err(Error::Preparation(ref why)) if why == "image is not pinned by digest"
            ));
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(images.in_flight(), 0);
        assert!(images.held().is_empty());
    }

    fn guest(key: &str, digest: &str, bytes: u64, idle: Duration) -> GuestEntry {
        GuestEntry {
            key: key.into(),
            digest: digest.into(),
            bytes,
            used: SystemTime::now() - idle,
        }
    }

    #[test]
    fn guest_images_give_back_only_what_does_not_fit_beside_the_podman_store() {
        // Both together within the budget: nothing to give back.
        assert_eq!(guest_overage(300, 500, 1_000), 0);
        assert_eq!(guest_overage(300, 700, 1_000), 0);
        // 100 over: that much of the guest images goes.
        assert_eq!(guest_overage(300, 800, 1_000), 100);
        // Never more than all the guest images, however far over Podman is.
        assert_eq!(guest_overage(300, 5_000, 1_000), 300);
        assert_eq!(guest_overage(0, 5_000, 1_000), 0);
        assert_eq!(guest_overage(u64::MAX, u64::MAX, 1), u64::MAX - 1);
    }

    #[test]
    fn guest_reclamation_takes_the_least_recently_used_and_spares_the_recent_and_the_pulled() {
        let images = Images::new(PathBuf::new());
        let hour = Duration::from_secs(3_600);
        let guests = [
            guest("old", "sha256:old", 100, hour * 5),
            guest("older", "sha256:older", 200, hour * 9),
            guest("recent", "sha256:recent", 400, Duration::from_secs(5)),
            guest("middle", "sha256:middle", 300, hour * 2),
        ];
        assert!(images.reclaimable_guests(&guests, 0).is_empty());
        // Least recently used first, stopping once enough is freed.
        assert_eq!(images.reclaimable_guests(&guests, 250), ["older", "old"]);
        assert_eq!(images.reclaimable_guests(&guests, 200), ["older"]);
        // Asking for more than there is takes every idle one and still spares the recent one.
        assert_eq!(
            images.reclaimable_guests(&guests, u64::MAX),
            ["older", "old", "middle"]
        );
        // An image whose digest is being pulled right now may be about to boot.
        images.state().pulling.insert(
            PullKey::anonymous("example.test/i@sha256:older"),
            Arc::new(Pull::default()),
        );
        assert_eq!(images.reclaimable_guests(&guests, 200), ["old", "middle"]);
    }

    #[test]
    fn guest_reclamation_is_bounded_per_pass() {
        let hour = Duration::from_secs(3_600);
        let guests: Vec<GuestEntry> = (0..MAX_IMAGE_REMOVALS + 5)
            .map(|i| guest(&format!("k{i}"), &format!("sha256:{i}"), 1, hour * 2))
            .collect();
        let none = HashSet::new();
        let planned = plan_guest_reclaim(&guests, &none, u64::MAX, SystemTime::now());
        assert_eq!(planned.len(), MAX_IMAGE_REMOVALS);
        // A stamp from the future (a clock step) is never old enough.
        let future = GuestEntry {
            used: SystemTime::now() + hour,
            ..guest("future", "sha256:f", 9, hour)
        };
        assert!(plan_guest_reclaim(&[future], &none, u64::MAX, SystemTime::now()).is_empty());
    }
}
