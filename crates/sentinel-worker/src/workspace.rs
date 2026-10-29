use std::{
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

use sentinel_core::AttemptId;

use crate::{Error, Result};

pub const WORKSPACES_DIR: &str = "workspaces";

/// Extension of the job `/tmp` directory next to a workspace (`<attempt>.tmp`).
pub const TMP_EXTENSION: &str = "tmp";

/// The job `/tmp` directory that belongs to the workspace at `workspace`.
pub fn tmp_beside(workspace: &Path) -> PathBuf {
    workspace.with_extension(TMP_EXTENSION)
}

pub struct Workspace {
    path: PathBuf,
    attempt: AttemptId,
}

impl Workspace {
    pub fn create(root: &Path, attempt: AttemptId) -> Result<Workspace> {
        // Only the parent is owner-only: a container user must enter the attempt's bind-mounted /workspace.
        let parent = root.join(WORKSPACES_DIR);
        crate::private_dir_all(&parent)?;
        let path = parent.join(attempt.to_string());
        match fs::create_dir(&path) {
            Ok(()) => Ok(Workspace { path, attempt }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::Workspace(
                format!("{} already exists", path.display()),
            )),
            Err(e) => Err(e.into()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// The job's `/tmp` on the workspace disk, beside the workspace so tools walking the checkout never see it
    /// and so it goes with the workspace: `destroy` and startup recovery remove both.
    pub fn tmp_path(&self) -> PathBuf {
        tmp_beside(&self.path)
    }

    /// Creates the job's `/tmp` directory, world-writable with the sticky bit as a `/tmp` is.
    pub fn create_tmp(&self) -> Result<PathBuf> {
        let path = self.tmp_path();
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o1777))?;
        Ok(path)
    }

    /// Removes the workspace and the job `/tmp` beside it; an error says what stayed behind.
    pub fn destroy(self) -> Result<()> {
        remove_attempt_dirs(&self.path)
    }

    pub fn leftovers(root: &Path) -> Result<Vec<AttemptId>> {
        let parent = root.join(WORKSPACES_DIR);
        let mut found = Vec::new();
        let entries = match fs::read_dir(&parent) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            // A job's `/tmp` directory survives its workspace only when removal half-failed; it is a leftover too.
            if let Some(id) = entry.file_name().to_str().and_then(|name| {
                name.strip_suffix(&format!(".{TMP_EXTENSION}"))
                    .unwrap_or(name)
                    .parse::<AttemptId>()
                    .ok()
            }) && !found.contains(&id)
            {
                found.push(id);
            }
        }
        Ok(found)
    }
}

/// Removes the workspace at `workspace` and the job `/tmp` beside it. Both are attempted whatever the first
/// does; the workspace's error is returned in preference to the `/tmp`'s. Finalization, the panic path and
/// recovery all use this one function so that none of them can forget a tree.
pub fn remove_attempt_dirs(workspace: &Path) -> Result<()> {
    let tmp = remove_tree(&tmp_beside(workspace));
    remove_tree(workspace)?;
    tmp
}

/// What one pass over the leftovers did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reaped {
    pub removed: usize,
    /// Attempts whose trees could not be removed, with the reason.
    pub failed: Vec<(AttemptId, String)>,
}

/// Removes the workspaces and job `/tmp` directories left under `root` by attempts that `is_active` does not
/// name. The directory is listed before `is_active` is asked about each attempt: an attempt creates its
/// workspace only after it is registered as active and is unregistered only after its own cleanup, so an
/// attempt that is not active when asked has nothing in progress, whatever the listing saw.
pub fn reap_leftovers(root: &Path, is_active: impl Fn(AttemptId) -> bool) -> Result<Reaped> {
    let mut reaped = Reaped::default();
    for attempt in Workspace::leftovers(root)? {
        if is_active(attempt) {
            continue;
        }
        let path = root.join(WORKSPACES_DIR).join(attempt.to_string());
        match remove_attempt_dirs(&path) {
            Ok(()) => reaped.removed += 1,
            Err(error) => reaped.failed.push((attempt, error.to_string())),
        }
    }
    Ok(reaped)
}

/// Directory levels below one held descriptor. A deeper tree is not abandoned: the directories at the limit
/// are moved up to a scratch directory under the root and the walk goes on from there, so no more than this
/// many descriptors are held at once whatever the depth.
const MAX_WALK_DEPTH: usize = 128;

/// Passes (each clears `MAX_WALK_DEPTH` more levels) before the walk gives up and removal reports the error.
const MAX_REROOTS: u32 = 1 << 14;

/// State of the walk across passes.
struct Reroot {
    /// The tree's root, where the scratch directories are made.
    root: libc::c_int,
    pass: u32,
    /// The scratch directory of this pass, made when the first directory needs moving into it.
    scratch: Option<OwnedFd>,
    moved: u64,
}

impl Reroot {
    fn scratch(&mut self) -> Option<libc::c_int> {
        if self.scratch.is_none() {
            // The job may have made a directory of the same name before it died: try the next one.
            for attempt in 0..8u32 {
                let name =
                    std::ffi::CString::new(format!(".sentinel-reroot-{}-{attempt}", self.pass))
                        .ok()?;
                // SAFETY: `self.root` is a live descriptor and `name` is NUL-terminated.
                let made = unsafe { libc::mkdirat(self.root, name.as_ptr(), 0o700) };
                if made == 0 {
                    self.scratch = open_dir_nofollow(self.root, &name);
                    break;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                    break;
                }
            }
        }
        self.scratch.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Moves the directory `name` of `parent` into this pass's scratch directory. When the move fails the
    /// removal that follows reports what stayed behind.
    fn relocate(&mut self, parent: libc::c_int, name: &std::ffi::CStr) {
        let Some(scratch) = self.scratch() else {
            return;
        };
        self.moved += 1;
        let Ok(to) = std::ffi::CString::new(self.moved.to_string()) else {
            return;
        };
        // SAFETY: both descriptors are live directories and both names are NUL-terminated; `renameat`
        // never follows a final symbolic link.
        unsafe {
            libc::renameat(parent, name.as_ptr(), scratch, to.as_ptr());
        }
    }
}

/// The job controls the tree, so nothing may follow a link it plants: each step is relative to a held descriptor.
pub fn remove_tree(path: &Path) -> Result<()> {
    if let Ok(root) = std::ffi::CString::new(path.as_os_str().as_bytes())
        && let Some(root) = open_dir_nofollow(libc::AT_FDCWD, &root)
    {
        make_tree_walkable(&root);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Makes every directory under `root` owner-accessible, moving what lies deeper than `MAX_WALK_DEPTH` levels up
/// so that the next pass reaches it. Returns the passes it took.
fn make_tree_walkable(root: &OwnedFd) -> u32 {
    let mut scratch: Option<OwnedFd> = None;
    let mut passes = 0;
    while passes < MAX_REROOTS {
        let mut walk = Reroot {
            root: root.as_raw_fd(),
            pass: passes,
            scratch: None,
            moved: 0,
        };
        make_walkable(scratch.as_ref().unwrap_or(root), 0, &mut walk);
        passes += 1;
        scratch = walk.scratch.take();
        if scratch.is_none() {
            break;
        }
    }
    passes
}

fn open_dir_nofollow(parent: libc::c_int, name: &std::ffi::CStr) -> Option<OwnedFd> {
    // SAFETY: `name` is NUL-terminated and `parent` is a live descriptor or
    // `AT_FDCWD`; the flags only open, never create.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    // SAFETY: a non-negative `openat` result is a descriptor this call owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Makes `dir` and what lies below it owner-accessible. Returns true for a directory at the depth limit that
/// has directories of its own: the caller moves it out of the way for the next pass.
fn make_walkable(dir: &OwnedFd, depth: usize, walk: &mut Reroot) -> bool {
    let fd = dir.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is open and `stat` is a writable `stat`.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: `fstat` returned 0, so it filled the structure.
    let mode = unsafe { stat.assume_init() }.st_mode;
    let through = format!("/proc/self/fd/{fd}");
    if mode & 0o700 != 0o700 {
        let _ = fs::set_permissions(&through, fs::Permissions::from_mode(0o700));
    }
    let Ok(entries) = fs::read_dir(&through) else {
        return false;
    };
    if depth >= MAX_WALK_DEPTH {
        return entries
            .flatten()
            .any(|entry| entry.file_type().is_ok_and(|t| t.is_dir()));
    }
    let children: Vec<std::ffi::CString> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| std::ffi::CString::new(entry.file_name().as_bytes()).ok())
        .collect();
    for name in &children {
        if let Some(child) = open_dir_nofollow(fd, name)
            && make_walkable(&child, depth + 1, walk)
        {
            walk.relocate(fd, name);
        }
    }
    false
}

/// `levels` nested directories below the existing `root`, built one descriptor at a time so that no path ever
/// grows past the platform's limit. Returns a handle to every level, the deepest last.
#[cfg(test)]
pub(crate) fn build_deep(root: &Path, levels: usize) -> Vec<fs::File> {
    let mut chain = Vec::with_capacity(levels);
    let mut at = fs::File::open(root).unwrap();
    for _ in 0..levels {
        let here = format!("/proc/self/fd/{}/d", at.as_raw_fd());
        fs::create_dir(&here).unwrap();
        let next = fs::File::open(&here).unwrap();
        chain.push(next.try_clone().unwrap());
        at = next;
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_tmp_is_world_writable_beside_the_workspace_and_goes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let ws = Workspace::create(dir.path(), attempt).unwrap();
        let tmp = ws.create_tmp().unwrap();
        assert_eq!(tmp.parent(), ws.path().parent());
        assert_ne!(tmp, ws.path());
        assert_eq!(
            fs::metadata(&tmp).unwrap().permissions().mode() & 0o7777,
            0o1777
        );
        // Created twice for one attempt is the same directory, not an error.
        assert_eq!(ws.create_tmp().unwrap(), tmp);
        fs::write(tmp.join("big"), b"x").unwrap();
        assert_eq!(Workspace::leftovers(dir.path()).unwrap(), vec![attempt]);
        ws.destroy().unwrap();
        assert!(!tmp.exists());
        assert!(Workspace::leftovers(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_job_tmp_left_without_its_workspace_is_still_a_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let ws = Workspace::create(dir.path(), attempt).unwrap();
        let tmp = ws.create_tmp().unwrap();
        remove_tree(ws.path()).unwrap();
        assert_eq!(Workspace::leftovers(dir.path()).unwrap(), vec![attempt]);
        remove_tree(&tmp).unwrap();
        assert!(Workspace::leftovers(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_read_only_tree_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let deep = root.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("file"), b"x").unwrap();
        for sub in [&deep, &root.join("a/b"), &root.join("a"), &root] {
            fs::set_permissions(sub, fs::Permissions::from_mode(0o500)).unwrap();
        }
        remove_tree(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_planted_link_never_changes_what_it_points_at() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o500)).unwrap();
        let root = dir.path().join("ws");
        fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub/link")).unwrap();
        remove_tree(&root).unwrap();
        assert!(!root.exists());
        let mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o500, "the link's target was chmodded");
        assert!(outside.join("keep").exists());
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn removing_nothing_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        remove_tree(&dir.path().join("absent")).unwrap();
    }

    fn mode_of(dir: &fs::File) -> u32 {
        fs::metadata(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn at(dir: &fs::File, name: &str) -> String {
        format!("/proc/self/fd/{}/{name}", dir.as_raw_fd())
    }

    #[test]
    fn a_tree_deeper_than_the_walk_is_made_walkable_all_the_way_down() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        fs::create_dir(&root).unwrap();
        let chain = build_deep(&root, 200);
        let deepest = chain.last().unwrap();
        fs::write(at(deepest, "payload"), b"x").unwrap();
        // A job that owns its tree seals the bottom levels; the walk must still reach them.
        for sealed in &chain[chain.len() - 3..] {
            fs::set_permissions(at(sealed, ""), fs::Permissions::from_mode(0o000)).unwrap();
        }
        let path = std::ffi::CString::new(root.as_os_str().as_bytes()).unwrap();
        let top = open_dir_nofollow(libc::AT_FDCWD, &path).unwrap();
        let passes = make_tree_walkable(&top);
        assert!(
            passes >= 2,
            "a 200-level tree needs a second pass, took {passes}"
        );
        for sealed in &chain[chain.len() - 3..] {
            assert_eq!(
                mode_of(sealed),
                0o700,
                "a sealed level below the walk limit was skipped"
            );
        }
        drop(top);
        remove_tree(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_tree_far_deeper_than_the_walk_is_removed_whole() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        fs::create_dir(&root).unwrap();
        let chain = build_deep(&root, 400);
        fs::write(at(chain.last().unwrap(), "payload"), b"x").unwrap();
        for sealed in chain.iter().rev().take(3) {
            fs::set_permissions(at(sealed, ""), fs::Permissions::from_mode(0o000)).unwrap();
        }
        drop(chain);
        remove_tree(&root).unwrap();
        assert!(!root.exists());
        let left: Vec<_> = fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_wide_level_at_the_walk_limit_is_removed_without_a_descriptor_each() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        fs::create_dir(&root).unwrap();
        // More directories at the limit than a worker may hold descriptors for.
        let chain = build_deep(&root, MAX_WALK_DEPTH - 1);
        let parent = chain.last().unwrap();
        for i in 0..1500 {
            fs::create_dir_all(at(parent, &format!("w{i}/inner"))).unwrap();
        }
        fs::set_permissions(at(parent, "w7/inner"), fs::Permissions::from_mode(0o000)).unwrap();
        drop(chain);
        remove_tree(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_link_planted_below_the_walk_limit_never_changes_what_it_points_at() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o500)).unwrap();
        let root = dir.path().join("ws");
        fs::create_dir(&root).unwrap();
        let chain = build_deep(&root, 150);
        std::os::unix::fs::symlink(&outside, at(chain.last().unwrap(), "link")).unwrap();
        drop(chain);
        remove_tree(&root).unwrap();
        assert!(!root.exists());
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o500,
            "the link's target was chmodded"
        );
        assert!(outside.join("keep").exists());
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn the_workspace_and_its_job_tmp_are_removed_by_one_call_even_when_the_first_fails() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let ws = Workspace::create(dir.path(), attempt).unwrap();
        let tmp = ws.create_tmp().unwrap();
        fs::write(tmp.join("scratch"), b"x").unwrap();
        fs::write(ws.path().join("src"), b"x").unwrap();
        remove_attempt_dirs(ws.path()).unwrap();
        assert!(!ws.path().exists() && !tmp.exists());

        // A workspace that cannot be removed (a file in its place) does not keep the job tmp alive, and is reported.
        fs::write(ws.path(), b"not a directory").unwrap();
        fs::create_dir(&tmp).unwrap();
        fs::write(tmp.join("scratch"), b"x").unwrap();
        assert!(remove_attempt_dirs(ws.path()).is_err());
        assert!(!tmp.exists());
    }

    #[test]
    fn leftovers_of_finished_attempts_are_reaped_and_active_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let (live, gone, half) = (AttemptId::new(), AttemptId::new(), AttemptId::new());
        for attempt in [live, gone] {
            let ws = Workspace::create(dir.path(), attempt).unwrap();
            ws.create_tmp().unwrap();
            fs::write(ws.path().join("f"), b"x").unwrap();
        }
        // A job /tmp whose workspace is already gone.
        let parent = dir.path().join(WORKSPACES_DIR);
        fs::create_dir(parent.join(format!("{half}.tmp"))).unwrap();
        // Something that is not an attempt's is left alone.
        fs::create_dir(parent.join("unrelated")).unwrap();
        let reaped = reap_leftovers(dir.path(), |attempt| attempt == live).unwrap();
        assert_eq!(
            reaped,
            Reaped {
                removed: 2,
                failed: Vec::new()
            }
        );
        assert!(parent.join(live.to_string()).join("f").exists());
        assert!(parent.join(format!("{live}.tmp")).exists());
        assert!(!parent.join(gone.to_string()).exists());
        assert!(!parent.join(format!("{gone}.tmp")).exists());
        assert!(!parent.join(format!("{half}.tmp")).exists());
        assert!(parent.join("unrelated").exists());
    }

    #[test]
    fn a_leftover_that_cannot_be_removed_is_reported_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (stuck, fine) = (AttemptId::new(), AttemptId::new());
        let parent = dir.path().join(WORKSPACES_DIR);
        fs::create_dir(&parent).unwrap();
        // A file where the workspace directory should be cannot be removed as a tree, whoever runs the test.
        fs::write(parent.join(stuck.to_string()), b"x").unwrap();
        fs::create_dir(parent.join(fine.to_string())).unwrap();
        let reaped = reap_leftovers(dir.path(), |_| false).unwrap();
        assert_eq!(reaped.removed, 1);
        assert_eq!(reaped.failed.len(), 1);
        assert_eq!(reaped.failed[0].0, stuck);
        assert!(!reaped.failed[0].1.is_empty());
        assert!(!parent.join(fine.to_string()).exists());
        assert!(parent.join(stuck.to_string()).exists());
    }
}
