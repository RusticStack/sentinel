//! Confined reads of a tree a job controlled (P07-1).
//!
//! Publication walks the declared cache paths of a workspace the job had
//! write access to. Every resolution here is anchored at a directory the
//! worker opened itself and never resolves through a symlink: on Linux each
//! step is descriptor-relative — `openat(O_NOFOLLOW)` per component,
//! `fstatat(AT_SYMLINK_NOFOLLOW)` for classification, `openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV` to reopen a file
//! by its relative path — so a component swapped for a symlink between two
//! steps can never redirect a read outside the declared tree. Sizes and
//! modes come from the metadata of the entry actually opened.
//!
//! Off Linux (development hosts only — the executor is Linux) the same
//! interface is path-based: every component is classified with
//! `symlink_metadata` and a symlink anywhere is refused, which is correct
//! for a quiescent tree but not race-free.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
};

/// What an entry is, classified without following it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
    /// Symlinks, devices, fifos, sockets — never followed, never read.
    Other,
}

/// A regular file's metadata, taken from the entry itself.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Meta {
    pub size: u64,
    /// The permission bits worth keeping (exec on tools).
    pub mode: u32,
    /// Bytes actually allocated on disk, where the platform reports it —
    /// the sparse-file signal.
    pub allocated: Option<u64>,
}

impl Meta {
    /// Allocated storage is less than half the logical size: holes carry
    /// most of the file, and a dense copy would amplify it.
    pub fn sparse(&self) -> bool {
        self.allocated
            .is_some_and(|a| a.saturating_mul(2) < self.size)
    }
}

/// A declared path as found beneath its anchor.
pub(crate) enum Node {
    /// Nothing there: the job never made it.
    Missing,
    Dir(Base),
    File(Meta),
    /// A symlink or special entry at the path, or a component above it
    /// that is not a real directory: refused, never followed.
    Other,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use rustix::{
        fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, ResolveFlags, Stat},
        io::Errno,
    };
    use std::os::{fd::OwnedFd, unix::ffi::OsStrExt};

    /// A directory descriptor every lookup is relative to.
    pub(crate) struct Base {
        fd: OwnedFd,
    }

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    /// `NONBLOCK` so a fifo swapped in after classification can never hold
    /// the open; the descriptor is re-classified with `fstat` before a read.
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);

    fn meta(stat: &Stat) -> Meta {
        Meta {
            size: stat.st_size as u64,
            mode: stat.st_mode & 0o7777,
            allocated: Some((stat.st_blocks as u64).saturating_mul(512)),
        }
    }

    fn kind(stat: &Stat) -> Kind {
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => Kind::Dir,
            FileType::RegularFile => Kind::File,
            _ => Kind::Other,
        }
    }

    /// Errors that mean "this is not (any more) a plain directory/file
    /// reachable without a symlink or a mount crossing".
    fn refused(e: Errno) -> bool {
        matches!(e, Errno::LOOP | Errno::NOTDIR | Errno::XDEV | Errno::NOENT)
    }

    impl Base {
        /// Open the trusted anchor — a worker-owned directory — as the root
        /// every later lookup is confined beneath.
        pub(crate) fn anchor(path: &Path) -> io::Result<Base> {
            let fd = rustix::fs::openat(
                CWD,
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Base { fd })
        }

        /// Resolve `rel` component by component beneath this base.
        pub(crate) fn resolve(&self, rel: &Path) -> io::Result<Node> {
            let comps: Vec<&OsStr> = rel.iter().collect();
            let Some((last, parents)) = comps.split_last() else {
                return Ok(Node::Other);
            };
            let mut owned: Option<OwnedFd> = None;
            for comp in parents {
                let at = owned.as_ref().unwrap_or(&self.fd);
                match rustix::fs::openat(at, *comp, DIR_FLAGS, Mode::empty()) {
                    Ok(fd) => owned = Some(fd),
                    Err(Errno::NOENT) => return Ok(Node::Missing),
                    Err(Errno::LOOP | Errno::NOTDIR | Errno::XDEV) => return Ok(Node::Other),
                    Err(e) => return Err(e.into()),
                }
            }
            let at = owned.as_ref().unwrap_or(&self.fd);
            let stat = match rustix::fs::statat(at, *last, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(Errno::NOENT) => return Ok(Node::Missing),
                Err(e) => return Err(e.into()),
            };
            Ok(match kind(&stat) {
                Kind::Dir => match rustix::fs::openat(at, *last, DIR_FLAGS, Mode::empty()) {
                    Ok(fd) => Node::Dir(Base { fd }),
                    Err(e) if refused(e) => Node::Other,
                    Err(e) => return Err(e.into()),
                },
                Kind::File => Node::File(meta(&stat)),
                Kind::Other => Node::Other,
            })
        }

        /// This directory's entries, classified without following, sorted
        /// by name bytes so a listing never depends on filesystem order.
        pub(crate) fn entries(&self) -> io::Result<Vec<(OsString, Kind)>> {
            let mut out = Vec::new();
            for entry in Dir::read_from(&self.fd)? {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let kind = match entry.file_type() {
                    FileType::Directory => Kind::Dir,
                    FileType::RegularFile => Kind::File,
                    FileType::Unknown => {
                        match rustix::fs::statat(
                            &self.fd,
                            entry.file_name(),
                            AtFlags::SYMLINK_NOFOLLOW,
                        ) {
                            Ok(stat) => kind(&stat),
                            // Vanished between the listing and the stat.
                            Err(Errno::NOENT) => continue,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    _ => Kind::Other,
                };
                out.push((OsStr::from_bytes(name).to_owned(), kind));
            }
            out.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            Ok(out)
        }

        /// The child directory `name`, opened without following; `None` when
        /// it vanished or is no longer a directory.
        pub(crate) fn dir(&self, name: &OsStr) -> io::Result<Option<Base>> {
            match rustix::fs::openat(&self.fd, name, DIR_FLAGS, Mode::empty()) {
                Ok(fd) => Ok(Some(Base { fd })),
                Err(e) if refused(e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// The child `name`'s metadata when it is a regular file.
        pub(crate) fn stat(&self, name: &OsStr) -> io::Result<Option<Meta>> {
            match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if kind(&stat) == Kind::File => Ok(Some(meta(&stat))),
                Ok(_) | Err(Errno::NOENT) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// Open the child `name` for reading when it is a regular file.
        pub(crate) fn open_child(&self, name: &OsStr) -> io::Result<Option<(File, Meta)>> {
            match rustix::fs::openat(&self.fd, name, FILE_FLAGS, Mode::empty()) {
                Ok(fd) => regular(fd),
                Err(e) if refused(e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// Open the regular file at `rel` beneath this base: one `openat2`
        /// that refuses symlinks at every component, escapes and mount
        /// crossings; per-component `openat(O_NOFOLLOW)` where the kernel
        /// has no `openat2` (before 5.6, or filtered by seccomp).
        pub(crate) fn open(&self, rel: &str) -> io::Result<Option<(File, Meta)>> {
            let flags = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
            match rustix::fs::openat2(&self.fd, rel, FILE_FLAGS, Mode::empty(), flags) {
                Ok(fd) => return regular(fd),
                Err(e) if refused(e) => return Ok(None),
                Err(Errno::NOSYS | Errno::PERM | Errno::INVAL) => {}
                Err(e) => return Err(e.into()),
            }
            let comps: Vec<&str> = rel.split('/').collect();
            let Some((last, parents)) = comps.split_last() else {
                return Ok(None);
            };
            let mut owned: Option<OwnedFd> = None;
            for comp in parents {
                let at = owned.as_ref().unwrap_or(&self.fd);
                match rustix::fs::openat(at, *comp, DIR_FLAGS, Mode::empty()) {
                    Ok(fd) => owned = Some(fd),
                    Err(e) if refused(e) => return Ok(None),
                    Err(e) => return Err(e.into()),
                }
            }
            let at = owned.as_ref().unwrap_or(&self.fd);
            match rustix::fs::openat(at, *last, FILE_FLAGS, Mode::empty()) {
                Ok(fd) => regular(fd),
                Err(e) if refused(e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
    }

    /// Classify an opened descriptor: only a regular file is read.
    fn regular(fd: OwnedFd) -> io::Result<Option<(File, Meta)>> {
        let stat = rustix::fs::fstat(&fd)?;
        if kind(&stat) != Kind::File {
            return Ok(None);
        }
        Ok(Some((File::from(fd), meta(&stat))))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    use std::{fs, path::PathBuf};

    /// A directory path every lookup is relative to.
    pub(crate) struct Base {
        path: PathBuf,
    }

    fn meta(m: &fs::Metadata) -> Meta {
        Meta {
            size: m.len(),
            mode: crate::publish::file_mode(m),
            allocated: None,
        }
    }

    fn kind(t: fs::FileType) -> Kind {
        if t.is_dir() {
            Kind::Dir
        } else if t.is_file() {
            Kind::File
        } else {
            Kind::Other
        }
    }

    impl Base {
        pub(crate) fn anchor(path: &Path) -> io::Result<Base> {
            if !fs::metadata(path)?.is_dir() {
                return Err(io::Error::new(io::ErrorKind::NotADirectory, "anchor"));
            }
            Ok(Base {
                path: path.to_path_buf(),
            })
        }

        pub(crate) fn resolve(&self, rel: &Path) -> io::Result<Node> {
            let comps: Vec<&OsStr> = rel.iter().collect();
            if comps.is_empty() {
                return Ok(Node::Other);
            }
            let mut cur = self.path.clone();
            for (i, comp) in comps.iter().enumerate() {
                cur.push(comp);
                let m = match fs::symlink_metadata(&cur) {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Node::Missing),
                    Err(e) => return Err(e),
                };
                let last = i + 1 == comps.len();
                match kind(m.file_type()) {
                    Kind::Dir if last => return Ok(Node::Dir(Base { path: cur })),
                    Kind::Dir => {}
                    Kind::File if last => return Ok(Node::File(meta(&m))),
                    _ => return Ok(Node::Other),
                }
            }
            Ok(Node::Other)
        }

        pub(crate) fn entries(&self) -> io::Result<Vec<(OsString, Kind)>> {
            let mut out = Vec::new();
            for entry in fs::read_dir(&self.path)? {
                let entry = entry?;
                let kind = match entry.file_type() {
                    Ok(t) => kind(t),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                out.push((entry.file_name(), kind));
            }
            out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            Ok(out)
        }

        pub(crate) fn dir(&self, name: &OsStr) -> io::Result<Option<Base>> {
            let path = self.path.join(name);
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => Ok(Some(Base { path })),
                Ok(_) => Ok(None),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub(crate) fn stat(&self, name: &OsStr) -> io::Result<Option<Meta>> {
            match fs::symlink_metadata(self.path.join(name)) {
                Ok(m) if m.is_file() => Ok(Some(meta(&m))),
                Ok(_) => Ok(None),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub(crate) fn open_child(&self, name: &OsStr) -> io::Result<Option<(File, Meta)>> {
            match self.stat(name)? {
                Some(_) => open_regular(&self.path.join(name)),
                None => Ok(None),
            }
        }

        pub(crate) fn open(&self, rel: &str) -> io::Result<Option<(File, Meta)>> {
            match self.resolve(Path::new(rel))? {
                Node::File(_) => open_regular(&self.path.join(rel)),
                _ => Ok(None),
            }
        }
    }

    fn open_regular(path: &Path) -> io::Result<Option<(File, Meta)>> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let m = file.metadata()?;
        if !m.is_file() {
            return Ok(None);
        }
        Ok(Some((file, meta(&m))))
    }
}

pub(crate) use imp::Base;
