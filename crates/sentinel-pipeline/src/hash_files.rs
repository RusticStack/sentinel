//! Bounded worker-side hashing. Linux path resolution is rooted in one pinned
//! directory descriptor; every open rejects symlinks, mount crossings and escape.
//! This is not a filesystem snapshot: callers hash before starting writable work.
use crate::expr::HashFilesError;

pub const MAX_HASH_VISITS: usize = 100_000;
pub const MAX_HASH_DEPTH: usize = 64;
pub const MAX_HASH_PATH: usize = 4096;
pub const MAX_HASH_PATTERN: usize = 1024;

/// Hash sorted, unique `path \0 length content` records. No filesystem access
/// is attempted on non-Linux hosts; offline validate/explain remain portable.
pub fn hash_files(root: &std::path::Path, patterns: &[&str]) -> Result<String, HashFilesError> {
    #[cfg(target_os = "linux")]
    {
        linux::hash(root, patterns)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, patterns);
        Err(HashFilesError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::expr::{MAX_HASH_BYTES, MAX_HASH_FILES, MAX_HASH_PATTERNS};
    use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
    use std::{collections::BTreeSet, fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};

    fn io(_: impl std::fmt::Debug) -> HashFilesError {
        // Never expose a filesystem path, parser input or operating-system payload.
        HashFilesError::Io("filesystem operation failed".into())
    }

    struct Tree {
        root: File,
        visits: usize,
        matches: BTreeSet<String>,
    }

    impl Tree {
        fn visit(&mut self) -> Result<(), HashFilesError> {
            if self.visits == MAX_HASH_VISITS {
                return Err(HashFilesError::TraversalLimit);
            }
            self.visits += 1;
            Ok(())
        }

        fn open(&mut self, path: &str, flags: OFlags) -> Result<File, HashFilesError> {
            self.visit()?;
            confined(&self.root, path, flags)
        }

        fn insert(&mut self, path: &str) -> Result<(), HashFilesError> {
            if self.matches.contains(path) {
                return Ok(());
            }
            if self.matches.len() == MAX_HASH_FILES {
                return Err(HashFilesError::TooManyFiles {
                    limit: MAX_HASH_FILES,
                });
            }
            self.matches.insert(path.to_owned());
            Ok(())
        }

        fn walk(
            &mut self,
            path: &mut String,
            segments: &[&str],
            depth: usize,
        ) -> Result<(), HashFilesError> {
            self.visit()?;
            let Some((seg, rest)) = segments.split_first() else {
                return Ok(());
            };
            if depth >= MAX_HASH_DEPTH {
                return Err(HashFilesError::DepthLimit);
            }
            if *seg == "**" && !rest.is_empty() {
                self.walk(path, rest, depth)?;
            }
            if !seg.contains('*') {
                let saved = append(path, seg)?;
                // Only an absent literal is a normal no-match. All other errors
                // (including a raced-away enumerated entry) invalidate the result.
                self.visit()?;
                let fd = openat2(
                    &self.root,
                    path.as_str(),
                    OFlags::PATH | OFlags::CLOEXEC,
                    Mode::empty(),
                    resolve(),
                );
                match fd {
                    Err(rustix::io::Errno::NOENT) => {}
                    Err(e) => return Err(io(e)),
                    Ok(fd) => self.descend(path, File::from(fd), rest, depth + 1)?,
                }
                path.truncate(saved);
                return Ok(());
            }
            let dir = self.open(
                if path.is_empty() { "." } else { path },
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            // getdents-backed streaming enumeration: never collect a directory.
            let entries = Dir::new(dir).map_err(io)?;
            for entry in entries {
                self.visit()?;
                let entry = entry.map_err(io)?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                let name =
                    std::str::from_utf8(bytes).map_err(|_| HashFilesError::InvalidFileName)?;
                if name.contains('\\') {
                    return Err(HashFilesError::InvalidFileName);
                }
                if *seg != "**" && !glob_segment(seg, name) {
                    continue;
                }
                let saved = append(path, name)?;
                let file = self.open(path, OFlags::PATH)?;
                if *seg == "**" {
                    let meta = file.metadata().map_err(io)?;
                    if meta.is_dir() {
                        self.walk(path, segments, depth + 1)?;
                    } else if rest.is_empty() {
                        if !meta.is_file() {
                            return Err(HashFilesError::UnsafeFile);
                        }
                        self.insert(path)?;
                    }
                } else {
                    self.descend(path, file, rest, depth + 1)?;
                }
                path.truncate(saved);
            }
            Ok(())
        }

        fn descend(
            &mut self,
            path: &mut String,
            file: File,
            rest: &[&str],
            depth: usize,
        ) -> Result<(), HashFilesError> {
            let meta = file.metadata().map_err(io)?;
            if meta.is_dir() {
                if !rest.is_empty() {
                    self.walk(path, rest, depth)?;
                }
            } else if !meta.is_file() {
                return Err(HashFilesError::UnsafeFile);
            } else if rest.is_empty() {
                self.insert(path)?;
            }
            Ok(())
        }
    }

    fn resolve() -> ResolveFlags {
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV
    }

    fn confined(root: &File, path: &str, flags: OFlags) -> Result<File, HashFilesError> {
        openat2(
            root,
            path,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            resolve(),
        )
        .map(File::from)
        .map_err(io)
    }

    fn append(path: &mut String, name: &str) -> Result<usize, HashFilesError> {
        let saved = path.len();
        if saved + usize::from(saved != 0) + name.len() > MAX_HASH_PATH {
            return Err(HashFilesError::PathLimit);
        }
        if saved != 0 {
            path.push('/');
        }
        path.push_str(name);
        Ok(saved)
    }

    pub(super) fn hash(root: &Path, patterns: &[&str]) -> Result<String, HashFilesError> {
        if patterns.is_empty() || patterns.len() > MAX_HASH_PATTERNS {
            return Err(HashFilesError::InvalidPattern("pattern count".into()));
        }
        // Validate everything before opening the root or allocating segment vectors.
        for pattern in patterns {
            if pattern.len() > MAX_HASH_PATTERN
                || !crate::schema::valid_relative_path(pattern)
                || pattern.split('/').count() > MAX_HASH_DEPTH
            {
                return Err(HashFilesError::InvalidPattern(
                    "invalid hash pattern".into(),
                ));
            }
        }
        let root = openat2(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(io)?;
        let mut tree = Tree {
            root,
            visits: 0,
            matches: BTreeSet::new(),
        };
        let mut path = String::new();
        for pattern in patterns {
            tree.walk(&mut path, &pattern.split('/').collect::<Vec<_>>(), 0)?;
        }
        if tree.matches.is_empty() {
            return Err(HashFilesError::NoMatch);
        }
        let mut hasher = blake3::Hasher::new();
        let mut remaining = MAX_HASH_BYTES;
        let mut buf = vec![0u8; 64 << 10];
        for path in &tree.matches {
            // O_PATH classifies special files without opening a device/FIFO for
            // I/O. Reopen the pinned regular inode via procfs, never its pathname.
            let pinned = confined(&tree.root, path, OFlags::PATH)?;
            let before = pinned.metadata().map_err(io)?;
            if !before.is_file() {
                return Err(HashFilesError::UnsafeFile);
            }
            if before.len() > remaining {
                return Err(HashFilesError::TooManyBytes {
                    limit: MAX_HASH_BYTES,
                });
            }
            use std::os::fd::AsRawFd;
            let mut file =
                File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(io)?;
            hasher.update(path.as_bytes());
            hasher.update(&[0]);
            hasher.update(&before.len().to_le_bytes());
            stream(
                &mut file,
                before.len(),
                &mut remaining,
                &mut buf,
                &mut hasher,
            )?;
            let after = file.metadata().map_err(io)?;
            if before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(HashFilesError::ChangedFile);
            }
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn stream(
        reader: &mut impl Read,
        len: u64,
        remaining: &mut u64,
        buf: &mut [u8],
        hasher: &mut blake3::Hasher,
    ) -> Result<(), HashFilesError> {
        let mut left = len;
        while left != 0 {
            let take = left.min(*remaining).min(buf.len() as u64) as usize;
            if take == 0 {
                return Err(HashFilesError::TooManyBytes {
                    limit: MAX_HASH_BYTES,
                });
            }
            let n = match reader.read(&mut buf[..take]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.map_err(io)?,
            };
            if n == 0 {
                return Err(HashFilesError::ChangedFile);
            }
            left -= n as u64;
            *remaining -= n as u64;
            hasher.update(&buf[..n]);
        }
        // A single bounded lookahead detects growth, even for an endless reader.
        // It is never hashed; at most one byte beyond the total budget is read.
        let mut extra = [0];
        if reader.read(&mut extra).map_err(io)? != 0 {
            return Err(HashFilesError::ChangedFile);
        }
        Ok(())
    }

    fn glob_segment(pattern: &str, name: &str) -> bool {
        let (p, n) = (pattern.as_bytes(), name.as_bytes());
        let (mut pi, mut ni) = (0, 0);
        let mut star = None;
        while ni < n.len() {
            if pi < p.len() && p[pi] == b'*' {
                star = Some((pi, ni));
                pi += 1;
            } else if pi < p.len() && p[pi] == n[ni] {
                pi += 1;
                ni += 1;
            } else if let Some((sp, sn)) = star {
                pi = sp + 1;
                ni = sn + 1;
                star = Some((sp, sn + 1));
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{fs, io::Cursor, os::unix::fs::symlink};

        #[test]
        fn deterministic_unique_records_and_recursive_patterns() {
            let a = tempfile::tempdir().unwrap();
            let b = tempfile::tempdir().unwrap();
            for root in [a.path(), b.path()] {
                fs::create_dir(root.join("sub")).unwrap();
                fs::write(root.join("lock"), b"abc").unwrap();
                fs::write(root.join("sub/lock"), b"def").unwrap();
            }
            let expected = hash(a.path(), &["lock", "sub/*"]).unwrap();
            assert_eq!(expected, hash(b.path(), &["**/lock", "lock"]).unwrap());
            assert_eq!(expected, hash(a.path(), &["**"]).unwrap());
            let mut h = blake3::Hasher::new();
            for (name, data) in [("lock", b"abc"), ("sub/lock", b"def")] {
                h.update(name.as_bytes());
                h.update(&[0]);
                h.update(&3u64.to_le_bytes());
                h.update(data);
            }
            assert_eq!(expected, h.finalize().to_hex().as_str());
            fs::write(a.path().join("lock"), b"abd").unwrap();
            assert_ne!(expected, hash(a.path(), &["**"]).unwrap());
            assert_eq!(hash(a.path(), &["absent"]), Err(HashFilesError::NoMatch));
            assert!(matches!(
                hash(a.path(), &["../secret"]),
                Err(HashFilesError::InvalidPattern(_))
            ));
        }

        #[test]
        fn rejects_links_special_files_and_missing_roots() {
            let d = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("secret"), b"secret").unwrap();
            symlink(outside.path(), d.path().join("link")).unwrap();
            for pattern in ["link/secret", "**/secret", "*"] {
                assert!(hash(d.path(), &[pattern]).is_err());
            }
            assert!(hash(&d.path().join("link"), &["secret"]).is_err());
            assert!(hash(&d.path().join("missing"), &["*"]).is_err());
            rustix::fs::mknodat(
                CWD,
                d.path().join("fifo"),
                rustix::fs::FileType::Fifo,
                Mode::RUSR | Mode::WUSR,
                0,
            )
            .unwrap();
            assert_eq!(hash(d.path(), &["fifo"]), Err(HashFilesError::UnsafeFile));
        }

        #[test]
        fn pinned_root_and_file_survive_path_replacement_without_following_links() {
            let d = tempfile::tempdir().unwrap();
            fs::create_dir(d.path().join("root")).unwrap();
            fs::write(d.path().join("root/file"), b"safe").unwrap();
            let root = File::open(d.path().join("root")).unwrap();
            fs::rename(d.path().join("root"), d.path().join("moved")).unwrap();
            symlink("/", d.path().join("root")).unwrap();
            let pinned = confined(&root, "file", OFlags::PATH).unwrap();
            fs::remove_file(d.path().join("moved/file")).unwrap();
            symlink("/etc/passwd", d.path().join("moved/file")).unwrap();
            assert!(confined(&root, "file", OFlags::RDONLY).is_err());
            use std::os::fd::AsRawFd;
            assert_eq!(
                fs::read(format!("/proc/self/fd/{}", pinned.as_raw_fd())).unwrap(),
                b"safe"
            );
        }

        #[test]
        fn streamed_growth_truncation_io_failure_and_budget_are_bounded() {
            let mut h = blake3::Hasher::new();
            let mut buf = [0; 8];
            assert_eq!(
                stream(&mut std::io::repeat(1), 4, &mut 4, &mut buf, &mut h),
                Err(HashFilesError::ChangedFile)
            );
            assert_eq!(
                stream(&mut Cursor::new(b"ab"), 4, &mut 4, &mut buf, &mut h),
                Err(HashFilesError::ChangedFile)
            );
            assert!(matches!(
                stream(&mut Cursor::new(b"abcd"), 4, &mut 3, &mut buf, &mut h),
                Err(HashFilesError::TooManyBytes { .. })
            ));
            struct Broken;
            impl Read for Broken {
                fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                    Err(std::io::Error::other("secret payload"))
                }
            }
            assert_eq!(
                stream(&mut Broken, 1, &mut 4, &mut buf, &mut h),
                Err(HashFilesError::Io("filesystem operation failed".into()))
            );
            stream(&mut Cursor::new(b"abcd"), 4, &mut 4, &mut buf, &mut h).unwrap();
        }

        #[test]
        fn limits_stop_deep_trees_duplicate_glob_work_and_large_files() {
            let d = tempfile::tempdir().unwrap();
            let mut p = d.path().to_path_buf();
            for _ in 0..=MAX_HASH_DEPTH {
                p.push("d");
                fs::create_dir(&p).unwrap();
            }
            assert_eq!(
                hash(d.path(), &["**/lock"]),
                Err(HashFilesError::DepthLimit)
            );
            let file = File::create(d.path().join("huge")).unwrap();
            file.set_len(MAX_HASH_BYTES + 1).unwrap();
            assert!(matches!(
                hash(d.path(), &["huge"]),
                Err(HashFilesError::TooManyBytes { .. })
            ));
            let mut tree = Tree {
                root: File::open(d.path()).unwrap(),
                visits: MAX_HASH_VISITS - 1,
                matches: BTreeSet::new(),
            };
            assert_eq!(
                tree.walk(&mut String::new(), &["*"], 0),
                Err(HashFilesError::TraversalLimit)
            );
            assert_eq!(
                append(&mut "a".repeat(MAX_HASH_PATH), "b"),
                Err(HashFilesError::PathLimit)
            );
        }

        #[test]
        fn streaming_directory_budget_counts_nonmatching_entries() {
            let d = tempfile::tempdir().unwrap();
            for i in 0..64 {
                fs::write(d.path().join(format!("unmatched-{i}")), b"").unwrap();
            }
            let mut tree = Tree {
                root: File::open(d.path()).unwrap(),
                visits: MAX_HASH_VISITS - 32,
                matches: BTreeSet::new(),
            };
            assert_eq!(
                tree.walk(&mut String::new(), &["*.lock"], 0),
                Err(HashFilesError::TraversalLimit)
            );
            assert!(tree.matches.is_empty());
            assert_eq!(tree.visits, MAX_HASH_VISITS);
        }

        #[test]
        fn unique_file_limit_is_not_spent_on_overlapping_patterns() {
            let d = tempfile::tempdir().unwrap();
            for i in 0..MAX_HASH_FILES {
                fs::write(d.path().join(format!("f{i}")), b"").unwrap();
            }
            let expected = hash(d.path(), &["*"]).unwrap();
            assert_eq!(hash(d.path(), &["*", "*"]).unwrap(), expected);
            fs::write(d.path().join("extra"), b"").unwrap();
            assert_eq!(
                hash(d.path(), &["*"]),
                Err(HashFilesError::TooManyFiles {
                    limit: MAX_HASH_FILES
                })
            );
        }

        #[test]
        fn ambiguous_names_and_intermediate_symlink_replacement_fail_closed() {
            use std::os::unix::ffi::OsStrExt;
            let d = tempfile::tempdir().unwrap();
            let invalid = d.path().join(std::ffi::OsStr::from_bytes(b"invalid-\xff"));
            fs::write(&invalid, b"").unwrap();
            assert_eq!(hash(d.path(), &["*"]), Err(HashFilesError::InvalidFileName));
            fs::remove_file(invalid).unwrap();
            fs::write(d.path().join("a\\b"), b"").unwrap();
            assert_eq!(hash(d.path(), &["*"]), Err(HashFilesError::InvalidFileName));
            fs::create_dir(d.path().join("sub")).unwrap();
            fs::write(d.path().join("sub/file"), b"safe").unwrap();
            let mut tree = Tree {
                root: File::open(d.path()).unwrap(),
                visits: 0,
                matches: BTreeSet::new(),
            };
            tree.walk(&mut String::new(), &["sub", "file"], 0).unwrap();
            fs::rename(d.path().join("sub"), d.path().join("old")).unwrap();
            symlink("/etc", d.path().join("sub")).unwrap();
            assert!(confined(&tree.root, tree.matches.first().unwrap(), OFlags::PATH).is_err());
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
#[test]
fn offline_platform_does_not_attempt_insecure_resolution() {
    assert_eq!(
        hash_files(std::path::Path::new("missing"), &["*"]),
        Err(HashFilesError::UnsupportedPlatform)
    );
}
