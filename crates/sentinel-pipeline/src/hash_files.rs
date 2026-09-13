//! `hash_files` resolver, run by the worker against the pinned checkout.
//!
//! Patterns are relative paths whose segments may contain `*` (any run of
//! characters within one segment) or be exactly `**` (zero or more
//! directories). Matching files are deduplicated, sorted by path, and hashed
//! as `path \0 len content` records with BLAKE3, so the key depends on both
//! names and contents and is identical on every host. Symlinks are never
//! followed. Limits stop a pattern such as `**` on a huge tree from turning
//! a cache key into a denial of service.
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::expr::{HashFilesError, MAX_HASH_BYTES, MAX_HASH_FILES, MAX_HASH_PATTERNS};

/// Resolve `patterns` under `root`. `root` must be the checkout root.
pub fn hash_files(root: &Path, patterns: &[&str]) -> Result<String, HashFilesError> {
    if patterns.is_empty() || patterns.len() > MAX_HASH_PATTERNS {
        return Err(HashFilesError::InvalidPattern("pattern count".into()));
    }
    let mut matched: Vec<PathBuf> = Vec::new();
    for pattern in patterns {
        if !crate::schema::valid_relative_path(pattern) {
            return Err(HashFilesError::InvalidPattern((*pattern).to_owned()));
        }
        let segments: Vec<&str> = pattern.split('/').collect();
        walk(root, PathBuf::new(), &segments, &mut matched)?;
    }
    matched.sort();
    matched.dedup();
    if matched.is_empty() {
        return Err(HashFilesError::NoMatch);
    }
    let mut hasher = blake3::Hasher::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 << 10];
    for rel in &matched {
        let rel_str = rel.to_string_lossy();
        // Canonical separator so Windows development hosts hash like Linux workers.
        let rel_str = rel_str.replace('\\', "/");
        let mut file =
            fs::File::open(root.join(rel)).map_err(|e| HashFilesError::Io(e.to_string()))?;
        let len = file
            .metadata()
            .map_err(|e| HashFilesError::Io(e.to_string()))?
            .len();
        total += len;
        if total > MAX_HASH_BYTES {
            return Err(HashFilesError::TooManyBytes {
                limit: MAX_HASH_BYTES,
            });
        }
        hasher.update(rel_str.as_bytes());
        hasher.update(&[0]);
        hasher.update(&len.to_le_bytes());
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| HashFilesError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn walk(
    root: &Path,
    rel: PathBuf,
    segments: &[&str],
    out: &mut Vec<PathBuf>,
) -> Result<(), HashFilesError> {
    let Some((seg, rest)) = segments.split_first() else {
        return Ok(());
    };
    let dir = root.join(&rel);
    if *seg == "**" {
        // Zero directories: try the remaining pattern here.
        walk(root, rel.clone(), rest, out)?;
        for entry in read_dir(&dir)? {
            if entry.1.is_dir() {
                walk(root, rel.join(&entry.0), segments, out)?;
            }
        }
        return Ok(());
    }
    if !seg.contains('*') {
        let next = rel.join(seg);
        let meta = match fs::symlink_metadata(root.join(&next)) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        return push_or_descend(root, next, meta.file_type(), rest, out);
    }
    for (name, kind) in read_dir(&dir)? {
        if glob_segment(seg, &name) {
            push_or_descend(root, rel.join(&name), kind, rest, out)?;
        }
    }
    Ok(())
}

fn push_or_descend(
    root: &Path,
    path: PathBuf,
    kind: fs::FileType,
    rest: &[&str],
    out: &mut Vec<PathBuf>,
) -> Result<(), HashFilesError> {
    if rest.is_empty() {
        if kind.is_file() {
            out.push(path);
            if out.len() > MAX_HASH_FILES {
                return Err(HashFilesError::TooManyFiles {
                    limit: MAX_HASH_FILES,
                });
            }
        }
        Ok(())
    } else if kind.is_dir() {
        walk(root, path, rest, out)
    } else {
        Ok(())
    }
}

fn read_dir(dir: &Path) -> Result<Vec<(String, fs::FileType)>, HashFilesError> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| HashFilesError::Io(e.to_string()))?;
        let kind = entry
            .file_type()
            .map_err(|e| HashFilesError::Io(e.to_string()))?;
        if kind.is_symlink() {
            continue;
        }
        out.push((entry.file_name().to_string_lossy().into_owned(), kind));
    }
    Ok(out)
}

/// `*` matches any run of characters (including none) within one segment.
fn glob_segment(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
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

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("crates/a")).unwrap();
        fs::create_dir_all(d.path().join("crates/b/deep")).unwrap();
        fs::write(d.path().join("Cargo.lock"), "lock").unwrap();
        fs::write(d.path().join("crates/a/Cargo.toml"), "a").unwrap();
        fs::write(d.path().join("crates/b/Cargo.toml"), "b").unwrap();
        fs::write(d.path().join("crates/b/deep/Cargo.toml"), "deep").unwrap();
        fs::write(d.path().join("README.md"), "r").unwrap();
        d
    }

    #[test]
    fn glob_segments() {
        assert!(glob_segment("*.toml", "Cargo.toml"));
        assert!(glob_segment("Cargo.*", "Cargo.lock"));
        assert!(glob_segment("*", "anything"));
        assert!(!glob_segment("*.toml", "Cargo.lock"));
        assert!(!glob_segment("a*c", "abd"));
        assert!(glob_segment("a*c*", "abcd"));
    }

    #[test]
    fn hashes_sorted_matches_and_is_content_and_name_sensitive() {
        let d = tree();
        let h1 = hash_files(d.path(), &["Cargo.lock", "crates/*/Cargo.toml"]).unwrap();
        assert_eq!(h1.len(), 64);
        let h_again = hash_files(d.path(), &["crates/*/Cargo.toml", "Cargo.lock"]).unwrap();
        assert_eq!(h1, h_again, "pattern order does not matter");
        let h_all = hash_files(d.path(), &["**/Cargo.toml", "Cargo.lock"]).unwrap();
        assert_ne!(h1, h_all, "** also matches crates/b/deep");
        fs::write(d.path().join("crates/a/Cargo.toml"), "changed").unwrap();
        assert_ne!(
            hash_files(d.path(), &["Cargo.lock", "crates/*/Cargo.toml"]).unwrap(),
            h1
        );
        fs::rename(d.path().join("Cargo.lock"), d.path().join("Cargo.lock2")).unwrap();
        assert_eq!(
            hash_files(d.path(), &["Cargo.lock"]),
            Err(HashFilesError::NoMatch)
        );
        assert!(matches!(
            hash_files(d.path(), &["../x"]),
            Err(HashFilesError::InvalidPattern(_))
        ));
        assert!(matches!(
            hash_files(d.path(), &[]),
            Err(HashFilesError::InvalidPattern(_))
        ));
    }

    #[test]
    fn same_tree_hashes_identically_from_another_root() {
        let a = tree();
        let b = tree();
        assert_eq!(
            hash_files(a.path(), &["**/*.toml"]).unwrap(),
            hash_files(b.path(), &["**/*.toml"]).unwrap()
        );
    }
}
