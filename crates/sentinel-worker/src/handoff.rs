//! Writing a handed-off artifact into the consuming job's workspace.
//!
//! The bytes come from the producer's own publication: the worker asks the controller for an artifact of a job it
//! needs, and writes each entry under the directory the job declared, verifying it against the digest the
//! publication recorded. Nothing is copied twice and nothing is cached here: if the fetch fails the job's
//! preparation fails, because the artifact is an input the job declared rather than an optional result.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use sentinel_link::session::HandoffSink;
use sentinel_protocol::handoff::{self, Entry};

use crate::{Error, Result};

/// The directory an entry's path is created under, refusing a symlink anywhere on the way: the workspace is the
/// job's own, so a link it planted must not redirect a write out of it.
pub fn create(root: &Path, into: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for segment in into.split('/') {
        path.push(segment);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(Error::Preparation(format!(
                    "the handoff directory `{into}` is not a directory"
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&path)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(path)
}

/// One artifact being written, entry by entry, as the controller streams it.
pub struct Writer {
    root: PathBuf,
    declared_entries: u32,
    declared_bytes: u64,
    entries: u32,
    bytes: u64,
    current: Option<EntryWriter>,
}

struct EntryWriter {
    file: File,
    hasher: blake3::Hasher,
    /// The length the manifest states, which the entry must reach exactly.
    len: u64,
    written: u64,
    next_seq: u32,
    digest: [u8; 32],
}

impl Writer {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            declared_entries: 0,
            declared_bytes: 0,
            entries: 0,
            bytes: 0,
            current: None,
        }
    }

    /// Opens one entry under the artifact's root, refusing a path that is not a plain relative one.
    fn open(&mut self, entry: &Entry) -> bool {
        if !entry.well_formed() || self.entries >= self.declared_entries {
            return false;
        }
        let (parent, name) = match entry.path.rsplit_once('/') {
            Some((parent, name)) => (Some(parent), name),
            None => (None, entry.path.as_str()),
        };
        let dir = match parent {
            None => self.root.clone(),
            Some(parent) => match create(&self.root, parent) {
                Ok(dir) => dir,
                Err(_) => return false,
            },
        };
        let path = dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => return false,
            Ok(_) | Err(_) => {}
        }
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(entry.mode & 0o755);
        }
        let Ok(file) = options.open(&path) else {
            return false;
        };
        self.entries += 1;
        self.current = Some(EntryWriter {
            file,
            hasher: blake3::Hasher::new(),
            len: entry.len,
            written: 0,
            next_seq: 0,
            digest: entry.digest,
        });
        true
    }

    /// Writes one body chunk. The entry is verified the moment it reaches the length the manifest stated, so a
    /// damaged publication is refused at the entry rather than after the whole artifact.
    fn write_chunk(&mut self, seq: u32, bytes: &[u8]) -> bool {
        let Some(current) = &mut self.current else {
            return false;
        };
        if seq != current.next_seq || current.written + bytes.len() as u64 > current.len {
            return false;
        }
        current.next_seq += 1;
        current.written += bytes.len() as u64;
        current.hasher.update(bytes);
        if current.file.write_all(bytes).is_err() {
            return false;
        }
        if current.written < current.len {
            return true;
        }
        let current = self.current.take().expect("just written");
        *current.hasher.finalize().as_bytes() == current.digest
    }
}

impl HandoffSink for Writer {
    fn begin(&mut self, entries: u32, bytes: u64) -> bool {
        if entries as usize > handoff::MAX_ENTRIES || bytes > handoff::MAX_BYTES {
            return false;
        }
        self.declared_entries = entries;
        self.declared_bytes = bytes;
        true
    }

    fn entry(&mut self, entry: &Entry) -> bool {
        self.current.is_none() && self.open(entry)
    }

    fn body(&mut self, seq: u32, bytes: &[u8]) -> bool {
        let total = self.bytes + bytes.len() as u64;
        if total > self.declared_bytes {
            return false;
        }
        if !self.write_chunk(seq, bytes) {
            return false;
        }
        self.bytes = total;
        true
    }

    fn end(&mut self) -> bool {
        self.current.is_none()
            && self.entries == self.declared_entries
            && self.bytes == self.declared_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, body: &[u8]) -> Entry {
        Entry {
            path: path.to_owned(),
            len: body.len() as u64,
            digest: *blake3::hash(body).as_bytes(),
            mode: 0o644,
        }
    }

    #[test]
    fn entries_are_written_where_the_manifest_put_them_and_verify() {
        let temp = tempfile::tempdir().unwrap();
        let root = create(temp.path(), "incoming/dist").unwrap();
        let mut writer = Writer::new(root.clone());
        let body = b"release bytes";
        assert!(writer.begin(1, body.len() as u64));
        assert!(writer.entry(&entry("bin/app", body)));
        assert!(writer.body(0, body), "the entry verifies on its last body");
        assert!(writer.end());
        assert_eq!(
            std::fs::read(root.join("bin/app")).unwrap(),
            body.to_vec(),
            "the artifact's own path is kept under the directory the job named"
        );
    }

    #[test]
    fn an_entry_that_does_not_match_its_digest_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = create(temp.path(), "incoming").unwrap();
        let mut writer = Writer::new(root);
        let mut entry = entry("app", b"release bytes");
        entry.len = 13;
        assert!(writer.begin(1, 13));
        assert!(writer.entry(&entry));
        assert!(
            !writer.body(0, b"tampered byte"),
            "the bytes are not what was published"
        );
    }

    #[test]
    fn a_path_that_leaves_the_directory_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = create(temp.path(), "incoming").unwrap();
        let mut writer = Writer::new(root);
        assert!(writer.begin(1, 1));
        let mut escaping = entry("app", b"x");
        escaping.path = "../outside".into();
        assert!(!writer.entry(&escaping));
        assert!(!writer.entry(&Entry {
            path: "/etc/passwd".into(),
            ..entry("app", b"x")
        }));
    }

    #[test]
    fn a_declared_directory_that_is_a_symlink_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("real")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("real"), temp.path().join("link")).unwrap();
        assert!(create(temp.path(), "link").is_err());
    }

    #[test]
    fn an_artifact_past_its_bounds_is_refused_before_a_body_arrives() {
        let temp = tempfile::tempdir().unwrap();
        let root = create(temp.path(), "incoming").unwrap();
        let mut writer = Writer::new(root);
        assert!(!writer.begin(handoff::MAX_ENTRIES as u32 + 1, 1));
        assert!(!writer.begin(1, handoff::MAX_BYTES + 1));
        assert!(writer.begin(1, 1));
        assert!(writer.entry(&entry("app", b"x")));
        assert!(
            !writer.body(0, b"xy"),
            "more bytes than the artifact declared are refused"
        );
    }

    #[test]
    fn a_body_that_breaks_the_entry_length_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = create(temp.path(), "incoming").unwrap();
        let mut writer = Writer::new(root);
        assert!(writer.begin(1, 4));
        assert!(writer.entry(&entry("app", b"abcd")));
        assert!(
            !writer.body(0, b"abcdef"),
            "an entry cannot grow past the length its manifest states"
        );
        assert!(!writer.end(), "an incomplete artifact is not accepted");
    }
}
