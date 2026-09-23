//! Bounded reads of files the CLI is pointed at: pipelines, credential
//! files, standard input. The bound is on the bytes actually read, never on
//! a length reported beforehand: a character device (`/dev/zero`), a FIFO
//! or a procfs file reports length 0, and a regular file can grow between a
//! size check and the read.
use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

/// The pipeline loader's own limit: a larger file is refused anyway.
pub const PIPELINE_BYTES: u64 = sentinel_pipeline::yaml::MAX_PIPELINE_FILE_BYTES as u64;

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    /// More than `limit` bytes were available; reading stopped there.
    TooLarge {
        limit: u64,
    },
    NotUtf8,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => e.fmt(f),
            ReadError::TooLarge { limit } => write!(f, "larger than the {limit}-byte limit"),
            ReadError::NotUtf8 => f.write_str("not UTF-8"),
        }
    }
}

/// At most `limit` bytes of `reader`; one more is an error, not a truncation.
pub fn read(reader: impl Read, limit: u64) -> Result<Vec<u8>, ReadError> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ReadError::Io)?;
    if bytes.len() as u64 > limit {
        return Err(ReadError::TooLarge { limit });
    }
    Ok(bytes)
}

/// The whole of `path`, at most `limit` bytes.
pub fn file(path: &Path, limit: u64) -> Result<Vec<u8>, ReadError> {
    read(File::open(path).map_err(ReadError::Io)?, limit)
}

/// The whole of `path` as UTF-8 text, at most `limit` bytes.
pub fn text(path: &Path, limit: u64) -> Result<String, ReadError> {
    String::from_utf8(file(path, limit)?).map_err(|_| ReadError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endless_source_stops_one_byte_past_the_limit() {
        // `io::repeat` is `/dev/zero`: no length, no end.
        match read(io::repeat(0), 1024) {
            Err(ReadError::TooLarge { limit: 1024 }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(read(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(matches!(
            read(&b"abcd"[..], 3),
            Err(ReadError::TooLarge { .. })
        ));
    }

    #[test]
    fn text_must_be_utf8_and_missing_files_are_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, [0xffu8, 0xfe]).unwrap();
        assert!(matches!(text(&path, 16), Err(ReadError::NotUtf8)));
        std::fs::write(&path, "ok").unwrap();
        assert_eq!(text(&path, 16).unwrap(), "ok");
        assert!(matches!(
            text(&dir.path().join("absent"), 16),
            Err(ReadError::Io(_))
        ));
    }
}
