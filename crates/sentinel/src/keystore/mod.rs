//! Only the backend a profile recorded at sign-in is ever read, so a profile never
//! silently changes stores.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::client::Error;

pub mod file;
#[cfg(windows)]
pub mod windows;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Os,
    File,
}

impl Backend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Backend::Os => "os",
            Backend::File => "file",
        }
    }
}

pub const OS_AVAILABLE: bool = cfg!(windows);

pub fn preferred() -> Result<Backend, Error> {
    match std::env::var("SENTINEL_CREDENTIAL_STORE") {
        Ok(v) if v == "file" => Ok(Backend::File),
        Ok(v) if v == "os" => Ok(Backend::Os),
        Ok(v) if !v.is_empty() => Err(Error::usage(
            "SENTINEL_CREDENTIAL_STORE must be \"file\" or \"os\"",
        )),
        _ => Ok(if OS_AVAILABLE {
            Backend::Os
        } else {
            Backend::File
        }),
    }
}

pub fn key(issuer: &str, profile: &str) -> String {
    format!("sentinel:{issuer}:{profile}")
}

// The path digest keeps each config directory's credential separate, matching its refresh lock.
pub fn scoped_key(dir: &Path, issuer: &str, profile: &str) -> String {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let digest = blake3::hash(canonical.as_os_str().as_encoded_bytes()).to_hex();
    format!("sentinel:{issuer}:{profile}:{}", &digest[..16])
}

pub fn read(
    backend: Backend,
    dir: &Path,
    os_key: &str,
    profile: &str,
) -> Result<Option<Vec<u8>>, Error> {
    match backend {
        Backend::File => file::read(dir, profile),
        Backend::Os => os::read(os_key).map_err(|e| os_error("read", &e)),
    }
}

pub fn write(
    backend: Backend,
    dir: &Path,
    os_key: &str,
    profile: &str,
    blob: &[u8],
) -> Result<(), Error> {
    match backend {
        Backend::File => file::write(dir, profile, blob),
        Backend::Os => os::write(os_key, blob).map_err(|e| os_error("write", &e)),
    }
}

pub fn delete(backend: Backend, dir: &Path, os_key: &str, profile: &str) -> Result<(), Error> {
    match backend {
        Backend::File => file::delete(dir, profile),
        Backend::Os => os::delete(os_key).map_err(|e| os_error("delete", &e)),
    }
}

fn os_error(what: &str, error: &std::io::Error) -> Error {
    Error::usage(format!(
        "cannot {what} the credential in the OS credential store: {error}"
    ))
}

mod os {
    #[cfg(not(windows))]
    use std::io;

    #[cfg(windows)]
    pub(super) use super::windows::{delete, read, write};

    #[cfg(not(windows))]
    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "no OS credential store on this platform (Linux keeps credentials in the owner-only file store by decision); use SENTINEL_CREDENTIAL_STORE=file",
        )
    }
    #[cfg(not(windows))]
    pub(super) fn read(_key: &str) -> io::Result<Option<Vec<u8>>> {
        Err(unsupported())
    }
    #[cfg(not(windows))]
    pub(super) fn write(_key: &str, _blob: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }
    #[cfg(not(windows))]
    pub(super) fn delete(_key: &str) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn os_store_is_refused_off_windows_and_names_the_file_store() {
        assert!(!OS_AVAILABLE);
        let dir = std::env::temp_dir();
        let message = read(Backend::Os, &dir, "sentinel:i:p", "p")
            .expect_err("no OS store off Windows")
            .to_string();
        assert!(
            message.contains("SENTINEL_CREDENTIAL_STORE=file"),
            "{message}"
        );
        assert!(write(Backend::Os, &dir, "k", "p", b"x").is_err());
        assert!(delete(Backend::Os, &dir, "k", "p").is_err());
    }
}
