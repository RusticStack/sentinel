//! Credential storage for profiles (O04): Windows Credential Manager, the
//! macOS Keychain, or an owner-only file under the configuration directory,
//! chosen by platform or `SENTINEL_CREDENTIAL_STORE=file|os`.
//!
//! A stored credential is one opaque blob per profile (the JSON
//! [`crate::profile::Credentials`]). The OS stores key it by the key the
//! profile recorded at sign-in ([`scoped_key`],
//! `sentinel:{issuer}:{profile}:{directory digest}`; profiles from before
//! that use [`key`]); the file store by profile name,
//! `credentials/<profile>.json`. Only the backend a profile recorded at
//! sign-in is ever read, so a profile never silently changes stores.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::client::Error;

pub mod file;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

/// Where a profile's credential lives. Recorded in `profiles.json` as
/// `"os"` or `"file"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Windows Credential Manager or the macOS Keychain.
    Os,
    /// `credentials/<profile>.json`, owner-only.
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

/// Whether this build has an OS credential store (Linux Secret Service is
/// deferred; Linux and other Unixes use the file store).
pub const OS_AVAILABLE: bool = cfg!(any(windows, target_os = "macos"));

/// The backend for a new sign-in: `SENTINEL_CREDENTIAL_STORE` when set,
/// otherwise the OS store where one exists and the file store elsewhere.
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

/// The OS-store key of a profile signed in before keys named their
/// configuration directory. The OS store is per user, so two configuration
/// directories share this key; profiles that recorded no key keep using it.
pub fn key(issuer: &str, profile: &str) -> String {
    format!("sentinel:{issuer}:{profile}")
}

/// The OS-store key for a new sign-in: the legacy key plus 16 hex digits of
/// BLAKE3 over the configuration directory's canonical path. Two
/// configuration directories (a CI runner's, a project's, a test's) then
/// hold independent credentials, matching their independent refresh locks
/// (`locks/<profile>.lock` lives in the directory). The key is recorded in
/// the profile at sign-in, so later spellings of the path do not matter.
pub fn scoped_key(dir: &Path, issuer: &str, profile: &str) -> String {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let digest = blake3::hash(canonical.as_os_str().as_encoded_bytes()).to_hex();
    format!("sentinel:{issuer}:{profile}:{}", &digest[..16])
}

/// Read a profile's credential blob; `Ok(None)` when none is stored.
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

/// Store (replace) a profile's credential blob.
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

/// Remove a profile's credential; absent is success.
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

/// The platform's OS store, or an `Unsupported` error where there is none.
mod os {
    #[cfg(not(any(windows, target_os = "macos")))]
    use std::io;

    #[cfg(target_os = "macos")]
    pub(super) use super::macos::{delete, read, write};
    #[cfg(windows)]
    pub(super) use super::windows::{delete, read, write};

    #[cfg(not(any(windows, target_os = "macos")))]
    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "no OS credential store on this platform; use SENTINEL_CREDENTIAL_STORE=file",
        )
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    pub(super) fn read(_key: &str) -> io::Result<Option<Vec<u8>>> {
        Err(unsupported())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    pub(super) fn write(_key: &str, _blob: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    pub(super) fn delete(_key: &str) -> io::Result<()> {
        Err(unsupported())
    }
}
