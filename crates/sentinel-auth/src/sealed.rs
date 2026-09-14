//! Authenticated encryption for the few values that must be recoverable.
//!
//! Almost everything here is a digest: passwords, sessions, credentials and
//! invitations are never stored in a form that could be presented back. A TOTP
//! shared secret is the exception — verifying a code requires the secret — so
//! it is sealed under a key that lives **outside** the database, in a file the
//! operator controls. A stolen `metadata.sqlite` then yields no seed and no
//! ability to mint codes.
//!
//! XChaCha20-Poly1305 through the maintained RustCrypto implementation: random
//! 192-bit nonces, so no counter has to be tracked, and associated data binds
//! each ciphertext to the row it belongs to.

use std::path::Path;

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// Version byte, so a future key rotation or cipher change is distinguishable
/// from corruption rather than guessed at.
const VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// The key file is missing, unreadable, or not exactly 32 bytes.
    Key(&'static str),
    /// The stored value is truncated, of an unknown version, or fails its
    /// authentication tag — including when it is presented with the wrong
    /// associated data.
    Unsealable,
}

/// A loaded master key. Held in memory for the life of the process; never
/// written to the database, a log or an error.
pub struct Key(chacha20poly1305::Key);

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(redacted)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.fill(0);
        core::hint::black_box(&mut self.0);
    }
}

impl Key {
    /// Read a 32-byte key from `path`. The file is the deployment's secret: it
    /// belongs outside the database directory's backups and is the operator's
    /// to protect, rotate and restore.
    pub fn load(path: &Path) -> Result<Key, SealError> {
        let bytes = std::fs::read(path).map_err(|_| SealError::Key("unreadable key file"))?;
        if bytes.len() != KEY_LEN {
            return Err(SealError::Key("key file must be exactly 32 bytes"));
        }
        let key = chacha20poly1305::Key::try_from(&bytes[..])
            .map_err(|_| SealError::Key("key file must be exactly 32 bytes"))?;
        Ok(Key(key))
    }

    /// Write a fresh key, refusing to overwrite an existing one: replacing a
    /// key makes every sealed value unreadable, which is a decision an operator
    /// makes deliberately, not a side effect of running a command twice.
    pub fn create(path: &Path) -> Result<(), SealError> {
        if path.exists() {
            return Err(SealError::Key("key file already exists"));
        }
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        write_private(path, &bytes).map_err(|_| SealError::Key("cannot write the key file"))?;
        bytes.fill(0);
        Ok(())
    }

    /// Seal `plaintext`, binding it to `context` (the row's identity). The
    /// result is `version || nonce || ciphertext`, safe to store as a blob.
    pub fn seal(&self, context: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("operating system entropy");
        let sealed = XChaCha20Poly1305::new(&self.0)
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: context,
                },
            )
            .expect("xchacha20-poly1305 encryption");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    /// Open a sealed value. Fails if the key, the context or any byte differs:
    /// a value sealed for one account cannot be opened as another's.
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        let Some((&VERSION, rest)) = sealed.split_first() else {
            return Err(SealError::Unsealable);
        };
        if rest.len() <= NONCE_LEN {
            return Err(SealError::Unsealable);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        XChaCha20Poly1305::new(&self.0)
            .decrypt(
                &XNonce::try_from(nonce).map_err(|_| SealError::Unsealable)?,
                Payload {
                    msg: ciphertext,
                    aad: context,
                },
            )
            .map_err(|_| SealError::Unsealable)
    }
}

/// Create the file owner-only from the start, so the key is never briefly
/// world-readable between `create` and a later `chmod`.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Windows is a development platform for Sentinel, not a controller host; the
/// file inherits the directory's ACL.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sentinel-sealed-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("master.key")
    }

    #[test]
    fn a_sealed_value_opens_only_with_its_key_and_its_context() {
        let path = scratch("roundtrip");
        let _ = std::fs::remove_file(&path);
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();

        let sealed = key.seal(b"usr_a", b"a totp seed");
        assert_eq!(key.open(b"usr_a", &sealed).unwrap(), b"a totp seed");
        assert_eq!(key.open(b"usr_b", &sealed), Err(SealError::Unsealable));
        assert!(!sealed.windows(4).any(|w| w == b"totp"), "plaintext leaked");

        // Two sealings of one value differ: the nonce is fresh each time.
        assert_ne!(sealed, key.seal(b"usr_a", b"a totp seed"));

        let other = scratch("other");
        let _ = std::fs::remove_file(&other);
        Key::create(&other).unwrap();
        let other = Key::load(&other).unwrap();
        assert_eq!(other.open(b"usr_a", &sealed), Err(SealError::Unsealable));
        assert!(!format!("{key:?}").contains("Key(["));
    }

    #[test]
    fn damaged_truncated_or_unknown_versions_are_refused() {
        let path = scratch("damaged");
        let _ = std::fs::remove_file(&path);
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();
        let sealed = key.seal(b"ctx", b"seed");

        for damaged in [
            Vec::new(),
            sealed[..1].to_vec(),
            sealed[..sealed.len() - 1].to_vec(),
            {
                let mut v = sealed.clone();
                v[0] = 2;
                v
            },
            {
                let mut v = sealed.clone();
                *v.last_mut().unwrap() ^= 1;
                v
            },
        ] {
            assert_eq!(key.open(b"ctx", &damaged), Err(SealError::Unsealable));
        }
    }

    #[test]
    fn a_key_file_is_created_once_and_must_be_the_right_size() {
        let path = scratch("create");
        let _ = std::fs::remove_file(&path);
        Key::create(&path).unwrap();
        assert_eq!(
            Key::create(&path),
            Err(SealError::Key("key file already exists"))
        );
        std::fs::write(&path, b"too short").unwrap();
        assert!(matches!(Key::load(&path), Err(SealError::Key(_))));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(Key::load(&path), Err(SealError::Key(_))));
    }
}
