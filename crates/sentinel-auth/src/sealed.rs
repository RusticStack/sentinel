//! Authenticated encryption for the few values that must be recoverable.
//!
//! Almost everything here is a digest: passwords, sessions, credentials and
//! invitations are never stored in a form that could be presented back. A TOTP
//! shared secret is the exception — verifying a code requires the secret — so
//! it is sealed under a key that lives **outside** the database, in a file the
//! operator controls. A stolen `metadata.sqlite` then yields no seed and no
//! ability to mint codes.
//!
//! XChaCha20-Poly1305 through RustCrypto: random 192-bit nonces and associated
//! data binding each ciphertext to its owner. The key file retains retired keys
//! during rotation; losing one makes its remaining ciphertexts unrecoverable.

use std::path::Path;

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInOut, Payload},
};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const LEGACY_VERSION: u8 = 1;
const VERSION: u8 = 2;
const MAGIC: &[u8; 8] = b"SNTLKEY2";
const MAX_KEYS: usize = 32;
const TAG_LEN: usize = 16;

/// Unambiguous ownership context for future tenant or repository secrets.
/// The caller validates the name and supplies the durable secret version.
pub fn secret_context(
    tenant: &[u8; 16],
    repo: Option<&[u8; 16]>,
    name: &str,
    version: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + 16 + 1 + 16 + 4 + name.len() + 8);
    out.extend_from_slice(b"secret/v1:\x00");
    out.extend_from_slice(tenant);
    match repo {
        Some(repo) => {
            out.push(1);
            out.extend_from_slice(repo);
        }
        None => out.push(0),
    }
    out.extend_from_slice(
        &u32::try_from(name.len())
            .expect("bounded secret name")
            .to_be_bytes(),
    );
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out
}

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
pub struct Key {
    active: u32,
    keys: Vec<(u32, chacha20poly1305::Key)>,
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(redacted)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        for (_, key) in &mut self.keys {
            key.fill(0);
            core::hint::black_box(key);
        }
    }
}

impl Key {
    /// Read a versioned or legacy 32-byte key from `path`. The file is the deployment's secret: it
    /// belongs outside the database directory's backups and is the operator's
    /// to protect, rotate and restore.
    pub fn load(path: &Path) -> Result<Key, SealError> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| SealError::Key("unreadable key file"))?;
        if !metadata.file_type().is_file() {
            return Err(SealError::Key("key path is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 {
                return Err(SealError::Key("key file must be owner-only"));
            }
        }
        if metadata.len() > (13 + MAX_KEYS * 36) as u64 {
            return Err(SealError::Key("invalid key file"));
        }
        let mut bytes = std::fs::read(path).map_err(|_| SealError::Key("unreadable key file"))?;
        let parsed = Self::decode(&bytes);
        bytes.fill(0);
        parsed
    }

    fn decode(bytes: &[u8]) -> Result<Self, SealError> {
        if bytes.len() == KEY_LEN {
            return Ok(Self {
                active: 0,
                keys: vec![(0, chacha20poly1305::Key::try_from(bytes).unwrap())],
            });
        }
        if bytes.len() < 13 || &bytes[..8] != MAGIC {
            return Err(SealError::Key("invalid key file"));
        }
        let active = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let count = bytes[12] as usize;
        if count == 0 || count > MAX_KEYS || bytes.len() != 13 + count * 36 {
            return Err(SealError::Key("invalid key file"));
        }
        let mut keys = Vec::with_capacity(count);
        for entry in bytes[13..].chunks_exact(36) {
            let id = u32::from_be_bytes(entry[..4].try_into().unwrap());
            if keys.last().is_some_and(|(previous, _)| id <= *previous) {
                return Err(SealError::Key("unordered key identifiers"));
            }
            keys.push((id, chacha20poly1305::Key::try_from(&entry[4..]).unwrap()));
        }
        if keys.last().is_none_or(|(id, _)| *id != active) {
            return Err(SealError::Key("active key missing"));
        }
        Ok(Self { active, keys })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.keys.len() * 36);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.active.to_be_bytes());
        out.push(self.keys.len() as u8);
        for (id, key) in &self.keys {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    /// Write a fresh key, refusing to overwrite an existing one: replacing a
    /// key makes every sealed value unreadable, which is a decision an operator
    /// makes deliberately, not a side effect of running a command twice.
    pub fn create(path: &Path) -> Result<(), SealError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        let key = Self {
            active: 1,
            keys: vec![(1, chacha20poly1305::Key::try_from(&bytes[..]).unwrap())],
        };
        bytes.fill(0);
        let mut encoded = key.encode();
        let result = write_private(path, &encoded);
        encoded.fill(0);
        result.map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SealError::Key("key file already exists")
            } else {
                SealError::Key("cannot write the key file")
            }
        })?;
        sync_parent(path).map_err(|_| SealError::Key("cannot sync key directory"))?;
        Ok(())
    }

    /// Rotate offline. `backup` is a new owner-only copy of the exact old key
    /// file. Keep it with the matching database backup; the active key file
    /// retains retired keys so existing ciphertexts remain readable.
    pub fn rotate(path: &Path, backup: &Path) -> Result<u32, SealError> {
        let mut key = Self::load(path)?;
        if key.keys.len() == MAX_KEYS || key.active == u32::MAX || backup == path {
            return Err(SealError::Key("key rotation unavailable"));
        }
        let new_id = key.active + 1;
        let mut old = std::fs::read(path).map_err(|_| SealError::Key("unreadable key file"))?;
        let backup_result = write_private(backup, &old);
        old.fill(0);
        backup_result.map_err(|_| SealError::Key("cannot create key backup"))?;
        sync_parent(backup).map_err(|_| SealError::Key("cannot sync key backup directory"))?;
        let mut fresh = [0u8; KEY_LEN];
        getrandom::fill(&mut fresh).expect("operating system entropy");
        key.keys
            .push((new_id, chacha20poly1305::Key::try_from(&fresh[..]).unwrap()));
        fresh.fill(0);
        key.active = new_id;
        let mut encoded = key.encode();
        let temp = path.with_extension(format!("key-{}-pending", new_id));
        let result = write_private(&temp, &encoded);
        encoded.fill(0);
        result.map_err(|_| SealError::Key("cannot stage rotated key"))?;
        std::fs::rename(&temp, path).map_err(|_| SealError::Key("cannot activate rotated key"))?;
        sync_parent(path).map_err(|_| SealError::Key("cannot sync key directory"))?;
        Ok(new_id)
    }

    fn active_key(&self) -> &chacha20poly1305::Key {
        &self.keys.last().unwrap().1
    }
    /// Seal `plaintext`, binding it to `context` (the row's identity). The
    /// result is `version || key_id || nonce || ciphertext`.
    pub fn seal(&self, context: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("operating system entropy");
        let mut header = [0u8; 5];
        header[0] = VERSION;
        header[1..].copy_from_slice(&self.active.to_be_bytes());
        let mut aad = Vec::with_capacity(header.len() + context.len());
        aad.extend_from_slice(&header);
        aad.extend_from_slice(context);
        let mut out = Vec::with_capacity(5 + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        let tag = XChaCha20Poly1305::new(self.active_key())
            .encrypt_inout_detached(
                &XNonce::from(nonce),
                &aad,
                (&mut out[5 + NONCE_LEN..]).into(),
            )
            .expect("xchacha20-poly1305 encryption");
        out.extend_from_slice(&tag);
        out
    }

    /// Open a sealed value. Fails if the key, the context or any byte differs:
    /// a value sealed for one account cannot be opened as another's.
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        let (id, offset, aad): (u32, usize, &[u8]) = match sealed.first() {
            Some(&LEGACY_VERSION) => (0, 1, context),
            Some(&VERSION) if sealed.len() >= 5 => (
                u32::from_be_bytes(sealed[1..5].try_into().unwrap()),
                5,
                context,
            ),
            _ => return Err(SealError::Unsealable),
        };
        if sealed.len() < offset + NONCE_LEN + TAG_LEN {
            return Err(SealError::Unsealable);
        }
        let index = self
            .keys
            .binary_search_by_key(&id, |(candidate, _)| *candidate)
            .map_err(|_| SealError::Unsealable)?;
        let key = &self.keys[index].1;
        let (nonce, ciphertext) = sealed[offset..].split_at(NONCE_LEN);
        let mut bound = Vec::new();
        let aad = if offset == 5 {
            bound.reserve(5 + aad.len());
            bound.extend_from_slice(&sealed[..5]);
            bound.extend_from_slice(aad);
            &bound[..]
        } else {
            aad
        };
        XChaCha20Poly1305::new(key)
            .decrypt(
                &XNonce::try_from(nonce).map_err(|_| SealError::Unsealable)?,
                Payload {
                    msg: ciphertext,
                    aad,
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

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
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

    /// A fresh directory for key files, removed when the test ends.
    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_sealed_value_opens_only_with_its_key_and_its_context() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();

        let sealed = key.seal(b"usr_a", b"a totp seed");
        assert_eq!(key.open(b"usr_a", &sealed).unwrap(), b"a totp seed");
        assert_eq!(key.open(b"usr_b", &sealed), Err(SealError::Unsealable));
        assert!(!sealed.windows(4).any(|w| w == b"totp"), "plaintext leaked");

        // Two sealings of one value differ: the nonce is fresh each time.
        assert_ne!(sealed, key.seal(b"usr_a", b"a totp seed"));

        let other = dir.path().join("other.key");
        Key::create(&other).unwrap();
        let other = Key::load(&other).unwrap();
        assert_eq!(other.open(b"usr_a", &sealed), Err(SealError::Unsealable));
        assert!(!format!("{key:?}").contains("Key(["));
    }

    #[test]
    fn damaged_truncated_or_unknown_versions_are_refused() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();
        let sealed = key.seal(b"ctx", b"seed");

        for damaged in [
            Vec::new(),
            sealed[..1].to_vec(),
            sealed[..sealed.len() - 1].to_vec(),
            {
                let mut v = sealed.clone();
                v[0] = 3;
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
        let dir = scratch();
        let path = dir.path().join("master.key");
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

    #[test]
    fn rotation_preserves_old_values_and_backup_restores_matching_snapshot() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        let backup = dir.path().join("master.backup");
        Key::create(&path).unwrap();
        let old = Key::load(&path).unwrap();
        let before = old.seal(b"tenant/repo/name/version", b"before");
        assert_eq!(Key::rotate(&path, &backup).unwrap(), 2);
        let current = Key::load(&path).unwrap();
        assert_eq!(
            current.open(b"tenant/repo/name/version", &before).unwrap(),
            b"before"
        );
        let after = current.seal(b"tenant/repo/name/version", b"after");
        assert_eq!(after[0], VERSION);
        assert_eq!(&after[1..5], &2u32.to_be_bytes());
        assert_eq!(
            Key::load(&backup)
                .unwrap()
                .open(b"tenant/repo/name/version", &before)
                .unwrap(),
            b"before"
        );
        assert_eq!(
            Key::load(&backup)
                .unwrap()
                .open(b"tenant/repo/name/version", &after),
            Err(SealError::Unsealable)
        );
        assert_eq!(
            Key::rotate(&path, &backup),
            Err(SealError::Key("cannot create key backup"))
        );
        let mut swapped = after.clone();
        swapped[4] = 1;
        assert_eq!(
            current.open(b"tenant/repo/name/version", &swapped),
            Err(SealError::Unsealable)
        );
        assert_eq!(
            current.open(b"tenant/other/name/version", &after),
            Err(SealError::Unsealable)
        );
    }

    #[test]
    fn legacy_key_and_ciphertext_survive_rotation() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        let backup = dir.path().join("legacy.backup");
        let bytes = [7u8; KEY_LEN];
        write_private(&path, &bytes).unwrap();
        let nonce = [9u8; NONCE_LEN];
        let cipher = XChaCha20Poly1305::new(&chacha20poly1305::Key::try_from(&bytes[..]).unwrap());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"legacy",
                    aad: b"owner",
                },
            )
            .unwrap();
        let mut sealed = vec![LEGACY_VERSION];
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        assert_eq!(Key::rotate(&path, &backup).unwrap(), 1);
        assert_eq!(
            Key::load(&path).unwrap().open(b"owner", &sealed).unwrap(),
            b"legacy"
        );
        assert_eq!(
            Key::load(&backup).unwrap().open(b"owner", &sealed).unwrap(),
            b"legacy"
        );
    }

    #[test]
    fn secret_context_binds_every_owner_and_version_component() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();
        let tenant = [1; 16];
        let repo = [2; 16];
        let context = secret_context(&tenant, Some(&repo), "TOKEN", 4);
        let sealed = key.seal(&context, b"value");
        assert_eq!(key.open(&context, &sealed).unwrap(), b"value");
        for wrong in [
            secret_context(&[3; 16], Some(&repo), "TOKEN", 4),
            secret_context(&tenant, Some(&[3; 16]), "TOKEN", 4),
            secret_context(&tenant, None, "TOKEN", 4),
            secret_context(&tenant, Some(&repo), "TOKEN2", 4),
            secret_context(&tenant, Some(&repo), "TOKEN", 5),
        ] {
            assert_eq!(key.open(&wrong, &sealed), Err(SealError::Unsealable));
        }
    }

    #[cfg(unix)]
    #[test]
    fn loose_key_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            Key::load(&path),
            Err(SealError::Key("key file must be owner-only"))
        ));
    }
}
