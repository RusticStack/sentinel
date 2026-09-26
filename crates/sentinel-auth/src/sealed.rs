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
//! [`Key::reseal`] moves a ciphertext to the active key, and [`Key::retire`]
//! drops every other key once no ciphertext needs it.
//!
//! The same key also derives (BLAKE3 `derive_key`) the subkey for
//! [`Key::fingerprinter`]: request fingerprints stored beside ciphertext must
//! not be computable from the database alone, or a stored digest of a value
//! would let a stolen database confirm guesses of that value offline.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInOut, Payload},
};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const LEGACY_VERSION: u8 = 1;
const VERSION: u8 = 2;
const MAGIC: &[u8; 8] = b"SNTLKEY2";
const MAX_KEYS: usize = 32;
const MAX_KEY_FILE: usize = 13 + MAX_KEYS * 36;
const TAG_LEN: usize = 16;
/// BLAKE3 `derive_key` context for the subkey that keys stored request
/// fingerprints. Globally unique and fixed: changing it invalidates every
/// retained retry record, never a ciphertext.
const FINGERPRINT_CONTEXT: &str = "sentinel 2026-09-26 stored request fingerprint v1";

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

/// The key ID a stored ciphertext needs: format 2 names it, format 1 is the
/// legacy raw key (ID 0). `None` for anything that is not a sealed value.
pub fn key_id(sealed: &[u8]) -> Option<u32> {
    match sealed.first() {
        Some(&LEGACY_VERSION) => Some(0),
        Some(&VERSION) if sealed.len() >= 5 => {
            Some(u32::from_be_bytes(sealed[1..5].try_into().unwrap()))
        }
        _ => None,
    }
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
    /// Derived from the active key once at load: keys [`Fingerprinter`].
    fingerprint_key: [u8; 32],
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(redacted)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        for (_, key) in &mut self.keys {
            key.as_mut_slice().zeroize();
        }
        self.fingerprint_key.zeroize();
    }
}

/// A keyed BLAKE3 MAC over request fields, for idempotency fingerprints that
/// are stored in the database. Its key state is wiped when it is dropped.
pub struct Fingerprinter(blake3::Hasher);

impl Fingerprinter {
    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    /// The first 128 bits of the MAC.
    pub fn finish(self) -> u128 {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.0.finalize().as_bytes()[..16]);
        u128::from_le_bytes(out)
    }
}

impl Drop for Fingerprinter {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A key file's bytes, wiped when dropped.
struct KeyBytes(Vec<u8>);

impl Drop for KeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    /// Read a versioned or legacy 32-byte key from `path`. The file is the deployment's secret: it
    /// belongs outside the database directory's backups and is the operator's
    /// to protect, rotate and restore.
    pub fn load(path: &Path) -> Result<Key, SealError> {
        let bytes = read_key_file(path)?;
        Self::decode(&bytes.0)
    }

    fn from_keys(active: u32, keys: Vec<(u32, chacha20poly1305::Key)>) -> Self {
        let active_key = &keys.last().expect("at least one key").1;
        let mut material = [0u8; KEY_LEN];
        material.copy_from_slice(active_key.as_slice());
        let fingerprint_key = blake3::derive_key(FINGERPRINT_CONTEXT, &material);
        material.zeroize();
        Self {
            active,
            keys,
            fingerprint_key,
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, SealError> {
        if bytes.len() == KEY_LEN {
            return Ok(Self::from_keys(
                0,
                vec![(0, chacha20poly1305::Key::try_from(bytes).unwrap())],
            ));
        }
        if bytes.len() < 13 || &bytes[..8] != MAGIC {
            return Err(SealError::Key("invalid key file"));
        }
        let active = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let count = bytes[12] as usize;
        if count == 0 || count > MAX_KEYS || bytes.len() != 13 + count * 36 {
            return Err(SealError::Key("invalid key file"));
        }
        let mut keys: Vec<(u32, chacha20poly1305::Key)> = Vec::with_capacity(count);
        for entry in bytes[13..].chunks_exact(36) {
            let id = u32::from_be_bytes(entry[..4].try_into().unwrap());
            if keys.last().is_some_and(|(previous, _)| id <= *previous) {
                for (_, key) in &mut keys {
                    key.as_mut_slice().zeroize();
                }
                return Err(SealError::Key("unordered key identifiers"));
            }
            keys.push((id, chacha20poly1305::Key::try_from(&entry[4..]).unwrap()));
        }
        if keys.last().is_none_or(|(id, _)| *id != active) {
            for (_, key) in &mut keys {
                key.as_mut_slice().zeroize();
            }
            return Err(SealError::Key("active key missing"));
        }
        Ok(Self::from_keys(active, keys))
    }

    fn encode(&self) -> KeyBytes {
        let mut out = Vec::with_capacity(13 + self.keys.len() * 36);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.active.to_be_bytes());
        out.push(self.keys.len() as u8);
        for (id, key) in &self.keys {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(key);
        }
        KeyBytes(out)
    }

    /// Write a fresh key, refusing to overwrite an existing one: replacing a
    /// key makes every sealed value unreadable, which is a decision an operator
    /// makes deliberately, not a side effect of running a command twice.
    pub fn create(path: &Path) -> Result<(), SealError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).expect("operating system entropy");
        let key = Self::from_keys(
            1,
            vec![(1, chacha20poly1305::Key::try_from(&bytes[..]).unwrap())],
        );
        bytes.zeroize();
        let encoded = key.encode();
        write_private(path, &encoded.0).map_err(|e| {
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
    /// retains retired keys so existing ciphertexts remain readable until
    /// [`Key::retire`] drops them after a full reseal.
    pub fn rotate(path: &Path, backup: &Path) -> Result<u32, SealError> {
        if backup == path {
            return Err(SealError::Key("the backup must be a different file"));
        }
        let old = read_key_file(path)?;
        let mut key = Self::decode(&old.0)?;
        if key.keys.len() == MAX_KEYS {
            return Err(SealError::Key(
                "the key file holds 32 keys; reseal and retire old keys first",
            ));
        }
        if key.active == u32::MAX {
            return Err(SealError::Key("key identifiers are exhausted"));
        }
        let new_id = key.active + 1;
        let staged = pending_path(path, new_id);
        clear_pending(&staged)?;
        write_private(backup, &old.0).map_err(|_| SealError::Key("cannot create key backup"))?;
        sync_parent(backup).map_err(|_| SealError::Key("cannot sync key backup directory"))?;
        let mut fresh = [0u8; KEY_LEN];
        getrandom::fill(&mut fresh).expect("operating system entropy");
        let mut keys = std::mem::take(&mut key.keys);
        keys.push((new_id, chacha20poly1305::Key::try_from(&fresh[..]).unwrap()));
        fresh.zeroize();
        let rotated = Self::from_keys(new_id, keys);
        replace(path, &staged, &rotated.encode())?;
        Ok(new_id)
    }

    /// Drop every key but the active one, offline. The caller has proven that
    /// no stored ciphertext names a retired key ([`Key::reseal`] every row
    /// first). `backup` receives an exclusive owner-only copy of the file as
    /// it was, to keep with the matching database snapshot. Returns how many
    /// keys were removed; zero leaves the file untouched and writes no backup.
    pub fn retire(path: &Path, backup: &Path) -> Result<usize, SealError> {
        if backup == path {
            return Err(SealError::Key("the backup must be a different file"));
        }
        let old = read_key_file(path)?;
        let mut key = Self::decode(&old.0)?;
        let retired = key.keys.len() - 1;
        if retired == 0 {
            return Ok(0);
        }
        let staged = pending_path(path, key.active);
        clear_pending(&staged)?;
        write_private(backup, &old.0).map_err(|_| SealError::Key("cannot create key backup"))?;
        sync_parent(backup).map_err(|_| SealError::Key("cannot sync key backup directory"))?;
        let mut keys = std::mem::take(&mut key.keys);
        let active = keys.pop().expect("an active key");
        for (_, retired) in &mut keys {
            retired.as_mut_slice().zeroize();
        }
        let kept = Self::from_keys(key.active, vec![active]);
        replace(path, &staged, &kept.encode())?;
        Ok(retired)
    }

    /// The ID new seals are written under.
    pub fn active_id(&self) -> u32 {
        self.active
    }

    /// How many keys this file holds, the active one included.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Never true: a loaded key always has an active entry.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// A keyed MAC for fingerprints stored beside ciphertext. Keyed by a
    /// subkey of the active key, so a database copy alone cannot compute it;
    /// after a rotation earlier fingerprints no longer match.
    pub fn fingerprinter(&self) -> Fingerprinter {
        Fingerprinter(blake3::Hasher::new_keyed(&self.fingerprint_key))
    }

    /// Reseal `sealed` under the active key with the same `context`, or
    /// `None` when it is already a format-2 value of the active key. The
    /// plaintext is wiped before returning.
    pub fn reseal(&self, context: &[u8], sealed: &[u8]) -> Result<Option<Vec<u8>>, SealError> {
        if sealed.first() == Some(&VERSION) && key_id(sealed) == Some(self.active) {
            return Ok(None);
        }
        let mut plain = self.open(context, sealed)?;
        let fresh = self.seal(context, &plain);
        plain.zeroize();
        Ok(Some(fresh))
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

/// Open the key file once and judge the opened handle, so the file checked
/// is the file read (P10S-9). On Unix the open refuses a symbolic link, and
/// the handle must be a regular file owned by this user with no group or
/// other access. The buffer is sized up front: no reallocation leaves an
/// unwiped copy of key material behind.
fn read_key_file(path: &Path) -> Result<KeyBytes, SealError> {
    let mut file = open_key_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| SealError::Key("unreadable key file"))?;
    if !metadata.is_file() {
        return Err(SealError::Key("key path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(SealError::Key("key file must be owner-only"));
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(SealError::Key("key file must be owned by this user"));
        }
    }
    if metadata.len() > MAX_KEY_FILE as u64 {
        return Err(SealError::Key("invalid key file"));
    }
    let mut bytes = KeyBytes(Vec::with_capacity(MAX_KEY_FILE + 1));
    (&mut file)
        .take(MAX_KEY_FILE as u64 + 1)
        .read_to_end(&mut bytes.0)
        .map_err(|_| SealError::Key("unreadable key file"))?;
    if bytes.0.len() > MAX_KEY_FILE {
        return Err(SealError::Key("invalid key file"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_key_file(path: &Path) -> Result<File, SealError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                SealError::Key("key path is not a regular file")
            } else {
                SealError::Key("unreadable key file")
            }
        })
}

/// Windows is a development platform only: refuse a link by name, then
/// judge the opened handle as on Unix.
#[cfg(not(unix))]
fn open_key_file(path: &Path) -> Result<File, SealError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| SealError::Key("unreadable key file"))?;
    if !metadata.file_type().is_file() {
        return Err(SealError::Key("key path is not a regular file"));
    }
    File::open(path).map_err(|_| SealError::Key("unreadable key file"))
}

/// `master.key` → `master.key-<id>-pending`, beside the key.
fn pending_path(path: &Path, id: u32) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!("-{id}-pending"));
    path.with_file_name(name)
}

/// A staged key file is never active and staging runs under the database
/// ownership lock, so one left by an interrupted rotation is removed rather
/// than blocking every later rotation (P10S-10).
fn clear_pending(staged: &Path) -> Result<(), SealError> {
    match std::fs::remove_file(staged) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SealError::Key(
            "cannot remove a stale pending key file beside the key",
        )),
    }
}

/// Stage `encoded` beside `path`, sync it, and atomically replace `path`. A
/// failure removes the staged file.
fn replace(path: &Path, staged: &Path, encoded: &KeyBytes) -> Result<(), SealError> {
    if write_private(staged, &encoded.0).is_err() {
        let _ = std::fs::remove_file(staged);
        return Err(SealError::Key("cannot stage the new key file"));
    }
    if std::fs::rename(staged, path).is_err() {
        let _ = std::fs::remove_file(staged);
        return Err(SealError::Key("cannot activate the new key file"));
    }
    sync_parent(path).map_err(|_| SealError::Key("cannot sync key directory"))
}

/// Create the file owner-only from the start, so the key is never briefly
/// world-readable between `create` and a later `chmod`.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
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
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Windows is a development platform for Sentinel, not a controller host; the
/// file inherits the directory's ACL.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
        std::fs::write(&path, vec![0u8; MAX_KEY_FILE + 1]).unwrap();
        assert_eq!(
            Key::load(&path).err(),
            Some(SealError::Key("invalid key file"))
        );
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(Key::load(&path), Err(SealError::Key(_))));
        std::fs::create_dir(&path).unwrap();
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
        assert_eq!(key_id(&sealed), Some(0));
        assert_eq!(Key::rotate(&path, &backup).unwrap(), 1);
        assert_eq!(
            Key::load(&path).unwrap().open(b"owner", &sealed).unwrap(),
            b"legacy"
        );
        assert_eq!(
            Key::load(&backup).unwrap().open(b"owner", &sealed).unwrap(),
            b"legacy"
        );
        // The backup is the exact old file: a raw legacy key stays raw.
        assert_eq!(std::fs::read(&backup).unwrap(), bytes);
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

    /// P10S-10: an interrupted rotation leaves `master.key-N-pending`; the
    /// next rotation replaces it instead of failing for good.
    #[test]
    fn a_stale_pending_key_file_does_not_block_rotation() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let stale = dir.path().join("master.key-2-pending");
        std::fs::write(&stale, b"left behind by a crash").unwrap();
        assert_eq!(Key::rotate(&path, &dir.path().join("backup")).unwrap(), 2);
        assert!(!stale.exists());
        assert_eq!(Key::load(&path).unwrap().active_id(), 2);
    }

    /// P10S-5: after every ciphertext is resealed, retiring keeps only the
    /// active key: old ciphertext no longer opens, resealed ciphertext does,
    /// and rotation is available again however many times it ran before.
    #[test]
    fn reseal_then_retire_drops_old_keys_and_lifts_the_rotation_ceiling() {
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let original = Key::load(&path).unwrap();
        let old = original.seal(b"row", b"value");
        for n in 0..(MAX_KEYS - 1) {
            Key::rotate(&path, &dir.path().join(format!("rotate-{n}"))).unwrap();
        }
        assert_eq!(
            Key::rotate(&path, &dir.path().join("full")),
            Err(SealError::Key(
                "the key file holds 32 keys; reseal and retire old keys first"
            ))
        );
        let full = Key::load(&path).unwrap();
        assert_eq!(full.len(), MAX_KEYS);
        let resealed = full.reseal(b"row", &old).unwrap().unwrap();
        assert_eq!(key_id(&resealed), Some(full.active_id()));
        assert_eq!(full.reseal(b"row", &resealed).unwrap(), None);
        assert_eq!(full.reseal(b"other", &old), Err(SealError::Unsealable));

        let backup = dir.path().join("retire-backup");
        assert_eq!(Key::retire(&path, &backup).unwrap(), MAX_KEYS - 1);
        let kept = Key::load(&path).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept.active_id(), full.active_id());
        assert_eq!(kept.open(b"row", &resealed).unwrap(), b"value");
        assert_eq!(kept.open(b"row", &old), Err(SealError::Unsealable));
        // The backup still opens the retired ciphertext.
        assert_eq!(
            Key::load(&backup).unwrap().open(b"row", &old).unwrap(),
            b"value"
        );
        // Nothing to retire: no backup is written.
        let again = dir.path().join("again");
        assert_eq!(Key::retire(&path, &again).unwrap(), 0);
        assert!(!again.exists());
        assert!(Key::rotate(&path, &dir.path().join("after-retire")).is_ok());
    }

    /// P10S-1: the stored fingerprint is a MAC under a subkey of the master
    /// key, so it differs across keys and cannot be recomputed from the
    /// request alone.
    #[test]
    fn fingerprints_are_keyed_by_the_master_key() {
        let dir = scratch();
        let (a, b) = (dir.path().join("a.key"), dir.path().join("b.key"));
        Key::create(&a).unwrap();
        Key::create(&b).unwrap();
        let (a, b) = (Key::load(&a).unwrap(), Key::load(&b).unwrap());
        let mac = |key: &Key, value: &[u8]| {
            let mut f = key.fingerprinter();
            f.update(b"TOKEN").update(value);
            f.finish()
        };
        assert_eq!(mac(&a, b"hunter2"), mac(&a, b"hunter2"));
        assert_ne!(mac(&a, b"hunter2"), mac(&a, b"hunter3"));
        assert_ne!(mac(&a, b"hunter2"), mac(&b, b"hunter2"));
        let unkeyed = blake3::hash(b"TOKENhunter2");
        assert_ne!(
            &mac(&a, b"hunter2").to_le_bytes()[..],
            &unkeyed.as_bytes()[..16]
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_key_permissions_and_links_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            Key::load(&link).err(),
            Some(SealError::Key("key path is not a regular file"))
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            Key::load(&path),
            Err(SealError::Key("key file must be owner-only"))
        ));
    }
}
