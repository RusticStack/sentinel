//! Windows Credential Manager backend: one `CRED_TYPE_GENERIC` credential per
//! profile, persisted `CRED_PERSIST_LOCAL_MACHINE` (this user, this machine,
//! not roamed), keyed by `sentinel:{issuer}:{profile}`.

use std::{io, ptr};

use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, GetLastError},
    Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    },
};

/// The largest blob Credential Manager stores for a generic credential
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`, 5 × 512 bytes).
const MAX_BLOB: usize = 5 * 512;

/// UTF-16, NUL-terminated.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> io::Error {
    // SAFETY: GetLastError only reads the calling thread's last-error value.
    let code = unsafe { GetLastError() };
    io::Error::from_raw_os_error(code as i32)
}

/// How long a Credential Manager call waits for another Sentinel process's.
const STORE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Held around every Credential Manager call. With several processes
/// writing at once, `CredReadW` was measured answering `ERROR_NOT_FOUND`
/// for an entry another thread had just written and nobody deleted (15 of
/// 20 probe processes, four at a time, lost reads; one process alone never
/// did). Sentinel processes of this logon session therefore take turns;
/// each call holds the lock for one short system call.
fn store_lock() -> io::Result<NamedLock> {
    NamedLock::acquire(r"Local\sentinel-credential-manager", STORE_WAIT)
}

pub fn read(key: &str) -> io::Result<Option<Vec<u8>>> {
    let _turn = store_lock()?;
    let target = wide(key);
    let mut credential: *mut CREDENTIALW = ptr::null_mut();
    // SAFETY: `target` is a NUL-terminated UTF-16 string alive for the call,
    // and `credential` is a valid out-pointer the call fills on success.
    let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if ok == 0 {
        let error = last_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            return Ok(None);
        }
        return Err(error);
    }
    // SAFETY: on success `credential` points to a CREDENTIALW allocated by
    // CredReadW whose blob is `CredentialBlobSize` readable bytes (or null
    // when empty); it is copied out before CredFree releases it, exactly once.
    let blob = unsafe {
        let record = &*credential;
        let blob = if record.CredentialBlob.is_null() || record.CredentialBlobSize == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(record.CredentialBlob, record.CredentialBlobSize as usize)
                .to_vec()
        };
        CredFree(credential.cast());
        blob
    };
    Ok(Some(blob))
}

pub fn write(key: &str, blob: &[u8]) -> io::Result<()> {
    if blob.len() > MAX_BLOB {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential larger than Credential Manager stores",
        ));
    }
    let _turn = store_lock()?;
    let mut target = wide(key);
    let mut user = wide("sentinel");
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob.len() as u32,
        // CredWriteW only reads the blob; the API type is merely not const.
        CredentialBlob: blob.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: user.as_mut_ptr(),
        ..CREDENTIALW::default()
    };
    // SAFETY: every pointer in `credential` (target name, user name, blob)
    // refers to memory alive for the duration of the call; CredWriteW copies
    // what it keeps and does not write through them.
    let ok = unsafe { CredWriteW(&credential, 0) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

pub fn delete(key: &str) -> io::Result<()> {
    let _turn = store_lock()?;
    let target = wide(key);
    // SAFETY: `target` is a NUL-terminated UTF-16 string alive for the call.
    let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ok == 0 {
        let error = last_error();
        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
            return Err(error);
        }
    }
    Ok(())
}

/// Held while a legacy shared entry is refreshed (P09C-8): the entry is
/// shared by every configuration directory of this user, while profile
/// locks live in each directory, so two directories could otherwise both
/// present its refresh token at once. A named mutex in this logon
/// session's namespace, named after the key's digest, serializes them.
pub struct LegacyLock(#[allow(dead_code)] NamedLock);

impl LegacyLock {
    /// Wait at most `deadline` for the legacy entry `key`.
    pub fn acquire(key: &str, deadline: std::time::Duration) -> io::Result<LegacyLock> {
        let digest = blake3::hash(key.as_bytes()).to_hex();
        NamedLock::acquire(
            &format!(r"Local\sentinel-legacy-{}", &digest[..32]),
            deadline,
        )
        .map(LegacyLock)
    }
}

/// An owned named mutex of this logon session. The OS releases it if the
/// holder dies (the next waiter then sees `WAIT_ABANDONED`, which still
/// grants ownership). Ownership belongs to the acquiring thread, which
/// releases it on drop; the guard is not `Send`.
struct NamedLock(windows_sys::Win32::Foundation::HANDLE);

impl NamedLock {
    fn acquire(name: &str, deadline: std::time::Duration) -> io::Result<NamedLock> {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{CreateMutexW, WaitForSingleObject},
        };
        let name = wide(name);
        // SAFETY: `name` is a NUL-terminated UTF-16 string alive for the
        // call; default security and no initial ownership.
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(last_error());
        }
        let millis = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: `handle` is the live mutex handle opened above.
        match unsafe { WaitForSingleObject(handle, millis) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(NamedLock(handle)),
            code => {
                let error = if code == WAIT_TIMEOUT {
                    io::Error::new(io::ErrorKind::TimedOut, "credential store is busy")
                } else {
                    last_error()
                };
                // SAFETY: the handle was opened above and is closed once.
                unsafe { CloseHandle(handle) };
                Err(error)
            }
        }
    }
}

impl Drop for NamedLock {
    fn drop(&mut self) {
        use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::ReleaseMutex};
        // SAFETY: this thread owns the mutex (the guard never leaves the
        // acquiring thread); the handle is closed once.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    use super::LegacyLock;

    /// One holder per legacy key at a time, across threads (and so across
    /// processes of this session); other keys are independent; a waiter
    /// past its deadline is told so.
    #[test]
    fn a_legacy_entry_is_refreshed_by_one_holder_at_a_time() {
        let key = format!("sentinel:test-legacy-lock:{}", std::process::id());
        let held = LegacyLock::acquire(&key, Duration::from_secs(1)).unwrap();
        let other = LegacyLock::acquire(&format!("{key}:other"), Duration::from_millis(1));
        assert!(other.is_ok(), "another key is independent");
        drop(other);
        let got = Arc::new(AtomicBool::new(false));
        let (k, flag) = (key.clone(), Arc::clone(&got));
        let waiter = thread::spawn(move || {
            let timed_out = LegacyLock::acquire(&k, Duration::from_millis(20));
            assert_eq!(
                timed_out.err().unwrap().kind(),
                std::io::ErrorKind::TimedOut
            );
            let lock = LegacyLock::acquire(&k, Duration::from_secs(10)).unwrap();
            flag.store(true, Ordering::SeqCst);
            drop(lock);
        });
        // The waiter cannot have it while this thread holds it.
        thread::sleep(Duration::from_millis(100));
        assert!(!got.load(Ordering::SeqCst));
        drop(held);
        waiter.join().unwrap();
        assert!(got.load(Ordering::SeqCst));
    }
}
