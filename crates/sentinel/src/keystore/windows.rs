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

pub fn read(key: &str) -> io::Result<Option<Vec<u8>>> {
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
