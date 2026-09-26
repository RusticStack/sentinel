//! The owner-only file store, `credentials/<profile>.json`, and the private
//! file helpers the profile module shares: on Unix, directories are created
//! `0700` and files `0600`, and a directory or file another user can reach
//! (`mode & 0o077 != 0`) or that another user owns is refused with the
//! command that fixes it. Files are replaced atomically (write a sibling,
//! `fsync`, rename), so a reader never sees half a credential and a crash
//! never loses a rotated refresh token that was reported written. On
//! Windows a directory Sentinel creates, and the `credentials` directory on
//! every credential write, get a protected DACL granting only the current
//! user and SYSTEM (inherited by the files inside), so the store is
//! owner-only wherever `SENTINEL_CONFIG_DIR` points — not only under the
//! per-user `%APPDATA%`.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::client::Error;

/// The largest credential or profiles file read back (a credential blob is
/// about 250 bytes; `profiles.json` a few hundred per profile).
const MAX_FILE: u64 = 1 << 20;

pub fn credentials_dir(dir: &Path) -> PathBuf {
    dir.join("credentials")
}

/// `credentials/<profile>.json` (profile names are validated by the caller
/// to a safe file-name alphabet).
pub fn path(dir: &Path, profile: &str) -> PathBuf {
    let mut path = credentials_dir(dir);
    path.push(format!("{profile}.json"));
    path
}

pub fn read(dir: &Path, profile: &str) -> Result<Option<Vec<u8>>, Error> {
    let creds = credentials_dir(dir);
    match fs::metadata(&creds) {
        Ok(meta) => check_meta(&creds, &meta, true)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read", &creds, &e)),
    }
    read_private(&path(dir, profile))
}

pub fn write(dir: &Path, profile: &str, blob: &[u8]) -> Result<(), Error> {
    ensure_private_dir(dir)?;
    let creds = credentials_dir(dir);
    ensure_private_dir(&creds)?;
    // A directory made by an older Sentinel, or by someone else, is brought
    // to owner-only before a refresh token goes into it (Unix refuses a
    // loose one in `ensure_private_dir` instead).
    #[cfg(windows)]
    acl::owner_only(&creds).map_err(|e| io_error("restrict access to", &creds, &e))?;
    write_private(&path(dir, profile), blob)
}

pub fn delete(dir: &Path, profile: &str) -> Result<(), Error> {
    let path = path(dir, profile);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error("delete", &path, &e)),
    }
}

/// Read a private file, checking the opened file itself (no race between
/// the check and the read). `Ok(None)` when it does not exist.
pub fn read_private(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("read", path, &e)),
    };
    let meta = file.metadata().map_err(|e| io_error("read", path, &e))?;
    check_meta(path, &meta, false)?;
    if meta.len() > MAX_FILE {
        return Err(Error::usage(format!(
            "{} is larger than a Sentinel file can be",
            path.display()
        )));
    }
    // The length check above is a fast refusal; the read is what is bounded,
    // since the file can grow after `metadata`.
    match crate::bounded::read(file, MAX_FILE) {
        Ok(data) => Ok(Some(data)),
        Err(crate::bounded::ReadError::Io(e)) => Err(io_error("read", path, &e)),
        Err(_) => Err(Error::usage(format!(
            "{} is larger than a Sentinel file can be",
            path.display()
        ))),
    }
}

/// Create `path` (and missing parents) owner-only, or check an existing one.
pub fn ensure_private_dir(path: &Path) -> Result<(), Error> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => check_meta(path, &meta, true),
        Ok(_) => Err(Error::usage(format!(
            "{} is not a directory",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(path)
                .map_err(|e| io_error("create", path, &e))?;
            #[cfg(windows)]
            acl::owner_only(path).map_err(|e| io_error("restrict access to", path, &e))?;
            Ok(())
        }
        Err(e) => Err(io_error("read", path, &e)),
    }
}

/// Check that `path` is owner-only and owned by this user (Unix; always
/// accepted elsewhere).
pub fn check_private(path: &Path) -> Result<(), Error> {
    let meta = fs::metadata(path).map_err(|e| io_error("read", path, &e))?;
    check_meta(path, &meta, meta.is_dir())
}

/// Check the already-open secret input itself, so the read and permission
/// check refer to the same file even if its path changes concurrently.
pub fn check_private_input(path: &Path, file: &File) -> Result<(), Error> {
    let meta = file.metadata().map_err(|e| io_error("inspect", path, &e))?;
    if !meta.is_file() {
        return Err(Error::usage("secret input must be a regular file"));
    }
    #[cfg(unix)]
    {
        check_unix(path, &meta, false, rustix::process::geteuid().as_raw())
    }
    #[cfg(windows)]
    {
        acl::check_input(file).map_err(|_| {
            Error::usage(format!(
                "{} must be owned by you and allow only you and SYSTEM; fix: icacls \"{}\" /setowner \"%USERNAME%\" && icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
                path.display(),
                path.display(),
                path.display()
            ))
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(())
    }
}

/// [`check_private`] as if the effective user were `euid`: lets tests
/// exercise the foreign-owner refusal without a second account.
#[cfg(unix)]
#[doc(hidden)]
pub fn check_private_as(path: &Path, euid: u32) -> Result<(), Error> {
    let meta = fs::metadata(path).map_err(|e| io_error("read", path, &e))?;
    check_unix(path, &meta, meta.is_dir(), euid)
}

#[cfg(unix)]
fn check_meta(path: &Path, meta: &fs::Metadata, dir: bool) -> Result<(), Error> {
    check_unix(path, meta, dir, rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
fn check_meta(_path: &Path, _meta: &fs::Metadata, _dir: bool) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn check_unix(path: &Path, meta: &fs::Metadata, dir: bool, euid: u32) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    if meta.uid() != euid {
        return Err(Error::usage(format!(
            "{} is owned by uid {}, not by you (uid {euid}); fix: sudo chown \"$(id -u)\" '{}' (or remove it)",
            path.display(),
            meta.uid(),
            path.display()
        )));
    }
    if mode & 0o077 != 0 {
        return Err(Error::usage(format!(
            "{} is accessible to other users (mode {mode:03o}); fix: chmod {} '{}'",
            path.display(),
            if dir { "700" } else { "600" },
            path.display()
        )));
    }
    Ok(())
}

/// Open (creating owner-only) a file for locking.
pub fn open_lock(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map_err(|e| io_error("open", path, &e))
}

/// Replace `path` atomically with `data`, owner-only and durable before the
/// rename.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok::<(), io::Error>(())
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_error("write", path, &e)
    })
}

fn io_error(what: &str, path: &Path, error: &io::Error) -> Error {
    Error::usage(format!("cannot {what} {}: {error}", path.display()))
}

/// Owner-only access on Windows: a protected DACL (no inherited entries)
/// granting full control to the current user and to SYSTEM, inherited by
/// everything created inside. The equivalent of `chmod 700`.
#[cfg(windows)]
mod acl {
    use std::{ffi::c_void, fs::File, io, iter, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, GENERIC_ALL, HANDLE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
                SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
                TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_TYPE, TRUSTEE_W,
            },
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSID, SECURITY_MAX_SID_SIZE, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY,
            TOKEN_USER, TokenUser, WinLocalSystemSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    fn entry(sid: *mut c_void, kind: TRUSTEE_TYPE) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: kind,
                ptstrName: sid.cast(),
            },
        }
    }

    pub(super) fn owner_only(path: &Path) -> io::Result<()> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer for the opened handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // TOKEN_USER plus the SID it points at: at most 16 + 68 bytes. u64
        // storage keeps the pointer inside TOKEN_USER aligned.
        let mut user = [0u64; 16];
        let mut len = 0u32;
        // SAFETY: `token` is the live token handle opened above; `user` is
        // writable and 8-aligned for its whole byte length, which is passed.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                user.as_mut_ptr().cast(),
                size_of_val(&user) as u32,
                &mut len,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: `token` was opened above and is closed exactly once.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(error);
        }
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // pointer refers into the same buffer, which outlives its uses below.
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut system = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut system_len = SECURITY_MAX_SID_SIZE;
        // SAFETY: `system` is writable for `system_len` bytes, the maximum
        // size of any SID; no domain SID is needed for LocalSystem.
        let ok = unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                system.as_mut_ptr().cast(),
                &mut system_len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let entries = [
            entry(user_sid, TRUSTEE_IS_USER),
            entry(system.as_mut_ptr().cast(), TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];
        let mut acl: *mut ACL = ptr::null_mut();
        // SAFETY: `entries` and the SIDs they point at live across the call;
        // `acl` receives a LocalAlloc'd ACL owned by this function.
        let code = unsafe { SetEntriesInAclW(2, entries.as_ptr(), ptr::null(), &mut acl) };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path alive for the call
        // and `acl` a valid ACL from SetEntriesInAclW; owner, group and SACL
        // are not being set, so their null pointers are not read.
        let code = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            )
        };
        // SAFETY: `acl` was allocated by SetEntriesInAclW (LocalAlloc) and
        // is freed exactly once, after its last use.
        unsafe { LocalFree(acl.cast()) };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }

    pub(super) fn check_input(file: &File) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer for the opened handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut user = [0u64; 16];
        let mut user_len = 0u32;
        // SAFETY: `token` is live; `user` is aligned writable storage large
        // enough for TOKEN_USER and its bounded SID.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                user.as_mut_ptr().cast(),
                size_of_val(&user) as u32,
                &mut user_len,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: this token was opened above and is closed exactly once.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(error);
        }
        // SAFETY: on success the token buffer begins with TOKEN_USER; its SID
        // pointer refers into `user`, which remains alive through the checks.
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut system = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut system_len = SECURITY_MAX_SID_SIZE;
        // SAFETY: writable storage is at least SECURITY_MAX_SID_SIZE bytes.
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                system.as_mut_ptr().cast(),
                &mut system_len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut owner: PSID = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the handle belongs to the still-open `file`; the returned
        // owner SID, DACL and descriptor are valid until the descriptor is
        // freed.
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        // The owner holds implicit WRITE_DAC whatever the DACL says, so a
        // file owned by anyone but this user or SYSTEM is refused too.
        // SAFETY: `owner` points into the live descriptor; both SIDs are
        // valid for these calls.
        let owned = !owner.is_null()
            && unsafe {
                EqualSid(owner, user_sid) != 0 || EqualSid(owner, system.as_mut_ptr().cast()) != 0
            };
        let result = if dacl.is_null() {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "null DACL"))
        } else if !owned {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owned by another principal",
            ))
        } else {
            let mut info = ACL_SIZE_INFORMATION::default();
            // SAFETY: `dacl` came from GetSecurityInfo and `info` is writable
            // for exactly its declared size.
            let ok = unsafe {
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of_val(&info) as u32,
                    AclSizeInformation,
                )
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                let mut safe = true;
                for index in 0..info.AceCount {
                    let mut ace = ptr::null_mut();
                    // SAFETY: `index` is below the ACE count returned for the
                    // same valid DACL and `ace` is a writable out-pointer.
                    if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                        safe = false;
                        break;
                    }
                    // SAFETY: GetAce returned an ACE within the DACL; every
                    // ACE begins with ACE_HEADER, as guaranteed by Win32.
                    let header =
                        unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
                    if header.AceType != 0 {
                        safe = false;
                        break;
                    }
                    // SAFETY: standard ACCESS_ALLOWED ACE type guarantees the
                    // ACCESS_ALLOWED_ACE header and SID field layout.
                    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                    let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
                    // SAFETY: both SIDs are valid for this loop iteration.
                    let user = unsafe { EqualSid(sid, user_sid) } != 0;
                    // SAFETY: the SYSTEM SID buffer remains alive here.
                    let system_user = unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } != 0;
                    if !user && !system_user {
                        safe = false;
                        break;
                    }
                }
                if safe {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "DACL allows another principal",
                    ))
                }
            }
        };
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe { LocalFree(descriptor.cast()) };
        result
    }
}
