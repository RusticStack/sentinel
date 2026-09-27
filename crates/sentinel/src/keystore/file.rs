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
//! per-user `%APPDATA%`. Every directory and file that already exists is
//! checked on its open handle, as on Unix: it must be owned by this user,
//! SYSTEM or Administrators, and its DACL may allow no one else; anything
//! looser is refused with the `icacls` command that fixes it.

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
    // A credentials directory made by an older Sentinel is brought to
    // owner-only before a refresh token goes into it; one owned by someone
    // else is still refused below (Unix refuses any loose one instead).
    #[cfg(windows)]
    if creds.is_dir() {
        acl::owner_only(&creds).map_err(|e| io_error("restrict access to", &creds, &e))?;
    }
    ensure_private_dir(&creds)?;
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
    #[cfg(windows)]
    check_windows(path, &file, false)?;
    #[cfg(not(windows))]
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

/// Check that `path` is owner-only and owned by this user (Unix mode and
/// owner; Windows owner and DACL).
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
            Error::usage(
                "secret input file permissions must allow only the current user and SYSTEM",
            )
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

/// Windows: open the object and judge its owner and DACL on the handle.
#[cfg(windows)]
fn check_meta(path: &Path, _meta: &fs::Metadata, dir: bool) -> Result<(), Error> {
    let file = acl::open(path).map_err(|e| io_error("inspect", path, &e))?;
    check_windows(path, &file, dir)
}

#[cfg(not(any(unix, windows)))]
fn check_meta(_path: &Path, _meta: &fs::Metadata, _dir: bool) -> Result<(), Error> {
    Ok(())
}

/// The Windows equivalent of the Unix owner and mode check (P09C-3): the
/// object must be owned by this user (or SYSTEM, or Administrators) and its
/// DACL may allow no one else, whether Sentinel created it or it existed
/// before. A refusal names the `icacls` commands that fix it.
#[cfg(windows)]
fn check_windows(path: &Path, file: &File, dir: bool) -> Result<(), Error> {
    let shown = path.display();
    match acl::check_private(file) {
        Ok(()) => Ok(()),
        Err(acl::Refusal::Io(e)) => Err(io_error("inspect the permissions of", path, &e)),
        Err(acl::Refusal::Owner(owner)) => Err(Error::usage(format!(
            "{shown} is owned by another account ({owner}), not by you; fix: remove it, or take \
             ownership (then run sentinel doctor for the ACL): takeown /F \"{shown}\"{}",
            if dir { " /R /D Y" } else { "" }
        ))),
        Err(acl::Refusal::Loose(others)) => {
            let listed = if others.is_empty() {
                "an entry Sentinel does not accept".to_owned()
            } else {
                others.join(", ")
            };
            let fix = if dir {
                let mut remove = String::new();
                for sid in &others {
                    remove.push_str(&format!(" *{sid}"));
                }
                let remove = if remove.is_empty() {
                    String::new()
                } else {
                    format!(" /remove:g{remove}")
                };
                format!(
                    "icacls \"{shown}\" /inheritance:r /grant:r *{user}:(OI)(CI)F *S-1-5-18:(OI)(CI)F{remove} \
                     && icacls \"{shown}\\*\" /reset /T /C",
                    user = acl::user_text()
                )
            } else {
                format!("icacls \"{shown}\" /reset")
            };
            Err(Error::usage(format!(
                "{shown} is accessible to other users (its ACL allows {listed}); fix: {fix}"
            )))
        }
    }
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
/// everything created inside — the equivalent of `chmod 700` — and the
/// checks that refuse anything looser, made on an open handle.
#[cfg(windows)]
mod acl {
    use std::{
        ffi::c_void,
        fs::{File, OpenOptions},
        io, iter,
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
        ptr,
        sync::OnceLock,
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, GENERIC_ALL, HANDLE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
                SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
                TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_TYPE,
                TRUSTEE_W,
            },
            CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetAclInformation, GetLengthSid, GetTokenInformation, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
            WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    /// `READ_CONTROL`: enough access to read an object's security.
    const READ_CONTROL: u32 = 0x0002_0000;
    /// `FILE_FLAG_BACKUP_SEMANTICS`: required to open a directory handle.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    /// A SID copied into owned, 4-aligned storage.
    struct Sid(Box<[u32]>);

    impl Sid {
        fn as_psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast()
        }

        /// Copy the SID at `sid`.
        ///
        /// # Safety
        /// `sid` must point at a valid SID.
        unsafe fn copy(sid: PSID) -> io::Result<Sid> {
            // SAFETY: the caller guarantees `sid` is a valid SID.
            let len = unsafe { GetLengthSid(sid) };
            let mut storage = vec![0u32; (len as usize).div_ceil(4)].into_boxed_slice();
            // SAFETY: `storage` is writable for at least `len` bytes and
            // `sid` is valid; CopySid writes exactly the SID's length.
            if unsafe { CopySid(len, storage.as_mut_ptr().cast(), sid) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Sid(storage))
        }

        fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Sid> {
            let mut storage = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
            let mut len = SECURITY_MAX_SID_SIZE;
            // SAFETY: `storage` is writable for SECURITY_MAX_SID_SIZE bytes,
            // the size of the largest SID; no domain SID is needed for the
            // built-in accounts asked for here.
            let ok = unsafe {
                CreateWellKnownSid(kind, ptr::null_mut(), storage.as_mut_ptr().cast(), &mut len)
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Sid(storage.into_boxed_slice()))
        }

        /// Whether `other` (a valid SID) is this SID.
        fn is(&self, other: PSID) -> bool {
            // SAFETY: both pointers refer to valid SIDs for the call.
            unsafe { EqualSid(self.as_psid(), other) != 0 }
        }

        /// The `S-1-…` text of the SID at `sid` (valid), for a fix command.
        fn text_of(sid: PSID) -> String {
            let mut wide: *mut u16 = ptr::null_mut();
            // SAFETY: `sid` is valid; on success `wide` receives a
            // LocalAlloc'd NUL-terminated string owned by this function.
            if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 || wide.is_null() {
                return "?".to_owned();
            }
            let mut len = 0;
            // SAFETY: the string is NUL-terminated, so every unit up to and
            // including the terminator is readable.
            while unsafe { *wide.add(len) } != 0 {
                len += 1;
            }
            // SAFETY: `len` units were just read as initialized.
            let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(wide, len) });
            // SAFETY: allocated by ConvertSidToStringSidW; freed once.
            unsafe { LocalFree(wide.cast()) };
            text
        }
    }

    /// This process's user and the built-in accounts the checks accept,
    /// looked up once per process.
    struct Sids {
        user: Sid,
        system: Sid,
        admins: Sid,
    }

    fn sids() -> io::Result<&'static Sids> {
        static SIDS: OnceLock<Sids> = OnceLock::new();
        if let Some(sids) = SIDS.get() {
            return Ok(sids);
        }
        let sids = Sids {
            user: token_user()?,
            system: Sid::well_known(WinLocalSystemSid)?,
            admins: Sid::well_known(WinBuiltinAdministratorsSid)?,
        };
        Ok(SIDS.get_or_init(|| sids))
    }

    fn token_user() -> io::Result<Sid> {
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
        // pointer refers into the same buffer, alive for the copy.
        unsafe { Sid::copy((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
    }

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
        let sids = sids()?;
        let entries = [
            entry(sids.user.as_psid(), TRUSTEE_IS_USER),
            entry(sids.system.as_psid(), TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];
        let mut acl: *mut ACL = ptr::null_mut();
        // SAFETY: `entries` and the SIDs they point at (process-lifetime
        // copies) live across the call; `acl` receives a LocalAlloc'd ACL
        // owned by this function.
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

    /// Why an object is not private.
    pub(super) enum Refusal {
        /// Owned by another account (the SID's text).
        Owner(String),
        /// The DACL lets another principal in: the SIDs it names (empty
        /// for a null DACL or an entry type that is not a plain allow or
        /// deny).
        Loose(Vec<String>),
        Io(io::Error),
    }

    /// What an object may grant.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Policy {
        /// A secret input file: allow entries for this user and SYSTEM
        /// only, nothing but allow entries, owner not checked.
        SecretInput,
        /// A configuration directory or file: owned by this user, SYSTEM
        /// or Administrators, and allow entries only for those (the
        /// Administrators group can take any file anyway); deny entries
        /// are fine.
        Private,
    }

    /// Open `path` (a file or a directory) with just enough access to read
    /// its security.
    pub(super) fn open(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    /// The configuration directory's rule, checked on the open object.
    pub(super) fn check_private(file: &File) -> Result<(), Refusal> {
        check(file, Policy::Private)
    }

    pub(super) fn check_input(file: &File) -> io::Result<()> {
        check(file, Policy::SecretInput).map_err(|refusal| match refusal {
            Refusal::Io(e) => e,
            _ => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DACL allows another principal",
            ),
        })
    }

    /// This user's SID text, for a fix command.
    pub(super) fn user_text() -> String {
        sids().map_or_else(|_| "?".to_owned(), |s| Sid::text_of(s.user.as_psid()))
    }

    fn check(file: &File, policy: Policy) -> Result<(), Refusal> {
        let sids = sids().map_err(Refusal::Io)?;
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let info = match policy {
            Policy::Private => DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Policy::SecretInput => DACL_SECURITY_INFORMATION,
        };
        // SAFETY: the handle belongs to the still-open `file`; the returned
        // owner SID and DACL point into the descriptor, valid until it is
        // freed below.
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                info,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(Refusal::Io(io::Error::from_raw_os_error(code as i32)));
        }
        let result = judge(sids, policy, owner, dacl);
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc;
        // `owner` and `dacl` are not used after this.
        unsafe { LocalFree(descriptor.cast()) };
        result
    }

    /// Judge an owner and a DACL, both from one live security descriptor.
    fn judge(sids: &Sids, policy: Policy, owner: PSID, dacl: *mut ACL) -> Result<(), Refusal> {
        let accepted = |sid: PSID| {
            sids.user.is(sid)
                || sids.system.is(sid)
                || (policy == Policy::Private && sids.admins.is(sid))
        };
        if policy == Policy::Private && (owner.is_null() || !accepted(owner)) {
            let who = if owner.is_null() {
                "nobody".to_owned()
            } else {
                Sid::text_of(owner)
            };
            return Err(Refusal::Owner(who));
        }
        if dacl.is_null() {
            // A null DACL grants everyone everything.
            return Err(Refusal::Loose(Vec::new()));
        }
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
            return Err(Refusal::Io(io::Error::last_os_error()));
        }
        let mut others = Vec::new();
        for index in 0..info.AceCount {
            let mut ace = ptr::null_mut();
            // SAFETY: `index` is below the ACE count returned for the same
            // valid DACL and `ace` is a writable out-pointer.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(Refusal::Io(io::Error::last_os_error()));
            }
            // SAFETY: GetAce returned an ACE within the DACL; every ACE
            // begins with ACE_HEADER.
            let kind = unsafe { (*ace.cast::<ACE_HEADER>()).AceType };
            match (kind, policy) {
                (ACCESS_ALLOWED_ACE_TYPE, _) => {}
                (ACCESS_DENIED_ACE_TYPE, Policy::Private) => continue,
                // Object, callback and other entry types are not judged.
                _ => return Err(Refusal::Loose(others)),
            }
            // SAFETY: an ACCESS_ALLOWED ACE has the ACCESS_ALLOWED_ACE
            // layout: the header, the mask, then the SID at `SidStart`.
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid: PSID = (&allowed.SidStart as *const u32).cast_mut().cast();
            if !accepted(sid) {
                let text = Sid::text_of(sid);
                if !others.contains(&text) {
                    others.push(text);
                }
            }
        }
        if others.is_empty() {
            Ok(())
        } else {
            Err(Refusal::Loose(others))
        }
    }
}
