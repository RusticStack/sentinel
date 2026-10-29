//! A SQLite VFS that wraps the platform default, forwards every call and records, in order, the writes, truncations and
//! syncs of the database file and its write-ahead log. A test rebuilds from that record the files a power cut at any
//! point would have left: bytes before the file's last completed sync are on disk, bytes after it may be, in any
//! subset, and a write may be torn at a sector boundary. Nothing here touches anything outside the test's own files.

use std::{
    ffi::{CString, c_char, c_int, c_void},
    ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use rusqlite::ffi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    Main,
    Wal,
}

impl File {
    fn slot(self) -> usize {
        match self {
            File::Main => 0,
            File::Wal => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Write {
        file: File,
        offset: u64,
        data: Vec<u8>,
    },
    Truncate {
        file: File,
        size: u64,
    },
    /// A completed sync: everything written to the file before it is on disk.
    Sync {
        file: File,
    },
    /// The test saw a write return success.
    Ack(u64),
}

struct State {
    real: *mut ffi::sqlite3_vfs,
    log: Mutex<Vec<Event>>,
    syncs: AtomicU64,
    /// The 1-based count of the sync that fails with an I/O error; 0 never.
    fail_sync_at: AtomicU64,
}

// SAFETY: `real` is SQLite's process-global default VFS, which is registered once and never freed, and is only
// dereferenced to call its function table; every other field is a lock or an atomic.
unsafe impl Send for State {}
// SAFETY: see above.
unsafe impl Sync for State {}

/// A registered recording VFS. The registration and its state live for the process, which is what SQLite requires of a
/// VFS; a test run registers a handful.
#[derive(Clone, Copy)]
pub struct CrashVfs {
    name: &'static str,
    state: &'static State,
}

#[repr(C)]
struct ShimFile {
    base: ffi::sqlite3_file,
    state: *const State,
    role: u8,
}

const REAL_OFFSET: usize = (size_of::<ShimFile>() + 15) & !15;

unsafe fn real_of(file: *mut ffi::sqlite3_file) -> *mut ffi::sqlite3_file {
    // SAFETY: szOsFile reserved the wrapped file's storage directly after the aligned shim header.
    unsafe { (file as *mut u8).add(REAL_OFFSET) as *mut ffi::sqlite3_file }
}

fn role_of(file: *mut ffi::sqlite3_file) -> (Option<File>, &'static State) {
    // SAFETY: SQLite only passes files this VFS opened, and `x_open` initialized the header before publishing methods.
    let shim = unsafe { &*(file as *const ShimFile) };
    let role = match shim.role {
        1 => Some(File::Main),
        2 => Some(File::Wal),
        _ => None,
    };
    // SAFETY: `state` points at the leaked, immortal state `x_open` copied in.
    (role, unsafe { &*shim.state })
}

macro_rules! forward {
    ($file:expr, $method:ident($($arg:expr),*)) => {{
        // SAFETY: the wrapped file was opened by the default VFS, so its method table is set while the shim is open.
        unsafe {
            let real = real_of($file);
            let methods = &*(*real).pMethods;
            (methods.$method.expect("default VFS method"))(real $(, $arg)*)
        }
    }};
}

unsafe extern "C" fn x_close(file: *mut ffi::sqlite3_file) -> c_int {
    forward!(file, xClose())
}

unsafe extern "C" fn x_read(
    file: *mut ffi::sqlite3_file,
    buf: *mut c_void,
    amt: c_int,
    ofst: ffi::sqlite3_int64,
) -> c_int {
    forward!(file, xRead(buf, amt, ofst))
}

unsafe extern "C" fn x_write(
    file: *mut ffi::sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    ofst: ffi::sqlite3_int64,
) -> c_int {
    let rc = forward!(file, xWrite(buf, amt, ofst));
    let (role, state) = role_of(file);
    if rc == ffi::SQLITE_OK
        && let Some(file) = role
    {
        // SAFETY: SQLite guarantees `buf` holds `amt` readable bytes for the duration of the call.
        let data = unsafe { slice::from_raw_parts(buf as *const u8, amt as usize) }.to_vec();
        state.record(Event::Write {
            file,
            offset: ofst as u64,
            data,
        });
    }
    rc
}

unsafe extern "C" fn x_truncate(file: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    let rc = forward!(file, xTruncate(size));
    let (role, state) = role_of(file);
    if rc == ffi::SQLITE_OK
        && let Some(file) = role
    {
        state.record(Event::Truncate {
            file,
            size: size as u64,
        });
    }
    rc
}

unsafe extern "C" fn x_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    let (role, state) = role_of(file);
    let Some(role) = role else {
        return forward!(file, xSync(flags));
    };
    let nth = state.syncs.fetch_add(1, Ordering::SeqCst) + 1;
    if state.fail_sync_at.load(Ordering::SeqCst) == nth {
        return ffi::SQLITE_IOERR_FSYNC;
    }
    let rc = forward!(file, xSync(flags));
    if rc == ffi::SQLITE_OK {
        state.record(Event::Sync { file: role });
    }
    rc
}

unsafe extern "C" fn x_file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    forward!(file, xFileSize(size))
}

unsafe extern "C" fn x_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    forward!(file, xLock(level))
}

unsafe extern "C" fn x_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    forward!(file, xUnlock(level))
}

unsafe extern "C" fn x_check_reserved_lock(file: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    forward!(file, xCheckReservedLock(out))
}

unsafe extern "C" fn x_file_control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    forward!(file, xFileControl(op, arg))
}

unsafe extern "C" fn x_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    forward!(file, xSectorSize())
}

unsafe extern "C" fn x_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    forward!(file, xDeviceCharacteristics())
}

unsafe extern "C" fn x_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    forward!(file, xShmMap(page, size, extend, out))
}

unsafe extern "C" fn x_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    n: c_int,
    flags: c_int,
) -> c_int {
    forward!(file, xShmLock(offset, n, flags))
}

unsafe extern "C" fn x_shm_barrier(file: *mut ffi::sqlite3_file) {
    forward!(file, xShmBarrier())
}

unsafe extern "C" fn x_shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    forward!(file, xShmUnmap(delete))
}

// Version 2: the default VFS's memory-mapped reads (version 3) stay off, so every read and write goes through here.
static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(x_close),
    xRead: Some(x_read),
    xWrite: Some(x_write),
    xTruncate: Some(x_truncate),
    xSync: Some(x_sync),
    xFileSize: Some(x_file_size),
    xLock: Some(x_lock),
    xUnlock: Some(x_unlock),
    xCheckReservedLock: Some(x_check_reserved_lock),
    xFileControl: Some(x_file_control),
    xSectorSize: Some(x_sector_size),
    xDeviceCharacteristics: Some(x_device_characteristics),
    xShmMap: Some(x_shm_map),
    xShmLock: Some(x_shm_lock),
    xShmBarrier: Some(x_shm_barrier),
    xShmUnmap: Some(x_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};

fn state_of(vfs: *mut ffi::sqlite3_vfs) -> &'static State {
    // SAFETY: `pAppData` is the leaked `State` `CrashVfs::register` stored; the registration is never released.
    unsafe { &*((*vfs).pAppData as *const State) }
}

unsafe extern "C" fn x_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let state = state_of(vfs);
    let shim = file as *mut ShimFile;
    // SAFETY: SQLite hands over szOsFile writable bytes; the header is written whole before methods are published.
    unsafe {
        ptr::write(
            shim,
            ShimFile {
                base: ffi::sqlite3_file {
                    pMethods: ptr::null(),
                },
                state,
                role: 0,
            },
        );
    }
    let real_vfs = state.real;
    // SAFETY: `real_vfs` is the default VFS and `real_of` addresses the storage reserved for its file.
    let rc = unsafe {
        ((*real_vfs).xOpen.expect("default xOpen"))(real_vfs, name, real_of(file), flags, out_flags)
    };
    if rc != ffi::SQLITE_OK {
        return rc;
    }
    let role = if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
        1
    } else if flags & ffi::SQLITE_OPEN_WAL != 0 {
        2
    } else {
        0
    };
    // SAFETY: the header was initialized above and the file is open.
    unsafe {
        (*shim).role = role;
        (*shim).base.pMethods = &METHODS;
    }
    rc
}

unsafe extern "C" fn x_delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync: c_int,
) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xDelete.expect("default xDelete"))(real, name, sync) }
}

unsafe extern "C" fn x_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xAccess.expect("default xAccess"))(real, name, flags, out) }
}

unsafe extern "C" fn x_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    n: c_int,
    out: *mut c_char,
) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xFullPathname.expect("default xFullPathname"))(real, name, n, out) }
}

unsafe extern "C" fn x_randomness(vfs: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xRandomness.expect("default xRandomness"))(real, n, out) }
}

unsafe extern "C" fn x_sleep(vfs: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xSleep.expect("default xSleep"))(real, micros) }
}

unsafe extern "C" fn x_current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    unsafe { ((*real).xCurrentTime.expect("default xCurrentTime"))(real, out) }
}

unsafe extern "C" fn x_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    n: c_int,
    out: *mut c_char,
) -> c_int {
    let real = state_of(vfs).real;
    // SAFETY: forwards SQLite's own arguments to the default VFS.
    match unsafe { (*real).xGetLastError } {
        // SAFETY: as above.
        Some(f) => unsafe { f(real, n, out) },
        None => 0,
    }
}

static REGISTERED: AtomicU64 = AtomicU64::new(0);

impl State {
    fn record(&self, event: Event) {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(event);
    }
}

impl CrashVfs {
    /// Registers a recording VFS over the default one under a name unique to this process.
    pub fn register() -> CrashVfs {
        let name: &'static str = Box::leak(
            format!(
                "sentinel-crash-{}-{}",
                std::process::id(),
                REGISTERED.fetch_add(1, Ordering::SeqCst)
            )
            .into_boxed_str(),
        );
        let c_name: &'static CString = Box::leak(Box::new(CString::new(name).unwrap()));
        // SAFETY: a null name asks for the default VFS; SQLite initializes itself on first use.
        let real = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
        assert!(!real.is_null(), "no default SQLite VFS");
        let state: &'static State = Box::leak(Box::new(State {
            real,
            log: Mutex::new(Vec::new()),
            syncs: AtomicU64::new(0),
            fail_sync_at: AtomicU64::new(0),
        }));
        // SAFETY: `real` is non-null and immortal.
        let (max_path, os_file) = unsafe { ((*real).mxPathname, (*real).szOsFile) };
        let vfs = Box::leak(Box::new(ffi::sqlite3_vfs {
            iVersion: 1,
            szOsFile: REAL_OFFSET as c_int + os_file,
            mxPathname: max_path,
            pNext: ptr::null_mut(),
            zName: c_name.as_ptr(),
            pAppData: state as *const State as *mut c_void,
            xOpen: Some(x_open),
            xDelete: Some(x_delete),
            xAccess: Some(x_access),
            xFullPathname: Some(x_full_pathname),
            // This VFS never loads extensions.
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(x_randomness),
            xSleep: Some(x_sleep),
            xCurrentTime: Some(x_current_time),
            xGetLastError: Some(x_get_last_error),
            xCurrentTimeInt64: None,
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        }));
        // SAFETY: `vfs` is leaked, so it outlives every connection that names it.
        let rc = unsafe { ffi::sqlite3_vfs_register(vfs, 0) };
        assert_eq!(rc, ffi::SQLITE_OK, "register the recording VFS");
        CrashVfs { name, state }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Makes the nth (1-based) sync of the database or its log fail with an I/O error; it is counted from now.
    pub fn fail_sync_number(&self, nth: u64) {
        self.state.syncs.store(0, Ordering::SeqCst);
        self.state.fail_sync_at.store(nth, Ordering::SeqCst);
    }

    /// Syncs of the database or its log seen since the last `fail_sync_number`, or since registration.
    pub fn syncs_seen(&self) -> u64 {
        self.state.syncs.load(Ordering::SeqCst)
    }

    /// Marks that the caller observed write `id` return success.
    pub fn ack(&self, id: u64) {
        self.state.record(Event::Ack(id));
    }

    pub fn events(&self) -> Vec<Event> {
        self.state
            .log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// What reaches the disk of the bytes written since a file's last completed sync.
#[derive(Clone, Copy, Debug)]
pub enum Persist {
    /// Nothing written since the file's last sync survives.
    Nothing,
    /// Every write reached the disk although its sync had not returned.
    Everything,
    /// Each unsynced write or truncation independently vanishes, survives, or (a write) is torn at a 512-byte
    /// sector, chosen from the seed.
    Chance(u64),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Image {
    pub main: Vec<u8>,
    pub wal: Vec<u8>,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn apply(bytes: &mut Vec<u8>, event: &Event, keep: Option<usize>) {
    match event {
        Event::Write { offset, data, .. } => {
            let data = &data[..keep.unwrap_or(data.len())];
            if data.is_empty() {
                return;
            }
            let end = *offset as usize + data.len();
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[*offset as usize..end].copy_from_slice(data);
        }
        Event::Truncate { size, .. } => bytes.resize(*size as usize, 0),
        Event::Sync { .. } | Event::Ack(_) => {}
    }
}

/// The files a power cut leaves just before `events[cut]` takes effect: with `cut` at a `Sync`, that sync had not
/// returned.
pub fn image_at(events: &[Event], cut: usize, persist: Persist) -> Image {
    let mut durable: [Vec<u8>; 2] = Default::default();
    let mut pending: [Vec<&Event>; 2] = Default::default();
    for event in &events[..cut] {
        match event {
            Event::Write { file, .. } | Event::Truncate { file, .. } => {
                pending[file.slot()].push(event);
            }
            Event::Sync { file } => {
                for event in pending[file.slot()].drain(..) {
                    apply(&mut durable[file.slot()], event, None);
                }
            }
            Event::Ack(_) => {}
        }
    }
    let mut rng = match persist {
        Persist::Chance(seed) => Rng(seed),
        _ => Rng(0),
    };
    for slot in 0..2 {
        for event in &pending[slot] {
            match persist {
                Persist::Nothing => {}
                Persist::Everything => apply(&mut durable[slot], event, None),
                Persist::Chance(_) => match rng.next() % 4 {
                    0 => {}
                    1 => {
                        let sectors = match event {
                            Event::Write { data, .. } => {
                                (rng.next() as usize) % (data.len() / 512 + 1)
                            }
                            _ => 0,
                        };
                        apply(&mut durable[slot], event, Some(sectors * 512));
                    }
                    _ => apply(&mut durable[slot], event, None),
                },
            }
        }
    }
    let [main, wal] = durable;
    Image { main, wal }
}
