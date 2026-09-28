//! Disk admission (D06): free-space watermarks, a metadata reserve and
//! hysteresis, so discretionary writes stop before the disk fills.
//!
//! One [`Admission`] guards the data directory's filesystem and is shared by
//! the object store and the log store. The model is a single axis of free
//! bytes:
//!
//! ```text
//! free < floor                       log appends refuse; metadata keeps the rest
//! free - reserve < low               discretionary admission closed
//! free - reserve > high              admission reopens (high >= low)
//! ```
//!
//! `floor` sits inside the reserve. The reserve in force is the configured
//! one or, once the metadata database has grown, twice its size on disk
//! (R01: [`Admission::set_metadata_bytes`]), whichever is larger.
//!
//! Discretionary writes — object staging, upload chunks, manifest files —
//! pass through [`Admission::admit`]; the charge tracks bytes promised but
//! not yet committed, so concurrent writers cannot all consume the same
//! free figure. The charge is released when the bytes land on disk (the
//! next probe sees them) or the write is abandoned.
//!
//! The probe result is cached for [`PROBE_TTL`]: admission checks cost an
//! atomic read on the hot path, and a burst of writes is accounted by the
//! in-flight charge between probes.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::{TenantId, UploadId};

use crate::{Error, Result};

/// How long a probe result is trusted; writes between probes are covered
/// by the in-flight charge.
const PROBE_TTL: Duration = Duration::from_secs(1);

/// Free bytes on the filesystem holding `path`, at the caller's privilege
/// level (`f_bavail`, or the per-user figure Windows reports — both already
/// exclude space the process could not claim).
#[cfg(unix)]
pub fn free_bytes(path: &Path) -> Result<u64> {
    let st = rustix::fs::statvfs(path).map_err(|e| Error::Io(e.into()))?;
    let block = if st.f_frsize != 0 {
        st.f_frsize
    } else {
        st.f_bsize
    };
    Ok(st.f_bavail.saturating_mul(block))
}

/// Total size of the filesystem holding `path`.
#[cfg(unix)]
pub fn total_bytes(path: &Path) -> Result<u64> {
    let st = rustix::fs::statvfs(path).map_err(|e| Error::Io(e.into()))?;
    let block = if st.f_frsize != 0 {
        st.f_frsize
    } else {
        st.f_bsize
    };
    Ok(st.f_blocks.saturating_mul(block))
}

/// Total size of the volume holding `path`, as the calling user sees it.
#[cfg(windows)]
pub fn total_bytes(path: &Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut total = std::mem::MaybeUninit::<u64>::uninit();
    // SAFETY: `wide` is a valid null-terminated UTF-16 string that outlives
    // the call; `total` points at writable memory the call fills on success.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            total.as_mut_ptr().cast(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: a successful call initialized it.
    Ok(unsafe { total.assume_init() })
}

const GIB: u64 = 1 << 30;

/// Default levels for a filesystem of `total` bytes (R01). Fixed levels fit
/// one disk size badly: 1 GiB of reserve is plenty on 50 GB and a rounding
/// error on 2 TB, where one busy hour of logs outruns it. The reserve is a
/// 64th of the disk and the low watermark a 32nd, each clamped (reserve
/// 1–16 GiB, low 2–32 GiB); high is twice low, the hysteresis band; the log
/// floor is an eighth of the reserve. On the 1 TB reference host this is a
/// 15.6 GiB reserve, closing at 31 GiB free above it and reopening at 62.
pub fn default_watermarks(total: u64) -> Watermarks {
    let reserve = (total / 64).clamp(GIB, 16 * GIB);
    let low = (total / 32).clamp(2 * GIB, 32 * GIB);
    Watermarks {
        reserve,
        low,
        high: low * 2,
        floor: reserve / 8,
    }
}

/// The Windows counterpart: `GetDiskFreeSpaceExW` answers the bytes the
/// calling user may actually use (quota-aware).
#[cfg(windows)]
pub fn free_bytes(path: &Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut avail = std::mem::MaybeUninit::<u64>::uninit();
    // SAFETY: `wide` is a valid null-terminated UTF-16 string that outlives
    // the call; `avail` points at writable memory the call fills on success.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            avail.as_mut_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: a successful call initialized it.
    Ok(unsafe { avail.assume_init() })
}

/// Configured levels, in bytes of filesystem free space. `reserve` is held
/// back for writes that must not stop — the metadata database and log
/// evidence; `low`/`high` are the close/reopen hysteresis for discretionary
/// admission; `floor` is where even log appends refuse so the database
/// still has room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermarks {
    pub reserve: u64,
    pub low: u64,
    pub high: u64,
    pub floor: u64,
}

impl Watermarks {
    /// `high >= low` is the hysteresis direction; `floor` must sit inside
    /// the reserve it protects.
    pub fn validate(&self) -> Result<()> {
        if self.reserve == 0 || self.high < self.low || self.floor > self.reserve {
            return Err(Error::InvalidInput("watermarks"));
        }
        Ok(())
    }
}

/// The admission state of one filesystem. Cheap to share; all counters are
/// interior-mutable.
pub struct Admission {
    probe: Box<dyn Fn() -> Result<u64> + Send + Sync>,
    marks: Watermarks,
    /// Probe cache: value + when it was taken.
    cached: Mutex<(u64, Instant)>,
    /// Closed below the low watermark, reopened above the high one.
    closed: AtomicBool,
    /// Bytes admitted but not yet committed on disk — the figure that
    /// keeps concurrent admissions honest between probes.
    inflight: AtomicU64,
    /// The same, per tenant: staged bytes not yet owned by a committed row.
    tenant_inflight: Mutex<HashMap<TenantId, u64>>,
    /// Per-upload admission charges this process made (`put_chunk` deltas),
    /// released at seal, abort or sweep.
    upload_charges: Mutex<HashMap<UploadId, u64>>,
    /// The metadata database's size on disk, reported by the maintenance
    /// pass; the reserve is never less than [`METADATA_RESERVE_FACTOR`]
    /// times it (R01), so a growing database keeps room to grow and to
    /// checkpoint.
    metadata: AtomicU64,
}

/// The reserve holds at least this many times the metadata database's
/// current size: room for its write-ahead log, a checkpoint and growth.
pub const METADATA_RESERVE_FACTOR: u64 = 2;

impl Admission {
    /// Guard the filesystem holding `dir`.
    pub fn new(dir: PathBuf, marks: Watermarks) -> Result<Admission> {
        marks.validate()?;
        let free = free_bytes(&dir).unwrap_or(u64::MAX);
        Ok(Admission {
            probe: Box::new(move || free_bytes(&dir)),
            marks,
            cached: Mutex::new((free, Instant::now() - PROBE_TTL)),
            closed: AtomicBool::new(false),
            inflight: AtomicU64::new(0),
            tenant_inflight: Mutex::new(HashMap::new()),
            upload_charges: Mutex::new(HashMap::new()),
            metadata: AtomicU64::new(0),
        })
    }

    /// An admission with a caller-supplied probe — deterministic tests and
    /// platforms without a filesystem answer drive their own figure.
    pub fn with_probe(
        marks: Watermarks,
        probe: impl Fn() -> Result<u64> + Send + Sync + 'static,
    ) -> Result<Admission> {
        marks.validate()?;
        Ok(Admission {
            probe: Box::new(probe),
            marks,
            cached: Mutex::new((0, Instant::now() - PROBE_TTL)),
            closed: AtomicBool::new(false),
            inflight: AtomicU64::new(0),
            tenant_inflight: Mutex::new(HashMap::new()),
            upload_charges: Mutex::new(HashMap::new()),
            metadata: AtomicU64::new(0),
        })
    }

    /// Record the metadata database's current size; the effective reserve
    /// follows it.
    pub fn set_metadata_bytes(&self, bytes: u64) {
        self.metadata.store(bytes, Ordering::Relaxed);
    }

    /// The reserve in force: the configured one, or more once the metadata
    /// database needs it.
    pub fn reserve(&self) -> u64 {
        self.marks.reserve.max(
            self.metadata
                .load(Ordering::Relaxed)
                .saturating_mul(METADATA_RESERVE_FACTOR),
        )
    }

    /// The cached free-space figure, refreshed at most every [`PROBE_TTL`].
    /// A failed probe keeps the last answer; with no answer yet it admits
    /// (a filesystem that cannot be measured cannot be watermarked, and
    /// writes still fail honestly at ENOSPC).
    pub fn free(&self) -> u64 {
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        self.probe_locked(&mut cached)
    }

    fn probe_locked(&self, cached: &mut (u64, Instant)) -> u64 {
        if cached.1.elapsed() >= PROBE_TTL
            && let Ok(free) = (self.probe)()
        {
            *cached = (free, Instant::now());
        }
        cached.0
    }

    /// What a discretionary write may consume: free minus the reserve
    /// minus what admissions already promised.
    fn discretionary(&self, free: u64) -> u64 {
        free.saturating_sub(self.reserve())
            .saturating_sub(self.inflight.load(Ordering::Relaxed))
    }

    /// Whether discretionary admission is currently open.
    pub fn is_open(&self) -> bool {
        self.gate(self.free()).is_ok()
    }

    fn gate(&self, free: u64) -> Result<()> {
        let avail = self.discretionary(free);
        if self.closed.load(Ordering::Relaxed) {
            if avail <= self.marks.high {
                return Err(Error::StorageFull);
            }
            self.closed.store(false, Ordering::Relaxed);
        }
        if avail < self.marks.low {
            self.closed.store(true, Ordering::Relaxed);
            return Err(Error::StorageFull);
        }
        Ok(())
    }

    /// Admit `bytes` of new stored data for `tenant`: charged against the
    /// free-space figure and the tenant's in-flight count until
    /// [`Admission::release`] runs (commit, discard or failure path).
    pub fn admit(&self, tenant: TenantId, bytes: u64) -> Result<()> {
        // The cache mutex serializes check-and-charge so two admissions
        // cannot both spend the same free figure.
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        let free = self.probe_locked(&mut cached);
        self.gate(free)?;
        if self.discretionary(free) < bytes {
            return Err(Error::StorageFull);
        }
        self.inflight.fetch_add(bytes, Ordering::Relaxed);
        if bytes > 0 {
            *self
                .tenant_inflight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(tenant)
                .or_default() += bytes;
        }
        Ok(())
    }

    /// Release a charge made by [`Admission::admit`].
    pub fn release(&self, tenant: TenantId, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.inflight.fetch_sub(bytes, Ordering::Relaxed);
        let mut per_tenant = self
            .tenant_inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(held) = per_tenant.get_mut(&tenant) {
            *held = held.saturating_sub(bytes);
            if *held == 0 {
                per_tenant.remove(&tenant);
            }
        }
    }

    /// Admit `bytes` without a tenant charge — uploads pre-count their
    /// declared length in `tenant_usage`, so chunk writes only owe the
    /// disk.
    pub fn admit_untracked(&self, upload: UploadId, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        let free = self.probe_locked(&mut cached);
        self.gate(free)?;
        if self.discretionary(free) < bytes {
            return Err(Error::StorageFull);
        }
        self.inflight.fetch_add(bytes, Ordering::Relaxed);
        *self
            .upload_charges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(upload)
            .or_default() += bytes;
        Ok(())
    }

    /// Release everything this process charged to an upload.
    pub fn release_upload(&self, upload: UploadId) {
        let charged = self
            .upload_charges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&upload);
        if let Some(bytes) = charged {
            self.inflight.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// Release part of an upload's charge — a chunk whose write or
    /// bookkeeping failed. The bytes may sit unrecorded in the file; the
    /// retry that covers them re-charges the same delta.
    pub fn release_upload_delta(&self, upload: UploadId, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut charges = self
            .upload_charges
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(held) = charges.get_mut(&upload) else {
            return;
        };
        let freed = (*held).min(bytes);
        *held -= freed;
        if *held == 0 {
            charges.remove(&upload);
        }
        drop(charges);
        self.inflight.fetch_sub(freed, Ordering::Relaxed);
    }

    /// Whether `bytes` could be admitted right now, without charging —
    /// `begin_upload` asks before promising a declared length.
    pub fn check(&self, bytes: u64) -> Result<()> {
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        let free = self.probe_locked(&mut cached);
        self.gate(free)?;
        if self.discretionary(free) < bytes {
            return Err(Error::StorageFull);
        }
        Ok(())
    }

    /// Room for a non-discretionary write (log evidence): refused only when
    /// free space falls below `floor`, protecting the reserve's other
    /// tenant — the metadata database.
    pub fn headroom(&self) -> bool {
        self.free() >= self.marks.floor
    }

    /// A tenant's staged-but-uncommitted bytes.
    pub fn inflight(&self, tenant: TenantId) -> u64 {
        self.tenant_inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&tenant)
            .copied()
            .unwrap_or(0)
    }

    /// All admitted-but-uncommitted bytes, every tenant.
    pub fn total_inflight(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// The configured levels (for `admin objects status`).
    pub fn watermarks(&self) -> Watermarks {
        self.marks
    }
}
