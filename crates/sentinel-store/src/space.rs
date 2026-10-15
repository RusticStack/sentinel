//! Free-space watermarks: discretionary writes stop before the disk fills; the reserve is kept for metadata and logs.
//! ```text
//! free < floor                       log appends refuse; metadata keeps the rest
//! free - reserve < low               discretionary admission closed
//! free - reserve > high              admission reopens (high >= low)
//! ```

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

const PROBE_TTL: Duration = Duration::from_secs(1);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermarks {
    pub reserve: u64,
    pub low: u64,
    pub high: u64,
    pub floor: u64,
}

impl Watermarks {
    pub fn validate(&self) -> Result<()> {
        if self.reserve == 0 || self.high < self.low || self.floor > self.reserve {
            return Err(Error::InvalidInput("watermarks"));
        }
        Ok(())
    }
}

pub struct Admission {
    probe: Box<dyn Fn() -> Result<u64> + Send + Sync>,
    marks: Watermarks,
    cached: Mutex<(u64, Instant)>,
    closed: AtomicBool,
    inflight: AtomicU64,
    tenant_inflight: Mutex<HashMap<TenantId, u64>>,
    upload_charges: Mutex<HashMap<UploadId, u64>>,
    metadata: AtomicU64,
    backlog_full: AtomicBool,
}

pub const METADATA_RESERVE_FACTOR: u64 = 2;

impl Admission {
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
            backlog_full: AtomicBool::new(false),
        })
    }

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
            backlog_full: AtomicBool::new(false),
        })
    }

    pub fn set_backlog_full(&self, full: bool) {
        self.backlog_full.store(full, Ordering::Relaxed);
    }

    pub fn backlog_full(&self) -> bool {
        self.backlog_full.load(Ordering::Relaxed)
    }

    pub fn set_metadata_bytes(&self, bytes: u64) {
        self.metadata.store(bytes, Ordering::Relaxed);
    }

    pub fn reserve(&self) -> u64 {
        self.marks.reserve.max(
            self.metadata
                .load(Ordering::Relaxed)
                .saturating_mul(METADATA_RESERVE_FACTOR),
        )
    }

    // Unmeasurable filesystems admit: writes still fail honestly at ENOSPC.
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

    fn discretionary(&self, free: u64) -> u64 {
        free.saturating_sub(self.reserve())
            .saturating_sub(self.inflight.load(Ordering::Relaxed))
    }

    pub fn is_open(&self) -> bool {
        self.gate(self.free()).is_ok()
    }

    fn gate(&self, free: u64) -> Result<()> {
        if self.backlog_full.load(Ordering::Relaxed) {
            return Err(Error::StorageFull);
        }
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

    pub fn admit(&self, tenant: TenantId, bytes: u64) -> Result<()> {
        // The cache mutex serializes check-and-charge: two admissions cannot spend the same free figure.
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

    pub fn check(&self, bytes: u64) -> Result<()> {
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        let free = self.probe_locked(&mut cached);
        self.gate(free)?;
        if self.discretionary(free) < bytes {
            return Err(Error::StorageFull);
        }
        Ok(())
    }

    pub fn headroom(&self) -> bool {
        self.free() >= self.marks.floor
    }

    pub fn inflight(&self, tenant: TenantId) -> u64 {
        self.tenant_inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&tenant)
            .copied()
            .unwrap_or(0)
    }

    pub fn total_inflight(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn watermarks(&self) -> Watermarks {
        self.marks
    }
}
