//! The shim sits first on PATH for the whole binary, so its dir must outlive every test: it is named per process and swept when that process exits.

use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn create(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let prefix = format!("sentinel-{tag}-shim-");
    if let Ok(entries) = fs::read_dir(&base) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
                continue;
            };
            if pid.parse::<u32>().is_ok() && !Path::new("/proc").join(pid).exists() {
                // Best effort: another account's leftover is not ours to remove.
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
    let dir = base.join(format!("{prefix}{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    dir
}
