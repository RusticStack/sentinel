//! Opening the sign-in URL in the user's browser (O04), one argv element and
//! no shell; the URL is always printed as well, so a headless machine or a
//! failed launch still lets the user open it by hand.
//!
//! The launcher is named by absolute path on Windows
//! (`%SystemRoot%\System32\rundll32.exe`, from `GetSystemDirectoryW`):
//! process creation searches the CLI's own directory before the system
//! directory, so a bare name would run a `rundll32.exe` planted beside
//! `sentinel.exe`. The browser never inherits Sentinel's own settings or
//! credentials: every `SENTINEL_*` variable (`SENTINEL_TOKEN` among them)
//! is removed from the launcher's environment.

use std::{
    ffi::{OsStr, OsString},
    process::{Command, Stdio},
};

/// The launcher program: `rundll32.exe` in the system directory on
/// Windows, `xdg-open` (looked up on `PATH`) on Linux.
pub fn opener() -> OsString {
    #[cfg(windows)]
    {
        system_rundll32()
    }
    #[cfg(not(windows))]
    {
        OsString::from("xdg-open")
    }
}

/// `{system directory}\rundll32.exe`; the system directory comes from the
/// OS, not from the environment.
#[cfg(windows)]
fn system_rundll32() -> OsString {
    use std::{os::windows::ffi::OsStringExt, path::Path};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    const MAX_PATH: usize = 260;
    let mut buf = [0u16; MAX_PATH];
    // SAFETY: `buf` is writable for exactly the length passed; the call
    // writes at most that many UTF-16 units and returns how many it wrote,
    // or the size it needs (larger than the buffer) when it did not fit.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if (1..buf.len()).contains(&len) {
        OsString::from_wide(&buf[..len])
    } else {
        // The system directory of every supported Windows.
        OsString::from(r"C:\Windows\System32")
    };
    Path::new(&dir).join("rundll32.exe").into_os_string()
}

/// The launcher for `url`: `rundll32 url.dll,FileProtocolHandler` on
/// Windows, `xdg-open` on Linux. The URL is one argument, no shell parses
/// it, and no `SENTINEL_*` variable reaches the browser.
pub fn command(url: &str) -> Command {
    command_with(opener(), url)
}

/// [`command`] with another launcher program: the test harness points it at
/// a stand-in instead of the real system launcher.
#[doc(hidden)]
pub fn command_with(program: impl AsRef<OsStr>, url: &str) -> Command {
    let mut command = Command::new(program);
    if cfg!(windows) {
        command.arg("url.dll,FileProtocolHandler");
    }
    command.arg(url);
    for (name, _) in std::env::vars_os() {
        let sentinel = name
            .to_str()
            .is_some_and(|n| n.len() >= 9 && n[..9].eq_ignore_ascii_case("SENTINEL_"));
        if sentinel {
            command.env_remove(&name);
        }
    }
    command
}

/// Print `url` on stderr and, when `launch`, hand it to the browser. Only
/// `http://` and `https://` URLs are ever launched.
pub fn open(url: &str, launch: bool) {
    open_with(url, launch, command)
}

/// [`open`] with another command builder (the test harness's stand-in).
#[doc(hidden)]
pub fn open_with(url: &str, launch: bool, build: impl FnOnce(&str) -> Command) {
    eprintln!("Open this URL in a browser to sign in:\n\n  {url}\n");
    if !launch || !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    let spawned = build(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        // The launcher exits on its own once the browser has the URL; it is
        // reaped when this short-lived process exits.
        Ok(_child) => eprintln!("A browser window should open; waiting for the sign-in…"),
        Err(e) => eprintln!("Could not start a browser ({e}); open the URL above yourself."),
    }
}
