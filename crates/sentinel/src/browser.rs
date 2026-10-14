//! Launched by absolute path on Windows so a planted `rundll32.exe` beside sentinel.exe never runs; no SENTINEL_* variable reaches the browser.

use std::{
    ffi::{OsStr, OsString},
    process::{Command, Stdio},
};

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
        OsString::from(r"C:\Windows\System32")
    };
    Path::new(&dir).join("rundll32.exe").into_os_string()
}

pub fn command(url: &str) -> Command {
    command_with(opener(), url)
}

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

pub fn open(url: &str, launch: bool) {
    open_with(url, launch, command)
}

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
        Ok(_child) => eprintln!("A browser window should open; waiting for the sign-in…"),
        Err(e) => eprintln!("Could not start a browser ({e}); open the URL above yourself."),
    }
}
