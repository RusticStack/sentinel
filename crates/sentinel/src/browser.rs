//! Opening the sign-in URL in the user's browser (O04), one argv element and
//! no shell; the URL is always printed as well, so a headless machine or a
//! failed launch still lets the user open it by hand.

use std::process::{Command, Stdio};

/// The launcher for `url`: `rundll32 url.dll,FileProtocolHandler` on
/// Windows, `open` on macOS, `xdg-open` elsewhere. The URL is one argument
/// and no shell parses it.
pub fn command(url: &str) -> Command {
    let mut command = if cfg!(windows) {
        let mut c = Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    command.arg(url);
    command
}

/// Print `url` on stderr and, when `launch`, hand it to the browser. Only
/// `http://` and `https://` URLs are ever launched.
pub fn open(url: &str, launch: bool) {
    eprintln!("Open this URL in a browser to sign in:\n\n  {url}\n");
    if !launch || !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    let spawned = command(url)
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
