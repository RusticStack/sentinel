//! The CLI's real browser opener, launched for real (O04 audit follow-up).
//!
//! No libtest harness: this binary plays three parts, chosen by how it was
//! started, so the production `browser::open` runs unmodified and its spawn
//! reaches a harmless stand-in instead of a browser.
//!
//! - **Test** (as built): copies itself into a temporary directory twice —
//!   as a runner and under the platform opener's name (`rundll32.exe`,
//!   `open`, `xdg-open`) — and starts the runner.
//! - **Runner**: calls `sentinel::browser::open` exactly as `sentinel auth
//!   login` does. The opener is found where the real one would be looked up
//!   first: on Windows the launching program's own directory comes before
//!   the system directory, and elsewhere `PATH` names the directory first.
//! - **Opener stand-in**: records the argv it received, NUL-separated, and
//!   exits. Nothing is opened.
//!
//! The URL carries shell metacharacters, quotes, spaces and variable syntax
//! for both `sh` and `cmd.exe`; the stand-in must receive it as one argv
//! element, byte for byte, and the canary commands inside it must not run.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

/// Where the stand-in writes what it received.
const OUT: &str = "SENTINEL_BROWSER_TEST_OUT";
/// Set on the runner: the URL to open, and whether to launch.
const URL: &str = "SENTINEL_BROWSER_TEST_URL";
const LAUNCH: &str = "SENTINEL_BROWSER_TEST_LAUNCH";

/// The launcher `browser::command` names on this platform.
const OPENER: &str = if cfg!(windows) {
    "rundll32.exe"
} else if cfg!(target_os = "macos") {
    "open"
} else {
    "xdg-open"
};

fn main() -> ExitCode {
    let me = std::env::current_exe().expect("current exe");
    if me.file_name().is_some_and(|name| name == OPENER) {
        return stand_in();
    }
    if let Some(url) = std::env::var_os(URL) {
        let url = url.into_string().expect("a UTF-8 URL");
        sentinel::browser::open(&url, std::env::var_os(LAUNCH).is_some());
        return ExitCode::SUCCESS;
    }
    let tests: [(&str, fn()); 4] = [
        (
            "the_opener_command_is_the_platform_launcher_with_the_url_as_one_argument",
            the_opener_command_is_the_platform_launcher_with_the_url_as_one_argument,
        ),
        (
            "the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell",
            the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell,
        ),
        (
            "a_url_that_is_not_http_is_printed_but_never_launched",
            a_url_that_is_not_http_is_printed_but_never_launched,
        ),
        (
            "no_browser_prints_the_url_and_launches_nothing",
            no_browser_prints_the_url_and_launches_nothing,
        ),
    ];
    println!("\nrunning {} tests", tests.len());
    for (name, test) in tests {
        test();
        println!("test {name} ... ok");
    }
    println!(
        "\ntest result: ok. {} passed; 0 failed; 0 ignored\n",
        tests.len()
    );
    ExitCode::SUCCESS
}

/// The opener stand-in: argv after the program name, NUL-separated, written
/// atomically so the test never reads half of it.
fn stand_in() -> ExitCode {
    let out = PathBuf::from(std::env::var_os(OUT).expect("the stand-in needs its output path"));
    let mut record = Vec::new();
    for arg in std::env::args_os().skip(1) {
        record.extend_from_slice(arg.into_string().expect("UTF-8 argv").as_bytes());
        record.push(0);
    }
    let staging = out.with_extension("tmp");
    fs::write(&staging, record).expect("record argv");
    fs::rename(&staging, &out).expect("publish argv");
    ExitCode::SUCCESS
}

/// A directory holding the runner and the opener stand-in, both copies of
/// this binary.
struct Stage {
    dir: tempfile::TempDir,
    runner: PathBuf,
    out: PathBuf,
}

impl Stage {
    fn new() -> Self {
        let me = std::env::current_exe().expect("current exe");
        let dir = tempfile::tempdir().expect("temporary directory");
        let runner = dir
            .path()
            .join(format!("runner{}", std::env::consts::EXE_SUFFIX));
        fs::copy(&me, &runner).expect("copy the runner");
        fs::copy(&me, dir.path().join(OPENER)).expect("copy the opener stand-in");
        let out = dir.path().join("argv.bin");
        Self { dir, runner, out }
    }

    /// Runs `browser::open(url, launch)` in the runner and returns its
    /// standard error.
    fn open(&self, url: &str, launch: bool) -> String {
        let mut command = Command::new(&self.runner);
        command.env(URL, url).env(OUT, &self.out);
        if launch {
            command.env(LAUNCH, "1");
        } else {
            command.env_remove(LAUNCH);
        }
        // Where the real opener is looked up first: `PATH` on Unix. On
        // Windows the runner's own directory already comes first.
        if cfg!(unix) {
            let mut path = OsString::from(self.dir.path());
            if let Some(inherited) = std::env::var_os("PATH") {
                path.push(":");
                path.push(inherited);
            }
            command.env("PATH", path);
        }
        let output = command.output().expect("run the runner");
        assert!(output.status.success(), "the runner failed: {output:?}");
        String::from_utf8(output.stderr).expect("UTF-8 stderr")
    }

    /// What the stand-in received, once it has written it.
    fn received(&self) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.out.exists() {
            assert!(Instant::now() < deadline, "the opener stand-in never ran");
            std::thread::sleep(Duration::from_millis(20));
        }
        let bytes = fs::read(&self.out).expect("read the recorded argv");
        let text = String::from_utf8(bytes).expect("UTF-8 argv");
        let mut args: Vec<String> = text.split('\0').map(str::to_owned).collect();
        assert_eq!(args.pop().as_deref(), Some(""), "NUL-terminated argv");
        args
    }

    /// Nothing was launched: after the runner exited (the spawn happens
    /// before it does), a stand-in would have left its record by now.
    fn assert_nothing_launched(&self) {
        std::thread::sleep(Duration::from_millis(500));
        assert!(!self.out.exists(), "an opener was started");
        assert!(!self.out.with_extension("tmp").exists());
    }
}

/// A URL that a shell (`sh` or `cmd.exe`) would split, expand or run parts
/// of. Each canary, if any shell ran it, would create a file in `dir`.
fn hostile_url(dir: &Path) -> (String, Vec<PathBuf>) {
    let canaries: Vec<PathBuf> = ["semicolon", "subshell", "backtick", "ampersand"]
        .iter()
        .map(|name| dir.join(format!("pwned-{name}")))
        .collect();
    let [semicolon, subshell, backtick, ampersand] =
        [0, 1, 2, 3].map(|i| canaries[i].display().to_string());
    let url = format!(
        "https://example.test/cb?a=1&b=2;touch {semicolon};x=$(touch {subshell})&y=`touch {backtick}`&z=' \"quoted\" '&w=%PATH%&v=$HOME ^caret | pipe & type nul > {ampersand} &sp ace\\\"tail"
    );
    (url, canaries)
}

fn the_opener_command_is_the_platform_launcher_with_the_url_as_one_argument() {
    let url = "https://example.test/a b?c=1&d='2'";
    let command = sentinel::browser::command(url);
    let args: Vec<&std::ffi::OsStr> = command.get_args().collect();
    if cfg!(windows) {
        assert_eq!(command.get_program(), "rundll32.exe");
        assert_eq!(args, ["url.dll,FileProtocolHandler", url]);
    } else {
        assert_eq!(command.get_program(), OPENER);
        assert_eq!(args, [url]);
    }
}

fn the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell() {
    let stage = Stage::new();
    let (url, canaries) = hostile_url(stage.dir.path());
    let stderr = stage.open(&url, true);
    assert!(stderr.contains(&url), "the URL is always printed: {stderr}");
    assert!(
        stderr.contains("A browser window should open"),
        "the launch was reported as failed: {stderr}"
    );
    let received = stage.received();
    if cfg!(windows) {
        assert_eq!(received, ["url.dll,FileProtocolHandler", url.as_str()]);
    } else {
        assert_eq!(received, [url.as_str()]);
    }
    for canary in canaries {
        assert!(!canary.exists(), "a shell ran part of the URL: {canary:?}");
    }
}

fn a_url_that_is_not_http_is_printed_but_never_launched() {
    let stage = Stage::new();
    for url in ["file:///etc/passwd", "javascript:alert(1)", "calc.exe"] {
        let stderr = stage.open(url, true);
        assert!(stderr.contains(url), "{stderr}");
        stage.assert_nothing_launched();
    }
}

fn no_browser_prints_the_url_and_launches_nothing() {
    let stage = Stage::new();
    let url = "https://example.test/sign-in?state=abc";
    let stderr = stage.open(url, false);
    assert!(stderr.contains(url), "{stderr}");
    assert!(!stderr.contains("A browser window should open"), "{stderr}");
    stage.assert_nothing_launched();
}
