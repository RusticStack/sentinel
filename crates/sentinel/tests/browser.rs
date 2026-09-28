//! The CLI's real browser opener, launched for real (O04 audit follow-up).
//!
//! No libtest harness: this binary plays three parts, chosen by how it was
//! started, so the production opener runs and its spawn reaches a harmless
//! stand-in instead of a browser.
//!
//! - **Test** (as built): copies itself into a temporary directory twice —
//!   as a runner and under the platform opener's name (`rundll32.exe`
//!   or `xdg-open`) — and starts the runner with credential-bearing
//!   `SENTINEL_*` variables set.
//! - **Runner**: opens the URL exactly as `sentinel auth login` does. On
//!   Linux that is `sentinel::browser::open` unchanged, with the stand-in
//!   first on `PATH`. On Windows production names the launcher by its
//!   absolute System32 path (P09C-5), so the runner hands the same
//!   `browser::open_with`/`command_with` path the stand-in's location
//!   instead; everything else — arguments, environment, spawn — is the
//!   production code.
//! - **Opener stand-in**: records the argv it received, NUL-separated, and
//!   the names of the `SENTINEL_*` variables it inherited, then exits.
//!   Nothing is opened.
//!
//! The URL carries shell metacharacters, quotes, spaces and variable syntax
//! for both `sh` and `cmd.exe`; the stand-in must receive it as one argv
//! element and the canary commands inside it must not run. On Windows the
//! stand-in is a Rust program that splits its command line by the MSVC
//! rules, which the real `rundll32` does not (it hands the raw rest of the
//! line to `FileProtocolHandler`); so there the test proves that no shell
//! ran and what the command line decodes to, not what `rundll32` itself
//! would see. The real authorization URL never contains spaces or quotes.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

/// Set on the runner: the URL to open, and whether to launch.
const URL: &str = "SENTINEL_BROWSER_TEST_URL";
const LAUNCH: &str = "SENTINEL_BROWSER_TEST_LAUNCH";
/// Where the stand-in records what it received, beside itself.
const ARGV_FILE: &str = "argv.bin";
const ENV_FILE: &str = "env.bin";

/// The launcher `browser::command` names on this platform.
const OPENER: &str = if cfg!(windows) {
    "rundll32.exe"
} else {
    "xdg-open"
};

fn main() -> ExitCode {
    let me = std::env::current_exe().expect("current exe");
    if me.file_name().is_some_and(|name| name == OPENER) {
        return stand_in(&me);
    }
    if let Some(url) = std::env::var_os(URL) {
        let url = url.into_string().expect("a UTF-8 URL");
        let launch = std::env::var_os(LAUNCH).is_some();
        if cfg!(windows) {
            let stand_in = me.with_file_name(OPENER);
            sentinel::browser::open_with(&url, launch, |url| {
                sentinel::browser::command_with(&stand_in, url)
            });
        } else {
            sentinel::browser::open(&url, launch);
        }
        return ExitCode::SUCCESS;
    }
    let tests: [(&str, fn()); 4] = [
        (
            "the_opener_command_is_the_platform_launcher_with_the_url_as_one_argument",
            the_opener_command_is_the_platform_launcher_with_the_url_as_one_argument,
        ),
        (
            "the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell_or_credentials",
            the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell_or_credentials,
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
    // Enough of libtest's command line for `cargo test` and cargo-nextest:
    // `--list` names the tests (none are ignored), and a name filter —
    // exact with `--exact`, a substring otherwise — picks which run.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    if flag("--list") {
        if !flag("--ignored") {
            for (name, _) in tests {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    if flag("--ignored") {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored\n");
        return ExitCode::SUCCESS;
    }
    let exact = flag("--exact");
    let filters: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let chosen: Vec<_> = tests
        .into_iter()
        .filter(|(name, _)| {
            filters.is_empty()
                || filters
                    .iter()
                    .any(|f| if exact { name == f } else { name.contains(f) })
        })
        .collect();
    println!("\nrunning {} tests", chosen.len());
    for (name, test) in &chosen {
        test();
        println!("test {name} ... ok");
    }
    println!(
        "\ntest result: ok. {} passed; 0 failed; 0 ignored\n",
        chosen.len()
    );
    ExitCode::SUCCESS
}

/// The opener stand-in: the `SENTINEL_*` variable names it inherited, then
/// its argv after the program name, NUL-separated, written atomically so
/// the test never reads half of it.
fn stand_in(me: &Path) -> ExitCode {
    let mut names = Vec::new();
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if name.to_ascii_uppercase().starts_with("SENTINEL_") {
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
    }
    fs::write(me.with_file_name(ENV_FILE), names).expect("record the environment");
    let mut record = Vec::new();
    for arg in std::env::args_os().skip(1) {
        record.extend_from_slice(arg.into_string().expect("UTF-8 argv").as_bytes());
        record.push(0);
    }
    let out = me.with_file_name(ARGV_FILE);
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
        let out = dir.path().join(ARGV_FILE);
        Self { dir, runner, out }
    }

    /// Runs the opener in the runner, with credentials in its environment,
    /// and returns its standard error.
    fn open(&self, url: &str, launch: bool) -> String {
        let mut command = Command::new(&self.runner);
        command
            .env(URL, url)
            .env("SENTINEL_TOKEN", format!("sntl_{}", "ab".repeat(32)))
            .env("SENTINEL_GIT_SECRET", "hunter2")
            .env("sentinel_lower_case", "x");
        if launch {
            command.env(LAUNCH, "1");
        } else {
            command.env_remove(LAUNCH);
        }
        // Where the real opener is looked up first: `PATH` on Unix.
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

    /// The `SENTINEL_*` variables the stand-in inherited (read after
    /// [`Stage::received`]).
    fn inherited(&self) -> Vec<String> {
        let bytes = fs::read(self.dir.path().join(ENV_FILE)).expect("read the environment");
        String::from_utf8(bytes)
            .expect("UTF-8 names")
            .split_terminator('\0')
            .map(str::to_owned)
            .collect()
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
        // P09C-5: an absolute path into the system directory, never a bare
        // name that the CLI's own directory could answer.
        let program = Path::new(command.get_program());
        assert!(program.is_absolute(), "{program:?}");
        let lower = program.to_string_lossy().to_ascii_lowercase();
        assert!(lower.ends_with(r"\system32\rundll32.exe"), "{program:?}");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        assert!(program.starts_with(system_root), "{program:?}");
        assert!(program.is_file(), "{program:?}");
        assert_eq!(args, ["url.dll,FileProtocolHandler", url]);
    } else {
        assert_eq!(command.get_program(), OPENER);
        assert_eq!(args, [url]);
    }
}

fn the_real_opener_receives_a_hostile_url_as_one_argv_element_without_a_shell_or_credentials() {
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
    // The runner held SENTINEL_TOKEN and other SENTINEL_* variables; the
    // browser inherits none of them.
    assert_eq!(stage.inherited(), Vec::<String>::new());
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
