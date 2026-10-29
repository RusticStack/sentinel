//! `sentinel worker uninstall` and `sentinel worker rollback` (Q11): the host-side half of the worker the
//! generated bootstrap script installs. The script calls them; they work on the layout it creates and
//! on its `install.state` record, so they remove exactly what the install made and nothing else.
//!
//! Everything that touches the system (systemd, lingering, the service account) goes through [`Host`], so
//! the tests run the same code against a recording stand-in and a scratch directory tree.

use std::{
    fs, io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::cli::{InstallLayoutArgs, RollbackArgs, UninstallArgs};

/// Why a command did not finish: the exit status and the line shown to the operator.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    /// The host or the request is unsupported; nothing was changed.
    pub fn refused(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}

/// The paths of one installed worker.
#[derive(Clone, Debug)]
pub struct Layout {
    pub prefix: PathBuf,
    pub conf_dir: PathBuf,
    pub data_dir: PathBuf,
    pub unit_file: PathBuf,
    pub unit: String,
    pub account: String,
}

impl Layout {
    pub fn from_args(args: &InstallLayoutArgs) -> Self {
        Self {
            prefix: args.prefix.clone(),
            conf_dir: args.conf_dir.clone(),
            data_dir: args.data_dir.clone(),
            unit_file: args.unit_file.clone(),
            unit: "sentinel-worker".to_owned(),
            account: "sentinel-worker".to_owned(),
        }
    }

    fn state_file(&self) -> PathBuf {
        self.prefix.join("install.state")
    }
}

/// What the commands need from the system.
pub trait Host {
    fn is_root(&self) -> bool;
    /// Run `systemctl` with fixed arguments; true when it succeeded.
    fn systemctl(&mut self, args: &[&str]) -> bool;
    fn disable_linger(&mut self, account: &str);
    fn account_exists(&mut self, account: &str) -> bool;
    /// Remove the account; true when it is gone afterwards.
    fn remove_account(&mut self, account: &str) -> bool;
    fn pause(&mut self, wait: Duration);
}

/// The real system.
pub struct System;

impl System {
    fn run(program: &str, args: &[&str]) -> bool {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

impl Host for System {
    fn is_root(&self) -> bool {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn systemctl(&mut self, args: &[&str]) -> bool {
        Self::run("systemctl", args)
    }

    fn disable_linger(&mut self, account: &str) {
        let _ = Self::run("loginctl", &["disable-linger", account]);
    }

    fn account_exists(&mut self, account: &str) -> bool {
        Self::run("getent", &["passwd", account])
    }

    fn remove_account(&mut self, account: &str) -> bool {
        Self::run("userdel", &[account]) || !self.account_exists(account)
    }

    fn pause(&mut self, wait: Duration) {
        thread::sleep(wait);
    }
}

pub fn uninstall(args: &UninstallArgs) -> Result<(), Failure> {
    let layout = Layout::from_args(&args.layout);
    let report = uninstall_with(&layout, &mut System, args.keep_data)?;
    for line in report {
        eprintln!("sentinel-worker: {line}");
    }
    Ok(())
}

pub fn rollback(args: &RollbackArgs) -> Result<(), Failure> {
    let layout = Layout::from_args(&args.layout);
    let said = rollback_with(&layout, &mut System, ACTIVE_WAIT)?;
    eprintln!("sentinel-worker: {said}");
    Ok(())
}

/// Seconds the restarted service has to come up, and then to stay up.
const ACTIVE_WAIT: u32 = 30;
const STABLE: Duration = Duration::from_secs(3);

fn state_value(state: &str, key: &str) -> Option<String> {
    state
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(str::to_owned)
}

fn read_state(layout: &Layout) -> Result<String, Failure> {
    match fs::read_to_string(layout.state_file()) {
        Ok(state) => Ok(state),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(Failure::failed("no worker is installed on this host"))
        }
        Err(error) => Err(Failure::failed(format!(
            "cannot read the install record {}: {error}",
            layout.state_file().display()
        ))),
    }
}

fn remove_tree(path: &Path, left: &mut Vec<String>) {
    let result = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        left.push(format!("could not remove {}: {error}", path.display()));
    }
}

/// Stop and remove the service, the release tree, the configuration, lingering and the account the
/// install created and, unless `keep_data`, the data directory with the worker's TLS and Tailcat keys.
/// Returns what it removed; any leftover is an error that names it, so a half-removed worker is never
/// reported as gone.
pub fn uninstall_with(
    layout: &Layout,
    host: &mut dyn Host,
    keep_data: bool,
) -> Result<Vec<String>, Failure> {
    if !host.is_root() {
        return Err(Failure::refused(
            "run it as root, for example: sudo sentinel worker uninstall",
        ));
    }
    let state = read_state(layout)?;
    let created_account = state_value(&state, "created_account").as_deref() == Some("1");
    let enabled_linger = state_value(&state, "enabled_linger").as_deref() == Some("1");

    let mut left = Vec::new();
    let unit = format!("{}.service", layout.unit);
    host.systemctl(&["stop", &unit]);
    host.systemctl(&["disable", &unit]);
    remove_tree(&layout.unit_file, &mut left);
    let mut staged = layout.unit_file.clone().into_os_string();
    staged.push(".new");
    remove_tree(Path::new(&staged), &mut left);
    host.systemctl(&["daemon-reload"]);
    remove_tree(&layout.prefix, &mut left);
    remove_tree(&layout.conf_dir, &mut left);
    if !keep_data {
        remove_tree(&layout.data_dir, &mut left);
    }
    if enabled_linger {
        host.disable_linger(&layout.account);
    }
    // The account goes with the install even when the data directory is kept, as the script's own
    // removal does: the kept identity belongs to a revoked worker and a reinstall starts clean.
    if created_account
        && host.account_exists(&layout.account)
        && !host.remove_account(&layout.account)
    {
        left.push(format!("could not remove the '{}' account", layout.account));
    }
    if !left.is_empty() {
        return Err(Failure::failed(format!(
            "the worker is only partly removed: {}",
            left.join("; ")
        )));
    }
    let mut removed = vec![
        "stopped and removed the sentinel-worker service".to_owned(),
        format!("removed {}", layout.prefix.display()),
        format!("removed {}", layout.conf_dir.display()),
    ];
    if keep_data {
        removed.push(format!(
            "kept {} (the worker's identity and caches); remove it before installing again",
            layout.data_dir.display()
        ));
    } else {
        removed.push(format!("removed {}", layout.data_dir.display()));
    }
    if created_account {
        removed.push(format!("removed the '{}' account", layout.account));
    }
    Ok(removed)
}

fn release_of(layout: &Layout, link: &str) -> Option<String> {
    fs::read_link(layout.prefix.join(link))
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Replace a symlink atomically: the new target is linked beside it and renamed over it.
fn point(layout: &Layout, link: &str, release: &str) -> io::Result<()> {
    let staged = layout.prefix.join(format!("{link}.new"));
    let _ = fs::remove_file(&staged);
    symlink(format!("releases/{release}"), &staged)?;
    fs::rename(&staged, layout.prefix.join(link))
}

fn record_release(layout: &Layout, release: &str) -> io::Result<()> {
    let state = fs::read_to_string(layout.state_file())?;
    let mut text = String::with_capacity(state.len() + release.len() + 16);
    for line in state.lines().filter(|line| !line.starts_with("release=")) {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("release=");
    text.push_str(release);
    text.push('\n');
    let staged = layout.prefix.join("install.state.tmp");
    fs::write(&staged, text)?;
    fs::rename(&staged, layout.state_file())
}

fn stays_up(layout: &Layout, host: &mut dyn Host, seconds: u32) -> bool {
    let unit = format!("{}.service", layout.unit);
    for _ in 0..seconds {
        if host.systemctl(&["is-active", "--quiet", &unit]) {
            host.pause(STABLE);
            return host.systemctl(&["is-active", "--quiet", &unit]);
        }
        host.pause(Duration::from_secs(1));
    }
    false
}

/// Switch to the previous release and restart; if that release does not stay up either, switch back.
pub fn rollback_with(
    layout: &Layout,
    host: &mut dyn Host,
    seconds: u32,
) -> Result<String, Failure> {
    if !host.is_root() {
        return Err(Failure::refused(
            "run it as root, for example: sudo sentinel worker rollback",
        ));
    }
    read_state(layout)?;
    let (Some(current), Some(previous)) = (
        release_of(layout, "current"),
        release_of(layout, "previous"),
    ) else {
        return Err(Failure::failed(
            "there is no previous release to roll back to",
        ));
    };
    if !layout
        .prefix
        .join("releases")
        .join(&previous)
        .join("sentinel")
        .is_file()
    {
        return Err(Failure::failed(
            "there is no previous release to roll back to",
        ));
    }
    let swap = |first: &str, second: &str| -> io::Result<()> {
        point(layout, "current", first)?;
        point(layout, "previous", second)?;
        record_release(layout, first)
    };
    swap(&previous, &current)
        .map_err(|error| Failure::failed(format!("cannot switch releases: {error}")))?;
    let unit = format!("{}.service", layout.unit);
    host.systemctl(&["restart", &unit]);
    if stays_up(layout, host, seconds) {
        return Ok(format!(
            "rolled back to {previous}; {current} is kept for another rollback"
        ));
    }
    swap(&current, &previous)
        .map_err(|error| Failure::failed(format!("cannot restore {current}: {error}")))?;
    host.systemctl(&["restart", &unit]);
    Err(Failure::failed(format!(
        "the previous release {previous} did not stay up; restored {current}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        root: bool,
        calls: Vec<String>,
        /// `is-active` answers, consumed in order; the last one repeats.
        active: Vec<bool>,
        account: bool,
        keeps_account: bool,
    }

    impl Host for Recorder {
        fn is_root(&self) -> bool {
            self.root
        }
        fn systemctl(&mut self, args: &[&str]) -> bool {
            self.calls.push(format!("systemctl {}", args.join(" ")));
            if args.first() == Some(&"is-active") {
                if self.active.len() > 1 {
                    return self.active.remove(0);
                }
                return self.active.first().copied().unwrap_or(true);
            }
            true
        }
        fn disable_linger(&mut self, account: &str) {
            self.calls.push(format!("disable-linger {account}"));
        }
        fn account_exists(&mut self, _: &str) -> bool {
            self.account
        }
        fn remove_account(&mut self, account: &str) -> bool {
            self.calls.push(format!("userdel {account}"));
            if !self.keeps_account {
                self.account = false;
            }
            !self.keeps_account
        }
        fn pause(&mut self, _: Duration) {}
    }

    fn root() -> Recorder {
        Recorder {
            root: true,
            ..Recorder::default()
        }
    }

    struct Tree {
        _dir: tempfile::TempDir,
        layout: Layout,
    }

    /// The tree the bootstrap script leaves after an install, plus a TLS key and a Tailcat key.
    fn installed(state: &str) -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let layout = Layout {
            prefix: base.join("opt"),
            conf_dir: base.join("etc"),
            data_dir: base.join("var"),
            unit_file: base.join("sentinel-worker.service"),
            unit: "sentinel-worker".into(),
            account: "sentinel-worker".into(),
        };
        for release in ["0.1.0-aaaa", "0.2.0-bbbb"] {
            let release_dir = layout.prefix.join("releases").join(release);
            fs::create_dir_all(&release_dir).unwrap();
            fs::write(release_dir.join("sentinel"), release).unwrap();
        }
        symlink("releases/0.2.0-bbbb", layout.prefix.join("current")).unwrap();
        symlink("releases/0.1.0-aaaa", layout.prefix.join("previous")).unwrap();
        fs::write(layout.state_file(), state).unwrap();
        fs::create_dir_all(&layout.conf_dir).unwrap();
        fs::write(layout.conf_dir.join("worker.toml"), "controller = \"x\"\n").unwrap();
        fs::create_dir_all(layout.data_dir.join("tailcat")).unwrap();
        fs::write(layout.data_dir.join("worker.key"), "KEY").unwrap();
        fs::write(layout.data_dir.join("worker.crt"), "CRT").unwrap();
        fs::write(layout.data_dir.join("worker.id"), "wrk_x\n").unwrap();
        fs::write(
            layout
                .data_dir
                .join("tailcat")
                .join("client-default.nodekey"),
            "nodekey:00",
        )
        .unwrap();
        fs::write(&layout.unit_file, "[Unit]\n").unwrap();
        Tree { _dir: dir, layout }
    }

    const STATE: &str = "format=1\ncreated_account=1\nenabled_linger=1\nrelease=0.2.0-bbbb\n";

    fn stray(tree: &Tree) -> Vec<PathBuf> {
        let l = &tree.layout;
        [&l.prefix, &l.conf_dir, &l.data_dir, &l.unit_file]
            .into_iter()
            .filter(|p| p.symlink_metadata().is_ok())
            .cloned()
            .collect()
    }

    #[test]
    fn uninstall_leaves_no_unit_key_or_data_and_undoes_only_what_the_install_did() {
        let tree = installed(STATE);
        let mut host = Recorder {
            account: true,
            ..root()
        };
        let said = uninstall_with(&tree.layout, &mut host, false).unwrap();
        assert!(stray(&tree).is_empty(), "{:?}", stray(&tree));
        assert!(said.iter().any(|line| line.contains("account")));
        assert_eq!(
            host.calls,
            [
                "systemctl stop sentinel-worker.service",
                "systemctl disable sentinel-worker.service",
                "systemctl daemon-reload",
                "disable-linger sentinel-worker",
                "userdel sentinel-worker",
            ]
        );
    }

    #[test]
    fn an_account_or_lingering_the_install_did_not_create_stays() {
        let tree = installed("format=1\nrelease=0.2.0-bbbb\n");
        let mut host = Recorder {
            account: true,
            ..root()
        };
        uninstall_with(&tree.layout, &mut host, false).unwrap();
        assert!(stray(&tree).is_empty());
        assert!(
            !host
                .calls
                .iter()
                .any(|c| c.starts_with("userdel") || c.starts_with("disable-linger")),
            "{:?}",
            host.calls
        );
    }

    #[test]
    fn keep_data_keeps_the_identity_for_the_operator_to_remove() {
        let tree = installed(STATE);
        let mut host = Recorder {
            account: true,
            ..root()
        };
        uninstall_with(&tree.layout, &mut host, true).unwrap();
        assert_eq!(stray(&tree), vec![tree.layout.data_dir.clone()]);
        assert!(tree.layout.data_dir.join("worker.key").is_file());
    }

    #[test]
    fn a_partial_removal_is_an_error_that_names_what_is_left() {
        let tree = installed(STATE);
        let mut host = Recorder {
            account: true,
            keeps_account: true,
            ..root()
        };
        let failure = uninstall_with(&tree.layout, &mut host, false).unwrap_err();
        assert_eq!(failure.code, 1);
        assert!(failure.message.contains("account"), "{}", failure.message);
    }

    #[test]
    fn uninstall_needs_root_and_an_install_record() {
        let tree = installed(STATE);
        let refused = uninstall_with(&tree.layout, &mut Recorder::default(), false).unwrap_err();
        assert_eq!(refused.code, 2);
        assert!(!stray(&tree).is_empty(), "nothing was touched");
        let bare = tempfile::tempdir().unwrap();
        let layout = Layout {
            prefix: bare.path().join("opt"),
            ..tree.layout.clone()
        };
        let missing = uninstall_with(&layout, &mut root(), false).unwrap_err();
        assert!(missing.message.contains("no worker is installed"));
    }

    #[test]
    fn rollback_swaps_the_releases_and_records_the_one_now_running() {
        let tree = installed(STATE);
        let said = rollback_with(&tree.layout, &mut root(), 2).unwrap();
        assert!(said.contains("0.1.0-aaaa"), "{said}");
        assert_eq!(
            release_of(&tree.layout, "current").as_deref(),
            Some("0.1.0-aaaa")
        );
        assert_eq!(
            release_of(&tree.layout, "previous").as_deref(),
            Some("0.2.0-bbbb")
        );
        let state = fs::read_to_string(tree.layout.state_file()).unwrap();
        assert_eq!(
            state_value(&state, "release").as_deref(),
            Some("0.1.0-aaaa")
        );
        assert!(
            state.contains("created_account=1"),
            "the record keeps what it knew"
        );
        // A second rollback returns to where it started.
        rollback_with(&tree.layout, &mut root(), 2).unwrap();
        assert_eq!(
            release_of(&tree.layout, "current").as_deref(),
            Some("0.2.0-bbbb")
        );
    }

    #[test]
    fn a_rollback_that_does_not_stay_up_puts_the_running_release_back() {
        let tree = installed(STATE);
        let mut host = Recorder {
            active: vec![false],
            ..root()
        };
        let failure = rollback_with(&tree.layout, &mut host, 2).unwrap_err();
        assert!(
            failure.message.contains("restored 0.2.0-bbbb"),
            "{}",
            failure.message
        );
        assert_eq!(
            release_of(&tree.layout, "current").as_deref(),
            Some("0.2.0-bbbb")
        );
        assert_eq!(
            release_of(&tree.layout, "previous").as_deref(),
            Some("0.1.0-aaaa")
        );
        let restarts = host
            .calls
            .iter()
            .filter(|c| c.starts_with("systemctl restart"))
            .count();
        assert_eq!(restarts, 2, "once to try, once to restore");
    }

    #[test]
    fn rollback_without_a_previous_release_changes_nothing() {
        let tree = installed(STATE);
        fs::remove_file(tree.layout.prefix.join("previous")).unwrap();
        let failure = rollback_with(&tree.layout, &mut root(), 2).unwrap_err();
        assert!(failure.message.contains("no previous release"));
        assert_eq!(
            release_of(&tree.layout, "current").as_deref(),
            Some("0.2.0-bbbb")
        );
        let refused = rollback_with(&tree.layout, &mut Recorder::default(), 2).unwrap_err();
        assert_eq!(refused.code, 2);
    }
}
