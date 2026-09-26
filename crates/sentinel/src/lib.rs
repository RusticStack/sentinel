//! Shared command options, the portable API client and its commands, and
//! Linux runtime foundations. These are internal development APIs, not a
//! stable plugin/SDK contract.

use clap::ValueEnum;

/// `print!` to standard output through [`client::stdout_fmt`]: a closed
/// pipe ends the command quietly with exit 0 instead of a panic.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::client::stdout_fmt(format_args!($($arg)*))
    };
}

/// `println!` to standard output through [`client::stdout_fmt`].
#[macro_export]
macro_rules! outln {
    () => {
        $crate::client::stdout_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::client::stdout_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

pub mod auth_cmd;
pub mod bounded;
pub mod browser;
pub mod client;
pub mod commands;
pub mod doctor;
pub mod keystore;
pub mod loopback;
pub mod mcp;
pub mod profile;
pub mod service_accounts;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
#[cfg_attr(
    all(target_os = "linux", any(feature = "server", feature = "worker")),
    derive(serde::Deserialize)
)]
#[cfg_attr(
    all(target_os = "linux", any(feature = "server", feature = "worker")),
    serde(rename_all = "lowercase")
)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
#[cfg_attr(
    all(target_os = "linux", any(feature = "server", feature = "worker")),
    derive(serde::Deserialize)
)]
#[cfg_attr(
    all(target_os = "linux", any(feature = "server", feature = "worker")),
    serde(rename_all = "lowercase")
)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
pub mod correlation;
#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
pub mod diagnostics;
#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
pub mod timing;
#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
pub mod work;
