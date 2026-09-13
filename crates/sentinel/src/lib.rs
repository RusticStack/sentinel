//! Shared command options and Linux runtime foundations.
//! These are internal development APIs, not a stable plugin/SDK contract.

use clap::ValueEnum;

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
