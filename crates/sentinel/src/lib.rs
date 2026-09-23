//! Shared command options, the portable API client and its commands, and
//! Linux runtime foundations. These are internal development APIs, not a
//! stable plugin/SDK contract.

use clap::ValueEnum;

pub mod auth_cmd;
pub mod browser;
pub mod client;
pub mod commands;
pub mod doctor;
pub mod keystore;
pub mod loopback;
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
