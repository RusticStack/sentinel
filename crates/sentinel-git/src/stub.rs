//! Non-Unix hosts: every entry point refuses explicitly. The controller and
//! worker roles are Linux; this exists so callers compile everywhere.
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::Access;

use crate::{Error, Result};

pub const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub struct Credential {
    pub username: String,
    pub secret: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Checkout {
    pub sha: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FetchedFile {
    pub commit: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub fn run(_: Command, _: Instant, _: &'static str) -> Result<Output> {
    Err(Error::UnsupportedPlatform)
}

pub fn checkout(
    _: &Path,
    _: &PinnedSource,
    _: Option<&Credential>,
    _: Duration,
) -> Result<Checkout> {
    Err(Error::UnsupportedPlatform)
}

pub fn checkout_authorized(
    _: &Path,
    _: &PinnedSource,
    _: &Access,
    _: Duration,
) -> Result<Checkout> {
    Err(Error::UnsupportedPlatform)
}

pub fn file_at(
    _: &Path,
    _: &str,
    _: Option<&Access>,
    _: &str,
    _: &str,
    _: usize,
    _: Duration,
) -> Result<FetchedFile> {
    Err(Error::UnsupportedPlatform)
}
