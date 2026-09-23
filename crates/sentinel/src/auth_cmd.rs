//! `sentinel auth login|status|logout` and `sentinel context use|show` (O04):
//! browser (loopback + PKCE) and device sign-in, grant import for agents,
//! status without token material, logout with server revocation.
//!
//! Stub: the argument shapes follow the plan and the owning unit (D) may
//! restructure them freely inside this file; `cli.rs` names only
//! [`AuthArgs`], [`ContextArgs`], [`run`] and [`run_context`].

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::client::{self, ClientArgs, Exit};

#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Sign in through the browser (or --device) and store the grant in a profile
    Login {
        /// Controller URL
        #[arg(long)]
        server: Option<String>,
        /// Profile to write (default: "default")
        #[arg(long, env = "SENTINEL_PROFILE")]
        profile: Option<String>,
        /// Use the device flow: approve a short code on another device
        #[arg(long)]
        device: bool,
        /// Print the sign-in URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Space-separated scopes to request
        #[arg(long)]
        scope: Option<String>,
        /// Import a provisioned sntl_rt_ refresh token from a file, or - for stdin
        #[arg(long, value_name = "PATH")]
        grant_file: Option<PathBuf>,
    },
    /// Show the profile, account, scopes and expiry; never token material
    Status {
        #[command(flatten)]
        client: ClientArgs,
        /// Do not contact the server
        #[arg(long)]
        offline: bool,
    },
    /// Revoke the grant on the server and delete the stored credential
    Logout {
        #[arg(long, env = "SENTINEL_PROFILE")]
        profile: Option<String>,
        /// Every profile
        #[arg(long, conflicts_with = "profile")]
        all: bool,
        /// Also remove the profile entry
        #[arg(long)]
        forget: bool,
    },
}

#[derive(Args, Debug)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommand,
}

#[derive(Subcommand, Debug)]
pub enum ContextCommand {
    /// Make a tenant the profile's default for commands that take --tenant
    Use {
        tenant: String,
        #[arg(long, env = "SENTINEL_PROFILE")]
        profile: Option<String>,
    },
    /// Show the profile's default tenant
    Show {
        #[command(flatten)]
        client: ClientArgs,
    },
}

pub fn run(args: AuthArgs) -> Result<(), client::Error> {
    let _ = args;
    Err(client::Error::new(
        Exit::Usage,
        "sentinel auth is not available yet",
    ))
}

pub fn run_context(args: ContextArgs) -> Result<(), client::Error> {
    let _ = args;
    Err(client::Error::new(
        Exit::Usage,
        "sentinel context is not available yet",
    ))
}
