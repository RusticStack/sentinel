//! `sentinel service-account create|allow|grant|grants|revoke` (O06): a
//! tenant administrator creates service principals, allows them
//! repositories, and issues grants whose refresh token goes to stdout once
//! (metadata to stderr) for `sentinel auth login --grant-file`.
//!
//! Stub: the argument shapes follow the plan and the owning unit (C) may
//! restructure them freely inside this file; `cli.rs` names only
//! [`ServiceAccountArgs`] and [`run`].

use clap::{Args, Subcommand};

use crate::client::{self, ClientArgs, Exit};

#[derive(Args, Debug)]
pub struct ServiceAccountArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: ServiceAccountCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceAccountCommand {
    /// Create a service principal in a tenant
    Create {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        #[arg(long)]
        name: String,
        /// reader or operator
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// Allow a service principal a repository
    Allow {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// The service principal's usr_ identifier
        account: String,
        #[arg(long)]
        repo: String,
        /// Comma-separated: read, run
        #[arg(long, default_value = "read,run")]
        access: String,
    },
    /// Issue a grant; only the refresh token goes to stdout
    Grant {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        account: String,
        #[arg(long)]
        name: String,
        /// Space-separated scopes
        #[arg(long)]
        scope: String,
        #[arg(long)]
        repo: Option<String>,
        /// Lifetime such as 30d; 1h to 90d
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
    },
    /// List a service principal's grants as metadata
    Grants {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        account: String,
    },
    /// Revoke a grant by its grt_ identifier
    Revoke { grant: String },
}

pub fn run(args: ServiceAccountArgs) -> Result<(), client::Error> {
    let _ = args;
    Err(client::Error::new(
        Exit::Usage,
        "sentinel service-account is not available yet",
    ))
}
