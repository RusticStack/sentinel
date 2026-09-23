//! `sentinel doctor` (O06): check the configuration directory, the profile,
//! reachability, the issuer, the credential store, and that the access token
//! works and refreshes — printing the exact fix for each failure and never a
//! secret. `--json` emits `sentinel.doctor/1`.
//!
//! Stub: the owning unit (F) may restructure [`DoctorArgs`] freely inside
//! this file; `cli.rs` names only [`DoctorArgs`] and [`run`].

use clap::Args;

use crate::client::{self, ClientArgs, Exit};

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub client: ClientArgs,
}

pub fn run(args: DoctorArgs) -> Result<(), client::Error> {
    let _ = args;
    Err(client::Error::new(
        Exit::Usage,
        "sentinel doctor is not available yet",
    ))
}
