#[cfg(all(any(feature = "server", feature = "worker"), not(target_os = "linux")))]
compile_error!(
    "Sentinel server and worker builds require Linux; omit these features for CLI builds."
);

mod cli;

#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
mod service;

use clap::Parser;
use std::process::ExitCode;

use cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (role, args) = match cli.command {
        Command::Server(args) => ("server", args),
        Command::Worker(args) => ("worker", args),
    };

    #[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
    {
        let enabled = match role {
            "server" => cfg!(feature = "server"),
            "worker" => cfg!(feature = "worker"),
            _ => unreachable!(),
        };
        if enabled {
            return match service::run(role, args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {}", error.message);
                    ExitCode::from(error.code)
                }
            };
        }
    }

    let _ = args;
    eprintln!(
        "error: {role} is unavailable in this build; use a Linux binary built with --features {role}"
    );
    ExitCode::from(2)
}
