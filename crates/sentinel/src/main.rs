#[cfg(all(any(feature = "server", feature = "worker"), not(target_os = "linux")))]
compile_error!(
    "Sentinel server and worker builds require Linux; omit these features for CLI builds."
);

#[cfg(all(target_os = "linux", feature = "server"))]
mod admin;
mod cli;
mod client;
#[cfg(all(target_os = "linux", feature = "server"))]
mod intake_admin;
mod pipeline;
#[cfg(all(target_os = "linux", feature = "server"))]
mod source_admin;

#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
mod service;

use clap::Parser;
use std::process::ExitCode;

use cli::{Cli, Command};

#[cfg(all(target_os = "linux", feature = "server"))]
fn run_admin(args: cli::AdminArgs) -> ExitCode {
    match admin::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", error.message);
            ExitCode::from(2)
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "server")))]
fn run_admin(_args: cli::AdminArgs) -> ExitCode {
    eprintln!(
        "error: admin runs on the controller's own host; use a Linux binary built with --features server"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (role, args) = match cli.command {
        Command::Server(args) => ("server", args),
        Command::Worker(args) => ("worker", args),
        Command::Pipeline(args) => return pipeline::run(args),
        Command::Api(args) => {
            return match client::run(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {}", error.message);
                    ExitCode::from(error.code)
                }
            };
        }
        Command::Admin(args) => return run_admin(args),
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
                    if !error.reported {
                        eprintln!("error: {}", error.message);
                    }
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
