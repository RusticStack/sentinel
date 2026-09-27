#[cfg(all(any(feature = "server", feature = "worker"), not(target_os = "linux")))]
compile_error!(
    "Sentinel server and worker builds require Linux; omit these features for CLI builds."
);

#[cfg(all(target_os = "linux", feature = "server"))]
mod admin;
mod api;
mod cli;
#[cfg(all(target_os = "linux", feature = "server"))]
mod intake_admin;
mod pipeline;
#[cfg(all(target_os = "linux", feature = "server"))]
mod source_admin;

#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
mod service;
#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
mod tailcat_admin;

use clap::Parser;
use sentinel::{client, commands::Invocation};
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

/// A worker host has no metadata store; only its Tailcat identity is
/// administered there.
#[cfg(all(target_os = "linux", feature = "worker", not(feature = "server")))]
fn run_admin(args: cli::AdminArgs) -> ExitCode {
    let cli::AdminCommand::Tailcat(args) = args.command else {
        eprintln!(
            "error: this admin command runs on the controller's own host; use a Linux binary built with --features server"
        );
        return ExitCode::from(2);
    };
    match tailcat_admin::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(all(target_os = "linux", any(feature = "server", feature = "worker"))))]
fn run_admin(_args: cli::AdminArgs) -> ExitCode {
    eprintln!(
        "error: admin runs on the controller's own host; use a Linux binary built with --features server"
    );
    ExitCode::from(2)
}

/// A client command's outcome as the process exit: the failure is reported
/// on stderr in the command's output mode, and its exit code is returned.
fn finish(outcome: Result<(), client::Error>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            client::report(&error);
            ExitCode::from(error.exit as u8)
        }
    }
}

/// Parse arguments. For `sentinel secret`, a parse error that would quote
/// an offending argument (a value typed where none is accepted, as in
/// `secret set TOKEN hunter2` or `--value=hunter2`) is replaced by a fixed
/// message, so the stray value is not copied into captured stderr (P10C-5).
fn parse() -> Result<Cli, ExitCode> {
    use clap::error::ErrorKind;
    let error = match Cli::try_parse() {
        Ok(cli) => return Ok(cli),
        Err(error) => error,
    };
    let secret = std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "secret");
    let quoting = matches!(
        error.kind(),
        ErrorKind::UnknownArgument
            | ErrorKind::InvalidValue
            | ErrorKind::InvalidSubcommand
            | ErrorKind::ValueValidation
            | ErrorKind::TooManyValues
            | ErrorKind::WrongNumberOfValues
            | ErrorKind::NoEquals
            | ErrorKind::InvalidUtf8
            | ErrorKind::ArgumentConflict
    );
    if secret && quoting {
        eprintln!(
            "error: unexpected or invalid argument to `sentinel secret` (not shown); secret values are never accepted as arguments: use --stdin, --file or the hidden prompt\n\nFor more information, try 'sentinel secret --help'."
        );
        return Err(ExitCode::from(2));
    }
    error.exit()
}

fn main() -> ExitCode {
    let cli = match parse() {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let (role, args) = match cli.command {
        Command::Server(args) => ("server", args),
        Command::Worker(args) => ("worker", args),
        Command::Pipeline(args) => return pipeline::run(args),
        Command::Api(args) => return finish(api::run(args)),
        Command::Mcp(args) => return finish(sentinel::mcp::run(args)),
        Command::Admin(args) => return run_admin(args),
        Command::Auth(args) => return finish(sentinel::auth_cmd::run(args)),
        Command::Context(args) => return finish(sentinel::auth_cmd::run_context(args)),
        Command::Doctor(args) => return finish(sentinel::doctor::run(args)),
        Command::ServiceAccount(args) => return finish(sentinel::service_accounts::run(args)),
        Command::Run(args) => return finish(sentinel::commands::run(Invocation::Run(args))),
        Command::Status(args) => return finish(sentinel::commands::run(Invocation::Status(args))),
        Command::Wait(args) => return finish(sentinel::commands::run(Invocation::Wait(args))),
        Command::Job(args) => return finish(sentinel::commands::run(Invocation::Job(args))),
        Command::Log(args) => return finish(sentinel::commands::run(Invocation::Log(args))),
        Command::Workers(args) => {
            return finish(sentinel::commands::run(Invocation::Workers(args)));
        }
        Command::Queue(args) => return finish(sentinel::commands::run(Invocation::Queue(args))),
        Command::Artifact(args) => {
            return finish(sentinel::commands::run(Invocation::Artifact(args)));
        }
        Command::Cache(args) => return finish(sentinel::commands::run(Invocation::Cache(args))),
        Command::Secret(args) => return finish(sentinel::commands::run(Invocation::Secret(args))),
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

#[cfg(test)]
mod secret_cli_tests {
    use clap::Parser;

    use crate::Cli;

    #[test]
    fn the_command_tree_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn set_refuses_conflicting_secret_input_sources() {
        let base = ["sentinel", "secret", "set", "TOKEN", "--tenant", "acme"];
        assert!(Cli::try_parse_from([base.as_slice(), &["--stdin"]].concat()).is_ok());
        assert!(
            Cli::try_parse_from([base.as_slice(), &["--stdin", "--file", "secret.txt"]].concat())
                .is_err()
        );
    }
}
