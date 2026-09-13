#[cfg(all(any(feature = "server", feature = "worker"), not(target_os = "linux")))]
compile_error!(
    "Sentinel server and worker builds require Linux; omit these features for CLI builds."
);

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("Sentinel is under development; commands are not implemented yet.");
    ExitCode::FAILURE
}
