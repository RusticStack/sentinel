use std::{path::Path, process::ExitCode};

use sentinel::bounded::{self, ReadError};
use sentinel::client::Output;
use sentinel_pipeline::{Explanation, compile_str, yaml::MAX_PIPELINE_FILE_BYTES};
use serde_json::json;

use crate::cli::{PipelineArgs, PipelineCommand};

pub fn run(args: PipelineArgs) -> ExitCode {
    match args.command {
        PipelineCommand::Validate { file, output } => run_with(&file, false, output.mode()),
        PipelineCommand::Explain { file, output } => run_with(&file, true, output.mode()),
    }
}

pub fn run_with(file: &Path, explain: bool, output: Output) -> ExitCode {
    let fail = |code: &str, message: String| {
        match output {
            Output::Text => eprintln!("{message}"),
            Output::Json | Output::Ndjson => eprintln!(
                "{}",
                json!({
                    "schema": "sentinel.error/1",
                    "code": code,
                    "message": message,
                    "retryable": false,
                })
            ),
        }
        ExitCode::from(1)
    };
    // Bound the read itself: device, FIFO and procfs files report length 0, and files can grow after a size check.
    let text = match bounded::text(file, MAX_PIPELINE_FILE_BYTES as u64) {
        Ok(t) => t,
        Err(ReadError::TooLarge { limit }) => {
            return fail(
                "invalid_pipeline",
                format!(
                    "error: {} exceeds the pipeline file limit of {limit} bytes",
                    file.display()
                ),
            );
        }
        Err(e) => {
            return fail(
                "client_usage",
                format!("error: cannot read {}: {e}", file.display()),
            );
        }
    };
    let compiled = match compile_str(&text) {
        Ok(c) => c,
        Err(e) => return fail("invalid_pipeline", format!("{}: {e}", file.display())),
    };
    let document = if explain {
        let explanation = Explanation::of(&compiled);
        if output == Output::Text {
            sentinel::out!("{}", explanation.render_text());
            return ExitCode::SUCCESS;
        }
        match serde_json::to_value(&explanation) {
            Ok(value) => value,
            Err(e) => return fail("client_remote", format!("error: {e}")),
        }
    } else {
        if output == Output::Text {
            return ExitCode::SUCCESS;
        }
        json!({
            "file": file.display().to_string(),
            "valid": true,
            "jobs": compiled.jobs.len(),
        })
    };
    sentinel::outln!("{document}");
    ExitCode::SUCCESS
}
