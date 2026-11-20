use std::{path::Path, process::ExitCode};

use sentinel::bounded::{self, ReadError};
use sentinel::client::Output;
use sentinel_pipeline::{Explanation, compile_document, yaml::MAX_PIPELINE_FILE_BYTES};
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
    // Every pipeline the document declares: the unnamed one, then the named ones by name.
    let pipelines = match compile_document(&text) {
        Ok(p) => p,
        Err(e) => return fail("invalid_pipeline", format!("{}: {e}", file.display())),
    };
    let document = if explain {
        let explanations: Vec<Explanation> = pipelines.iter().map(Explanation::of).collect();
        if output == Output::Text {
            for (i, explanation) in explanations.iter().enumerate() {
                if i > 0 {
                    sentinel::outln!();
                }
                sentinel::out!("{}", explanation.render_text());
            }
            return ExitCode::SUCCESS;
        }
        let values = match serde_json::to_value(&explanations) {
            Ok(value) => value,
            Err(e) => return fail("client_remote", format!("error: {e}")),
        };
        match values {
            serde_json::Value::Array(mut values) if values.len() == 1 => {
                values.pop().unwrap_or(serde_json::Value::Null)
            }
            other => json!({"schema": "sentinel.explain/1", "pipelines": other}),
        }
    } else {
        if output == Output::Text {
            return ExitCode::SUCCESS;
        }
        json!({
            "file": file.display().to_string(),
            "valid": true,
            "pipelines": pipelines.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
            "jobs": pipelines.iter().map(|p| p.jobs.len()).sum::<usize>(),
        })
    };
    sentinel::outln!("{document}");
    ExitCode::SUCCESS
}
