//! Offline `sentinel pipeline validate|explain`. Reads one file, applies the
//! same bounded loader, decoder and compiler the server uses, and reports.
//! Exit codes: 0 valid, 1 invalid or unreadable (message on stderr), 2 usage.
//!
//! Output parity with the networked commands (`docs/cli.md#output`): in JSON
//! mode a success is one document on stdout — `sentinel.explain/1` for
//! `explain`, `{"file", "valid": true, "jobs"}` for `validate` — and a
//! failure is one `sentinel.error/1` line on stderr (`invalid_pipeline` or
//! `client_usage` for an unreadable file) with stdout left empty. `explain
//! --json` selects it today; [`run_with`] takes the mode so a shared
//! `--output` flag only has to pass it through.
use std::{path::Path, process::ExitCode};

use sentinel::client::Output;
use sentinel_pipeline::{Explanation, compile_str, yaml::MAX_PIPELINE_FILE_BYTES};
use serde_json::json;

use crate::cli::{PipelineArgs, PipelineCommand};

pub fn run(args: PipelineArgs) -> ExitCode {
    match args.command {
        PipelineCommand::Validate { file } => run_with(&file, false, Output::Text),
        PipelineCommand::Explain { file, json } => {
            run_with(&file, true, if json { Output::Json } else { Output::Text })
        }
    }
}

/// Validate (and with `explain`, describe) one file in `output` mode.
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
    // Bound the read before parsing so a huge file fails fast without allocation.
    let size = match std::fs::metadata(file) {
        Ok(m) => m.len(),
        Err(e) => {
            return fail(
                "client_usage",
                format!("error: cannot read {}: {e}", file.display()),
            );
        }
    };
    if size > MAX_PIPELINE_FILE_BYTES as u64 {
        return fail(
            "invalid_pipeline",
            format!(
                "error: {} is {size} bytes; the limit is {MAX_PIPELINE_FILE_BYTES}",
                file.display()
            ),
        );
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
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
            print!("{}", explanation.render_text());
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
    // One compact line in both JSON modes, as `explain --json` always printed.
    println!("{document}");
    ExitCode::SUCCESS
}
