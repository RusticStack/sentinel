//! Offline `sentinel pipeline validate|explain`. Reads one file, applies the
//! same bounded loader, decoder and compiler the server uses, and reports.
//! Exit codes: 0 valid, 1 invalid or unreadable (message on stderr), 2 usage.
use std::{fs, process::ExitCode};

use sentinel_pipeline::{Explanation, compile_str, yaml::MAX_PIPELINE_FILE_BYTES};

use crate::cli::{PipelineArgs, PipelineCommand};

pub fn run(args: PipelineArgs) -> ExitCode {
    let (file, explain, json) = match args.command {
        PipelineCommand::Validate { file } => (file, false, false),
        PipelineCommand::Explain { file, json } => (file, true, json),
    };
    // Bound the read before parsing so a huge file fails fast without allocation.
    let size = match fs::metadata(&file) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", file.display());
            return ExitCode::from(1);
        }
    };
    if size > MAX_PIPELINE_FILE_BYTES as u64 {
        eprintln!(
            "error: {} is {size} bytes; the limit is {MAX_PIPELINE_FILE_BYTES}",
            file.display()
        );
        return ExitCode::from(1);
    }
    let text = match fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", file.display());
            return ExitCode::from(1);
        }
    };
    let compiled = match compile_str(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", file.display());
            return ExitCode::from(1);
        }
    };
    if explain {
        let explanation = Explanation::of(&compiled);
        if json {
            match serde_json::to_string(&explanation) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(1);
                }
            }
        } else {
            print!("{}", explanation.render_text());
        }
    }
    ExitCode::SUCCESS
}
