//! The legacy `sentinel api …` commands (W08), kept with their flags and
//! output: `me`, `run`, `status`, `runs`, `cancel`, `rerun`, `logs`,
//! `workers`, `queue`, `drain`, `undrain`. They run on the shared
//! [`sentinel::client::Client`] with a static credential from `--token-file`,
//! `--token` or `SENTINEL_TOKEN` (an `sntl_` credential or an `sntl_at_`
//! access token) and the server from `--server` or `SENTINEL_SERVER`, and
//! exit with the shared exit codes.

use std::path::Path;

use sentinel::bounded;
use sentinel::client::{self, Client, Error, Output};
use serde_json::{Value, json};

use crate::cli::{ApiArgs, ApiCommand};

fn read_token(path: &Path) -> Result<String, Error> {
    Ok(client::read_token_file(path)?.trim().to_owned())
}

fn connect(args: &ApiArgs) -> Result<Client, Error> {
    let server = args
        .server
        .clone()
        .ok_or_else(|| Error::usage("give --server URL or set SENTINEL_SERVER"))?;
    let token = match (&args.token_file, &args.token) {
        (Some(path), _) => read_token(path)?,
        (None, Some(token)) => token.clone(),
        (None, None) => {
            return Err(Error::usage(
                "give --token-file, --token or set SENTINEL_TOKEN",
            ));
        }
    };
    Client::with_token(&server, &token)
}

pub fn run(args: ApiArgs) -> Result<(), Error> {
    let output = client::ClientArgs {
        json: args.json,
        ..client::ClientArgs::default()
    }
    .output();
    let client = connect(&args)?;
    let json_out = output == Output::Json;
    let out = |value: Value, text: String| client::emit(output, &value, || text);
    match &args.command {
        ApiCommand::Me => {
            let me = client.get("/api/v1/me")?;
            out(
                me.clone(),
                format!(
                    "{} via {}{}\n",
                    me["user"],
                    me["via"],
                    if me["super_admin"] == true {
                        " (super admin)"
                    } else {
                        ""
                    }
                ),
            );
        }
        ApiCommand::Run {
            tenant,
            repo,
            pipeline,
            source,
            sha,
            r#ref,
            idempotency_key,
        } => {
            let text = bounded::text(pipeline, bounded::PIPELINE_BYTES)
                .map_err(|e| Error::usage(format!("cannot read the pipeline: {e}")))?;
            let body =
                json!({ "pipeline": text, "source": { "repo": source, "sha": sha, "ref": r#ref } });
            let run = client.post(
                &format!("/api/v1/tenants/{tenant}/repos/{repo}/runs"),
                &body,
                idempotency_key.as_deref(),
            )?;
            out(
                run.clone(),
                format!("{}\n{}", run["id"].as_str().unwrap_or(""), jobs_text(&run)),
            );
        }
        ApiCommand::Status { run } => {
            let view = client.get(&format!("/api/v1/runs/{run}"))?;
            out(
                view.clone(),
                format!(
                    "{} {}\n{}",
                    view["id"].as_str().unwrap_or(""),
                    view["state"].as_str().unwrap_or(""),
                    jobs_text(&view)
                ),
            );
        }
        ApiCommand::Runs {
            tenant,
            repo,
            limit,
        } => {
            let list = client.get(&format!(
                "/api/v1/tenants/{tenant}/repos/{repo}/runs?limit={limit}"
            ))?;
            let mut text = String::new();
            for run in list["runs"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "{} {} {}\n",
                    run["id"].as_str().unwrap_or(""),
                    run["state"].as_str().unwrap_or(""),
                    run["sha"].as_str().unwrap_or("")
                ));
            }
            out(list.clone(), text);
        }
        ApiCommand::Cancel { run, job } => {
            let (path, label) = match (run, job) {
                (Some(run), None) => (format!("/api/v1/runs/{run}/cancel"), run.clone()),
                (None, Some(job)) => (format!("/api/v1/jobs/{job}/cancel"), job.clone()),
                _ => return Err(Error::usage("give exactly one of --run or --job")),
            };
            let result = client.post(&path, &json!({}), None)?;
            out(result.clone(), format!("{label}: cancellation recorded\n"));
        }
        ApiCommand::Rerun { job } => {
            let result = client.post(&format!("/api/v1/jobs/{job}/rerun"), &json!({}), None)?;
            out(
                result.clone(),
                format!("{job}: {}\n", result["state"].as_str().unwrap_or("")),
            );
        }
        ApiCommand::Logs { attempt, follow } => {
            let mut after = 0u64;
            loop {
                let page = client.get(&format!(
                    "/api/v1/attempts/{attempt}/logs?after={after}&wait={}",
                    u8::from(*follow)
                ))?;
                if json_out {
                    sentinel::outln!("{page}");
                } else {
                    use std::io::Write;
                    for frame in page["frames"].as_array().into_iter().flatten() {
                        let text = frame["text"].as_str().unwrap_or("");
                        if frame["stream"] == "stderr" {
                            let _ = std::io::stderr().write_all(text.as_bytes());
                        } else {
                            client::stdout_bytes(text.as_bytes());
                        }
                    }
                    client::stdout_flush();
                }
                if let Some(last) = page["frames"].as_array().and_then(|f| f.last()) {
                    after = last["seq"].as_u64().unwrap_or(after);
                }
                if page["complete"] == true {
                    if !json_out {
                        for gap in page["gaps"].as_array().into_iter().flatten() {
                            eprintln!(
                                "[sentinel: frames {}-{} were lost on the worker]",
                                gap[0], gap[1]
                            );
                        }
                    }
                    return Ok(());
                }
                if !*follow {
                    if !json_out {
                        eprintln!("[sentinel: log incomplete; use --follow to wait for the rest]");
                    }
                    return Ok(());
                }
            }
        }
        ApiCommand::Workers { tenant } => {
            let view = client.get(&format!("/api/v1/workers?tenant={tenant}"))?;
            let mut text = String::new();
            for pool in view["pools"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "pool {} ({})\n",
                    pool["name"].as_str().unwrap_or(""),
                    pool["kind"].as_str().unwrap_or("")
                ));
                for worker in pool["workers"].as_array().into_iter().flatten() {
                    text.push_str(&format!(
                        "  {} {} {} {}\n",
                        worker["id"].as_str().unwrap_or(""),
                        worker["name"].as_str().unwrap_or(""),
                        worker["arch"].as_str().unwrap_or(""),
                        if worker["connected"] == true {
                            "connected"
                        } else {
                            "offline"
                        }
                    ));
                }
            }
            out(view.clone(), text);
        }
        ApiCommand::Queue { tenant, limit } => {
            let view = client.get(&format!("/api/v1/queue?tenant={tenant}&limit={limit}"))?;
            let mut text = String::new();
            for job in view["jobs"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "{} {:<12} {:>7} {}{}\n",
                    job["job"].as_str().unwrap_or(""),
                    job["repo"].as_str().unwrap_or(""),
                    age_text(job["age_ms"].as_u64().unwrap_or(0)),
                    job["reason"]["code"].as_str().unwrap_or(""),
                    job["reason"]["detail"]
                        .as_str()
                        .map(|detail| format!(" ({detail})"))
                        .unwrap_or_default(),
                ));
            }
            if view["truncated"] == true {
                text.push_str(&format!(
                    "{} of {} waiting jobs shown; raise --limit for the rest\n",
                    view["jobs"].as_array().map_or(0, Vec::len),
                    view["total"].as_u64().unwrap_or(0),
                ));
            }
            out(view.clone(), text);
        }
        ApiCommand::Drain { worker } | ApiCommand::Undrain { worker } => {
            let drain = matches!(args.command, ApiCommand::Drain { .. });
            let result = client.post(
                &format!(
                    "/api/v1/workers/{worker}/{}",
                    if drain { "drain" } else { "undrain" }
                ),
                &json!({}),
                None,
            )?;
            out(
                result.clone(),
                format!(
                    "{worker}: {}\n",
                    if drain {
                        "takes no new attempts"
                    } else {
                        "takes work again"
                    }
                ),
            );
        }
    }
    Ok(())
}

fn jobs_text(run: &Value) -> String {
    let mut text = String::new();
    for job in run["jobs"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "  {:<24} {:<12} {}{}\n",
            job["name"].as_str().unwrap_or(""),
            job["state"].as_str().unwrap_or(""),
            job["failure_class"].as_str().unwrap_or(""),
            job["attempt"]
                .as_str()
                .map(|a| format!(" {a}"))
                .unwrap_or_default()
        ));
    }
    text
}

/// A waiting age as a person reads it: seconds, then minutes, then hours.
fn age_text(age_ms: u64) -> String {
    let secs = age_ms / 1000;
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{}s", secs / 60, secs % 60),
        _ => format!("{}h{}m", secs / 3600, (secs % 3600) / 60),
    }
}
