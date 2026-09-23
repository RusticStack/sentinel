//! `run dispatch|status|list|cancel|wait`, `status` and `wait`.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use super::{
    List, PAGE, Paging, busy_backoff, jobs_text, parse_duration, passed, segment, tenant, text,
};
use crate::client::{self, Client, Error, Exit, Output};

pub(super) struct Dispatch {
    pub tenant: Option<String>,
    pub repo: String,
    pub pipeline: PathBuf,
    pub source: String,
    pub sha: String,
    pub ref_name: Option<String>,
    pub idempotency_key: Option<String>,
}

pub(super) fn dispatch(client: &Client, output: Output, args: &Dispatch) -> Result<(), Error> {
    let slug = tenant(client, args.tenant.clone())?;
    let repo = segment("repository", &args.repo)?;
    let pipeline = crate::bounded::text(&args.pipeline, crate::bounded::PIPELINE_BYTES)
        .map_err(|e| Error::usage(format!("cannot read the pipeline: {e}")))?;
    let body = json!({
        "pipeline": pipeline,
        "source": { "repo": args.source, "sha": args.sha, "ref": args.ref_name },
    });
    let run = client.post(
        &format!("/api/v1/tenants/{slug}/repos/{repo}/runs"),
        &body,
        args.idempotency_key.as_deref(),
    )?;
    client::emit(output, &run, || {
        format!(
            "{} {}\n{}",
            text(&run, "id"),
            text(&run, "state"),
            jobs_text(&run)
        )
    });
    Ok(())
}

pub(super) fn status(client: &Client, output: Output, run: &str) -> Result<(), Error> {
    let run = segment("run", run)?;
    let view = client.get(&format!("/api/v1/runs/{run}"))?;
    client::emit(output, &view, || {
        format!(
            "{} {}\n{}",
            text(&view, "id"),
            text(&view, "state"),
            jobs_text(&view)
        )
    });
    Ok(())
}

/// Newest first, page by page: each page is printed (text, NDJSON) before
/// the next is requested, and at most the cap is ever printed. A listing
/// cut short names the cursor that continues it.
pub(super) fn list(
    client: &Client,
    output: Output,
    tenant_flag: Option<String>,
    repo: &str,
    paging: &Paging,
) -> Result<(), Error> {
    let cap = paging.cap()?;
    let slug = tenant(client, tenant_flag)?;
    let repo = segment("repository", repo)?;
    let mut before = match &paging.before {
        Some(cursor) => Some(segment("cursor", cursor)?.to_owned()),
        None => None,
    };
    let mut list = List::new(output);
    let mut shown = 0usize;
    let more = loop {
        let size = (cap - shown).min(PAGE);
        let mut path = format!("/api/v1/tenants/{slug}/repos/{repo}/runs?limit={size}");
        if let Some(cursor) = &before {
            path.push_str("&before=");
            path.push_str(cursor);
        }
        let page = client.get(&path)?;
        let runs = page["runs"].as_array().map_or(&[][..], Vec::as_slice);
        for run in runs.iter().take(cap - shown) {
            list.item(run.clone(), || {
                format!(
                    "{} {:<12} {} {}\n",
                    text(run, "id"),
                    text(run, "state"),
                    text(run, "sha"),
                    run["created_ms"].as_i64().unwrap_or(0)
                )
            });
        }
        shown += runs.len().min(cap - shown);
        let next = page["next"].as_str().map(str::to_owned);
        match next {
            Some(next) if shown < cap && !runs.is_empty() => before = Some(next),
            next => break next,
        }
    };
    if let Some(next) = &more
        && output == Output::Text
    {
        eprintln!("more runs: continue with --before {next}");
    }
    let mut extra = Map::new();
    extra.insert("next".into(), more.map_or(Value::Null, Value::String));
    list.finish("runs", extra);
    Ok(())
}

pub(super) fn cancel(client: &Client, output: Output, run: &str) -> Result<(), Error> {
    let run = segment("run", run)?;
    let result = client.post(&format!("/api/v1/runs/{run}/cancel"), &json!({}), None)?;
    client::emit(output, &result, || {
        format!("{run}: cancellation recorded\n")
    });
    Ok(())
}

/// Each wait request parks on the server at most this long.
const WAIT_SLICE: Duration = Duration::from_secs(25);

/// Follow a run until it finishes, one long poll at a time: the server
/// answers when the run's version moves, so an idle wait costs one request
/// per 25 s. Exit 0 when it passed, 8 when it finished otherwise, 7 when
/// the deadline came first. A `rate_limited` answer (every subscriber slot
/// taken) is waited out with jitter, never counted as a failure.
///
/// Text prints a line per change and the job table at the end; NDJSON one
/// `{version, changed, finished, run}` line per change; JSON the final run.
pub(super) fn wait(
    client: &Client,
    output: Output,
    run: &str,
    timeout: Option<&str>,
) -> Result<(), Error> {
    let run = segment("run", run)?;
    let deadline = timeout
        .map(parse_duration)
        .transpose()?
        .map(|limit| Instant::now() + limit);
    let mut since: Option<String> = None;
    let mut last: Option<Value> = None;
    loop {
        let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        if remaining.is_some_and(|r| r.is_zero()) {
            return Err(timed_out(run, last.as_ref()));
        }
        let slice = remaining.map_or(WAIT_SLICE, |r| r.min(WAIT_SLICE));
        let mut path = format!(
            "/api/v1/runs/{run}/wait?timeout_ms={}",
            slice.as_millis().max(1)
        );
        if let Some(version) = &since {
            path.push_str("&since=");
            path.push_str(version);
        }
        let answer = match client.get(&path) {
            Ok(answer) => answer,
            Err(error) => match busy_backoff(&error) {
                Some(pause) => {
                    let pause = remaining.map_or(pause, |r| r.min(pause));
                    std::thread::sleep(pause);
                    continue;
                }
                None => return Err(error),
            },
        };
        since = answer["version"].as_str().map(str::to_owned);
        if since.is_none() {
            return Err(Error::remote("the server's wait answer has no version"));
        }
        if answer["changed"] == true {
            match output {
                Output::Ndjson => client::emit(output, &answer, String::new),
                Output::Text => crate::out!("{}", progress(&answer["run"])),
                Output::Json => {}
            }
        }
        if answer["finished"] == true {
            let view = &answer["run"];
            match output {
                Output::Json => client::emit(output, view, String::new),
                Output::Text => crate::out!("{}", jobs_text(view)),
                Output::Ndjson => {}
            }
            if passed(view) {
                return Ok(());
            }
            return Err(Error::new(
                Exit::RunFailed,
                format!("run {run} finished {}", text(view, "state")),
            ));
        }
        last = Some(answer);
    }
}

/// One text line per change: the run's state and how many jobs finished.
fn progress(run: &Value) -> String {
    let jobs = run["jobs"].as_array().map_or(&[][..], Vec::as_slice);
    let done = jobs.iter().filter(|j| j["terminal"] == true).count();
    format!(
        "{} {} ({done}/{} jobs finished)\n",
        text(run, "id"),
        text(run, "state"),
        jobs.len()
    )
}

fn timed_out(run: &str, last: Option<&Value>) -> Error {
    let state = last.map_or("unknown", |answer| text(&answer["run"], "state"));
    Error::new(
        Exit::Timeout,
        format!("deadline reached; run {run} is still {state}"),
    )
}
