//! The O05 command surface over [`crate::client::Client`]: `run`, `status`,
//! `wait`, `job`, `log`, `workers`, `queue`, `artifact` and `cache`, with
//! text, JSON and NDJSON output, pagination and the stable exit codes
//! (`docs/cli.md`).
//!
//! Output: text is for people; `--output json` prints one document (a list
//! is collected, at most [`MAX_ITEMS`] items); `--output ndjson` prints one
//! compact line per item as each page arrives, so a consumer can stream a
//! ten-thousand-run listing without the whole of it in memory on either
//! side. Failures are reported by `main` in the same mode.

use std::time::Duration;

use clap::{Args, Subcommand};
use serde_json::Value;

use crate::client::{self, Client, ClientArgs, Error, Output};

mod artifacts;
mod fleet;
mod logs;
mod runs;

/// Most items a listing prints, whatever `--limit` or `--all` asks for.
pub const MAX_ITEMS: usize = 10_000;
/// Items per page request; the server's own ceiling.
const PAGE: usize = 500;
/// Items a listing shows without `--limit` or `--all`.
const DEFAULT_ITEMS: usize = 20;

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: RunCommand,
}

/// `--limit`, `--before`, `--all` for listings that page.
#[derive(Args, Clone, Debug, Default)]
pub struct Paging {
    /// Items to list (default 20, at most 10000)
    #[arg(long, conflicts_with = "all")]
    pub limit: Option<usize>,
    /// Start after this item (the `next` of a previous listing)
    #[arg(long, value_name = "CURSOR")]
    pub before: Option<String>,
    /// Every item, page by page, up to 10000
    #[arg(long)]
    pub all: bool,
}

impl Paging {
    /// How many items to print at most.
    fn cap(&self) -> Result<usize, Error> {
        match (self.all, self.limit) {
            (true, _) => Ok(MAX_ITEMS),
            (false, None) => Ok(DEFAULT_ITEMS),
            (false, Some(n)) if (1..=MAX_ITEMS).contains(&n) => Ok(n),
            (false, Some(_)) => Err(Error::usage(format!(
                "--limit must be 1..{MAX_ITEMS}; use --all for everything"
            ))),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum RunCommand {
    /// Dispatch a pipeline file against a pinned source revision
    Dispatch {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        #[arg(long)]
        repo: String,
        /// The `.sentinel.yml` to run; every image must be pinned by digest
        #[arg(long, value_name = "FILE")]
        pipeline: std::path::PathBuf,
        /// Clone URL or path the workers fetch from
        #[arg(long)]
        source: String,
        /// Full commit SHA to check out
        #[arg(long)]
        sha: String,
        /// Ref name kept as provenance
        #[arg(long)]
        r#ref: Option<String>,
        /// Idempotency key so a retried dispatch creates one run
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// A run and its jobs
    Status { run: String },
    /// Runs of a repository, newest first
    List {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        #[arg(long)]
        repo: String,
        #[command(flatten)]
        paging: Paging,
    },
    /// Record cancellation for a run
    Cancel { run: String },
    /// Wait until a run finishes: exit 0 passed, 8 not passed, 7 deadline
    Wait {
        run: String,
        /// Give up after this long, such as 90s, 10m or 1h (default: no limit)
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
    },
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    pub run: String,
}

#[derive(Args, Debug)]
pub struct WaitArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    pub run: String,
    /// Give up after this long, such as 90s, 10m or 1h (default: no limit)
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[derive(Args, Debug)]
pub struct JobArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: JobCommand,
}

#[derive(Subcommand, Debug)]
pub enum JobCommand {
    /// Record cancellation for one job
    Cancel { job: String },
    /// A new attempt of a finished job
    Rerun { job: String },
}

#[derive(Args, Debug)]
pub struct LogArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: LogCommand,
}

#[derive(Subcommand, Debug)]
pub enum LogCommand {
    /// An attempt's log; --follow waits until it is complete
    Show {
        attempt: String,
        #[arg(long)]
        follow: bool,
        /// Only this step's frames
        #[arg(long)]
        step: Option<u32>,
    },
    /// Find a literal string in an attempt's log
    Search {
        attempt: String,
        /// The literal to find (1..256 bytes, case-sensitive)
        #[arg(long)]
        text: String,
        /// Matching lines to print (default 100, at most 10000)
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Args, Debug)]
pub struct WorkersArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: WorkersCommand,
}

#[derive(Subcommand, Debug)]
pub enum WorkersCommand {
    /// Pools and workers a tenant may use, with connection state
    List {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
    },
    /// Stop one worker taking new attempts (platform admin)
    Drain { worker: String },
    /// Offer a drained worker work again (platform admin)
    Undrain { worker: String },
}

#[derive(Args, Debug)]
pub struct QueueArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    /// Tenant slug (default: the profile's context)
    #[arg(long, value_name = "SLUG")]
    pub tenant: Option<String>,
    /// Waiting jobs to show (default 100, at most 500); the total is still reported
    #[arg(long)]
    pub limit: Option<usize>,
}

#[derive(Args, Debug)]
pub struct ArtifactArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: ArtifactCommand,
}

#[derive(Subcommand, Debug)]
pub enum ArtifactCommand {
    /// Every artifact of a run
    List { run: String },
    /// One artifact and its manifest
    Show { run: String, artifact: String },
    /// Download one manifest entry, checking its length and digest
    Download {
        run: String,
        artifact: String,
        /// The entry's path inside the artifact
        #[arg(long)]
        path: String,
        /// Where to write it; replaced only once the bytes verify
        #[arg(long, value_name = "FILE")]
        out: std::path::PathBuf,
        /// Tenant slug that owns the run (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
    },
}

#[derive(Args, Debug)]
pub struct CacheArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// Cache records of one attempt
    Show { attempt: String },
}

/// One of the O05 top-level commands, as parsed.
#[derive(Debug)]
pub enum Invocation {
    Run(RunArgs),
    Status(StatusArgs),
    Wait(WaitArgs),
    Job(JobArgs),
    Log(LogArgs),
    Workers(WorkersArgs),
    Queue(QueueArgs),
    Artifact(ArtifactArgs),
    Cache(CacheArgs),
}

pub fn run(invocation: Invocation) -> Result<(), client::Error> {
    match invocation {
        Invocation::Run(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                RunCommand::Dispatch {
                    tenant,
                    repo,
                    pipeline,
                    source,
                    sha,
                    r#ref,
                    idempotency_key,
                } => runs::dispatch(
                    &client,
                    output,
                    &runs::Dispatch {
                        tenant,
                        repo,
                        pipeline,
                        source,
                        sha,
                        ref_name: r#ref,
                        idempotency_key,
                    },
                ),
                RunCommand::Status { run } => runs::status(&client, output, &run),
                RunCommand::List {
                    tenant,
                    repo,
                    paging,
                } => runs::list(&client, output, tenant, &repo, &paging),
                RunCommand::Cancel { run } => runs::cancel(&client, output, &run),
                RunCommand::Wait { run, timeout } => {
                    runs::wait(&client, output, &run, timeout.as_deref())
                }
            }
        }
        Invocation::Status(args) => {
            let (client, output) = connect(&args.client)?;
            runs::status(&client, output, &args.run)
        }
        Invocation::Wait(args) => {
            let (client, output) = connect(&args.client)?;
            runs::wait(&client, output, &args.run, args.timeout.as_deref())
        }
        Invocation::Job(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                JobCommand::Cancel { job } => fleet::job(&client, output, &job, false),
                JobCommand::Rerun { job } => fleet::job(&client, output, &job, true),
            }
        }
        Invocation::Log(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                LogCommand::Show {
                    attempt,
                    follow,
                    step,
                } => logs::show(&client, output, &attempt, follow, step),
                LogCommand::Search {
                    attempt,
                    text,
                    limit,
                } => logs::search(&client, output, &attempt, &text, limit),
            }
        }
        Invocation::Workers(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                WorkersCommand::List { tenant } => fleet::workers(&client, output, tenant),
                WorkersCommand::Drain { worker } => fleet::drain(&client, output, &worker, true),
                WorkersCommand::Undrain { worker } => fleet::drain(&client, output, &worker, false),
            }
        }
        Invocation::Queue(args) => {
            let (client, output) = connect(&args.client)?;
            fleet::queue(&client, output, args.tenant, args.limit)
        }
        Invocation::Artifact(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                ArtifactCommand::List { run } => artifacts::list(&client, output, &run),
                ArtifactCommand::Show { run, artifact } => {
                    artifacts::show(&client, output, &run, &artifact)
                }
                ArtifactCommand::Download {
                    run,
                    artifact,
                    path,
                    out,
                    tenant,
                } => artifacts::download(&client, output, &run, &artifact, &path, &out, tenant),
            }
        }
        Invocation::Cache(args) => {
            let (client, output) = connect(&args.client)?;
            match args.command {
                CacheCommand::Show { attempt } => artifacts::cache(&client, output, &attempt),
            }
        }
    }
}

/// Resolve the output mode first, so even a connection failure is
/// reported the way the user asked.
fn connect(args: &ClientArgs) -> Result<(Client, Output), Error> {
    let output = args.output();
    Ok((Client::connect(args)?, output))
}

/// `--tenant`, else the profile's context, else a usage error naming both.
fn tenant(client: &Client, flag: Option<String>) -> Result<String, Error> {
    let slug = flag
        .or_else(|| client.default_tenant().map(str::to_owned))
        .ok_or_else(|| {
            Error::usage("give --tenant SLUG, or choose one with: sentinel context use SLUG")
        })?;
    segment("tenant", &slug)?;
    Ok(slug)
}

/// A value placed into a URL path or query: identifiers, slugs and names
/// only use `[A-Za-z0-9._-]`, and anything else is refused locally rather
/// than escaped into a different request.
fn segment<'a>(what: &str, value: &'a str) -> Result<&'a str, Error> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(Error::usage(format!("malformed {what}: {value:?}")));
    }
    Ok(value)
}

/// `90`, `90s`, `500ms`, `10m`, `2h`.
fn parse_duration(text: &str) -> Result<Duration, Error> {
    let invalid = || Error::usage(format!("malformed duration {text:?}; use 90s, 10m or 1h"));
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let n: u64 = number.parse().map_err(|_| invalid())?;
    let duration = match unit {
        "ms" => Duration::from_millis(n),
        "" | "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.checked_mul(60).ok_or_else(invalid)?),
        "h" => Duration::from_secs(n.checked_mul(3600).ok_or_else(invalid)?),
        _ => return Err(invalid()),
    };
    if duration.is_zero() {
        return Err(invalid());
    }
    Ok(duration)
}

/// A string field of a server document, or `""`.
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

/// Whether a failure was a subscriber-slot refusal worth waiting out, and
/// for how long: the server's `retry_after_ms` (else one second), plus up
/// to half again of jitter so refused pollers do not return in lockstep.
fn busy_backoff(error: &Error) -> Option<Duration> {
    let api = error.api.as_ref()?;
    if api["code"] != "rate_limited" {
        return None;
    }
    let base = api["details"]["retry_after_ms"].as_u64().unwrap_or(1_000);
    Some(Duration::from_millis(base + jitter(base / 2 + 1)))
}

/// A cheap, dependency-free spread in `0..bound`: the clock's sub-second
/// nanoseconds, mixed. Not random enough for anything but de-synchronizing
/// retries.
fn jitter(bound: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let mixed = nanos.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 17;
    mixed % bound.max(1)
}

/// Print a list: text lines and NDJSON items as they come; JSON collects
/// and prints once in [`List::finish`].
struct List {
    output: Output,
    items: Vec<Value>,
}

impl List {
    fn new(output: Output) -> List {
        List {
            output,
            items: Vec::new(),
        }
    }

    fn item(&mut self, value: Value, text: impl FnOnce() -> String) {
        match self.output {
            Output::Json => self.items.push(value),
            output => client::emit_item(output, &value, text),
        }
    }

    /// JSON: `{key: [items], …extra}` as one document. Text and NDJSON
    /// have already printed everything.
    fn finish(self, key: &str, extra: serde_json::Map<String, Value>) {
        if self.output == Output::Json {
            let mut doc = serde_json::Map::with_capacity(extra.len() + 1);
            doc.insert(key.to_owned(), Value::Array(self.items));
            doc.extend(extra);
            client::emit(Output::Json, &Value::Object(doc), String::new);
        }
    }
}

/// A job table for text output.
fn jobs_text(run: &Value) -> String {
    let mut out = String::new();
    for job in run["jobs"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  {:<24} {:<12} {}{}\n",
            text(job, "name"),
            text(job, "state"),
            text(job, "failure_class"),
            job["attempt"]
                .as_str()
                .map(|a| format!(" {a}"))
                .unwrap_or_default()
        ));
    }
    out
}

/// A run's outcome as `wait` judges it: `passed` and `skipped` pass.
fn passed(run: &Value) -> bool {
    matches!(text(run, "state"), "passed" | "skipped")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Exit;

    #[test]
    fn durations_parse_with_units_and_refuse_nonsense() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        for bad in ["", "0s", "s", "1d", "-5s", "1.5m", "99999999999999999999h"] {
            assert_eq!(parse_duration(bad).unwrap_err().exit, Exit::Usage, "{bad}");
        }
    }

    #[test]
    fn path_values_are_refused_rather_than_escaped() {
        assert!(segment("run", "run_0123").is_ok());
        assert!(segment("repo", "my.repo-name_2").is_ok());
        for bad in ["", "a/b", "a?b", "a#b", "a%2F", "a b", "..\u{e9}"] {
            assert_eq!(segment("x", bad).unwrap_err().exit, Exit::Usage, "{bad:?}");
        }
    }

    #[test]
    fn only_rate_limited_answers_back_off_with_jitter() {
        let limited = Error {
            message: String::new(),
            exit: Exit::Busy,
            api: Some(serde_json::json!({
                "code": "rate_limited", "details": { "retry_after_ms": 1000 }
            })),
        };
        let wait = busy_backoff(&limited).unwrap();
        assert!(wait >= Duration::from_millis(1000) && wait <= Duration::from_millis(1501));
        let other = Error {
            api: Some(serde_json::json!({ "code": "internal" })),
            ..Error::remote("x")
        };
        assert!(busy_backoff(&other).is_none());
        assert!(busy_backoff(&Error::remote("x")).is_none());
    }

    #[test]
    fn listing_caps_are_bounded() {
        let paging = |limit, all| Paging {
            limit,
            before: None,
            all,
        };
        assert_eq!(paging(None, false).cap().unwrap(), DEFAULT_ITEMS);
        assert_eq!(paging(None, true).cap().unwrap(), MAX_ITEMS);
        assert_eq!(paging(Some(7), false).cap().unwrap(), 7);
        assert!(paging(Some(0), false).cap().is_err());
        assert!(paging(Some(MAX_ITEMS + 1), false).cap().is_err());
    }
}
