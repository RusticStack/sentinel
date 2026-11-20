//! The guided migration's two reads: at a pinned commit, the `runs-on:` diff a repository would
//! receive and, on request, the native pipeline plan its workflows become; and the shadow parity
//! of the job pairs a migration is running, compared over the commits they ran on.
//!
//! The controller does not read repository content at a revision yet — a Contents client and
//! the migration permissions are H01's and H04's — so the caller sends the workflow files it
//! read at the pinned commit, exactly what the analyzer takes. Everything the response holds
//! is computed here from those files, the versioned tables and this deployment's own facts;
//! no model, no guess and no value the workflow states.

use sentinel_core::auth::{Permissions, Scopes};
use sentinel_pipeline::workflow::{
    self, DockerHosts, Images, MAX_WORKFLOW_FILES, Options, WorkflowFile, analyze, plan,
};
use sentinel_protocol::negotiate::Capabilities;
use sentinel_protocol::{
    diagnostics::{self, ReportFormat, StepReference},
    error::{ApiError, ErrorCode},
    limits::MAX_PIPELINE_FILE_BYTES,
};
use sentinel_store::{auth as authz, lookup, parity};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::Request;
use crate::routes::{Route, body, body_limit, err, identify, ok, parse, store_error};
use crate::{State, auth};

/// What a preview takes: the commit, the workflow files read at it, and whether the native
/// plan is wanted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    commit: String,
    workflows: Vec<WorkflowText>,
    #[serde(default)]
    native: Option<NativeRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowText {
    path: String,
    text: String,
}

/// The digest-pinned images a native job may run in: a pipeline job names its own image, and
/// the workflow it came from does not.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRequest {
    #[serde(default)]
    images: ImageList,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ImageList {
    linux: Option<String>,
    linux_arm64: Option<String>,
    windows: Option<String>,
}

pub(crate) fn preview(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let asked: Preview = parse(&body(request)?)?;
    if asked.workflows.len() > MAX_WORKFLOW_FILES {
        return Err(err(
            ErrorCode::InvalidRequest,
            "more workflow files than one analysis reads",
        )
        .with_detail("limit", MAX_WORKFLOW_FILES));
    }
    for workflow in &asked.workflows {
        if workflow.text.len() > MAX_PIPELINE_FILE_BYTES {
            return Err(err(ErrorCode::PayloadTooLarge, "workflow file too large")
                .with_detail("limit_bytes", MAX_PIPELINE_FILE_BYTES));
        }
    }
    // The repository's read path, and the deployment's own fact about Docker: a job that needs
    // a daemon can only move where a micro-VM guest serves its class.
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    let microvm = state
        .store
        .read(move |c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, principal, repo, Permissions::READ)?;
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM workers WHERE revoked_ms IS NULL AND (capabilities & ?1) != 0)",
                [Capabilities::ISOLATION_MICROVM.0 as i64],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .map_err(store_error)?;
    let docker = if microvm {
        DockerHosts::MicrovmGuests
    } else {
        DockerHosts::ContainerOnly
    };
    let files: Vec<WorkflowFile<'_>> = asked
        .workflows
        .iter()
        .map(|workflow| WorkflowFile {
            path: &workflow.path,
            text: &workflow.text,
        })
        .collect();
    let commit = asked.commit.to_ascii_lowercase();
    let inventory = analyze(&commit, &files, docker)
        .map_err(|error| err(ErrorCode::InvalidRequest, format!("workflows: {error}")))?;
    let images = asked.native.as_ref().map(|native| Images {
        linux: native.images.linux.as_deref(),
        linux_arm64: native.images.linux_arm64.as_deref(),
        windows: native.images.windows.as_deref(),
    });
    let planned = plan(
        &inventory,
        &files,
        &Options {
            docker,
            native: images.is_some(),
            images: images.unwrap_or_default(),
        },
    )
    .map_err(|error| err(ErrorCode::InvalidRequest, format!("preview: {error}")))?;
    ok(json!({
        "schema": workflow::PLAN_SCHEMA,
        "revision": planned.revision,
        "label_table": planned.label_table,
        "rule_table": planned.rule_table,
        "docker": match docker {
            DockerHosts::MicrovmGuests => "microvm_guests",
            DockerHosts::ContainerOnly => "container_only",
        },
        "workflows": planned.workflows.iter().map(workflow_json).collect::<Vec<Value>>(),
    }))
}

fn workflow_json(workflow: &workflow::WorkflowPlan) -> Value {
    json!({
        "path": workflow.path,
        "diff": workflow.diff,
        "changes": workflow.changes.iter().map(|change| json!({
            "job": change.job,
            "line": change.line,
            "before": change.before,
            "after": change.after,
        })).collect::<Vec<Value>>(),
        "kept": workflow.kept.iter().map(|kept| json!({
            "job": kept.job,
            "reasons": kept.reasons.iter().map(|reason| reason.as_str()).collect::<Vec<&str>>(),
            "notes": kept.reasons.iter().map(|reason| reason.note()).collect::<Vec<&str>>(),
            "varies": kept.varies,
        })).collect::<Vec<Value>>(),
        "native": workflow.native.as_ref().map(|native| json!({
            "path": native.path,
            "text": native.text,
            "secrets": native.secrets,
            "notes": native.notes,
            "jobs": native.jobs.iter().map(|job| json!({
                "github": job.github,
                "jobs": job.jobs,
                "kept": job.kept,
                "env": job.env,
                "steps": job.steps.iter().map(|step| json!({
                    "github": step.github,
                    "kind": step.kind.as_str(),
                    "env": step.env,
                    "native": step.native,
                    "script": step.script,
                })).collect::<Vec<Value>>(),
            })).collect::<Vec<Value>>(),
        })),
        "native_refused": workflow.native_refused,
    })
}

/// The parity report's shape ([compatibility](../docs/compatibility.md)).
pub const PARITY_SCHEMA: &str = "sentinel.migration-parity/1";
/// The recorded Actions pages one report compares: two pages of jobs are a few pushes, and past
/// this a caller sends another report.
pub const MAX_ACTIONS_PAGES: usize = 8;
/// The test reports one request may carry, and the most text each may be: a report is the evidence
/// two jobs' counts were read from, and the pairs it covers are a page's, not a week's.
pub const MAX_REPORTS: usize = 8;
pub const MAX_REPORT_BYTES: usize = 256 << 10;
/// The most body one report may be: the reports it carries, and the pairs and pages beside them.
/// A parity request is the one read route whose body holds evidence rather than identifiers.
pub const MAX_PARITY_BODY_BYTES: usize = 2 << 20;

/// What a parity report takes: the job pairs to compare, what the Actions jobs pages stated, and
/// the test reports either side produced.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityRequest {
    #[serde(default)]
    pairs: Vec<ParityPair>,
    #[serde(default)]
    actions: Vec<Value>,
    #[serde(default)]
    tests: Vec<TestText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityPair {
    sha: String,
    original: String,
    shadow: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestText {
    sha: String,
    job: String,
    format: String,
    report: String,
}

/// `POST /api/v1/tenants/{slug}/repos/{name}/migration/parity` — the shadow's parity per job pair
/// over the commits the caller asks about. A read: it writes nothing and contacts nobody, and every
/// figure it answers with is either what the Actions pages stated or what Sentinel recorded.
pub(crate) fn parity_report(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let asked: ParityRequest = parse(&body_limit(request, MAX_PARITY_BODY_BYTES)?)?;
    if asked.actions.len() > MAX_ACTIONS_PAGES {
        return Err(err(
            ErrorCode::InvalidRequest,
            "more Actions pages than one report compares",
        )
        .with_detail("limit", MAX_ACTIONS_PAGES));
    }
    if asked.pairs.len() > parity::MAX_PAIRS {
        return Err(err(
            ErrorCode::InvalidRequest,
            "more job pairs than one report compares",
        )
        .with_detail("limit", parity::MAX_PAIRS));
    }
    if asked.tests.len() > MAX_REPORTS {
        return Err(err(
            ErrorCode::InvalidRequest,
            "more test reports than one report compares",
        )
        .with_detail("limit", MAX_REPORTS));
    }
    let mut pages = Vec::with_capacity(asked.actions.len());
    for page in &asked.actions {
        pages.push(
            sentinel_github::actions::decode_page(page).map_err(|error| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("actions jobs page: {error}"),
                )
            })?,
        );
    }
    let tests = test_counts(&asked.tests)?;
    let pairs: Vec<parity::Pair<'_>> = asked
        .pairs
        .iter()
        .map(|pair| parity::Pair {
            sha: &pair.sha,
            original: &pair.original,
            shadow: &pair.shadow,
        })
        .collect();
    let origins: Vec<parity::Origin<'_>> = pages
        .iter()
        .flat_map(|page| page.jobs.iter())
        .map(|job| parity::Origin {
            sha: &job.head_sha,
            job: &job.name,
            job_id: job.id,
            conclusion: job.conclusion.as_deref(),
            duration_ms: job.duration_ms,
        })
        .collect();
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    let reported = state
        .store
        .read(move |c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, principal, repo, Permissions::READ)?;
            parity::report(
                c,
                tenant,
                repo,
                parity::Input {
                    pairs: &pairs,
                    origins: &origins,
                    reports: &tests,
                },
            )
        })
        .map_err(store_error)?;
    ok(json!({
        "schema": PARITY_SCHEMA,
        "shadow_prefix": parity::SHADOW_PREFIX,
        "pairs": reported.pairs.iter().map(pair_json).collect::<Vec<Value>>(),
        "jobs": reported.aggregates.iter().map(|aggregate| json!({
            "job": aggregate.job,
            "samples": aggregate.samples,
            "matched": aggregate.matched,
            "mismatched": aggregate.mismatched,
            "original": spread_json(aggregate.original),
            "shadow": spread_json(aggregate.shadow),
        })).collect::<Vec<Value>>(),
        "unpaired": reported.unpaired.iter().map(|unpaired| json!({
            "sha": unpaired.sha,
            "shadow": unpaired.shadow,
        })).collect::<Vec<Value>>(),
    }))
}

/// Count the tests each report states, in the format it was written in: the pipeline's own parsers
/// read them, so a parity comparison counts what Sentinel would have counted for the same file.
fn test_counts(tests: &[TestText]) -> Result<Vec<parity::Reported<'_>>, ApiError> {
    let mut counts = Vec::with_capacity(tests.len());
    for test in tests {
        if test.report.len() > MAX_REPORT_BYTES {
            return Err(err(ErrorCode::PayloadTooLarge, "test report too large")
                .with_detail("limit_bytes", MAX_REPORT_BYTES));
        }
        let format = match test.format.as_str() {
            "junit_xml" => ReportFormat::JunitXml,
            "go_test_json" => ReportFormat::GoTestJson,
            _ => {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    "a test report states no test counts in this format",
                )
                .with_detail("format", test.format.as_str()));
            }
        };
        let step = StepReference {
            index: 0,
            key: None,
        };
        let parsed = match format {
            ReportFormat::JunitXml => diagnostics::parse_junit_xml(test.report.as_bytes(), None),
            _ => diagnostics::parse_go_test_json(test.report.as_bytes(), step),
        };
        let counts_stated = parsed
            .tests
            .ok_or_else(|| err(ErrorCode::Internal, "a parsed report stated no test counts"))?;
        counts.push(parity::Reported {
            sha: &test.sha,
            job: &test.job,
            format,
            counts: counts_stated,
        });
    }
    Ok(counts)
}

fn pair_json(pair: &parity::PairReport) -> Value {
    json!({
        "sha": pair.sha,
        "job": pair.job,
        "shadow": pair.shadow,
        "mode": pair.mode.map(parity::Mode::as_str),
        "original": pair.original.as_ref().map(side_json),
        "shadow_side": pair.shadow_side.as_ref().map(side_json),
        "queue_ms": pair.queue_ms,
        "verdict": if pair.matched() { "match" } else { "mismatch" },
        "mismatches": pair.mismatches.iter().map(|m| m.as_str()).collect::<Vec<&str>>(),
    })
}

fn side_json(side: &parity::Side) -> Value {
    json!({
        "conclusion": side.conclusion,
        "duration_ms": side.duration_ms,
        "tests": side.tests.counts().map(|counts| json!({
            "format": side.tests.format().map(ReportFormat::as_str),
            "total": counts.total,
            "failed": counts.failed,
            "skipped": counts.skipped,
        })),
    })
}

fn spread_json(spread: parity::Spread) -> Value {
    json!({ "p50_ms": spread.p50_ms, "p95_ms": spread.p95_ms })
}
