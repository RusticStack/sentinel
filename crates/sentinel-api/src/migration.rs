//! The guided migration's two writes of an analysis: the preview at a pinned commit — the
//! `runs-on:` diff a repository would receive and, on request, the native pipeline plan its
//! workflows become — and the pull request that applies that diff.
//!
//! The preview takes the workflow files from its caller, because it reads nothing from GitHub. The
//! write reads them itself, at the commit it is told, through the App's migration token: the branch
//! it commits is built from the bytes GitHub holds, so the diff it applies is the diff it described
//! ([workflow analysis](../../../docs/workflow-analysis.md#verification)).
//!
//! Everything either answer holds is computed here from the workflows, the versioned tables and this
//! deployment's own facts; no model, no guess and no value the workflow states.

use sentinel_core::auth::{Permissions, Scopes};
use sentinel_core::{RepoId, TenantId, UnixMillis, UserId};
use sentinel_github::migration::{self as remote, Migrate, Outcome, Rewritten};
use sentinel_pipeline::workflow::{
    self, DockerHosts, Images, MAX_WORKFLOW_FILES, Options, WorkflowFile, analyze, plan,
};
use sentinel_protocol::negotiate::Capabilities;
use sentinel_protocol::{
    diagnostics::{self, ReportFormat, StepReference},
    error::{ApiError, ErrorCode},
    limits::MAX_PIPELINE_FILE_BYTES,
};
use sentinel_store::{
    auth as authz, lookup,
    migration::{PullRequest as Recorded, Writes},
    parity, sources, sources_forge,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::Request;
use crate::routes::{Route, body, body_limit, err, identify, ok, parse, store_error};
use crate::{State, auth};

/// The answer a migration write states: a versioned contract, so a client can branch on it
/// ([compatibility](../../../docs/compatibility.md)).
pub const PULL_REQUEST_SCHEMA: &str = "sentinel.migration-pull-request/1";

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
    // The repository's read path, then the deployment's own fact about Docker.
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    state
        .store
        .read(move |c| {
            let tenant = lookup::tenant_by_slug(c, &slug)?;
            let repo = lookup::repo_by_name(c, tenant, &name)?;
            authz::require_repo(c, principal, repo, Permissions::READ)
        })
        .map_err(store_error)?;
    let docker = docker_hosts(state)?;
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

/// The deployment's own fact about Docker: a job that needs a daemon can only move where a
/// micro-VM guest serves its class.
fn docker_hosts(state: &State) -> Result<DockerHosts, ApiError> {
    let microvm = state
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM workers WHERE revoked_ms IS NULL AND (capabilities & ?1) != 0)",
                [Capabilities::ISOLATION_MICROVM.0 as i64],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .map_err(store_error)?;
    Ok(if microvm {
        DockerHosts::MicrovmGuests
    } else {
        DockerHosts::ContainerOnly
    })
}

/// What a migration write takes: open the pull request at a commit, or close the one it opened.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    action: Action,
    #[serde(default)]
    commit: Option<String>,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Action {
    /// Create the `sentinel/migrate` branch and its pull request, or update what it already has.
    Open,
    /// Close the open pull request, leaving the branch in place.
    Close,
}

/// What the gate and the write facts of one repository are: the switch and the installation the
/// gate read, then everything a write names. Read in the transaction that records a refusal.
enum Gate {
    Refused(Writes),
    Open {
        tenant: TenantId,
        repo: RepoId,
        installation: u64,
        account: u64,
        forge_repo: u64,
        remote: String,
    },
}

/// The route that applies a migration: the branch named `sentinel/migrate` from the analysed
/// commit, the diff as one commit, and the pull request against the default branch — or the close
/// of that pull request. Re-running it updates the branch and the pull request instead of opening a
/// second one, and a protection rule that declines the update is reported, never forced.
pub(crate) fn pull_request(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::TENANT_ADMIN)?;
    let asked: Start = parse(&body(request)?)?;
    let action = asked.action;
    let commit = match (action, asked.commit) {
        (Action::Open, Some(commit)) => {
            let commit = commit.to_ascii_lowercase();
            if !remote::commit_id(&commit) {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    "commit is not a full commit id",
                ));
            }
            Some(commit)
        }
        (Action::Open, None) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "opening a migration pull request needs the commit it is analysed at",
            ));
        }
        (Action::Close, Some(_)) => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "closing a migration pull request takes no commit",
            ));
        }
        (Action::Close, None) => None,
    };

    // The gate first: it reads the switch and the installation snapshot as they are now and records
    // a refusal in the repository's own audit trail, so no request to GitHub is made for a write the
    // tenant has not authorised.
    let now = UnixMillis::now();
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    let gate = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            // A migration writes to the tenant's repository, so it is the same authority the
            // switch takes: the tenant's administrator.
            authz::require_tenant_admin(tx, principal, tenant)?;
            let writes =
                sentinel_store::migration::authorize(tx, tenant, repo, Some(principal.user), now)?;
            if writes != Writes::Permitted {
                return Ok(Gate::Refused(writes));
            }
            let grant = sources_forge::grant(tx, tenant, repo)?;
            let remote = sources::load_metadata(tx, repo)?.binding.remote;
            Ok(Gate::Open {
                tenant,
                repo,
                installation: grant.installation,
                account: grant.account,
                forge_repo: grant.repo,
                remote,
            })
        })
        .map_err(store_error)?;
    let Gate::Open {
        tenant,
        repo,
        installation,
        account,
        forge_repo,
        remote: bound_remote,
    } = gate
    else {
        let Gate::Refused(writes) = gate else {
            unreachable!("the gate answers refused or open")
        };
        return Err(refused(writes));
    };

    // A write acts as the App: without one in force there is nothing to open a pull request with.
    let Some(app) = state.github_app.app() else {
        return Err(err(
            ErrorCode::Conflict,
            "the controller has no GitHub App in force",
        )
        .with_detail("reason", "not_configured"));
    };
    let _slot = state
        .github_app
        .take_call()
        .ok_or_else(crate::github_app::busy)?;
    let (owner, repository) =
        sentinel_github::checks::repository_path(&bound_remote).ok_or_else(|| {
            err(
                ErrorCode::Conflict,
                "the repository is bound to a remote that is not a GitHub repository",
            )
            .with_detail("reason", "remote")
        })?;
    let token = app
        .migration_token(installation, account, forge_repo, &bound_remote, now.0)
        .map_err(upstream)?;

    let actor = who.principal.user;
    match action {
        Action::Close => {
            let outcome = match app.close_migration(&token, &owner, &repository) {
                Ok(outcome) => outcome,
                Err(error) => {
                    record(state, tenant, repo, actor, Recorded::Refused)?;
                    return Err(upstream(error));
                }
            };
            match outcome {
                Outcome::Closed(pull) => {
                    record(state, tenant, repo, actor, Recorded::Closed)?;
                    answered(None, Some((&pull, "closed")), None)
                }
                // Nothing was open: the answer states that, and nothing is recorded as closed that
                // was not.
                Outcome::Nothing => answered(None, None, None),
                Outcome::Opened(_) | Outcome::Updated(_) => {
                    Err(err(ErrorCode::Internal, "closing answered an open"))
                }
            }
        }
        Action::Open => {
            let commit = commit.as_deref().unwrap_or_default();
            let files = app
                .workflows(&token, &owner, &repository, commit)
                .map_err(upstream)?;
            if files.is_empty() {
                return Err(err(
                    ErrorCode::Conflict,
                    "the repository has no workflow to migrate at this commit",
                )
                .with_detail("reason", "no_workflows"));
            }
            let views: Vec<WorkflowFile<'_>> = files
                .iter()
                .map(|file| WorkflowFile {
                    path: &file.path,
                    text: &file.text,
                })
                .collect();
            let docker = docker_hosts(state)?;
            let inventory = analyze(commit, &views, docker)
                .map_err(|error| err(ErrorCode::InvalidRequest, format!("workflows: {error}")))?;
            let planned = plan(
                &inventory,
                &views,
                &Options {
                    docker,
                    native: false,
                    images: Images::default(),
                },
            )
            .map_err(|error| err(ErrorCode::InvalidRequest, format!("preview: {error}")))?;
            let applied: Vec<Rewritten<'_>> = planned
                .workflows
                .iter()
                .filter_map(|workflow| {
                    workflow.applied.as_deref().map(|text| Rewritten {
                        path: &workflow.path,
                        text,
                    })
                })
                .collect();
            if applied.is_empty() {
                return Err(err(
                    ErrorCode::Conflict,
                    "no workflow's runs-on changes at this commit",
                )
                .with_detail("reason", "no_change"));
            }
            let (title, message, body) = describe(commit, &planned);
            let outcome = match app.migrate(
                &token,
                &owner,
                &repository,
                &Migrate {
                    commit,
                    files: &applied,
                    message: &message,
                    title: &title,
                    body: &body,
                },
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    record(state, tenant, repo, actor, Recorded::Refused)?;
                    return Err(upstream(error));
                }
            };
            match outcome {
                Outcome::Opened(pull) => {
                    record(state, tenant, repo, actor, Recorded::Opened)?;
                    answered(Some(commit), Some((&pull, "opened")), Some(&planned))
                }
                Outcome::Updated(pull) => {
                    record(state, tenant, repo, actor, Recorded::Updated)?;
                    answered(Some(commit), Some((&pull, "updated")), Some(&planned))
                }
                Outcome::Closed(_) | Outcome::Nothing => {
                    Err(err(ErrorCode::Internal, "opening answered a close"))
                }
            }
        }
    }
}

/// The one answer both actions state: the branch, the pull request when there is one, the workflows
/// the diff rewrote and the jobs it kept on GitHub's runners.
fn answered(
    commit: Option<&str>,
    pull: Option<(&remote::Pull, &'static str)>,
    planned: Option<&workflow::Plan>,
) -> Route {
    ok(json!({
        "schema": PULL_REQUEST_SCHEMA,
        "branch": remote::BRANCH,
        "revision": commit,
        "pull_request": pull.map(|(pull, state)| json!({
            "number": pull.number,
            "url": pull.url,
            "head": pull.head,
            "base": pull.base,
            "state": state,
        })),
        "changed": planned.map(changed_json).unwrap_or_default(),
        "kept": planned.map(kept_json).unwrap_or_default(),
    }))
}

/// What became of an attempt goes in the repository's audit trail, so who ran a migration and when
/// survives it.
fn record(
    state: &State,
    tenant: TenantId,
    repo: RepoId,
    actor: UserId,
    outcome: Recorded,
) -> Result<(), ApiError> {
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| {
            sentinel_store::migration::record_pull_request(
                tx,
                tenant,
                repo,
                Some(actor),
                outcome,
                now,
            )
        })
        .map_err(store_error)
}

fn refused(writes: Writes) -> ApiError {
    match writes {
        Writes::Permitted => err(ErrorCode::Internal, "the gate answered nothing"),
        Writes::Off => err(
            ErrorCode::Conflict,
            "guided migration is off for this tenant",
        )
        .with_detail("reason", "off"),
        Writes::Missing(missing) => err(
            ErrorCode::Conflict,
            "the GitHub App's installations do not grant what a migration writes with",
        )
        .with_detail("missing", missing),
        Writes::Unbound => err(
            ErrorCode::Conflict,
            "the repository is bound through no live installation to write with",
        )
        .with_detail("reason", "unbound"),
    }
}

/// GitHub's answer as the API states it: a refusal a person's setting decided is a `409` that names
/// it, and a broken call is an upstream failure. Nothing GitHub said is echoed, so no workflow, path
/// or credential text reaches a client from it.
fn upstream(error: sentinel_github::Error) -> ApiError {
    use sentinel_github::Error as Github;
    match error {
        Github::Refused("branch protection") => err(
            ErrorCode::Conflict,
            "the sentinel/migrate branch's protection declined the update",
        )
        .with_detail("reason", "branch_protected"),
        Github::Refused(_) => err(
            ErrorCode::Conflict,
            "GitHub declined the migration pull request",
        )
        .with_detail("reason", "pull_request_refused"),
        Github::Config(_) | Github::Callback(_) => {
            err(ErrorCode::Internal, "the migration write was built wrong")
        }
        Github::Denied(_) | Github::Response(_) | Github::Transport(_) => err(
            ErrorCode::UpstreamFailed,
            "GitHub did not answer the migration write; retry shortly",
        ),
    }
}

/// What the commit and the pull request say: the same text for the same plan, so re-running a
/// migration at one commit rewrites nothing a person did not re-analyse.
fn describe(commit: &str, planned: &workflow::Plan) -> (String, String, String) {
    let title = "Move workflow jobs to Sentinel runners".to_owned();
    let message = format!(
        "Move workflow jobs to Sentinel runners\n\nGuided migration at commit {commit}; only the runs-on lines change.\n"
    );
    let mut body = String::with_capacity(1024);
    body.push_str("Guided migration of `");
    body.push_str(commit);
    body.push_str("` (label table ");
    body.push_str(&planned.label_table.to_string());
    body.push_str(
        "): only `runs-on:` lines change.\n\n| Workflow | Job | Was | Now |\n|---|---|---|---|\n",
    );
    for workflow in &planned.workflows {
        for change in &workflow.changes {
            body.push_str("| `");
            body.push_str(&workflow.path);
            body.push_str("` | `");
            body.push_str(&change.job);
            body.push_str("` | `");
            body.push_str(change.before.trim());
            body.push_str("` | `");
            body.push_str(change.after.trim());
            body.push_str("` |\n");
        }
    }
    let mut kept_any = false;
    for workflow in &planned.workflows {
        for kept in &workflow.kept {
            if !kept_any {
                body.push_str("\nJobs that stay on GitHub's runners:\n\n");
                kept_any = true;
            }
            body.push_str("- `");
            body.push_str(&workflow.path);
            body.push_str("` `");
            body.push_str(&kept.job);
            body.push_str("`: ");
            if kept.varies && kept.reasons.is_empty() {
                body.push_str("its runs-on cells name different classes");
            }
            for (index, reason) in kept.reasons.iter().enumerate() {
                if index > 0 {
                    body.push_str(", ");
                }
                body.push_str(reason.note());
            }
            body.push('\n');
        }
    }
    body.push_str("\nRe-running the migration updates this branch and this pull request.\n");
    (title, message, body)
}

fn changed_json(planned: &workflow::Plan) -> Vec<Value> {
    let mut out = Vec::with_capacity(planned.workflows.len());
    for workflow in &planned.workflows {
        if workflow.changes.is_empty() {
            continue;
        }
        out.push(json!({
            "path": workflow.path,
            "jobs": workflow.changes.iter().map(|change| change.job.as_str()).collect::<Vec<&str>>(),
        }));
    }
    out
}

fn kept_json(planned: &workflow::Plan) -> Vec<Value> {
    let mut out = Vec::new();
    for workflow in &planned.workflows {
        for kept in &workflow.kept {
            out.push(json!({
                "path": workflow.path,
                "job": kept.job,
                "reasons": kept.reasons.iter().map(|reason| reason.as_str()).collect::<Vec<&str>>(),
                "notes": kept.reasons.iter().map(|reason| reason.note()).collect::<Vec<&str>>(),
                "varies": kept.varies,
            }));
        }
    }
    out
}
