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
use sentinel_github::protection;
use sentinel_pipeline::workflow::{
    self, DockerHosts, Images, Inventory, MAX_WORKFLOW_FILES, Options, Phase, WorkflowFile,
    analyze, plan,
};
use sentinel_protocol::negotiate::Capabilities;
use sentinel_protocol::{
    diagnostics::{self, ReportFormat, StepReference},
    error::{ApiError, ErrorCode},
    limits::MAX_PIPELINE_FILE_BYTES,
};
use sentinel_store::{
    auth as authz, lookup,
    migration::{PullRequest as Recorded, SettingsWrite, Step as RecordedStep, Writes},
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
            phase: Phase::Label,
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
pub(crate) fn docker_hosts(state: &State) -> Result<DockerHosts, ApiError> {
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
                    phase: Phase::Label,
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

/// What the switch route answers: a versioned contract, so a client can branch on it
/// ([compatibility](../../../docs/compatibility.md)).
pub const SWITCH_SCHEMA: &str = "sentinel.migration-switch/1";
/// The most body one switch request may be: a commit id and two flags.
const MAX_SWITCH_BODY_BYTES: usize = 4 << 10;

/// What a switch request takes: the step, the analysed commit, and — on the native path — the plan
/// the workflows become, whose digest-pinned images are what lets a job leave GitHub's runners.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchRequest {
    action: SwitchStep,
    commit: String,
    #[serde(default)]
    native: Option<NativeRequest>,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SwitchStep {
    /// Runner mode: the pull request that adds a non-required copy of every migrating job.
    Shadow,
    /// Runner mode: the pull request that drops those copies and moves the originals' labels, with
    /// the branch protection read before it and after it compared.
    Switch,
    /// The native path: the exact required-check change, and whether this deployment may make it.
    Preview,
    /// The native path: make it, prove it, and open the pull request that disables the jobs it
    /// replaced.
    Apply,
    /// The native path: compare the settings a person applied with the preview.
    Verify,
}

impl SwitchStep {
    const fn is_native(self) -> bool {
        matches!(self, Self::Preview | Self::Apply | Self::Verify)
    }
}

/// The gate and the write facts of one repository, as the switch reads them.
enum SwitchGate {
    Refused(Writes),
    SettingsRefused(SettingsWrite),
    Open(SwitchOpen),
}

struct SwitchOpen {
    tenant: TenantId,
    repo: RepoId,
    installation: u64,
    account: u64,
    forge_repo: u64,
    remote: String,
    /// The tenant's opt-in to Sentinel making the settings change itself, read with the gate.
    opt_in: bool,
}

/// One branch's settings as the route saw them: what it read, the change it computed, and what it
/// read back after a write.
struct Viewed {
    branch: String,
    before: protection::Required,
    change: protection::Change,
    after: Option<protection::Required>,
}

impl Viewed {
    /// Whether the set read back is the set the change stated. A read that never happened states no
    /// verdict, because a comparison nothing was compared against is not a pass.
    fn equal(&self) -> Option<bool> {
        let after = self.after.as_ref()?;
        Some(
            after.contexts == self.change.contexts() && after.strict == self.change.settings.strict,
        )
    }
}

fn settings_json(viewed: &Viewed) -> Value {
    let expected = viewed.change.contexts();
    let removed: Vec<&String> = viewed
        .before
        .contexts
        .iter()
        .filter(|context| !expected.contains(&context.as_str()))
        .collect();
    let added: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|context| !viewed.before.contexts.iter().any(|held| held == context))
        .collect();
    json!({
        "branch": viewed.branch,
        "before": {"required": viewed.before.contexts, "strict": viewed.before.strict},
        "change": {
            "added": added,
            "removed": removed,
            "replaced": viewed.change.replaced.iter().map(|(context, check)| json!({
                "context": context,
                "check": check,
            })).collect::<Vec<Value>>(),
        },
        "expected": {
            "required": expected,
            "strict": viewed.change.settings.strict,
        },
        "protected": viewed.before.protected,
        "after": viewed.after.as_ref().map(|after| json!({
            "required": after.contexts,
            "strict": after.strict,
        })),
        "verdict": match viewed.equal() {
            Some(true) => "equal",
            Some(false) => "moved",
            None => "unread",
        },
        "rulesets": viewed.before.rulesets,
        "from_rulesets": viewed.before.from_rulesets,
    })
}

/// Whether a required context is the check a job of this name reports: its own name, or one of its
/// matrix cells, which GitHub writes as `<job> (<values>)`.
fn answers(contexts: &[String], name: &str) -> bool {
    contexts.iter().any(|context| {
        context == name
            || context
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with(" ("))
    })
}

/// The jobs a native plan replaced, as the required-check change needs them: the GitHub job id and
/// the name its check carries, which is the job's own `name:` when it states one.
fn replaced(inventory: &Inventory, planned: &workflow::Plan) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for planned_workflow in &planned.workflows {
        let Some(native) = planned_workflow.native.as_ref() else {
            continue;
        };
        let jobs: &[workflow::Job] = inventory
            .workflows
            .iter()
            .find(|found| found.path == planned_workflow.path)
            .map_or(&[], |found| found.jobs.as_slice());
        for mapping in native
            .jobs
            .iter()
            .filter(|mapping| !mapping.jobs.is_empty())
        {
            let name = jobs
                .iter()
                .find(|job| job.id == mapping.github)
                .and_then(|job| job.name.clone());
            out.push((mapping.github.clone(), name));
        }
    }
    out
}

/// What the switch's pull request says, per step: the same text for the same plan at the same
/// commit, so a re-run rewrites nothing a person did not re-analyse.
fn describe_switch(
    commit: &str,
    planned: &workflow::Plan,
    step: SwitchStep,
) -> (&'static str, String, String) {
    let (title, lead) = match step {
        SwitchStep::Shadow => (
            "Run GitHub Actions jobs on Sentinel in parallel",
            "Adds a non-required copy of each migrated job, on a Sentinel runner, beside the unchanged\noriginal: both run on the same commits while GitHub's runners stay authoritative.\n",
        ),
        SwitchStep::Switch => (
            "Switch workflow jobs to Sentinel runners",
            "Drops the shadow copies and moves the originals' `runs-on:` labels to Sentinel. Job names,\nand so the check names a required check names, are unchanged.\n",
        ),
        _ => (
            "Disable the workflow jobs a Sentinel pipeline replaced",
            "Disables, with `if: ${{ false }}`, every workflow job the native pipeline replaced. Job\nnames are unchanged, so the checks a required check names keep their names.\n",
        ),
    };
    let message = format!("{title}\n\nGuided migration at commit {commit}.\n");
    let mut body = String::with_capacity(512);
    body.push_str(lead);
    body.push_str("\nGuided migration of `");
    body.push_str(commit);
    body.push_str("` at label table ");
    body.push_str(&planned.label_table.to_string());
    if step.is_native() {
        body.push_str(" and rule table ");
        body.push_str(&planned.rule_table.to_string());
    }
    body.push_str(".\n\n| Workflow | Job | What |\n|---|---|---|\n");
    for planned_workflow in &planned.workflows {
        for change in &planned_workflow.changes {
            body.push_str("| `");
            body.push_str(&planned_workflow.path);
            body.push_str("` | `");
            body.push_str(&change.job);
            body.push_str("` | ");
            if step == SwitchStep::Shadow {
                body.push_str("copy added");
            } else if step == SwitchStep::Switch {
                body.push_str("runs-on moved to `");
                body.push_str(change.after.trim());
                body.push('`');
            } else {
                body.push_str("disabled");
            }
            body.push_str(" |\n");
        }
    }
    body.push_str("\nRe-running the migration updates this branch and this pull request.\n");
    (title, message, body)
}

/// The native path's answer: the settings as read and written, what this deployment may do with
/// them, the jobs it disabled and the pull request that carries the disabled workflows.
fn native_answer(
    commit: &str,
    viewed: &Viewed,
    opt_in: bool,
    administration: bool,
    pull: Option<(&remote::Pull, &'static str)>,
    planned: &workflow::Plan,
) -> Value {
    json!({
        "schema": SWITCH_SCHEMA,
        "mode": "native",
        "revision": commit,
        "settings": settings_json(viewed),
        "permitted": {"settings": opt_in, "administration": administration},
        "pull_request": pull.map(|(pull, state)| json!({
            "number": pull.number,
            "url": pull.url,
            "head": pull.head,
            "base": pull.base,
            "state": state,
        })),
        "disabled": planned.workflows.iter().flat_map(|workflow| workflow.disabled.clone()).collect::<Vec<String>>(),
        "changed": changed_json(planned),
        "kept": kept_json(planned),
    })
}

/// `POST /api/v1/tenants/{slug}/repos/{name}/migration/switch` — the step that takes a repository
/// from shadowed to switched. Runner mode's steps are the pull requests that add the copies and
/// then drop them, with the branch protection read before and after; the native path's are the
/// required-check change, which is a preview unless the tenant opted in and the App holds
/// repository administration, and the pull request that disables the replaced jobs
/// ([migration switch](../../../docs/migration-switch.md)).
pub(crate) fn switch(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::TENANT_ADMIN)?;
    let asked: SwitchRequest = parse(&body_limit(request, MAX_SWITCH_BODY_BYTES)?)?;
    let commit = asked.commit.to_ascii_lowercase();
    if !remote::commit_id(&commit) {
        return Err(err(
            ErrorCode::InvalidRequest,
            "commit is not a full commit id",
        ));
    }
    let step = asked.action;
    if asked.native.is_some() != step.is_native() {
        return Err(err(
            ErrorCode::InvalidRequest,
            if step.is_native() {
                "the native path's settings steps need the native plan"
            } else {
                "the runner-mode steps take no native plan"
            },
        ));
    }

    // The gate first, in the transaction that records a refusal: the settings write takes the
    // strict one, which reads the tenant's opt-in beside the migration switch.
    let now = UnixMillis::now();
    let (slug, name) = (slug.to_owned(), name.to_owned());
    let principal = who.principal;
    let settings_write = step == SwitchStep::Apply;
    let gate = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let repo = lookup::repo_by_name(tx, tenant, &name)?;
            authz::require_tenant_admin(tx, principal, tenant)?;
            if settings_write {
                match sentinel_store::migration::authorize_settings(
                    tx,
                    tenant,
                    repo,
                    Some(principal.user),
                    now,
                )? {
                    SettingsWrite::Permitted => {}
                    refused => return Ok(SwitchGate::SettingsRefused(refused)),
                }
            } else {
                match sentinel_store::migration::authorize(
                    tx,
                    tenant,
                    repo,
                    Some(principal.user),
                    now,
                )? {
                    Writes::Permitted => {}
                    refused => return Ok(SwitchGate::Refused(refused)),
                }
            }
            let grant = sources_forge::grant(tx, tenant, repo)?;
            let remote = sources::load_metadata(tx, repo)?.binding.remote;
            let opt_in = sentinel_store::migration::settings(tx, tenant)?;
            Ok(SwitchGate::Open(SwitchOpen {
                tenant,
                repo,
                installation: grant.installation,
                account: grant.account,
                forge_repo: grant.repo,
                remote,
                opt_in,
            }))
        })
        .map_err(store_error)?;
    let open = match gate {
        SwitchGate::Open(open) => open,
        SwitchGate::Refused(writes) => return Err(refused(writes)),
        SwitchGate::SettingsRefused(writes) => return Err(refused_settings(writes)),
    };
    let SwitchOpen {
        tenant,
        repo,
        installation,
        account,
        forge_repo,
        remote: bound_remote,
        opt_in,
    } = open;

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

    // The workflows are the commit's own, read through the App as the pull request route reads
    // them, so the plan is computed from the bytes GitHub holds and never from what a caller sent.
    let token = app
        .migration_token(installation, account, forge_repo, &bound_remote, now.0)
        .map_err(upstream)?;
    let files = app
        .workflows(&token, &owner, &repository, &commit)
        .map_err(upstream)?;
    if files.is_empty() {
        return Err(err(
            ErrorCode::Conflict,
            "the repository has no workflow to switch at this commit",
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
    let inventory = analyze(&commit, &views, docker)
        .map_err(|error| err(ErrorCode::InvalidRequest, format!("workflows: {error}")))?;
    let images = asked.native.as_ref().map(|native| Images {
        linux: native.images.linux.as_deref(),
        linux_arm64: native.images.linux_arm64.as_deref(),
        windows: native.images.windows.as_deref(),
    });
    let planned = plan(
        &inventory,
        &views,
        &Options {
            docker,
            native: images.is_some(),
            images: images.unwrap_or_default(),
            phase: match step {
                SwitchStep::Shadow => Phase::Shadow,
                SwitchStep::Switch => Phase::Switch,
                SwitchStep::Preview | SwitchStep::Apply | SwitchStep::Verify => Phase::Disable,
            },
        },
    )
    .map_err(|error| err(ErrorCode::InvalidRequest, format!("switch: {error}")))?;

    // The settings as they are now. Reading a branch's protection is repository administration, so
    // the one token that reads and writes it is minted once and its refusal is a fact the answer
    // states rather than a failed route: GitHub mints a token carrying what the installation
    // grants, and one that comes back without administration is that permission's answer.
    let (protection_token, administration) =
        match app.administration_token(installation, account, forge_repo, &bound_remote, now.0) {
            Ok(token) => (Some(token), true),
            Err(sentinel_github::Error::Denied(_)) => (None, false),
            Err(error) => return Err(upstream(error)),
        };
    let mut viewed = match &protection_token {
        Some(protection_token) => {
            let before = app
                .protection(protection_token, &owner, &repository)
                .map_err(upstream)?;
            let change = if step.is_native() {
                protection::change(&before, &replaced(&inventory, &planned))
            } else {
                protection::Change {
                    settings: before.checks.clone(),
                    replaced: Vec::new(),
                }
            };
            Some(Viewed {
                branch: before.branch.clone(),
                before,
                change,
                after: None,
            })
        }
        None => None,
    };

    let actor = who.principal.user;
    if !step.is_native() {
        // The switch's whole promise is that the gate did not move, and that promise is kept by
        // comparing two reads: without the permission to make them there is nothing to compare, so
        // the step that carries it is refused rather than run on an assertion.
        if step == SwitchStep::Switch && viewed.is_none() {
            record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
            return Err(err(
                ErrorCode::Conflict,
                "the App's installation does not hold repository administration",
            )
            .with_detail("reason", "administration"));
        }
        // A required check one of the dropped copies answers would stop existing the moment the
        // copies go. A merge gate that moves is a person's decision, so the switch is refused
        // rather than run.
        if let (SwitchStep::Switch, Some(viewed)) = (step, viewed.as_ref()) {
            let moving: Vec<&str> = planned
                .workflows
                .iter()
                .flat_map(|workflow| workflow.dropped.iter())
                .filter(|copy| answers(&viewed.before.contexts, &copy.name))
                .map(|copy| copy.name.as_str())
                .collect();
            if !moving.is_empty() {
                record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
                return Err(err(
                    ErrorCode::Conflict,
                    "a required check names one of the copies the switch drops",
                )
                .with_detail("reason", "required_check")
                .with_detail("checks", moving));
            }
        }
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
                if step == SwitchStep::Shadow {
                    "every migrating job already has its copy at this commit"
                } else {
                    "no copy to drop and no label to move at this commit"
                },
            )
            .with_detail("reason", "no_change"));
        }
        let (title, message, body) = describe_switch(&commit, &planned, step);
        let outcome = match app.migrate(
            &token,
            &owner,
            &repository,
            &Migrate {
                commit: &commit,
                files: &applied,
                message: &message,
                title,
                body: &body,
            },
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                record(state, tenant, repo, actor, Recorded::Refused)?;
                return Err(upstream(error));
            }
        };
        let (pull, opened) = match &outcome {
            Outcome::Opened(pull) => (Recorded::Opened, pull),
            Outcome::Updated(pull) => (Recorded::Updated, pull),
            Outcome::Closed(_) | Outcome::Nothing => {
                return Err(err(ErrorCode::Internal, "a switch answered a close"));
            }
        };
        if let (SwitchStep::Switch, Some(viewed), Some(protection_token)) =
            (step, viewed.as_mut(), protection_token.as_ref())
        {
            // The proof: the protection read after the pull request against the one read before it.
            // Equal is what the switch promises; a difference is reported, never asserted away.
            viewed.after = Some(
                app.protection(protection_token, &owner, &repository)
                    .map_err(upstream)?,
            );
            let equal = viewed.equal() == Some(true);
            record_step(
                state,
                tenant,
                repo,
                actor,
                if equal {
                    RecordedStep::Switched
                } else {
                    RecordedStep::SwitchedMoved
                },
            )?;
        }
        record(state, tenant, repo, actor, pull)?;
        return ok(json!({
            "schema": SWITCH_SCHEMA,
            "mode": "runner",
            "revision": commit,
            "settings": viewed.as_ref().map(settings_json),
            "permitted": {"settings": opt_in, "administration": administration},
            "pull_request": {
                "number": opened.number,
                "url": opened.url,
                "head": opened.head,
                "base": opened.base,
                "state": if pull == Recorded::Opened { "opened" } else { "updated" },
            },
            "shadow": planned.workflows.iter().flat_map(|workflow| {
                workflow.shadow.iter().map(|copy| json!({
                    "job": copy.job,
                    "original": copy.original,
                    "name": copy.name,
                    "class": copy.class,
                }))
            }).collect::<Vec<Value>>(),
            "dropped": planned.workflows.iter().flat_map(|workflow| {
                workflow.dropped.iter().map(|copy| json!({
                    "job": copy.job,
                    "original": copy.original,
                    "name": copy.name,
                    "class": copy.class,
                }))
            }).collect::<Vec<Value>>(),
            "changed": changed_json(&planned),
            "kept": kept_json(&planned),
        }));
    }

    // Why this deployment may not make the settings write, or `None` when it may. The opt-in and
    // the grant come first: a tenant that never opted in learns that rather than what a ruleset
    // would have stopped.
    let blocked = if !opt_in {
        Some("settings")
    } else if viewed.is_none() {
        Some("administration")
    } else {
        let viewed = viewed.as_ref().expect("a read the grant admits");
        if !viewed.before.protected {
            Some("unprotected")
        } else {
            let expected = viewed.change.contexts();
            let removed: Vec<String> = viewed
                .before
                .contexts
                .iter()
                .filter(|context| !expected.contains(&context.as_str()))
                .cloned()
                .collect();
            viewed.before.editable(&removed).err()
        }
    };

    if step == SwitchStep::Apply
        && let Some(reason) = blocked
    {
        record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
        return Err(err(
            ErrorCode::Conflict,
            match reason {
                "administration" => {
                    "the App's installation does not hold repository administration"
                }
                "settings" => "the tenant has not opted into Sentinel changing its required checks",
                "unprotected" => "the branch has no protection rule to change",
                _ => {
                    "a required check the change removes is stated by a ruleset this deployment does not edit"
                }
            },
        )
        .with_detail("reason", reason));
    }

    match step {
        SwitchStep::Preview => {
            let mut permitted = json!({"settings": opt_in, "administration": administration});
            if let Some(reason) = blocked {
                permitted["reason"] = json!(reason);
            }
            return ok(json!({
                "schema": SWITCH_SCHEMA,
                "mode": "native",
                "revision": commit,
                "settings": viewed.as_ref().map(settings_json),
                "permitted": permitted,
                "pull_request": Value::Null,
                "disabled": planned.workflows.iter().flat_map(|workflow| workflow.disabled.clone()).collect::<Vec<String>>(),
                "changed": changed_json(&planned),
                "kept": kept_json(&planned),
            }));
        }
        SwitchStep::Verify => {
            let (Some(viewed), Some(protection_token)) =
                (viewed.as_mut(), protection_token.as_ref())
            else {
                record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
                return Err(err(
                    ErrorCode::Conflict,
                    "the App's installation does not hold repository administration",
                )
                .with_detail("reason", "administration"));
            };
            viewed.after = Some(
                app.protection(protection_token, &owner, &repository)
                    .map_err(upstream)?,
            );
            let equal = viewed.equal() == Some(true);
            record_step(
                state,
                tenant,
                repo,
                actor,
                if equal {
                    RecordedStep::Verified
                } else {
                    RecordedStep::Moved
                },
            )?;
            let answer = native_answer(&commit, viewed, opt_in, administration, None, &planned);
            return ok(answer);
        }
        _ => {}
    }

    // Apply: the settings write first, because the jobs it disables are only disabled once the
    // checks that replace them are required. The same token that read the set writes it.
    let (Some(viewed), Some(protection_token)) = (viewed.as_mut(), protection_token.as_ref())
    else {
        record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
        return Err(err(
            ErrorCode::Conflict,
            "the App's installation does not hold repository administration",
        )
        .with_detail("reason", "administration"));
    };
    if let Err(error) = app.set_required(
        protection_token,
        &owner,
        &repository,
        &viewed.branch,
        &viewed.change.settings,
    ) {
        record_step(state, tenant, repo, actor, RecordedStep::Refused)?;
        return Err(upstream(error));
    }
    viewed.after = Some(
        app.protection(protection_token, &owner, &repository)
            .map_err(upstream)?,
    );
    let equal = viewed.equal() == Some(true);
    record_step(
        state,
        tenant,
        repo,
        actor,
        if equal {
            RecordedStep::Applied
        } else {
            RecordedStep::Moved
        },
    )?;
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
    let pull = if applied.is_empty() {
        None
    } else {
        let (title, message, body) = describe_switch(&commit, &planned, SwitchStep::Apply);
        let outcome = match app.migrate(
            &token,
            &owner,
            &repository,
            &Migrate {
                commit: &commit,
                files: &applied,
                message: &message,
                title,
                body: &body,
            },
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                record(state, tenant, repo, actor, Recorded::Refused)?;
                return Err(upstream(error));
            }
        };
        let (outcome, opened) = match &outcome {
            Outcome::Opened(pull) => (Recorded::Opened, pull),
            Outcome::Updated(pull) => (Recorded::Updated, pull),
            Outcome::Closed(_) | Outcome::Nothing => {
                return Err(err(ErrorCode::Internal, "a switch answered a close"));
            }
        };
        record(state, tenant, repo, actor, outcome)?;
        Some((
            opened.clone(),
            if outcome == Recorded::Opened {
                "opened"
            } else {
                "updated"
            },
        ))
    };
    ok(native_answer(
        &commit,
        viewed,
        opt_in,
        administration,
        pull.as_ref().map(|(pull, step)| (pull, *step)),
        &planned,
    ))
}

/// What became of one step of the switch goes in the repository's audit trail, so who switched a
/// repository and when survives it.
fn record_step(
    state: &State,
    tenant: TenantId,
    repo: RepoId,
    actor: UserId,
    step: RecordedStep,
) -> Result<(), ApiError> {
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| {
            sentinel_store::migration::record_step(tx, tenant, repo, Some(actor), step, now)
        })
        .map_err(store_error)
}

fn refused_settings(writes: SettingsWrite) -> ApiError {
    match writes {
        SettingsWrite::Permitted => err(ErrorCode::Internal, "the gate answered nothing"),
        SettingsWrite::Off => err(
            ErrorCode::Conflict,
            "guided migration is off for this tenant",
        )
        .with_detail("reason", "off"),
        SettingsWrite::Missing(missing) => err(
            ErrorCode::Conflict,
            "the GitHub App's installations do not grant what a migration writes with",
        )
        .with_detail("missing", missing),
        SettingsWrite::Unbound => err(
            ErrorCode::Conflict,
            "the repository is bound through no live installation to write with",
        )
        .with_detail("reason", "unbound"),
        SettingsWrite::NotOpted => err(
            ErrorCode::Conflict,
            "the tenant has not opted into Sentinel changing its required checks",
        )
        .with_detail("reason", "settings"),
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
