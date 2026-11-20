//! The guided migration's rollback (H07): one action that opens the revert pull request, puts the
//! branch's required checks back on the native path, or re-enters shadow mode.
//!
//! What it restores is a state, not an intention: the workflow bytes come from GitHub at the
//! revision the caller names — a commit's file bytes never change — and the revert commit's parent
//! is the default branch's head, so the pull request proposes the state as it is today with the
//! pre-switch workflows in it and nothing else. A revision that is not the pre-switch state is
//! refused before anything is written, because the migration would already have nothing to move at
//! it. Every step is one row in the repository's source audit trail
//! ([workflow analysis](../../../docs/workflow-analysis.md#rollback)).
//!
//! Nothing here stores a revision, a pull request number or a settings copy. GitHub holds the
//! bytes, the branch holds the pull request, and the pre-switch required checks are the document
//! the switch's own preview promised, carried by the caller that reviewed it.

use sentinel_core::auth::Scopes;
use sentinel_core::{RepoId, TenantId, UnixMillis, UserId};
use sentinel_github::migration::{self as remote, Migrate, Outcome, Rewritten};
use sentinel_github::rollback::{
    self as settings, Protected, RequiredCheck, RequiredChecks, Restore, Set,
};
use sentinel_pipeline::workflow::{Images, Options, WorkflowFile, analyze, plan};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{
    auth as authz, lookup, migration::Writes, parity, rollback::Step, sources, sources_forge,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::Request;
use crate::routes::{Route, body, err, identify, ok, parse, store_error};
use crate::{State, auth};

/// The answer a rollback states: a versioned contract, so a client can branch on it
/// ([compatibility](../../../docs/compatibility.md)).
pub const ROLLBACK_SCHEMA: &str = "sentinel.migration-rollback/1";

/// What a rollback takes: which restore, the revision it restores, and — on the native path — the
/// pre-switch required checks the switch's preview promised and whether to apply them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollback {
    action: Action,
    commit: String,
    #[serde(default)]
    settings: Option<Settings>,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Action {
    /// Put the pre-switch workflows back: labels back in runner mode, the replaced jobs re-enabled
    /// on the native path.
    Revert,
    /// Put a shadow revision's workflows back, re-entering shadow mode.
    Shadow,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Revert => "revert",
            Self::Shadow => "shadow",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    required_checks: Checks,
    #[serde(default)]
    apply: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checks {
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    checks: Vec<CheckText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckText {
    context: String,
    #[serde(default)]
    app_id: Option<u64>,
}

/// `POST /api/v1/tenants/{slug}/repos/{name}/migration/rollback` — one rollback action, gated
/// exactly as a migration write is, recorded step by step.
pub(crate) fn rollback(state: &State, request: &mut Request, slug: &str, name: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::TENANT_ADMIN)?;
    let asked: Rollback = parse(&body(request)?)?;
    let commit = asked.commit.to_ascii_lowercase();
    if !remote::commit_id(&commit) {
        return Err(err(
            ErrorCode::InvalidRequest,
            "commit is not a full commit id",
        ));
    }
    // The pre-switch document is bounded before anything else, so a malformed one is a `400` and
    // never a half-done rollback.
    let settings = asked
        .settings
        .as_ref()
        .map(|ask| target(ask).map(|document| (document, ask.apply)))
        .transpose()?;

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

    // The revision the caller names, as GitHub holds it: the bytes a restore puts back are these,
    // never a rendering of a plan.
    let files = app
        .workflows(&token, &owner, &repository, &commit)
        .map_err(upstream)?;
    if files.is_empty() {
        return Err(err(
            ErrorCode::Conflict,
            "the revision this rollback names holds no workflow",
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
    let docker = crate::migration::docker_hosts(state)?;
    let inventory = analyze(&commit, &views, docker)
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

    // What the revision restores, decided from the revision itself: a pre-switch state is one the
    // migration would still move, and a shadow state is one that holds a copy beside its original.
    let restored: Vec<(&str, Vec<&str>)> = match asked.action {
        Action::Revert => {
            let back: Vec<(&str, Vec<&str>)> = planned
                .workflows
                .iter()
                .filter(|workflow| !workflow.changes.is_empty())
                .map(|workflow| {
                    (
                        workflow.path.as_str(),
                        workflow.changes.iter().map(|c| c.job.as_str()).collect(),
                    )
                })
                .collect();
            if back.is_empty() {
                return Err(err(
                    ErrorCode::Conflict,
                    "the revision this rollback names is already migrated",
                )
                .with_detail("reason", "not_pre_switch"));
            }
            back
        }
        Action::Shadow => {
            let copies: Vec<(&str, Vec<&str>)> = inventory
                .workflows
                .iter()
                .filter_map(|workflow| {
                    let jobs: Vec<&str> = workflow
                        .jobs
                        .iter()
                        .filter(|job| {
                            job.name
                                .as_deref()
                                .unwrap_or(job.id.as_str())
                                .starts_with(parity::SHADOW_PREFIX)
                        })
                        .map(|job| job.id.as_str())
                        .collect();
                    (!jobs.is_empty()).then_some((workflow.path.as_str(), jobs))
                })
                .collect();
            if copies.is_empty() {
                return Err(err(
                    ErrorCode::Conflict,
                    "the revision this rollback names holds no shadow copy",
                )
                .with_detail("reason", "no_shadow"));
            }
            copies
        }
    };

    // What the restore is built on: the default branch's own head, read from GitHub, so the revert
    // proposes today's state with the pre-switch workflows in it.
    let branch = app
        .branch_workflows(&token, &owner, &repository)
        .map_err(upstream)?;
    let removed: Vec<&str> = branch
        .workflows
        .iter()
        .map(String::as_str)
        .filter(|path| !files.iter().any(|file| file.path == *path))
        .collect();
    let written: Vec<Rewritten<'_>> = files
        .iter()
        .map(|file| Rewritten {
            path: &file.path,
            text: &file.text,
        })
        .collect();
    let (message, title, body) = describe(asked.action, &commit, &restored);
    let outcome = match app.restore(
        &token,
        &owner,
        &repository,
        &Restore {
            write: Migrate {
                commit: &branch.head,
                files: &written,
                message: &message,
                title: &title,
                body: &body,
            },
            remove: &removed,
        },
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            record(state, tenant, repo, who.principal.user, Step::Declined)?;
            return Err(upstream(error));
        }
    };
    let (pull, opened) = match outcome {
        Outcome::Opened(pull) => (pull, true),
        Outcome::Updated(pull) => (pull, false),
        Outcome::Closed(_) | Outcome::Nothing => {
            return Err(err(ErrorCode::Internal, "a restore answered a close"));
        }
    };
    record(
        state,
        tenant,
        repo,
        who.principal.user,
        match asked.action {
            Action::Revert => Step::Reverted,
            Action::Shadow => Step::Shadow,
        },
    )?;

    // The native path's other half: the required checks the switch replaced, put back. Shown, and
    // applied only when the caller opts in and the installation grants what a settings write needs.
    let mut answer = Value::Null;
    if let Some((target, apply)) = &settings {
        let admin =
            match app.administration_token(installation, account, forge_repo, &bound_remote, now.0)
            {
                Ok(token) => Some(token),
                Err(sentinel_github::Error::Denied(_)) => None,
                Err(error) => return Err(upstream(error)),
            };
        let (stated, step) = settings_step(
            app,
            admin.as_ref(),
            &owner,
            &repository,
            &branch.name,
            target,
            *apply,
        )?;
        record(state, tenant, repo, who.principal.user, step)?;
        answer = stated;
    }

    ok(json!({
        "schema": ROLLBACK_SCHEMA,
        "action": asked.action.as_str(),
        "branch": remote::BRANCH,
        "revision": commit,
        "from": branch.head,
        "pull_request": Some(json!({
            "number": pull.number,
            "url": pull.url,
            "head": pull.head,
            "base": pull.base,
            "state": if opened { "opened" } else { "updated" },
        })),
        "workflows": restored.iter().map(|(path, jobs)| json!({
            "path": path, "jobs": jobs,
        })).collect::<Vec<Value>>(),
        "deleted": removed,
        "settings": answer,
    }))
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

/// The pre-switch required checks the caller states, bounded before any request is made.
fn target(settings: &Settings) -> Result<RequiredChecks, ApiError> {
    let stated = &settings.required_checks;
    if stated.checks.len() > settings::MAX_CHECKS {
        return Err(err(
            ErrorCode::InvalidRequest,
            "more required checks than a branch states",
        )
        .with_detail("limit", settings::MAX_CHECKS));
    }
    let mut checks = Vec::with_capacity(stated.checks.len());
    for check in &stated.checks {
        if !settings::context_text(&check.context) {
            return Err(err(
                ErrorCode::InvalidRequest,
                "a required check names no context a branch can wait for",
            )
            .with_detail("limit_bytes", settings::MAX_CONTEXT));
        }
        checks.push(RequiredCheck {
            context: check.context.clone(),
            app_id: check.app_id,
        });
    }
    Ok(RequiredChecks {
        strict: stated.strict,
        checks,
    })
}

/// The settings step: what the branch states now against the pre-switch document, and the change
/// back — shown, or applied when the caller opts in and the token may write protection. The read is
/// repeated after a write, so `verified` says what GitHub states rather than what was sent.
fn settings_step(
    app: &sentinel_github::app::App,
    admin: Option<&sentinel_github::app::Token>,
    owner: &str,
    repo: &str,
    branch: &str,
    target: &RequiredChecks,
    apply: bool,
) -> Result<(Value, Step), ApiError> {
    let Some(token) = admin else {
        return Ok((
            settings_json(
                branch,
                None,
                None,
                target,
                true,
                false,
                Some("not_permitted"),
                None,
            ),
            Step::SettingsFailed,
        ));
    };
    let current = match app
        .required_checks(token, owner, repo, branch)
        .map_err(upstream)?
    {
        Protected::Checks(checks) => checks,
        Protected::NotPermitted => {
            return Ok((
                settings_json(
                    branch,
                    None,
                    None,
                    target,
                    true,
                    false,
                    Some("not_permitted"),
                    None,
                ),
                Step::SettingsFailed,
            ));
        }
        Protected::Unprotected => {
            return Ok((
                settings_json(
                    branch,
                    Some(false),
                    None,
                    target,
                    true,
                    false,
                    Some("not_protected"),
                    None,
                ),
                Step::SettingsFailed,
            ));
        }
    };
    let change = current.change_to(target);
    if change.is_empty() {
        return Ok((
            settings_json(
                branch,
                Some(true),
                Some(&current),
                target,
                false,
                false,
                Some("unchanged"),
                Some(true),
            ),
            Step::SettingsShown,
        ));
    }
    if !apply {
        return Ok((
            settings_json(
                branch,
                Some(true),
                Some(&current),
                target,
                true,
                false,
                Some("not_requested"),
                None,
            ),
            Step::SettingsShown,
        ));
    }
    let (reason, verified, step) = match app
        .set_required_checks(token, owner, repo, branch, target)
        .map_err(upstream)?
    {
        Set::NotPermitted => (Some("not_permitted"), None, Step::SettingsFailed),
        Set::Unprotected => (Some("not_protected"), None, Step::SettingsFailed),
        Set::Applied => {
            let stated = app
                .required_checks(token, owner, repo, branch)
                .map_err(upstream)?;
            let exact = matches!(stated, Protected::Checks(ref stated) if stated == target);
            let reason = if exact { None } else { Some("mismatch") };
            (
                reason,
                Some(exact),
                if exact {
                    Step::SettingsApplied
                } else {
                    Step::SettingsFailed
                },
            )
        }
    };
    Ok((
        settings_json(
            branch,
            Some(true),
            Some(&current),
            target,
            true,
            true,
            reason,
            verified,
        ),
        step,
    ))
}

/// The settings half of the answer: what the branch states, the document to put back, the change
/// between them and what became of it.
#[allow(clippy::too_many_arguments)]
fn settings_json(
    branch: &str,
    protected: Option<bool>,
    current: Option<&RequiredChecks>,
    target: &RequiredChecks,
    changed: bool,
    applied: bool,
    reason: Option<&str>,
    verified: Option<bool>,
) -> Value {
    let change = current.map(|current| current.change_to(target));
    json!({
        "branch": branch,
        "protected": protected,
        "current": current.map(document_json),
        "target": document_json(target),
        "changed": changed,
        "remove": change.as_ref().map(|change| change.remove.iter().map(check_json).collect::<Vec<Value>>()),
        "restore": change.as_ref().map(|change| change.restore.iter().map(check_json).collect::<Vec<Value>>()),
        "strict": change.as_ref().and_then(|change| change.strict),
        "applied": applied,
        "reason": reason,
        "verified": verified,
    })
}

fn document_json(checks: &RequiredChecks) -> Value {
    json!({
        "strict": checks.strict,
        "checks": checks.checks.iter().map(check_json).collect::<Vec<Value>>(),
    })
}

fn check_json(check: &RequiredCheck) -> Value {
    json!({"context": check.context, "app_id": check.app_id})
}

/// What became of a rollback step goes in the repository's audit trail, so who ran it and when
/// survives the call.
fn record(
    state: &State,
    tenant: TenantId,
    repo: RepoId,
    actor: UserId,
    step: Step,
) -> Result<(), ApiError> {
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| sentinel_store::rollback::record(tx, tenant, repo, Some(actor), step, now))
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
/// it, and a broken call is an upstream failure. Nothing GitHub said is echoed.
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
            "GitHub declined the rollback pull request",
        )
        .with_detail("reason", "pull_request_refused"),
        Github::Denied(_) => err(
            ErrorCode::Conflict,
            "the GitHub App's installations do not grant what a rollback writes with",
        )
        .with_detail("reason", "not_permitted"),
        Github::Config(_) | Github::Callback(_) => {
            err(ErrorCode::Internal, "the rollback write was built wrong")
        }
        Github::Response(_) | Github::Transport(_) => err(
            ErrorCode::UpstreamFailed,
            "GitHub did not answer the rollback; retry shortly",
        ),
    }
}

/// What the commit and the pull request say: the same text for the same revision and the same jobs,
/// so re-running a rollback rewrites nothing.
fn describe(
    action: Action,
    commit: &str,
    restored: &[(&str, Vec<&str>)],
) -> (String, String, String) {
    let message = match action {
        Action::Revert => format!(
            "Restore the workflows from {commit}\n\nGuided migration rollback: the runs-on lines go back to the labels GitHub ran.\n"
        ),
        Action::Shadow => format!(
            "Restore the shadow workflows from {commit}\n\nGuided migration rollback: shadow mode is entered again.\n"
        ),
    };
    let title = match action {
        Action::Revert => "Roll back the migration: restore GitHub's runners".to_owned(),
        Action::Shadow => "Roll back to the migration's shadow".to_owned(),
    };
    let mut body = String::with_capacity(512);
    body.push_str(match action {
        Action::Revert => "Guided migration rollback of `",
        Action::Shadow => "Shadow mode re-entered from `",
    });
    body.push_str(commit);
    body.push_str("`: these workflow files are restored exactly as that revision holds them.\n\n");
    body.push_str("| Workflow | Jobs |\n|---|---|\n");
    for (path, jobs) in restored {
        body.push_str("| `");
        body.push_str(path);
        body.push_str("` | ");
        for (index, job) in jobs.iter().enumerate() {
            if index > 0 {
                body.push_str(", ");
            }
            body.push('`');
            body.push_str(job);
            body.push('`');
        }
        body.push_str(" |\n");
    }
    if action == Action::Revert {
        body.push_str(
            "\nOn the native path the branch's required checks move back with it, in the same rollback.\n",
        );
    }
    (message, title, body)
}
