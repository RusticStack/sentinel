//! The guided migration's preview: at a pinned commit, the `runs-on:` diff a repository would
//! receive and, on request, the native pipeline plan its workflows become.
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
use sentinel_protocol::{error::ErrorCode, limits::MAX_PIPELINE_FILE_BYTES};
use sentinel_store::{auth as authz, lookup};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::Request;
use crate::routes::{Route, body, err, identify, ok, parse, store_error};
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
