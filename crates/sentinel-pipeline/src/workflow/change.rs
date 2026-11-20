//! The change a guided migration would make, in the step it is asked for: the `runs-on:` diff
//! per workflow, the copies runner mode runs beside the unchanged originals and the switch that
//! drops them, the native path's disable, the jobs that stay on GitHub's runners with their
//! reasons, and — on request — the native pipeline plan.
//!
//! A change is text surgery on the workflow as it is written — label lines, whole job blocks, a
//! job's `if:` line — and nothing else. Every phase applies its edits to the text and analyses
//! the result again, so a plan that would touch another line, or land on a job it did not mean,
//! is refused rather than shown.

use std::fmt;

use sentinel_core::runner::RunnerClass;

use super::{
    Classified, Construct, Destination, DockerHosts, Inventory, Job, KeepReason, RuleTable,
    Workflow, WorkflowError, WorkflowErrorKind, WorkflowFile, analyze,
    native::{self, Images, Native},
};
use crate::yaml::{self, ValueSpan};

/// The plan's own version: a preview's JSON shape is a contract, so it says which one it is.
pub const SCHEMA: &str = "sentinel.migration-preview/1";

/// Lines of context a hunk shows on each side, as a unified diff does.
const CONTEXT: u32 = 3;

/// Which step of a migration a plan is for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    /// The `runs-on:` diff alone: what the preview shows and the migration's first pull request
    /// applies.
    #[default]
    Label,
    /// A non-required copy of every migrating job beside its unchanged original, which is how
    /// runner mode runs the same commits twice.
    Shadow,
    /// The switch: every copy dropped and the originals' labels moved.
    Switch,
    /// The native path's switch: every job a pipeline replaced disabled, and nothing else.
    Disable,
}

/// The prefix a copy's job name carries: the same spelling the per-job check Sentinel publishes
/// uses (`sentinel_store::checks::JOB_PREFIX`), so a copy is non-required by construction.
pub const COPY_PREFIX: &str = "sentinel / ";

/// The prefix a copy's job id carries: `sentinel-<the original's id>`.
const COPY_ID: &str = "sentinel-";

/// The `if:` a disabled job states. An always-false condition stops the job without moving its
/// id, its name or any other key, so the check name GitHub requires keeps its authority.
const DISABLED: &str = "${{ false }}";

/// One copy a shadow plan adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowJob {
    /// The copy's job id: `sentinel-<original id>`.
    pub job: String,
    pub original: String,
    /// The copy's `name:`, `sentinel / <the original's name, or its id>`.
    pub name: String,
    /// The Sentinel class the copy asks for, as the original's `runs-on:` becomes.
    pub class: String,
}

/// What to produce, and the deployment's own fact the re-analysis is checked against.
pub struct Options<'a> {
    /// The analyzer's own input: whether this deployment's classes run in microVM guests.
    pub docker: DockerHosts,
    /// Generate the native plan too.
    pub native: bool,
    /// The digest-pinned images a native job may run in, by platform.
    pub images: Images<'a>,
    /// Which step of the migration the plan is for.
    pub phase: Phase,
}

/// What a migration preview would change, for one commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub revision: String,
    pub label_table: u16,
    pub rule_table: u16,
    /// Sorted by path, as the inventory is.
    pub workflows: Vec<WorkflowPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPlan {
    pub path: String,
    /// A unified diff of the lines the plan changes; empty when it changes none.
    pub diff: String,
    /// The workflow's text after the plan, and `None` when the workflow is unchanged: what a
    /// migration commits, so the commit is this plan's output and not a second rewrite of it.
    pub applied: Option<String>,
    pub changes: Vec<LabelChange>,
    /// The copies this plan added, in job order (Shadow).
    pub shadow: Vec<ShadowJob>,
    /// The copies this plan dropped, in job order (Switch).
    pub dropped: Vec<ShadowJob>,
    /// The jobs this plan disabled (Disable).
    pub disabled: Vec<String>,
    /// The jobs that keep running on GitHub's runners, with the reasons.
    pub kept: Vec<KeptJob>,
    /// The native pipeline this workflow becomes, when it was asked for and can be served.
    pub native: Option<Native>,
    /// Why no native pipeline was produced, when one was asked for.
    pub native_refused: Option<&'static str>,
}

/// One line set the plan rewrites, or adds: a `runs-on:` value, a copy's whole block, a job's
/// `if:`. `before` and `after` are the whole lines the change replaces and produces, so the diff
/// never shows a partial line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelChange {
    pub job: String,
    /// 1-based line of the first line the change replaces, and for an insertion (`before` empty)
    /// the line the added lines start at in the text the plan produces.
    pub line: u32,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptJob {
    pub job: String,
    /// One entry per cell the label table keeps, deduplicated in the order met.
    pub reasons: Vec<KeepReason>,
    /// Set when every cell names a class but they differ: a `runs-on:` value is one label
    /// set, so no single edit can name them all.
    pub varies: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// A workflow the inventory holds was not given as text, or the reverse.
    Files,
    /// The label's text is not the value the inventory read, so a rewrite would not land
    /// on the label.
    Rewrite {
        path: String,
        job: String,
    },
    /// Rewriting a workflow produced one the analyzer no longer reads as intended.
    Unverified {
        path: String,
        job: String,
    },
    /// A copy's id is taken by another job, or is one a surviving job still needs. `job` is the
    /// copy's id.
    Copy {
        path: String,
        job: String,
    },
    /// The disable phase needs the native plan, which was not asked for or was refused.
    Native {
        path: String,
    },
    Analyze(WorkflowError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Files => f.write_str("every workflow must be given with its text"),
            Self::Rewrite { path, job } => write!(
                f,
                "{path}: jobs.{job}: the label is not written where the diff can rewrite it"
            ),
            Self::Unverified { path, job } if job.is_empty() => {
                write!(
                    f,
                    "{path}: the rewrite changed more than the change it states"
                )
            }
            Self::Unverified { path, job } => write!(
                f,
                "{path}: jobs.{job}: the rewrite changed more than the change it states"
            ),
            Self::Copy { path, job } => write!(
                f,
                "{path}: jobs.{job}: the copy's id is taken already or still needed"
            ),
            Self::Native { path } => {
                write!(f, "{path}: the disable phase needs the native plan")
            }
            Self::Analyze(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for PlanError {}

/// The diff and native plan for one inventory.
pub fn plan(
    inventory: &Inventory,
    files: &[WorkflowFile<'_>],
    options: &Options<'_>,
) -> Result<Plan, PlanError> {
    if files.len() != inventory.workflows.len() {
        return Err(PlanError::Files);
    }
    let mut workflows = Vec::with_capacity(inventory.workflows.len());
    for workflow in &inventory.workflows {
        let text = files
            .iter()
            .find(|file| file.path == workflow.path)
            .map(|file| file.text)
            .ok_or(PlanError::Files)?;
        let native = if options.native {
            native::generate(inventory, workflow, &options.images)
        } else {
            native::Generated::NOT_ASKED
        };
        let rewritten = match options.phase {
            Phase::Label => labels(inventory, workflow, text, options)?,
            Phase::Shadow => shadow(inventory, workflow, text, options)?,
            Phase::Switch => switch(inventory, workflow, text, options)?,
            Phase::Disable => disable(inventory, workflow, text, native.native.as_ref(), options)?,
        };
        workflows.push(WorkflowPlan {
            path: workflow.path.clone(),
            diff: render_diff(&workflow.path, text, &rewritten.changes),
            applied: rewritten.applied,
            changes: rewritten.changes,
            shadow: rewritten.shadow,
            dropped: rewritten.dropped,
            disabled: rewritten.disabled,
            kept: kept_jobs(workflow),
            native: native.native,
            native_refused: native.refused,
        });
    }
    Ok(Plan {
        revision: inventory.revision.clone(),
        label_table: inventory.label_table,
        rule_table: inventory.rule_table,
        workflows,
    })
}

/// The jobs that stay on GitHub's runners, with the reasons the label table gives.
fn kept_jobs(workflow: &Workflow) -> Vec<KeptJob> {
    let mut out = Vec::new();
    for job in &workflow.jobs {
        let mut reasons: Vec<KeepReason> = Vec::new();
        let mut classes: Option<RunnerClass> = None;
        let mut varies = false;
        for cell in &job.cells {
            match cell.destination {
                Destination::Keep(reason) => {
                    if !reasons.contains(&reason) {
                        reasons.push(reason);
                    }
                }
                Destination::Class(target) => match classes {
                    None => classes = Some(target.class),
                    Some(first) if first == target.class => {}
                    Some(_) => varies = true,
                },
            }
        }
        if !reasons.is_empty() {
            out.push(KeptJob {
                job: job.id.clone(),
                reasons,
                varies: false,
            });
        } else if varies {
            out.push(KeptJob {
                job: job.id.clone(),
                reasons: Vec::new(),
                varies: true,
            });
        }
    }
    out
}

/// What one phase made of one workflow's text.
struct Rewritten {
    changes: Vec<LabelChange>,
    /// The text after the plan; `None` when the plan changed nothing.
    applied: Option<String>,
    shadow: Vec<ShadowJob>,
    dropped: Vec<ShadowJob>,
    disabled: Vec<String>,
}

impl Rewritten {
    const NONE: Self = Self {
        changes: Vec::new(),
        applied: None,
        shadow: Vec::new(),
        dropped: Vec::new(),
        disabled: Vec::new(),
    };
}

/// `Phase::Label`: rewrites every job's label set to the class it resolves to, then proves the
/// rewrite.
fn labels(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    options: &Options<'_>,
) -> Result<Rewritten, PlanError> {
    let spans = spans_of(workflow, text)?;
    let mut edits: Vec<Edit> = Vec::new();
    let mut expected: Vec<(String, RunnerClass)> = Vec::new();
    for job in &workflow.jobs {
        if let Some((edit, class)) = label_edit(text, &spans, workflow, job)? {
            expected.push((job.id.clone(), class));
            edits.push(edit);
        }
    }
    let jobs: Vec<&Job> = workflow.jobs.iter().collect();
    let applied = (!edits.is_empty()).then(|| apply(text, &mut edits));
    verify(
        inventory,
        workflow,
        &jobs,
        applied.as_deref().unwrap_or(text),
        &expected,
        options,
    )?;
    Ok(Rewritten {
        changes: edits.iter().map(Edit::change).collect(),
        applied,
        ..Rewritten::NONE
    })
}

/// `Phase::Shadow`: adds a copy of every job the label table moves, beside its unchanged
/// original, then proves the workflow holds the originals it started with and one copy each.
fn shadow(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    options: &Options<'_>,
) -> Result<Rewritten, PlanError> {
    let spans = spans_of(workflow, text)?;
    let mut copies: Vec<ShadowJob> = Vec::new();
    let mut held: Vec<ExpectedCopy<'_>> = Vec::new();
    let mut edits: Vec<Edit> = Vec::new();
    for job in &workflow.jobs {
        // A copy of a copy would shadow the shadow, so the copies a workflow already holds are
        // the only jobs a second shadow of it leaves alone.
        if is_copy(workflow, job) {
            continue;
        }
        let Some((class, _)) = settled(job) else {
            continue;
        };
        let copy = ShadowJob {
            job: format!("{COPY_ID}{}", job.id),
            original: job.id.clone(),
            name: copy_name(job),
            class: class.to_string(),
        };
        let needs = copy_needs(workflow, job);
        if let Some(existing) = workflow.jobs.iter().find(|other| other.id == copy.job) {
            if existing.name.as_deref() != Some(copy.name.as_str()) || !resolves_to(existing, class)
            {
                return Err(PlanError::Copy {
                    path: workflow.path.clone(),
                    job: copy.job,
                });
            }
            held.push(ExpectedCopy {
                shadow: copy,
                needs: existing.needs.clone(),
                original: job,
                class,
                added: false,
            });
            continue;
        }
        let span = job_span(&spans, workflow, &job.id)?;
        let first = line_start(text, span.key.unwrap_or(span.start));
        let block = copy_block(workflow, job, &text[first..span.end], &copy, &needs, class)?;
        edits.push(Edit::insert(text, copy.job.clone(), span.end, block));
        copies.push(copy.clone());
        held.push(ExpectedCopy {
            shadow: copy,
            needs,
            original: job,
            class,
            added: true,
        });
    }
    let applied = (!edits.is_empty()).then(|| apply(text, &mut edits));
    verify_shadow(
        inventory,
        workflow,
        applied.as_deref().unwrap_or(text),
        &held,
        options,
    )?;
    Ok(Rewritten {
        changes: edits.iter().map(Edit::change).collect(),
        applied,
        shadow: copies,
        ..Rewritten::NONE
    })
}

/// `Phase::Switch`: drops every copy and moves the surviving jobs' labels, which is the text a
/// label plan of the unshadowed workflow produces, then proves it.
fn switch(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    options: &Options<'_>,
) -> Result<Rewritten, PlanError> {
    let copies: Vec<&Job> = workflow
        .jobs
        .iter()
        .filter(|job| is_copy(workflow, job))
        .collect();
    if copies.is_empty() {
        return labels(inventory, workflow, text, options);
    }
    let mut survivors: Vec<&Job> = Vec::with_capacity(workflow.jobs.len() - copies.len());
    for job in &workflow.jobs {
        if is_copy(workflow, job) {
            continue;
        }
        // Dropping the copy would leave this job needing one that no longer exists.
        if let Some(need) = job
            .needs
            .iter()
            .find(|need| copies.iter().any(|copy| copy.id == **need))
        {
            return Err(PlanError::Copy {
                path: workflow.path.clone(),
                job: need.clone(),
            });
        }
        survivors.push(job);
    }
    let spans = spans_of(workflow, text)?;
    let mut edits: Vec<Edit> = Vec::new();
    let mut dropped: Vec<ShadowJob> = Vec::new();
    for copy in &copies {
        let span = job_span(&spans, workflow, &copy.id)?;
        let first = line_start(text, span.key.unwrap_or(span.start));
        dropped.push(ShadowJob {
            job: copy.id.clone(),
            original: copy.id.strip_prefix(COPY_ID).unwrap_or_default().to_owned(),
            name: copy.name.clone().unwrap_or_default(),
            class: settled(copy).map_or_else(String::new, |(class, _)| class.to_string()),
        });
        edits.push(Edit::drop(copy.id.clone(), first, span.end, text));
    }
    let mut expected: Vec<(String, RunnerClass)> = Vec::new();
    for job in &survivors {
        if let Some((edit, class)) = label_edit(text, &spans, workflow, job)? {
            expected.push((job.id.clone(), class));
            edits.push(edit);
        }
    }
    let applied = (!edits.is_empty()).then(|| apply(text, &mut edits));
    verify(
        inventory,
        workflow,
        &survivors,
        applied.as_deref().unwrap_or(text),
        &expected,
        options,
    )?;
    Ok(Rewritten {
        changes: edits
            .iter()
            .filter(|edit| edit.recorded)
            .map(Edit::change)
            .collect(),
        applied,
        dropped,
        ..Rewritten::NONE
    })
}

/// `Phase::Disable`: the native path's switch, which stops every job a pipeline replaced and
/// nothing else.
fn disable(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    native: Option<&Native>,
    options: &Options<'_>,
) -> Result<Rewritten, PlanError> {
    let Some(native) = native else {
        return Err(PlanError::Native {
            path: workflow.path.clone(),
        });
    };
    let served: Vec<&str> = native
        .jobs
        .iter()
        .filter(|mapping| !mapping.jobs.is_empty())
        .map(|mapping| mapping.github.as_str())
        .collect();
    let spans = spans_of(workflow, text)?;
    let mut edits: Vec<Edit> = Vec::new();
    let mut disabled: Vec<String> = Vec::new();
    for job in &workflow.jobs {
        if !served.contains(&job.id.as_str()) {
            continue;
        }
        disabled.push(job.id.clone());
        let path = format!("jobs.{}.if", job.id);
        if let Some(span) = spans
            .iter()
            .find(|span| span.path == path && span.key.is_some())
        {
            let unrewritten = PlanError::Rewrite {
                path: workflow.path.clone(),
                job: job.id.clone(),
            };
            let (first, last, after) = replace_value(text, span, DISABLED).ok_or(unrewritten)?;
            edits.push(Edit::replace(text, job.id.clone(), first, last, after));
            continue;
        }
        let span = job_span(&spans, workflow, &job.id)?;
        let prefix = format!("jobs.{}.", job.id);
        let indent = spans
            .iter()
            .filter(|span| span.path.starts_with(&prefix))
            .filter_map(|span| span.key)
            .min()
            .and_then(|key| indent_of(text, key))
            .ok_or_else(|| PlanError::Unverified {
                path: workflow.path.clone(),
                job: job.id.clone(),
            })?;
        let at = line_end(text, span.key.unwrap_or(span.start));
        edits.push(Edit::insert(
            text,
            job.id.clone(),
            at,
            format!("{indent}if: {DISABLED}\n"),
        ));
    }
    if edits.is_empty() {
        return Ok(Rewritten::NONE);
    }
    let rewritten = apply(text, &mut edits);
    verify_disable(inventory, workflow, &rewritten, &disabled, options)?;
    Ok(Rewritten {
        changes: edits.iter().map(Edit::change).collect(),
        applied: Some(rewritten),
        disabled,
        ..Rewritten::NONE
    })
}

/// The one class a job's labels resolve to, and the labels as written, when every cell
/// agrees on it.
fn settled(job: &Job) -> Option<(RunnerClass, &[String])> {
    let mut class = None;
    for cell in &job.cells {
        let Destination::Class(target) = cell.destination else {
            return None;
        };
        match class {
            None => class = Some(target.class),
            Some(first) if first == target.class => {}
            Some(_) => return None,
        }
    }
    Some((class?, &job.demand.labels))
}

/// Whether every cell of a job's labels resolves to this class.
fn resolves_to(job: &Job, class: RunnerClass) -> bool {
    !job.cells.is_empty()
        && job.cells.iter().all(|cell| match cell.destination {
            Destination::Class(target) => target.class == class,
            Destination::Keep(_) => false,
        })
}

/// The name a copy carries: the prefix and the original's `name:`, or its id when it states
/// none.
fn copy_name(job: &Job) -> String {
    let mut name = String::with_capacity(COPY_PREFIX.len() + 32);
    name.push_str(COPY_PREFIX);
    name.push_str(job.name.as_deref().unwrap_or(&job.id));
    name
}

/// What a copy needs: the copy of every job it needs that has one, and the original id of every
/// job that has none.
fn copy_needs(workflow: &Workflow, job: &Job) -> Vec<String> {
    job.needs
        .iter()
        .map(|need| {
            let copied = workflow.jobs.iter().any(|other| {
                other.id == *need && !is_copy(workflow, other) && settled(other).is_some()
            });
            if copied {
                format!("{COPY_ID}{need}")
            } else {
                need.clone()
            }
        })
        .collect()
}

/// Whether a job is a copy: a name under [`COPY_PREFIX`], an id of `sentinel-<another job>` and a
/// `runs-on:` that resolves to one class.
fn is_copy(workflow: &Workflow, job: &Job) -> bool {
    job.name
        .as_deref()
        .is_some_and(|name| name.starts_with(COPY_PREFIX))
        && job
            .id
            .strip_prefix(COPY_ID)
            .is_some_and(|original| workflow.jobs.iter().any(|other| other.id == original))
        && settled(job).is_some()
}

/// One job a shadow plan must find in the text it produced.
struct ExpectedCopy<'a> {
    shadow: ShadowJob,
    needs: Vec<String>,
    original: &'a Job,
    class: RunnerClass,
    /// Whether this plan added the copy; one the workflow already held is compared on the two
    /// facts that let the plan leave it alone.
    added: bool,
}

/// The copy of one job's block: its id and name, the class it asks for and the copies it needs,
/// with every other line the original's. The block is copied through text surgery — dedented,
/// spanned, edited, re-indented — so no line the edits do not name can move.
fn copy_block(
    workflow: &Workflow,
    job: &Job,
    block: &str,
    copy: &ShadowJob,
    needs: &[String],
    class: RunnerClass,
) -> Result<String, PlanError> {
    let (indent, block) = unindent(block);
    let spans = yaml::spans(&block).map_err(|error| {
        PlanError::Analyze(WorkflowError {
            path: workflow.path.clone(),
            kind: WorkflowErrorKind::Yaml(error),
        })
    })?;
    let unverified = || PlanError::Unverified {
        path: workflow.path.clone(),
        job: job.id.clone(),
    };
    // The block is one mapping whose key is the job's id, so its own keys sit under that path.
    let prefix = format!("{}.", job.id);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let key = spans
        .iter()
        .find(|span| span.path == job.id && span.key.is_some())
        .and_then(|span| span.key)
        .ok_or_else(unverified)?;
    edits.push((key, key + job.id.len(), copy.job.clone()));
    let name = format!("{prefix}name");
    match spans
        .iter()
        .find(|span| span.path == name && span.key.is_some())
    {
        Some(span) => {
            edits.push(replace_value(&block, span, &quoted(&copy.name)).ok_or_else(unverified)?)
        }
        None => {
            // A copy states its name first when the original states none, so the name a check
            // could require never comes from a key the copy did not add.
            let indent = spans
                .iter()
                .filter(|span| span.path != job.id)
                .filter_map(|span| span.key)
                .min()
                .and_then(|at| indent_of(&block, at))
                .ok_or_else(unverified)?;
            let at = line_end(&block, 0);
            edits.push((at, at, format!("{indent}name: {}\n", quoted(&copy.name))));
        }
    }
    let runs_on = format!("{prefix}runs-on");
    let span = spans
        .iter()
        .find(|span| span.path == runs_on && span.key.is_some())
        .ok_or_else(unverified)?;
    edits.push(replace_value(&block, span, &class.to_string()).ok_or_else(unverified)?);
    let needs_path = format!("{prefix}needs");
    if let Some(span) = spans
        .iter()
        .find(|span| span.path == needs_path && span.key.is_some())
    {
        let value = format!("[{}]", needs.join(", "));
        edits.push(replace_value(&block, span, &value).ok_or_else(unverified)?);
    }
    edits.sort_by_key(|(first, _, _)| *first);
    let rewritten: String = splice(&block, edits.iter().map(|(f, l, a)| (*f, *l, a.as_str())));
    Ok(indent_block(indent, rewritten))
}

/// The plan's text with the job's own indentation removed, and that indentation.
fn unindent(block: &str) -> (&str, String) {
    let indent = &block[..block.len() - block.trim_start_matches(' ').len()];
    let mut out = String::with_capacity(block.len());
    for line in block.split_inclusive('\n') {
        out.push_str(line.strip_prefix(indent).unwrap_or(line));
    }
    (indent, out)
}

/// The block with `indent` put back, blank lines staying blank, ending a line so the job after
/// it starts on its own.
fn indent_block(indent: &str, block: String) -> String {
    let mut out = String::with_capacity(block.len() + indent.len() * 8);
    for line in block.split_inclusive('\n') {
        if line != "\n" {
            out.push_str(indent);
        }
        out.push_str(line);
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// A name as a YAML scalar: quoted, so a name the workflow wrote with punctuation or an
/// expression stays the text it was.
fn quoted(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('\'');
    for c in name.chars() {
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// The indentation of the line `at` sits on, when only spaces come before it.
fn indent_of(text: &str, at: usize) -> Option<&str> {
    let first = line_start(text, at);
    let indent = &text[first..at];
    indent.bytes().all(|b| b == b' ').then_some(indent)
}

/// The value spans of one workflow's text, as the plan's own edits need them.
fn spans_of(workflow: &Workflow, text: &str) -> Result<Vec<ValueSpan>, PlanError> {
    yaml::spans(text).map_err(|error| {
        PlanError::Analyze(WorkflowError {
            path: workflow.path.clone(),
            kind: WorkflowErrorKind::Yaml(error),
        })
    })
}

/// The span of a job's own value: from its key to the end of its block's last line.
fn job_span<'a>(
    spans: &'a [ValueSpan],
    workflow: &Workflow,
    job: &str,
) -> Result<&'a ValueSpan, PlanError> {
    spans
        .iter()
        .find(|span| span.path == format!("jobs.{job}") && span.key.is_some())
        .ok_or_else(|| PlanError::Unverified {
            path: workflow.path.clone(),
            job: job.to_owned(),
        })
}

/// The edit that moves one job's `runs-on:` to its class, and the class it lands on.
fn label_edit(
    text: &str,
    spans: &[ValueSpan],
    workflow: &Workflow,
    job: &Job,
) -> Result<Option<(Edit, RunnerClass)>, PlanError> {
    let Some((class, declared)) = settled(job) else {
        return Ok(None);
    };
    if declared.len() == 1 && declared[0] == class.to_string() {
        return Ok(None);
    }
    let unrewritten = || PlanError::Rewrite {
        path: workflow.path.clone(),
        job: job.id.clone(),
    };
    let path = format!("jobs.{}.runs-on", job.id);
    let span = spans
        .iter()
        .find(|span| span.path == path && span.key.is_some())
        .ok_or_else(unrewritten)?;
    let edit = Edit::of(text, span, &class.to_string(), &job.id).ok_or_else(unrewritten)?;
    Ok(Some((edit, class)))
}

/// One set of whole lines the plan replaces, adds or drops.
struct Edit {
    job: String,
    /// Byte offset of the first line the change replaces.
    first: usize,
    /// Byte offset one past the last line it replaces.
    last: usize,
    /// The lines the change replaces and produces, whole, so the diff never shows part of
    /// a line.
    before: String,
    after: String,
    /// 1-based line of the first line the change replaces, and for an insertion the line the
    /// added lines start at in the text the plan produces.
    line: u32,
    /// Whether the change is one the plan lists: a switch's dropped copy is applied and named
    /// in `dropped`, not as a change.
    recorded: bool,
}

impl Edit {
    fn of(text: &str, span: &ValueSpan, label: &str, job: &str) -> Option<Self> {
        let (first, last, after) = replace_value(text, span, label)?;
        Some(Self::replace(text, job.to_owned(), first, last, after))
    }

    fn replace(text: &str, job: String, first: usize, last: usize, after: String) -> Self {
        Self {
            job,
            first,
            last,
            before: text[first..last].to_owned(),
            after,
            line: line_of(text, first),
            recorded: true,
        }
    }

    fn insert(text: &str, job: String, at: usize, block: String) -> Self {
        // A block the file did not end a line with needs a newline before it.
        let after = if at > 0 && !text[..at].ends_with('\n') {
            format!("\n{block}")
        } else {
            block
        };
        Self {
            job,
            first: at,
            last: at,
            before: String::new(),
            after,
            line: line_of(text, at),
            recorded: true,
        }
    }

    fn drop(job: String, first: usize, last: usize, text: &str) -> Self {
        Self {
            job,
            first,
            last,
            before: text[first..last].to_owned(),
            after: String::new(),
            line: line_of(text, first),
            recorded: false,
        }
    }

    fn change(&self) -> LabelChange {
        LabelChange {
            job: self.job.clone(),
            line: self.line,
            before: self.before.clone(),
            after: self.after.clone(),
        }
    }
}

/// The whole lines a value's rewrite replaces and produces.
fn replace_value(text: &str, span: &ValueSpan, value: &str) -> Option<(usize, usize, String)> {
    let start = after_key_colon(text, span)?;
    let end = span.end;
    if start >= end || end > text.len() {
        return None;
    }
    // A block value keeps its newline, so the rewritten line stands on its own.
    let replacement = if text[..end].ends_with('\n') {
        format!(" {value}\n")
    } else {
        format!(" {value}")
    };
    let first = line_start(text, start);
    let last = line_end(text, end - 1);
    let mut after = String::with_capacity(last - first + value.len() + 2);
    after.push_str(&text[first..start]);
    after.push_str(&replacement);
    after.push_str(&text[end..last]);
    Some((first, last, after))
}

fn after_key_colon(text: &str, span: &ValueSpan) -> Option<usize> {
    let key = span.key?;
    let rest = text.get(key..span.end)?;
    let colon = rest.find(':')?;
    Some(key + colon + 1)
}

pub(super) fn line_start(text: &str, at: usize) -> usize {
    text[..at].rfind('\n').map_or(0, |i| i + 1)
}

pub(super) fn line_end(text: &str, at: usize) -> usize {
    text[at..].find('\n').map_or(text.len(), |i| at + i + 1)
}

pub(super) fn line_of(text: &str, at: usize) -> u32 {
    (text[..at].bytes().filter(|b| *b == b'\n').count() + 1) as u32
}

/// The text after the edits, which are applied in the order they start at. Each edit is placed
/// where it lands in the text this produces, so a later change's line is the earlier changes'
/// lines added in.
fn apply(text: &str, edits: &mut [Edit]) -> String {
    edits.sort_by_key(|edit| edit.first);
    let mut added = 0i64;
    for edit in edits.iter_mut() {
        if edit.before.is_empty() {
            edit.line = (line_of(text, edit.first) as i64 + added).max(1) as u32;
        }
        added += count_lines(&edit.after) as i64 - count_lines(&edit.before) as i64;
    }
    splice(
        text,
        edits
            .iter()
            .map(|edit| (edit.first, edit.last, edit.after.as_str())),
    )
}

/// Applies sorted, non-overlapping replacements to `text`.
fn splice<'a>(text: &str, edits: impl Iterator<Item = (usize, usize, &'a str)>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (first, last, after) in edits {
        out.push_str(&text[cursor..first]);
        out.push_str(after);
        cursor = last;
    }
    out.push_str(&text[cursor..]);
    out
}

/// One workflow's text, analysed on its own.
fn reanalyzed(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    options: &Options<'_>,
) -> Result<Workflow, PlanError> {
    let files = [WorkflowFile {
        path: &workflow.path,
        text,
    }];
    let analyzed =
        analyze(&inventory.revision, &files, options.docker).map_err(PlanError::Analyze)?;
    analyzed
        .workflows
        .into_iter()
        .next()
        .ok_or(PlanError::Files)
}

/// The rewritten text must read as the same workflow holding exactly the intended labels, or
/// the plan is refused: a diff that touched another line would change the job, not its
/// placement.
fn verify(
    inventory: &Inventory,
    workflow: &Workflow,
    jobs: &[&Job],
    text: &str,
    expected: &[(String, RunnerClass)],
    options: &Options<'_>,
) -> Result<(), PlanError> {
    let rewritten = reanalyzed(inventory, workflow, text, options)?;
    if rewritten.path != workflow.path
        || rewritten.jobs.len() != jobs.len()
        || rewritten.triggers != workflow.triggers
        || rewritten.name != workflow.name
    {
        return Err(PlanError::Unverified {
            path: workflow.path.clone(),
            job: String::new(),
        });
    }
    for (job, changed) in jobs.iter().zip(&rewritten.jobs) {
        if job.id != changed.id {
            return Err(PlanError::Unverified {
                path: workflow.path.clone(),
                job: job.id.clone(),
            });
        }
        let Some((_, class)) = expected.iter().find(|(id, _)| *id == job.id) else {
            if job.cells != changed.cells {
                return Err(PlanError::Unverified {
                    path: workflow.path.clone(),
                    job: job.id.clone(),
                });
            }
            continue;
        };
        let settled = !changed.cells.is_empty()
            && changed.cells.iter().all(|cell| match cell.destination {
                Destination::Class(target) => target.class == *class,
                Destination::Keep(_) => false,
            });
        // Only the placement may differ: the steps, the matrix and every other recorded
        // fact of the job must be the ones the label diff started with.
        if !settled
            || changed.steps != job.steps
            || changed.matrix != job.matrix
            || changed.needs != job.needs
            || changed.secrets != job.secrets
            || changed.constructs != job.constructs
        {
            return Err(PlanError::Unverified {
                path: workflow.path.clone(),
                job: job.id.clone(),
            });
        }
    }
    Ok(())
}

/// The shadowed text must read as the same workflow with its originals untouched and one copy
/// of every job the plan copied, or the plan is refused: a copy is only worth running beside an
/// original that did not move.
fn verify_shadow(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    copies: &[ExpectedCopy<'_>],
    options: &Options<'_>,
) -> Result<(), PlanError> {
    let rewritten = reanalyzed(inventory, workflow, text, options)?;
    let added = copies.iter().filter(|copy| copy.added).count();
    if rewritten.path != workflow.path
        || rewritten.triggers != workflow.triggers
        || rewritten.name != workflow.name
        || rewritten.jobs.len() != workflow.jobs.len() + added
    {
        return Err(PlanError::Unverified {
            path: workflow.path.clone(),
            job: String::new(),
        });
    }
    let mut upcoming = workflow.jobs.iter().peekable();
    for job in &rewritten.jobs {
        match upcoming.peek() {
            Some(original) if original.id == job.id => {
                if job != *original {
                    return Err(PlanError::Unverified {
                        path: workflow.path.clone(),
                        job: job.id.clone(),
                    });
                }
                upcoming.next();
                continue;
            }
            _ => {}
        }
        let failed = || PlanError::Unverified {
            path: workflow.path.clone(),
            job: job.id.clone(),
        };
        let copy = copies
            .iter()
            .find(|copy| copy.shadow.job == job.id)
            .ok_or_else(failed)?;
        if job.name.as_deref() != Some(copy.shadow.name.as_str())
            || !resolves_to(job, copy.class)
            || job.cells.len() != copy.original.cells.len()
        {
            return Err(failed());
        }
        if copy.added && (job.needs != copy.needs || !same_facts(job, copy.original)) {
            return Err(failed());
        }
    }
    Ok(())
}

/// The disabled text must read as the same workflow with exactly the replaced jobs turned off,
/// or the plan is refused: a check name is the job's name, so nothing about the job may move.
fn verify_disable(
    inventory: &Inventory,
    workflow: &Workflow,
    text: &str,
    disabled: &[String],
    options: &Options<'_>,
) -> Result<(), PlanError> {
    let rewritten = reanalyzed(inventory, workflow, text, options)?;
    if rewritten.path != workflow.path
        || rewritten.triggers != workflow.triggers
        || rewritten.name != workflow.name
        || rewritten.jobs.len() != workflow.jobs.len()
    {
        return Err(PlanError::Unverified {
            path: workflow.path.clone(),
            job: String::new(),
        });
    }
    for (job, changed) in workflow.jobs.iter().zip(&rewritten.jobs) {
        let failed = || PlanError::Unverified {
            path: workflow.path.clone(),
            job: job.id.clone(),
        };
        if job.id != changed.id || job.name != changed.name {
            return Err(failed());
        }
        if !disabled.contains(&job.id) {
            if job != changed {
                return Err(failed());
            }
            continue;
        }
        if job.needs != changed.needs
            || job.cells != changed.cells
            || job.demand != changed.demand
            || !same_facts(job, changed)
            || !changed.condition
            || changed.constructs != disabled_constructs(job)
        {
            return Err(failed());
        }
    }
    Ok(())
}

/// Whether two recordings of a job agree on every fact a plan does not change. What a phase
/// edits is the id, the name, what the job needs, what its `runs-on:` resolves to and the one
/// `if:` it states; the construct list is compared by the phase that may have added one.
fn same_facts(a: &Job, b: &Job) -> bool {
    a.timeout_minutes == b.timeout_minutes
        && a.environment == b.environment
        && a.outputs == b.outputs
        && a.reusable == b.reusable
        && a.permissions == b.permissions
        && a.concurrency == b.concurrency
        && a.env == b.env
        && a.defaults == b.defaults
        && a.continue_on_error == b.continue_on_error
        && a.matrix == b.matrix
        && a.container == b.container
        && a.services == b.services
        && a.steps == b.steps
        && a.caches == b.caches
        && a.artifacts == b.artifacts
        && a.secrets == b.secrets
        && a.variables == b.variables
}

/// The constructs a job records once it states an `if:`: the analyzer adds one entry, after
/// `needs:` when the job states one and first otherwise.
fn disabled_constructs(job: &Job) -> Vec<Classified> {
    let mut constructs = job.constructs.clone();
    if !job.condition {
        let at = usize::from(
            constructs
                .first()
                .is_some_and(|entry| entry.construct == Construct::Needs),
        );
        constructs.insert(
            at,
            Classified {
                construct: Construct::Condition,
                rule: RuleTable::V1.classify(&Construct::Condition),
            },
        );
    }
    constructs
}

/// A unified diff of the lines the plan changes, with the three lines of context either side.
fn render_diff(path: &str, text: &str, changes: &[LabelChange]) -> String {
    if changes.is_empty() {
        return String::new();
    }
    // Each change's place in the text the plan started from: an insertion states the line its
    // block takes in the text the plan produces, so the lines the earlier changes added are
    // taken back out.
    let mut placed: Vec<(u32, i64)> = Vec::with_capacity(changes.len());
    let mut added = 0i64;
    for change in changes {
        let line = if change.before.is_empty() {
            (change.line as i64 - added).max(1) as u32
        } else {
            change.line
        };
        placed.push((line, added));
        added += count_lines(&change.after) as i64 - count_lines(&change.before) as i64;
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    let mut index = 0;
    while index < changes.len() {
        // A hunk gathers the changes whose context would otherwise overlap.
        let first = index;
        let mut last = index;
        while last + 1 < changes.len()
            && placed[last + 1].0
                <= placed[last].0 + count_lines(&changes[last].after) + 2 * CONTEXT
        {
            last += 1;
        }
        let start_line = placed[first].0.saturating_sub(CONTEXT).max(1);
        let end_line = placed[last].0 + count_lines(&changes[last].after) + CONTEXT;
        let before_len = (end_line - start_line + 1) as usize;
        let delta: i64 = placed[first].1;
        let after_len = before_len as i64 + delta_of(&changes[first..=last]);
        let after_start = start_line as i64 + delta;
        out.push_str(&format!(
            "@@ -{start_line},{before_len} +{after_start},{after_len} @@\n"
        ));
        let mut line = start_line;
        for (change, (at, _)) in changes[first..=last].iter().zip(&placed[first..=last]) {
            while line < *at {
                push_context(&mut out, lines.get(line as usize - 1).copied());
                line += 1;
            }
            for removed in split_lines(&change.before) {
                out.push('-');
                out.push_str(removed);
            }
            for inserted in split_lines(&change.after) {
                out.push('+');
                out.push_str(inserted);
            }
            line += count_lines(&change.before);
        }
        let context_end = (start_line as usize - 1 + before_len).min(lines.len());
        while (line as usize - 1) < context_end {
            push_context(&mut out, lines.get(line as usize - 1).copied());
            line += 1;
        }
        // The hunks are disjoint, so the next one starts after this one's changes.
        index = last + 1;
    }
    out
}

fn delta_of(changes: &[LabelChange]) -> i64 {
    changes
        .iter()
        .map(|c| count_lines(&c.after) as i64 - count_lines(&c.before) as i64)
        .sum()
}

fn push_context(out: &mut String, line: Option<&str>) {
    let Some(line) = line else {
        return;
    };
    out.push(' ');
    out.push_str(line);
    if !line.ends_with('\n') {
        out.push('\n');
    }
}

fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

fn count_lines(text: &str) -> u32 {
    if text.is_empty() {
        0
    } else {
        text.bytes().filter(|b| *b == b'\n').count() as u32 + u32::from(!text.ends_with('\n'))
    }
}
