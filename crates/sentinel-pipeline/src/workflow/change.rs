//! The change a guided migration would make: the `runs-on:` diff per workflow, the jobs that
//! stay on GitHub's runners with their reasons, and — on request — the native pipeline plan.
//!
//! The diff changes label lines and nothing else. Every rewrite is applied to the text and
//! analysed again, so a plan that would touch another line, or land on a job it did not
//! mean, is refused rather than shown.

use std::fmt;

use sentinel_core::runner::RunnerClass;

use super::{
    Destination, DockerHosts, Inventory, KeepReason, WorkflowError, WorkflowFile, analyze,
    native::{self, Images, Native},
};
use crate::yaml;

/// The plan's own version: a preview's JSON shape is a contract, so it says which one it is.
pub const SCHEMA: &str = "sentinel.migration-preview/1";

/// Lines of context a hunk shows on each side, as a unified diff does.
const CONTEXT: u32 = 3;

/// What to produce, and the deployment's own fact the re-analysis is checked against.
pub struct Options<'a> {
    /// The analyzer's own input: whether this deployment's classes run in microVM guests.
    pub docker: DockerHosts,
    /// Generate the native plan too.
    pub native: bool,
    /// The digest-pinned images a native job may run in, by platform.
    pub images: Images<'a>,
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
    /// A unified diff of the label lines; empty when no job's labels change.
    pub diff: String,
    pub changes: Vec<LabelChange>,
    /// The jobs that keep running on GitHub's runners, with the reasons.
    pub kept: Vec<KeptJob>,
    /// The native pipeline this workflow becomes, when it was asked for and can be served.
    pub native: Option<Native>,
    /// Why no native pipeline was produced, when one was asked for.
    pub native_refused: Option<&'static str>,
}

/// One `runs-on:` value the diff rewrites. `before` and `after` are the whole lines the
/// change replaces and produces, so the diff never shows a partial line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelChange {
    pub job: String,
    /// 1-based line of the first line the change replaces.
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
    /// Rewriting a label produced a workflow the analyzer no longer reads as intended.
    Unverified {
        path: String,
        job: String,
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
            Self::Unverified { path, job } => write!(
                f,
                "{path}: jobs.{job}: rewriting the label changed more than the label"
            ),
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
        let rewritten = rewrite(inventory, workflow, text, options)?;
        let native = if options.native {
            native::generate(inventory, workflow, &options.images)
        } else {
            native::Generated::NOT_ASKED
        };
        workflows.push(WorkflowPlan {
            path: workflow.path.clone(),
            diff: render_diff(&workflow.path, text, &rewritten.changes),
            changes: rewritten.changes,
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
fn kept_jobs(workflow: &super::Workflow) -> Vec<KeptJob> {
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

struct Rewritten {
    changes: Vec<LabelChange>,
}

/// Rewrites every job's label set to the class it resolves to, then proves the rewrite.
fn rewrite(
    inventory: &Inventory,
    workflow: &super::Workflow,
    text: &str,
    options: &Options<'_>,
) -> Result<Rewritten, PlanError> {
    let spans = yaml::spans(text).map_err(|e| {
        PlanError::Analyze(WorkflowError {
            path: workflow.path.clone(),
            kind: super::WorkflowErrorKind::Yaml(e),
        })
    })?;
    let mut edits: Vec<Edit> = Vec::new();
    let mut expected: Vec<(String, RunnerClass)> = Vec::new();
    for job in &workflow.jobs {
        let Some((class, declared)) = settled(job) else {
            continue;
        };
        if declared.len() == 1 && declared[0] == class.to_string() {
            continue;
        }
        let path = format!("jobs.{}.runs-on", job.id);
        let span = spans
            .iter()
            .find(|span| span.path == path && span.key.is_some())
            .ok_or_else(|| PlanError::Rewrite {
                path: workflow.path.clone(),
                job: job.id.clone(),
            })?;
        let edit =
            Edit::of(text, span, &class.to_string(), job).ok_or_else(|| PlanError::Rewrite {
                path: workflow.path.clone(),
                job: job.id.clone(),
            })?;
        edits.push(edit);
        expected.push((job.id.clone(), class));
    }
    edits.sort_by_key(|edit| edit.first);
    let rewritten = apply(text, &edits);
    verify(inventory, workflow, &rewritten, &expected, options)?;
    Ok(Rewritten {
        changes: edits.iter().map(|edit| edit.change()).collect(),
    })
}

/// The one class a job's labels resolve to, and the labels as written, when every cell
/// agrees on it.
fn settled(job: &super::Job) -> Option<(RunnerClass, &[String])> {
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

/// One value the plan replaces, with the whole lines it covers.
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
    line: u32,
}

impl Edit {
    fn of(text: &str, span: &yaml::ValueSpan, label: &str, job: &super::Job) -> Option<Self> {
        let start = after_key_colon(text, span)?;
        let end = span.end;
        if start >= end || end > text.len() {
            return None;
        }
        // A block value keeps its newline, so the rewritten line stands on its own.
        let replacement = if text[..end].ends_with('\n') {
            format!(" {label}\n")
        } else {
            format!(" {label}")
        };
        let first = line_start(text, start);
        let last = line_end(text, end - 1);
        let mut after = String::with_capacity(last - first);
        after.push_str(&text[first..start]);
        after.push_str(&replacement);
        after.push_str(&text[end..last]);
        Some(Self {
            job: job.id.clone(),
            first,
            last,
            before: text[first..last].to_owned(),
            after,
            line: line_of(text, first),
        })
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

fn after_key_colon(text: &str, span: &yaml::ValueSpan) -> Option<usize> {
    let key = span.key?;
    let rest = text.get(key..span.end)?;
    let colon = rest.find(':')?;
    Some(key + colon + 1)
}

fn line_start(text: &str, at: usize) -> usize {
    text[..at].rfind('\n').map_or(0, |i| i + 1)
}

fn line_end(text: &str, at: usize) -> usize {
    text[at..].find('\n').map_or(text.len(), |i| at + i + 1)
}

fn line_of(text: &str, at: usize) -> u32 {
    (text[..at].bytes().filter(|b| *b == b'\n').count() + 1) as u32
}

fn apply(text: &str, edits: &[Edit]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for edit in edits {
        out.push_str(&text[cursor..edit.first]);
        out.push_str(&edit.after);
        cursor = edit.last;
    }
    out.push_str(&text[cursor..]);
    out
}

/// The rewritten text must read as the same workflow with exactly the intended labels, or
/// the plan is refused: a diff that touched another line would change the job, not its
/// placement.
fn verify(
    inventory: &Inventory,
    workflow: &super::Workflow,
    text: &str,
    expected: &[(String, RunnerClass)],
    options: &Options<'_>,
) -> Result<(), PlanError> {
    let files = [WorkflowFile {
        path: &workflow.path,
        text,
    }];
    let analyzed =
        analyze(&inventory.revision, &files, options.docker).map_err(PlanError::Analyze)?;
    let Some(rewritten) = analyzed.workflows.first() else {
        return Err(PlanError::Files);
    };
    if rewritten.path != workflow.path
        || rewritten.jobs.len() != workflow.jobs.len()
        || rewritten.triggers != workflow.triggers
        || rewritten.name != workflow.name
    {
        return Err(PlanError::Unverified {
            path: workflow.path.clone(),
            job: String::new(),
        });
    }
    for (job, changed) in workflow.jobs.iter().zip(&rewritten.jobs) {
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

/// A unified diff of the label lines, with the three lines of context either side.
fn render_diff(path: &str, text: &str, changes: &[LabelChange]) -> String {
    if changes.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    let mut index = 0;
    while index < changes.len() {
        // A hunk gathers the changes whose context would otherwise overlap.
        let first = index;
        let mut last = index;
        while last + 1 < changes.len()
            && changes[last + 1].line
                <= changes[last].line + count_lines(&changes[last].after) + 2 * CONTEXT
        {
            last += 1;
        }
        let start_line = changes[first].line.saturating_sub(CONTEXT).max(1);
        let end_line = changes[last].line + count_lines(&changes[last].after) + CONTEXT;
        let before_len = (end_line - start_line + 1) as usize;
        let delta: i64 = changes[..first]
            .iter()
            .map(|c| count_lines(&c.after) as i64 - count_lines(&c.before) as i64)
            .sum();
        let after_len = before_len as i64 + delta_of(&changes[first..=last]);
        let after_start = start_line as i64 + delta;
        out.push_str(&format!(
            "@@ -{start_line},{before_len} +{after_start},{after_len} @@\n"
        ));
        let mut line = start_line;
        for change in &changes[first..=last] {
            while line < change.line {
                push_context(&mut out, lines.get(line as usize - 1).copied());
                line += 1;
            }
            for removed in split_lines(&change.before) {
                out.push('-');
                out.push_str(removed);
            }
            for added in split_lines(&change.after) {
                out.push('+');
                out.push_str(added);
            }
            line += count_lines(&change.before);
        }
        let context_end = (start_line as usize - 1 + before_len).min(lines.len());
        while (line as usize - 1) < context_end {
            push_context(&mut out, lines.get(line as usize - 1).copied());
            line += 1;
        }
        // The hunks are disjoint, so the next one starts after this one's context.
        while index < changes.len() && changes[index].line < line {
            index += 1;
        }
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
