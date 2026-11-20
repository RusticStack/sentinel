//! One suggestion for a construct the rule table marks unsupported: a rewrite of the workflow's
//! own text, offered only once the analyzer reads the rewritten workflow as exactly the change
//! the rewrite states. A rewrite that lands anywhere else is refused rather than shown, and
//! nothing here writes anything: a suggestion is advice, and the migration that applies it is a
//! separate, audited write.

use serde::Serialize;

use super::{
    Classified, Construct, DockerHosts, Job, Rule, RuleTable, Workflow, WorkflowError,
    WorkflowErrorKind, WorkflowFile, analyze,
    change::{line_end, line_of, line_start},
};
use crate::yaml::{self, ValueSpan};

/// What a suggestion is: a shape a client may rely on, so it says which one it is.
pub const SCHEMA: &str = "sentinel.migration-suggestion/1";

/// The analyzer reads a workflow at a pinned commit. A suggestion compares one workflow with
/// itself — the same commit on both sides — so the revision cancels out and is never in the answer.
const REVISION: &str = "0000000000000000000000000000000000000000";

/// The last step index a request may name: the analyzer's own ceiling.
pub const MAX_STEP_INDEX: u64 = super::MAX_STEPS as u64 - 1;

/// What a caller asks for: one workflow's text, and the construct the analyzer refused.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub path: &'a str,
    pub text: &'a str,
    /// The job the construct belongs to; `None` for a workflow-level construct.
    pub job: Option<&'a str>,
    /// The step it belongs to, by the analyzer's own order; `None` for a job-level construct.
    pub step: Option<usize>,
    /// The construct's name as the inventory records it (`on`, `shell`, `continue-on-error`).
    pub construct: &'a str,
}

/// The rewrite, its stated change, and the whole lines it replaces and produces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub schema: &'static str,
    /// The construct's name as the inventory records it.
    pub construct: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<usize>,
    /// The rule table's own reason the construct is unsupported.
    pub reason: &'static str,
    /// What the rewrite does, and what it costs.
    pub change: &'static str,
    /// 1-based line of the first line the rewrite replaces.
    pub line: u32,
    pub before: String,
    pub after: String,
    /// A suggestion is never applied by Sentinel: the caller decides, and the migration write
    /// re-analyses whatever it commits.
    pub applied: bool,
    /// The lines hold the repository's own workflow text, which is evidence, never instructions.
    pub untrusted: bool,
}

/// Why no suggestion is offered. Every variant is a refusal: a caller is told what the analyzer
/// knows and is never handed a rewrite that did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The analyzer refused the workflow, so nothing can be classified.
    Analyze(WorkflowError),
    /// There is no such job or step, or the step does not state the construct.
    NotFound(String),
    /// The construct is not one the analyzer records where the request names it, or a rewrite
    /// does not apply there.
    Invalid(&'static str),
    /// The construct translates as it is or with a stated change: there is nothing to suggest.
    Translates(Rule),
    /// No rewrite is known for this construct; the reason it stays unsupported is the answer.
    NoRewrite(&'static str),
    /// A rewrite was written and then failed to verify: it is withheld, never offered.
    Unverified(&'static str),
}

impl Refusal {
    /// The `sentinel.error/1` code a transport answers this refusal with.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Analyze(_) | Self::Invalid(_) | Self::Translates(_) => "invalid_request",
            Self::NotFound(_) | Self::NoRewrite(_) | Self::Unverified(_) => "not_found",
        }
    }

    /// One sentence: what is known, and why no rewrite is offered.
    pub fn message(&self) -> String {
        match self {
            Self::Analyze(error) => error.to_string(),
            Self::NotFound(message) => message.clone(),
            Self::Invalid(message) => (*message).to_owned(),
            Self::Translates(Rule::Translatable) => {
                "nothing to suggest: the construct translates as it is".to_owned()
            }
            Self::Translates(Rule::WithChange { change }) => format!(
                "nothing to suggest: the construct translates with a stated change: {change}"
            ),
            Self::Translates(Rule::Unsupported { .. }) => {
                "nothing to suggest: the construct is not unsupported".to_owned()
            }
            Self::NoRewrite(reason) => {
                format!("no suggestion exists for this construct: {reason}")
            }
            Self::Unverified(reason) => {
                format!("no suggestion is offered: it did not verify, because {reason}")
            }
        }
    }
}

/// The suggestion for one construct, or the refusal that says why none is offered.
pub fn suggest(request: &Request<'_>) -> Result<Suggestion, Refusal> {
    let workflow = analyzed(request.path, request.text)?;
    let spans = yaml::spans(request.text)
        .map_err(|error| Refusal::Analyze(yaml_error(request.path, error)))?;
    let draft = draft(&workflow, request, &spans)?;
    let rewritten = format!(
        "{}{}{}",
        &request.text[..draft.first],
        draft.after,
        &request.text[draft.last..]
    );
    if analyzed(request.path, &rewritten)? != draft.expected {
        return Err(Refusal::Unverified(UNVERIFIED));
    }
    Ok(Suggestion {
        schema: SCHEMA,
        construct: request.construct.to_owned(),
        job: request.job.map(str::to_owned),
        step: request.step,
        reason: draft.reason,
        change: draft.change,
        line: line_of(request.text, draft.first),
        before: request.text[draft.first..draft.last].to_owned(),
        after: draft.after,
        applied: false,
        untrusted: true,
    })
}

const NOT_WRITTEN: &str = "the construct is not written on the lines a rewrite replaces";

const UNVERIFIED: &str = "the rewritten workflow no longer reads as the change it states";

/// One workflow's text analysed on its own, as both sides of the comparison are.
fn analyzed(path: &str, text: &str) -> Result<Workflow, Refusal> {
    let files = [WorkflowFile { path, text }];
    analyze(REVISION, &files, DockerHosts::ContainerOnly)
        .map_err(Refusal::Analyze)?
        .workflows
        .into_iter()
        .next()
        .ok_or(Refusal::Invalid("a suggestion reads exactly one workflow"))
}

fn yaml_error(path: &str, error: yaml::YamlError) -> WorkflowError {
    WorkflowError {
        path: path.to_owned(),
        kind: WorkflowErrorKind::Yaml(error),
    }
}

/// A rewrite before it is applied: the workflow it must analyse as, the bytes it replaces, the
/// lines it produces, and what it states.
struct Draft {
    expected: Workflow,
    first: usize,
    last: usize,
    after: String,
    reason: &'static str,
    change: &'static str,
}

fn draft(
    workflow: &Workflow,
    request: &Request<'_>,
    spans: &[ValueSpan],
) -> Result<Draft, Refusal> {
    match request.construct {
        "on" => trigger(workflow, request, spans),
        "continue-on-error" | "shell" | "environment" | "outputs" => {
            let job = job_of(workflow, request)?;
            match request.step {
                Some(index) => step_construct(workflow, job, index, request, spans),
                None => job_construct(workflow, job, request, spans),
            }
        }
        name => unrewritten(workflow, request, name),
    }
}

fn job_of<'a>(workflow: &'a Workflow, request: &Request<'_>) -> Result<&'a Job, Refusal> {
    let id = request
        .job
        .ok_or(Refusal::Invalid("a job construct names the job it is in"))?;
    workflow
        .jobs
        .iter()
        .find(|job| job.id == id)
        .ok_or_else(|| Refusal::NotFound(format!("the workflow has no job `{id}`")))
}

/// The recorded construct, when it is there and unsupported: its reason is what a suggestion states.
fn unsupported(
    scope: &[Classified],
    construct: &Construct,
) -> Result<(Rule, &'static str), Refusal> {
    let found = scope
        .iter()
        .find(|classified| classified.construct == *construct)
        .ok_or_else(|| {
            Refusal::NotFound(format!(
                "the workflow records no `{}` here",
                construct.name()
            ))
        })?;
    match found.rule {
        Rule::Unsupported { reason } => Ok((found.rule, reason)),
        rule => Err(Refusal::Translates(rule)),
    }
}

/// One job key with no native equivalent: dropping it is the whole change.
fn job_construct(
    workflow: &Workflow,
    job: &Job,
    request: &Request<'_>,
    spans: &[ValueSpan],
) -> Result<Draft, Refusal> {
    let (construct, change) = match request.construct {
        "continue-on-error" => (
            Construct::ContinueOnError,
            "a failing step fails its job: if the step may fail legitimately its own command \
             states it (`|| true`), so the step's status is what says so",
        ),
        "environment" => (
            Construct::Environment,
            "deployment environments and the approvals that gate them are not modelled: the \
             job's secrets become secret names the repository provisions",
        ),
        "outputs" => (
            Construct::Outputs,
            "declared outputs and artifact handoff between jobs do not exist yet (I04): the jobs \
             that read them become artifact reads when they land",
        ),
        _ => return Err(Refusal::Invalid("this construct has no job-level rewrite")),
    };
    let (_, reason) = unsupported(&job.constructs, &construct)?;
    let path = format!("jobs.{}.{}", job.id, construct.name());
    let (first, last) = removed(request.text, spans, &path)?;
    let mut expected = workflow.clone();
    let expected_job = &mut expected.jobs[job_index(workflow, &job.id)?];
    match construct {
        Construct::ContinueOnError => expected_job.continue_on_error = false,
        Construct::Environment => expected_job.environment = None,
        Construct::Outputs => expected_job.outputs.clear(),
        _ => unreachable!("only the three job keys reach here"),
    }
    forget(expected_job, &construct);
    Ok(Draft {
        expected,
        first,
        last,
        after: String::new(),
        reason,
        change,
    })
}

/// One step key with no native equivalent.
fn step_construct(
    workflow: &Workflow,
    job: &Job,
    index: usize,
    request: &Request<'_>,
    spans: &[ValueSpan],
) -> Result<Draft, Refusal> {
    let step = job
        .steps
        .get(index)
        .ok_or_else(|| Refusal::NotFound(format!("the job `{}` has no step {index}", job.id)))?;
    let at = format!("jobs.{}.steps.{index}", job.id);
    match request.construct {
        "continue-on-error" if step.continue_on_error => {
            let (_, reason) = unsupported(&job.constructs, &Construct::ContinueOnError)?;
            let (first, last) = removed(request.text, spans, &format!("{at}.continue-on-error"))?;
            let mut expected = workflow.clone();
            let expected_job = &mut expected.jobs[job_index(workflow, &job.id)?];
            expected_job.steps[index].continue_on_error = false;
            forget(expected_job, &Construct::ContinueOnError);
            Ok(Draft {
                expected,
                first,
                last,
                after: String::new(),
                reason,
                change: "a failing step fails its job: if the step may fail legitimately its own \
                         command states it (`|| true`), so the step's status is what says so",
            })
        }
        "continue-on-error" => Err(Refusal::NotFound(format!(
            "the step {index} of `{}` states no continue-on-error",
            job.id
        ))),
        "shell" => {
            let Some(shell) = step.shell.clone() else {
                return Err(Refusal::NotFound(format!(
                    "the step {index} of `{}` states no shell",
                    job.id
                )));
            };
            let construct = Construct::Shell { shell };
            let (_, reason) = unsupported(&job.constructs, &construct)?;
            let span = find(spans, &format!("{at}.shell"))?;
            let (first, last, after) = replaced(request.text, span.start, span.end, "bash");
            let mut expected = workflow.clone();
            let rewritten = Construct::Shell {
                shell: "bash".to_owned(),
            };
            let classified = Classified {
                rule: RuleTable::V1.classify(&rewritten),
                construct: rewritten,
            };
            let expected_job = &mut expected.jobs[job_index(workflow, &job.id)?];
            expected_job.steps[index].shell = Some("bash".to_owned());
            let recorded = expected_job
                .constructs
                .iter()
                .position(|entry| entry.construct == construct)
                .ok_or(Refusal::Unverified(NOT_WRITTEN))?;
            expected_job.constructs[recorded] = classified;
            Ok(Draft {
                expected,
                first,
                last,
                after,
                reason,
                change: "the step runs under bash: its commands are rewritten for sh/bash, and a \
                         PowerShell or Windows script is ported or the job stays on GitHub",
            })
        }
        _ => Err(Refusal::Invalid("this construct has no step-level rewrite")),
    }
}

/// The rewritten job no longer records the construct it dropped.
fn forget(job: &mut Job, construct: &Construct) {
    job.constructs
        .retain(|classified| classified.construct != *construct);
}

fn job_index(workflow: &Workflow, id: &str) -> Result<usize, Refusal> {
    workflow
        .jobs
        .iter()
        .position(|job| job.id == id)
        .ok_or_else(|| Refusal::NotFound(format!("the workflow has no job `{id}`")))
}

/// A trigger with no native equivalent: `pull_request_target` becomes the pull request itself.
fn trigger(
    workflow: &Workflow,
    request: &Request<'_>,
    spans: &[ValueSpan],
) -> Result<Draft, Refusal> {
    if request.job.is_some() || request.step.is_some() {
        return Err(Refusal::Invalid(
            "`on` is a workflow construct and names no job",
        ));
    }
    // `on:` holds one construct per event, so the trigger a request names is the one the rule
    // table refuses: a workflow with two refused triggers is the caller's to rewrite by hand.
    let refused: Vec<(&str, &'static str)> = workflow
        .constructs
        .iter()
        .filter_map(
            |classified| match (&classified.construct, classified.rule) {
                (Construct::Trigger { event }, Rule::Unsupported { reason }) => {
                    Some((event.as_str(), reason))
                }
                _ => None,
            },
        )
        .collect();
    let (event, reason) = match refused.as_slice() {
        [single] => *single,
        [] => {
            let rule = workflow
                .constructs
                .iter()
                .find(|classified| matches!(classified.construct, Construct::Trigger { .. }))
                .map_or(Rule::Translatable, |classified| classified.rule);
            return Err(Refusal::Translates(rule));
        }
        _ => {
            return Err(Refusal::Invalid(
                "the workflow has more than one unsupported trigger; rewrite its `on:` by hand",
            ));
        }
    };
    if event != "pull_request_target" {
        return Err(Refusal::NoRewrite(reason));
    }
    if workflow
        .triggers
        .iter()
        .any(|trigger| trigger.event == "pull_request")
    {
        return Err(Refusal::Unverified(
            "the workflow already runs on pull_request, so renaming this trigger would state \
             that event twice",
        ));
    }
    let mut expected = workflow.clone();
    for trigger in &mut expected.triggers {
        if trigger.event == event {
            trigger.event = "pull_request".to_owned();
        }
    }
    for classified in &mut expected.constructs {
        if classified.construct
            == (Construct::Trigger {
                event: event.to_owned(),
            })
        {
            classified.construct = Construct::Trigger {
                event: "pull_request".to_owned(),
            };
            classified.rule = RuleTable::V1.classify(&classified.construct);
        }
    }
    // A block mapping names the event as a key of `on:`; a sequence names it as an item. Either
    // way the text holds the event once, and only that token moves.
    let (first, last) = match spans
        .iter()
        .find(|span| span.path == format!("on.{event}"))
        .and_then(|span| span.key)
    {
        Some(key) => {
            let end = key + event.len();
            if request.text.get(key..end) != Some(event) {
                return Err(Refusal::Unverified(NOT_WRITTEN));
            }
            (key, end)
        }
        None => {
            let span = spans
                .iter()
                .find(|span| {
                    span.path.starts_with("on.")
                        && !span.path["on.".len()..].contains('.')
                        && request.text.get(span.start..span.end) == Some(event)
                })
                .ok_or(Refusal::Unverified(NOT_WRITTEN))?;
            (span.start, span.end)
        }
    };
    let (first, last, after) = replaced(request.text, first, last, "pull_request");
    Ok(Draft {
        expected,
        first,
        last,
        after,
        reason,
        change: "the workflow runs on the pull request itself instead of the privileged \
                 pull_request_target context: no write token, no repository secrets, and nothing \
                 from a fork's head is trusted — a job that needed that context moves behind \
                 workflow_dispatch",
    })
}

/// A construct the analyzer records but whose rewrite this table does not have an answer for.
fn unrewritten(workflow: &Workflow, request: &Request<'_>, name: &str) -> Result<Draft, Refusal> {
    let scope = match request.job {
        None => &workflow.constructs,
        Some(id) => {
            &workflow
                .jobs
                .iter()
                .find(|job| job.id == id)
                .ok_or_else(|| Refusal::NotFound(format!("the workflow has no job `{id}`")))?
                .constructs
        }
    };
    let mut matching = scope
        .iter()
        .filter(|classified| classified.construct.name() == name);
    let first = matching.next().ok_or_else(|| {
        Refusal::NotFound(format!(
            "the workflow records no `{name}` where the request names it"
        ))
    })?;
    if matching.next().is_some() {
        return Err(Refusal::Invalid(
            "the workflow records more than one construct of that name; rewrite the workflow's \
             own text for it",
        ));
    }
    match first.rule {
        Rule::Unsupported { reason } => Err(Refusal::NoRewrite(reason)),
        rule => Err(Refusal::Translates(rule)),
    }
}

/// The span of one value, when the inventory recorded it where a rewrite can land.
fn find<'a>(spans: &'a [ValueSpan], path: &str) -> Result<&'a ValueSpan, Refusal> {
    spans
        .iter()
        .find(|span| span.path == path && span.key.is_some())
        .ok_or(Refusal::Unverified(NOT_WRITTEN))
}

/// The whole line a token sits on, with that token replaced: a rewrite never shows part of a line.
fn replaced(text: &str, at: usize, end: usize, replacement: &str) -> (usize, usize, String) {
    let first = line_start(text, at);
    let last = line_end(text, end.saturating_sub(1));
    let mut after = String::with_capacity(last - first + replacement.len());
    after.push_str(&text[first..at]);
    after.push_str(replacement);
    after.push_str(&text[end..last]);
    (first, last, after)
}

/// The whole lines a key and its value take, from the key's own line through the end of the
/// value's last line. A key that does not start its line is refused: deleting the line would
/// delete its neighbour.
fn removed(text: &str, spans: &[ValueSpan], path: &str) -> Result<(usize, usize), Refusal> {
    let span = find(spans, path)?;
    let key = span.key.ok_or(Refusal::Unverified(NOT_WRITTEN))?;
    let first = line_start(text, key);
    if !text[first..key]
        .bytes()
        .all(|byte| byte == b' ' || byte == b'\t')
    {
        return Err(Refusal::Unverified(NOT_WRITTEN));
    }
    let last = line_end(text, span.end.saturating_sub(1));
    Ok((first, last))
}
