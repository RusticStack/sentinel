//! The native path: the deterministic `.sentinel.yml` a workflow becomes, built from the
//! inventory and the rule table and checked by the pipeline compiler before it is shown.
//!
//! The inventory holds names, paths and keys and never a value — no `run:` script, no `env`
//! value, no condition. A generated job therefore carries the structure the analyzer read:
//! its triggers, class, needs, timeout, caches, artifacts, secrets and one stub script per
//! `run:` step, at `scripts/ci/<workflow>/<job>/<step>.sh`. The mapping says which GitHub
//! step each stub stands for and what the pipeline could not carry, so nothing is dropped
//! without being named.

use std::fmt::Write as _;

use sentinel_core::runner::{RunnerClass, RunnerOs};

use super::{
    ActionRef, ArtifactDirection, Construct, Destination, Inventory, Job, Rule, RuleTable, Step,
    Workflow,
};
use crate::schema::{
    MAX_ARTIFACTS, MAX_CACHES, MAX_ENV_VARS, MAX_ID_BYTES, MAX_JOBS as MAX_PIPELINE_JOBS,
    MAX_SECRETS, MAX_STEPS_PER_JOB, MAX_TIMEOUT_SECS,
};

/// Where the stub scripts a generated pipeline runs live, relative to the repository root.
pub const STUBS: &str = "scripts/ci";

/// The digest-pinned images a generated job may run in, by the platform its class names.
#[derive(Clone, Copy, Debug, Default)]
pub struct Images<'a> {
    pub linux: Option<&'a str>,
    pub linux_arm64: Option<&'a str>,
    pub windows: Option<&'a str>,
}

impl<'a> Images<'a> {
    fn of(&self, os: RunnerOs) -> Option<&'a str> {
        let image = match os {
            RunnerOs::Ubuntu2404 => self.linux,
            RunnerOs::Ubuntu2404Arm => self.linux_arm64,
            RunnerOs::Windows2025 => self.windows,
        }?;
        crate::schema::valid_image(image).then_some(image)
    }
}

/// What one workflow's native plan holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Native {
    /// Where the pipeline belongs in the repository.
    pub path: String,
    /// The generated `.sentinel.yml`, which the pipeline compiler accepts.
    pub text: String,
    /// Every GitHub job, and what the pipeline does with it.
    pub jobs: Vec<JobMapping>,
    /// The secret names the pipeline declares, sorted: what the repository must provision.
    pub secrets: Vec<String>,
    /// The stated changes the translation makes that the pipeline cannot express.
    pub notes: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobMapping {
    pub github: String,
    /// The pipeline jobs the GitHub job became, one per matrix cell; empty when it is kept.
    pub jobs: Vec<String>,
    /// Why the job stays on GitHub's runners.
    pub kept: Vec<&'static str>,
    /// The environment variable names the job and its workflow set. A pipeline declares
    /// env in values, and the inventory holds names only, so the plan lists them here.
    pub env: Vec<String>,
    pub steps: Vec<StepMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepMapping {
    /// 1-based position of the GitHub step in its job.
    pub github: u32,
    pub kind: StepKind,
    /// The environment variable names the GitHub step sets, which the plan does not carry.
    pub env: Vec<String>,
    /// The pipeline step the GitHub step became, named once (every cell job has it).
    pub native: Option<String>,
    /// The stub script to write, for a step of kind `Script`.
    pub script: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// A `run:` step: its commands go in the stub.
    Script,
    /// A setup action: the job's image replaces it.
    Image,
    /// The compiled checkout; the workspace is already the pinned revision.
    Checkout,
    /// A cache the job declares.
    Cache,
    /// An artifact the job declares.
    Artifact,
}

impl StepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Image => "image",
            Self::Checkout => "checkout",
            Self::Cache => "cache",
            Self::Artifact => "artifact",
        }
    }
}

/// What generating one workflow produced.
pub(super) struct Generated {
    pub native: Option<Native>,
    /// Why the whole workflow has no native pipeline.
    pub refused: Option<&'static str>,
}

impl Generated {
    pub(super) const NOT_ASKED: Self = Self {
        native: None,
        refused: None,
    };

    fn refused(reason: &'static str) -> Self {
        Self {
            native: None,
            refused: Some(reason),
        }
    }
}

pub const NOTE_INPUTS: &str =
    "`workflow_dispatch` inputs are not carried: a manual trigger takes none (I01)";
pub const NOTE_ENV: &str = "env is not carried: the inventory holds names only and a pipeline declares values, so every name is listed in the mapping";
pub const NOTE_KEYS: &str =
    "a cache key naming a context with no native equivalent is generated as `fill-me`";
pub const NOTE_STUBS: &str =
    "each `run:` step becomes a stub script under scripts/ci/ that holds its commands";

const TRIGGER: &str = "a native trigger cannot express this event's filters";
const CONDITION: &str =
    "the `if` expression is not part of the inventory (it holds names, never values)";
const MATRIX_ENTRIES: &str =
    "a matrix with include or exclude entries expands differently per cell";
const NO_IMAGE: &str = "no digest-pinned image was given for this job's platform";
const NO_STEPS: &str =
    "no job is left: every job's steps or constructs need a path the native plan cannot take";
const NEEDS: &str = "a job it needs stays on GitHub's runners";
const JOB_LIMIT: &str = "the pipeline would declare more than 64 jobs";
const DECL_LIMIT: &str =
    "the job declares more env names, caches, artifacts or secrets than a pipeline accepts";
const SECRET_NAME: &str = "a secret name the native schema will not accept (it must be upper-case)";
const TIMEOUT: &str = "a timeout longer than a pipeline allows";
const PATH: &str = "a path the native schema will not accept";
const NOT_COMPILED: &str = "the generated pipeline did not pass the pipeline compiler";

/// The native plan for one workflow, or why it has none.
pub(super) fn generate(
    inventory: &Inventory,
    workflow: &Workflow,
    images: &Images<'_>,
) -> Generated {
    let table = RuleTable::V1;
    // A construct the rule table does not translate keeps the whole workflow on GitHub: a
    // pipeline cannot carry half a workflow's triggers.
    for classified in &workflow.constructs {
        if let Rule::Unsupported { reason } = classified.rule {
            return Generated::refused(reason);
        }
    }
    let mut notes: Vec<&'static str> = Vec::new();
    let Some(on) = triggers(workflow, &mut notes) else {
        return Generated::refused(TRIGGER);
    };
    let concurrency = match &workflow.concurrency {
        None => None,
        // A conditional cancel has no native form: the pipeline's `cancel_in_progress` is a constant.
        Some(concurrency) if concurrency.cancel_conditional => {
            return Generated::refused(TRIGGER);
        }
        Some(concurrency) => match translate(&concurrency.group) {
            // A group may only use what the controller knows when it admits the run.
            Some(group)
                if crate::expr::Template::parse(&group)
                    .is_ok_and(|template| template.min_phase() <= crate::expr::Phase::Dispatch) =>
            {
                Some((group, concurrency.cancel_in_progress))
            }
            _ => return Generated::refused(TRIGGER),
        },
    };
    let mut planner = Planner {
        images,
        stem: stem(&workflow.path),
        workflow_env: &workflow.env,
        workflow_defaults: workflow.defaults.as_ref(),
        notes: &mut notes,
        secrets: Vec::new(),
        jobs: Vec::new(),
    };
    for job in &workflow.jobs {
        let planned = planner.plan(job, table);
        planner.jobs.push(planned);
    }
    settle(&mut planner.jobs);
    unique_ids(&mut planner.jobs);
    if planner.jobs.iter().all(|job| job.kept.is_some()) {
        let reason = planner
            .jobs
            .iter()
            .find_map(|job| job.kept)
            .unwrap_or(NO_STEPS);
        return Generated::refused(reason);
    }
    let mut text = String::with_capacity(1024);
    render(
        &mut text,
        &workflow.path,
        &inventory.revision,
        &on,
        concurrency,
        &planner.jobs,
    );
    // A pipeline the compiler refuses is never shown: the validator is the last word on
    // what the native path produced.
    if crate::compile_str(&text).is_err() {
        return Generated::refused(NOT_COMPILED);
    }
    let mut secrets = std::mem::take(&mut planner.secrets);
    secrets.sort();
    secrets.dedup();
    let mut jobs: Vec<JobMapping> = planner
        .jobs
        .into_iter()
        .map(Planned::into_mapping)
        .collect();
    jobs.sort_by(|a, b| a.github.cmp(&b.github));
    notes.push(NOTE_STUBS);
    notes.dedup();
    notes.sort_unstable();
    Generated {
        native: Some(Native {
            path: pipeline_path(inventory, workflow),
            text,
            jobs,
            secrets,
            notes,
        }),
        refused: None,
    }
}

/// `.sentinel.yml` for a repository with one workflow, `.sentinel/<name>.yml` when several
/// are candidates: one pipeline is active at a time (I01).
fn pipeline_path(inventory: &Inventory, workflow: &Workflow) -> String {
    if inventory.workflows.len() == 1 {
        ".sentinel.yml".to_owned()
    } else {
        let mut path = String::from(".sentinel/");
        path.push_str(stem(&workflow.path));
        path.push_str(".yml");
        path
    }
}

/// The workflow file's name without its extension.
fn stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    for suffix in [".yml", ".yaml"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            return stem;
        }
    }
    name
}

/// The `on:` the workflow's triggers become, or why one cannot be expressed.
fn triggers(workflow: &Workflow, notes: &mut Vec<&'static str>) -> Option<On> {
    let mut on = On::default();
    for trigger in &workflow.triggers {
        // A filter that changes when the workflow fires has no native counterpart: dropping
        // it would run the pipeline on changes GitHub never ran it on.
        if !trigger.paths.is_empty()
            || !trigger.paths_ignore.is_empty()
            || !trigger.branches_ignore.is_empty()
            || !trigger.tags_ignore.is_empty()
            || (!trigger.types.is_empty() && trigger.event != "workflow_dispatch")
        {
            return None;
        }
        match trigger.event.as_str() {
            "push" => {
                if trigger.branches.is_empty() && trigger.tags.is_empty() {
                    on.push = Some(Filter::default());
                }
                if !trigger.branches.is_empty() {
                    on.push = Some(Filter {
                        branches: trigger.branches.clone(),
                    });
                }
                if !trigger.tags.is_empty() {
                    on.tag = Some(Filter {
                        branches: trigger.tags.clone(),
                    });
                }
            }
            "pull_request" => {
                on.pull_request = Some(Filter {
                    branches: trigger.branches.clone(),
                })
            }
            "merge_group" => {
                on.merge_group = Some(Filter {
                    branches: trigger.branches.clone(),
                })
            }
            "workflow_dispatch" => {
                if !trigger.inputs.is_empty() {
                    notes.push(NOTE_INPUTS);
                }
                on.manual = true;
            }
            // The rule table refuses these before the plan reaches the triggers.
            _ => return None,
        }
    }
    on.any().then_some(on)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Filter {
    branches: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct On {
    push: Option<Filter>,
    pull_request: Option<Filter>,
    merge_group: Option<Filter>,
    tag: Option<Filter>,
    manual: bool,
}

impl On {
    fn any(&self) -> bool {
        self.push.is_some()
            || self.pull_request.is_some()
            || self.merge_group.is_some()
            || self.tag.is_some()
            || self.manual
    }
}

/// One GitHub job as planned: the pipeline jobs it becomes, or why it is kept.
struct Planned {
    github: String,
    /// The pipeline job ids, one per cell.
    ids: Vec<String>,
    /// Per cell: the class, whether it needs a micro-VM guest, and the image.
    cells: Vec<PlannedCell>,
    kept: Option<&'static str>,
    /// The GitHub jobs it needs; resolved to pipeline ids when the pipeline is written.
    needs: Vec<String>,
    env: Vec<String>,
    caches: Vec<PlannedCache>,
    artifacts: Vec<PlannedArtifact>,
    secrets: Vec<String>,
    steps: Vec<PlannedStep>,
    timeout_secs: Option<u64>,
}

struct PlannedCell {
    class: RunnerClass,
    requires_microvm: bool,
    image: String,
    axes: Vec<(String, String)>,
}

struct PlannedStep {
    /// 1-based position of the GitHub step this one stands for.
    github: u32,
    kind: StepKind,
    env: Vec<String>,
    id: String,
    native: Option<String>,
    script: Option<String>,
    shell: Option<&'static str>,
    workdir: Option<String>,
    timeout_secs: Option<u64>,
}

struct PlannedCache {
    name: String,
    key: String,
    paths: Vec<String>,
}

struct PlannedArtifact {
    name: String,
    paths: Vec<String>,
}

impl Planned {
    fn into_mapping(self) -> JobMapping {
        let env = self.env;
        JobMapping {
            github: self.github,
            jobs: self.ids,
            kept: self.kept.into_iter().collect(),
            env,
            steps: self.steps.iter().map(PlannedStep::mapping).collect(),
        }
    }
}

impl PlannedStep {
    fn mapping(&self) -> StepMapping {
        StepMapping {
            github: self.github,
            kind: self.kind,
            env: self.env.clone(),
            native: self.native.clone(),
            script: self.script.clone(),
        }
    }
}

struct Planner<'a> {
    images: &'a Images<'a>,
    stem: &'a str,
    workflow_env: &'a [String],
    workflow_defaults: Option<&'a super::Defaults>,
    notes: &'a mut Vec<&'static str>,
    secrets: Vec<String>,
    jobs: Vec<Planned>,
}

impl Planner<'_> {
    fn plan(&mut self, job: &Job, table: RuleTable) -> Planned {
        let mut planned = Planned {
            github: job.id.clone(),
            ids: Vec::new(),
            cells: Vec::new(),
            kept: None,
            needs: job.needs.clone(),
            env: Vec::new(),
            caches: Vec::new(),
            artifacts: Vec::new(),
            secrets: Vec::new(),
            steps: Vec::new(),
            timeout_secs: None,
        };
        if let Err(reason) = self.translate(&mut planned, job, table) {
            planned.kept = Some(reason);
            planned.ids.clear();
            planned.cells.clear();
            planned.steps.clear();
            planned.env.clear();
            planned.caches.clear();
            planned.artifacts.clear();
            planned.secrets.clear();
        }
        planned
    }

    fn translate(
        &mut self,
        planned: &mut Planned,
        job: &Job,
        table: RuleTable,
    ) -> Result<(), &'static str> {
        for classified in &job.constructs {
            if let Rule::Unsupported { reason } = classified.rule {
                return Err(reason);
            }
        }
        if job.condition || job.steps.iter().any(|step| step.condition) {
            return Err(CONDITION);
        }
        // A shell or a working directory the native schema cannot state is a change to
        // what the job does, not a change of placement: the job keeps running on GitHub.
        for defaults in [self.workflow_defaults, job.defaults.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some(shell) = defaults.shell.as_deref()
                && !matches!(shell, "sh" | "bash")
            {
                return Err(shell_reason(shell));
            }
            if let Some(dir) = defaults.working_directory.as_deref()
                && !crate::schema::valid_relative_path(dir)
            {
                return Err(PATH);
            }
        }
        for step in &job.steps {
            if step
                .workdir
                .as_deref()
                .is_some_and(|dir| !crate::schema::valid_relative_path(dir))
            {
                return Err(PATH);
            }
        }
        if let Some(matrix) = &job.matrix
            && (!matrix.include.is_empty() || !matrix.exclude.is_empty())
        {
            return Err(MATRIX_ENTRIES);
        }
        // A pipeline has no matrix: one job per cell, over every axis the job declares.
        let Some(cells) = expansion(job) else {
            return Err(JOB_LIMIT);
        };
        if cells.len() > MAX_PIPELINE_JOBS {
            return Err(JOB_LIMIT);
        }
        for axes in &cells {
            let Some(destination) = placement(job, axes) else {
                return Err(MATRIX_ENTRIES);
            };
            let Destination::Class(target) = destination else {
                let Destination::Keep(reason) = destination else {
                    unreachable!("a destination is a class or a reason")
                };
                return Err(reason.note());
            };
            let image = self.images.of(target.class.os).ok_or(NO_IMAGE)?;
            planned.cells.push(PlannedCell {
                class: target.class,
                requires_microvm: target.requires_microvm,
                image: image.to_owned(),
                axes: axes.clone(),
            });
        }
        if job.env.len() + self.workflow_env.len() > MAX_ENV_VARS
            || job.caches.len() > MAX_CACHES
            || job.artifacts.len() > MAX_ARTIFACTS
            || job.secrets.len() > MAX_SECRETS
            || job.steps.len() > MAX_STEPS_PER_JOB
        {
            return Err(DECL_LIMIT);
        }
        if job.secrets.iter().any(|name| !valid_secret_name(name)) {
            return Err(SECRET_NAME);
        }
        planned.timeout_secs = match job.timeout_minutes {
            None | Some(0) => None,
            Some(minutes) if minutes * 60 > MAX_TIMEOUT_SECS => return Err(TIMEOUT),
            Some(minutes) => Some(minutes * 60),
        };
        let mut used_steps: Vec<String> = Vec::new();
        for (index, step) in job.steps.iter().enumerate() {
            let position = index as u32 + 1;
            match step_kind(step, table)? {
                StepKind::Script => planned.steps.push(PlannedStep {
                    github: position,
                    kind: StepKind::Script,
                    env: step.env.clone(),
                    id: unique(&step_id(step, position), &mut used_steps),
                    native: None,
                    script: Some(self.stub(job, position)),
                    shell: self.shell(job, step),
                    workdir: self.workdir(job, step),
                    timeout_secs: step
                        .timeout_minutes
                        .filter(|minutes| *minutes > 0)
                        .map(|minutes| minutes * 60)
                        // A pipeline refuses a step timeout past its job's: the shorter
                        // bound is the one the job already had.
                        .filter(|secs| planned.timeout_secs.is_none_or(|job| *secs <= job)),
                }),
                kind => planned.steps.push(PlannedStep {
                    github: position,
                    kind,
                    env: step.env.clone(),
                    id: String::new(),
                    native: None,
                    script: None,
                    shell: None,
                    workdir: None,
                    timeout_secs: None,
                }),
            }
        }
        if !planned
            .steps
            .iter()
            .any(|step| step.kind == StepKind::Script)
        {
            return Err(NO_STEPS);
        }
        // The pipeline names the step the mapping gives, and the compiler needs each id once.
        for step in planned
            .steps
            .iter_mut()
            .filter(|s| s.kind == StepKind::Script)
        {
            step.native = Some(step.id.clone());
        }
        for (index, cache) in job.caches.iter().enumerate() {
            if cache
                .paths
                .iter()
                .any(|path| !crate::schema::valid_cache_path(path))
            {
                return Err(PATH);
            }
            let key = match cache.key.as_deref().and_then(translate) {
                Some(key) => key,
                None => {
                    self.notes.push(NOTE_KEYS);
                    "fill-me".to_owned()
                }
            };
            planned.caches.push(PlannedCache {
                name: format!("cache-{}", index + 1),
                key,
                paths: cache.paths.clone(),
            });
        }
        let mut used_artifacts: Vec<String> = Vec::new();
        for (index, artifact) in job.artifacts.iter().enumerate() {
            if artifact.direction != ArtifactDirection::Upload {
                return Err("artifact handoff between jobs does not exist yet (I04)");
            }
            if artifact
                .paths
                .iter()
                .any(|path| !crate::schema::valid_relative_path(path))
            {
                return Err(PATH);
            }
            let name = match artifact.name.as_deref() {
                Some(name) if crate::schema::valid_id(name) => name.to_owned(),
                _ => format!("artifacts-{}", index + 1),
            };
            let name = unique(&name, &mut used_artifacts);
            planned.artifacts.push(PlannedArtifact {
                name,
                paths: artifact.paths.clone(),
            });
        }
        planned.env = self.workflow_env.to_vec();
        planned.env.extend(job.env.iter().cloned());
        if !planned.env.is_empty() || job.steps.iter().any(|step| !step.env.is_empty()) {
            self.notes.push(NOTE_ENV);
        }
        for name in &job.secrets {
            if !self.secrets.iter().any(|existing| existing == name) {
                self.secrets.push(name.clone());
            }
        }
        planned.secrets = job.secrets.clone();
        planned.ids = planned
            .cells
            .iter()
            .map(|cell| cell_id(&job.id, &cell.axes))
            .collect();
        Ok(())
    }

    fn shell(&self, job: &Job, step: &Step) -> Option<&'static str> {
        let name = step
            .shell
            .as_deref()
            .or_else(|| self.workflow_defaults.and_then(|d| d.shell.as_deref()))
            .or_else(|| job.defaults.as_ref().and_then(|d| d.shell.as_deref()));
        match name {
            Some("bash") => Some("bash"),
            _ => None,
        }
    }

    fn workdir(&self, job: &Job, step: &Step) -> Option<String> {
        let path = step
            .workdir
            .clone()
            .or_else(|| {
                self.workflow_defaults
                    .and_then(|d| d.working_directory.clone())
            })
            .or_else(|| {
                job.defaults
                    .as_ref()
                    .and_then(|d| d.working_directory.clone())
            })?;
        crate::schema::valid_relative_path(&path).then_some(path)
    }

    fn stub(&self, job: &Job, position: u32) -> String {
        let mut out = String::with_capacity(STUBS.len() + 64);
        let _ = write!(
            out,
            "{STUBS}/{}/{}/{position:02}.sh",
            self.stem,
            normalize(&job.id)
        );
        out
    }
}

/// A job that stays is a job its dependents cannot run behind: the pipeline has no such job.
fn settle(jobs: &mut [Planned]) {
    loop {
        let mut changed = false;
        for index in 0..jobs.len() {
            if jobs[index].kept.is_some() {
                continue;
            }
            let blocked = jobs[index].needs.iter().any(|need| {
                jobs.iter()
                    .any(|other| other.github == *need && other.kept.is_some())
            });
            if blocked {
                jobs[index].kept = Some(NEEDS);
                jobs[index].ids.clear();
                jobs[index].cells.clear();
                jobs[index].steps.clear();
                changed = true;
            }
        }
        if !changed {
            return;
        }
    }
}

/// What one GitHub step becomes, or why the job cannot be served natively.
fn step_kind(step: &Step, table: RuleTable) -> Result<StepKind, &'static str> {
    let Some(action) = &step.action else {
        return Ok(StepKind::Script);
    };
    let uses = uses_text(action);
    let rule = table.classify(&Construct::Action { uses: uses.clone() });
    match rule {
        Rule::Unsupported { reason } => Err(reason),
        // `actions/checkout` is the table's one translatable action: the compiled checkout
        // already ran, so the step itself disappears.
        Rule::Translatable => Ok(StepKind::Checkout),
        Rule::WithChange { .. } => {
            let repository = uses.split_once('@').map_or(uses.as_str(), |(repo, _)| repo);
            let repository = repository.to_ascii_lowercase();
            Ok(match repository.as_str() {
                "actions/upload-artifact" => StepKind::Artifact,
                "actions/cache"
                | "actions/cache/restore"
                | "actions/cache/save"
                | "swatinem/rust-cache" => StepKind::Cache,
                // The setup actions and toolchain actions: the image carries the toolchain.
                _ => StepKind::Image,
            })
        }
    }
}

fn uses_text(action: &ActionRef) -> String {
    match action {
        ActionRef::Repository {
            repository,
            version,
            ..
        } => {
            let mut out = String::with_capacity(repository.len() + version.len() + 1);
            out.push_str(repository);
            out.push('@');
            out.push_str(version);
            out
        }
        ActionRef::Docker { image } => {
            let mut out = String::with_capacity(image.len() + 9);
            out.push_str("docker://");
            out.push_str(image);
            out
        }
        ActionRef::Local { path } => path.clone(),
    }
}

/// The rule table's own wording for a shell no native step runs.
fn shell_reason(shell: &str) -> &'static str {
    match RuleTable::V1.classify(&Construct::Shell {
        shell: shell.to_owned(),
    }) {
        Rule::Unsupported { reason } => reason,
        _ => "steps run under sh or bash; no other shell is available",
    }
}

/// Two job ids, or two axis values, can normalize to one id: the pipeline's ids must be
/// unique, so the later one is numbered.
fn unique_ids(jobs: &mut [Planned]) {
    let mut used: Vec<String> = Vec::new();
    for job in jobs.iter_mut() {
        for id in &mut job.ids {
            *id = unique(id, &mut used);
        }
    }
}

/// `base` if it is free, else the same id numbered: a pipeline needs one id per thing.
fn unique(base: &str, used: &mut Vec<String>) -> String {
    if !used.iter().any(|existing| existing == base) {
        used.push(base.to_owned());
        return base.to_owned();
    }
    let mut serial = 2;
    loop {
        let tail = format!("-{serial}");
        let mut candidate = String::with_capacity(base.len() + tail.len());
        candidate.push_str(base);
        candidate.truncate(MAX_ID_BYTES - tail.len());
        candidate.push_str(&tail);
        if !used.contains(&candidate) {
            used.push(candidate.clone());
            return candidate;
        }
        serial += 1;
    }
}

/// Every cell of the job's own matrix: a pipeline has no matrix, so each becomes a job.
fn expansion(job: &Job) -> Option<Vec<Vec<(String, String)>>> {
    let Some(matrix) = &job.matrix else {
        return Some(vec![Vec::new()]);
    };
    let mut cells: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for axis in &matrix.axes {
        let mut next: Vec<Vec<(String, String)>> =
            Vec::with_capacity(cells.len() * axis.values.len());
        for cell in &cells {
            for value in &axis.values {
                let mut widened = cell.clone();
                widened.push((axis.name.clone(), value.clone()));
                next.push(widened);
            }
        }
        cells = next;
    }
    Some(cells)
}

/// Where one cell of the matrix lands: the placement cell whose axes it holds.
fn placement(job: &Job, axes: &[(String, String)]) -> Option<Destination> {
    job.cells
        .iter()
        .find(|cell| {
            cell.axes
                .iter()
                .all(|(axis, value)| axes.iter().any(|(a, v)| a == axis && v == value))
        })
        .map(|cell| cell.destination)
}

fn step_id(step: &Step, position: u32) -> String {
    match step.id.as_deref() {
        Some(id) if crate::schema::valid_id(id) => id.to_owned(),
        _ => format!("step-{position}"),
    }
}

fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_ID_BYTES
        && !bytes[0].is_ascii_digit()
        && name != "CI"
        && !name.starts_with("SENTINEL_")
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

/// The pipeline job id for one matrix cell: the job's own id and its axis values.
fn cell_id(base: &str, axes: &[(String, String)]) -> String {
    let mut out = normalize(base);
    for (_, value) in axes {
        out.push('-');
        out.push_str(&normalize(value));
    }
    out.truncate(MAX_ID_BYTES);
    out
}

/// A job id or axis value in the pipeline's own vocabulary.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        let byte = byte.to_ascii_lowercase();
        let kept =
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_';
        out.push(if kept { byte as char } else { '-' });
    }
    match out.bytes().next() {
        Some(byte) if byte.is_ascii_lowercase() || byte.is_ascii_digit() => {}
        _ => out.insert(0, 'j'),
    }
    out
}

/// GitHub expressions in a native template, or `None` when one has no native equivalent.
fn translate(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let end = after.find("}}")?;
        out.push_str(&rest[..start]);
        out.push_str("${{ ");
        out.push_str(&expression(after[..end].trim())?);
        out.push_str(" }}");
        rest = &after[end + 2..];
    }
    if rest.contains("}}") {
        return None;
    }
    out.push_str(rest);
    crate::expr::Template::parse(&out).ok().map(|_| out)
}

/// One GitHub expression in the native vocabulary; an identifier or context without a
/// native meaning is refused rather than guessed at.
fn expression(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if !byte.is_ascii() {
            return None;
        }
        if byte == b'\'' || byte == b'"' {
            let start = at;
            at += 1;
            loop {
                if at >= bytes.len() {
                    return None;
                }
                if bytes[at] == byte {
                    if bytes.get(at + 1) == Some(&byte) {
                        at += 2;
                        continue;
                    }
                    at += 1;
                    break;
                }
                at += 1;
            }
            out.push_str(&text[start..at]);
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = at;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            let mut path = text[start..at].to_owned();
            while bytes.get(at) == Some(&b'.') {
                let segment = at + 1;
                let mut end = segment;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                if end == segment {
                    break;
                }
                path.push('.');
                path.push_str(&text[segment..end]);
                at = end;
            }
            if bytes.get(at) == Some(&b'(') {
                out.push_str(match path.as_str() {
                    "hashFiles" => "hash_files",
                    "success" | "failure" | "always" | "cancelled" | "contains" | "starts_with"
                    | "ends_with" => path.as_str(),
                    _ => return None,
                });
                continue;
            }
            out.push_str(match path.as_str() {
                "github.ref" => "event.ref",
                "github.sha" => "event.sha",
                "github.event_name" => "event.name",
                "github.base_ref" => "event.base_ref",
                "github.repository" => "repo.name",
                "github.run_id" => "run.id",
                "true" | "false" | "null" => path.as_str(),
                _ => return None,
            });
            continue;
        }
        out.push(byte as char);
        at += 1;
    }
    Some(out)
}

/// Writes the pipeline: fixed key order, two-space indentation, no key whose value is
/// empty, so the same inventory always produces the same bytes.
fn render(
    out: &mut String,
    path: &str,
    revision: &str,
    on: &On,
    concurrency: Option<(String, bool)>,
    jobs: &[Planned],
) {
    let _ = writeln!(
        out,
        "# Sentinel native pipeline, generated from {path} at {revision}."
    );
    let _ = writeln!(
        out,
        "# Every `run:` step is a stub under {STUBS}/: its commands are not part of the"
    );
    let _ = writeln!(
        out,
        "# workflow analysis, which records names and never values."
    );
    let _ = writeln!(out, "schema: 1");
    let _ = writeln!(out, "on:");
    for (key, filter) in [
        ("push", &on.push),
        ("pull_request", &on.pull_request),
        ("merge_group", &on.merge_group),
        ("tag", &on.tag),
    ] {
        let Some(filter) = filter else { continue };
        let _ = writeln!(out, "  {key}:");
        if !filter.branches.is_empty() {
            let _ = writeln!(out, "    branches: {}", flow(&filter.branches));
        }
    }
    if on.manual {
        let _ = writeln!(out, "  manual: true");
    }
    if let Some((group, cancel)) = &concurrency {
        let _ = writeln!(out, "concurrency:");
        let _ = writeln!(out, "  group: {}", scalar(group));
        if *cancel {
            let _ = writeln!(out, "  cancel_in_progress: true");
        }
    }
    let _ = writeln!(out, "jobs:");
    for job in jobs.iter().filter(|job| job.kept.is_none()) {
        for (index, id) in job.ids.iter().enumerate() {
            render_job(out, jobs, job, id, &job.cells[index]);
        }
    }
}

fn render_job(out: &mut String, jobs: &[Planned], job: &Planned, id: &str, cell: &PlannedCell) {
    let _ = writeln!(out, "  {id}:");
    let _ = writeln!(out, "    image: {}", scalar(&cell.image));
    let needs: Vec<String> = job
        .needs
        .iter()
        .filter_map(|need| jobs.iter().find(|other| other.github == *need))
        .flat_map(|other| other.ids.iter().cloned())
        .collect();
    if !needs.is_empty() {
        let _ = writeln!(out, "    needs: {}", flow(&needs));
    }
    let _ = writeln!(out, "    runs_on:");
    let _ = writeln!(out, "      labels: [{}]", cell.class);
    match cell.class.os {
        RunnerOs::Ubuntu2404 => {}
        RunnerOs::Ubuntu2404Arm => {
            let _ = writeln!(out, "      arch: arm64");
        }
        RunnerOs::Windows2025 => {
            let _ = writeln!(out, "      os: windows");
        }
    }
    if cell.requires_microvm {
        let _ = writeln!(out, "      isolation: microvm");
    }
    if let Some(secs) = job.timeout_secs {
        let _ = writeln!(out, "    timeout: {}m", secs / 60);
    }
    if !job.caches.is_empty() {
        let _ = writeln!(out, "    cache:");
        for cache in &job.caches {
            let _ = writeln!(out, "      - name: {}", scalar(&cache.name));
            let _ = writeln!(out, "        key: {}", scalar(&cache.key));
            let _ = writeln!(out, "        paths: {}", flow(&cache.paths));
        }
    }
    if !job.artifacts.is_empty() {
        let _ = writeln!(out, "    artifacts:");
        for artifact in &job.artifacts {
            let _ = writeln!(out, "      - name: {}", scalar(&artifact.name));
            let _ = writeln!(out, "        paths: {}", flow(&artifact.paths));
        }
    }
    if !job.secrets.is_empty() {
        let _ = writeln!(out, "    secrets: {}", flow(&job.secrets));
    }
    let _ = writeln!(out, "    steps:");
    for step in job
        .steps
        .iter()
        .filter(|step| step.kind == StepKind::Script)
    {
        let mut run = String::with_capacity(step.script.as_deref().map_or(0, str::len) + 3);
        run.push_str("sh ");
        run.push_str(step.script.as_deref().unwrap_or_default());
        let _ = writeln!(out, "      - id: {}", scalar(&step.id));
        let _ = writeln!(out, "        run: {}", scalar(&run));
        if let Some(shell) = step.shell {
            let _ = writeln!(out, "        shell: {shell}");
        }
        if let Some(workdir) = &step.workdir {
            let _ = writeln!(out, "        workdir: {}", scalar(workdir));
        }
        if let Some(secs) = step.timeout_secs {
            let _ = writeln!(out, "        timeout: {}m", secs / 60);
        }
    }
}

/// `[a, b]` with each value quoted only where YAML needs it.
fn flow(values: &[String]) -> String {
    let mut out = String::with_capacity(values.iter().map(|v| v.len() + 2).sum::<usize>() + 2);
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&scalar(value));
    }
    out.push(']');
    out
}

/// A value written plainly where YAML reads it back as the same string, quoted otherwise.
fn scalar(text: &str) -> String {
    if plain(text) {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            out.push('\'');
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

fn plain(text: &str) -> bool {
    let first = match text.as_bytes().first() {
        Some(first) => *first,
        None => return false,
    };
    if b"-?:,[]{}#&*!|>'\"%@` ".contains(&first) {
        return false;
    }
    !text
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b == b'$' || b == b'\'' || b == b'"' || b == b'{')
        && !text.contains(": ")
        && !text.contains(" #")
        && !text.ends_with(' ')
        && text.parse::<i64>().is_err()
        && text.parse::<f64>().is_err()
        && !matches!(
            text,
            "true" | "false" | "null" | "~" | "yes" | "no" | "on" | "off" | "True" | "False"
        )
}
