//! Bounded, deterministic inventory of a repository's GitHub Actions workflows, read at a
//! pinned commit for guided migration.
//!
//! The analyzer reads `.github/workflows/*.yml` through the pipeline loader's limits, so a
//! hostile or oversized workflow is refused before it is materialised, then records every
//! trigger, job, matrix, `runs-on:`, action with its version, container, service, secret and
//! variable reference, permission, concurrency, cache and artifact it finds. Two versioned
//! tables decide what happens next: [`LabelTable`] maps a `runs-on:` label set to a Sentinel
//! runner class or keeps the job on GitHub's runners with its reason, and [`RuleTable`]
//! classifies each construct for the optional native path. No model is involved and nothing
//! is guessed: a key outside the documented workflow vocabulary is refused, never skipped.

use std::fmt;

use crate::yaml::{self, Node, YamlError};

mod change;
mod labels;
mod native;
mod rules;
mod suggest;

pub use change::{
    COPY_PREFIX, KeptJob, LabelChange, Options, Phase, Plan, PlanError, SCHEMA as PLAN_SCHEMA,
    ShadowJob, WorkflowPlan, plan,
};
pub use labels::{
    ClassTarget, Declared, Destination, DockerHosts, KeepReason, LABEL_TABLE_VERSION, LabelTable,
};
pub use native::{
    Images, JobMapping, NOTE_ENV, NOTE_INPUTS, NOTE_KEYS, NOTE_STUBS, Native, STUBS, StepKind,
    StepMapping,
};
pub use rules::{Construct, RULE_TABLE_VERSION, Rule, RuleTable};
pub use suggest::{
    MAX_STEP_INDEX, Refusal, Request as SuggestRequest, SCHEMA as SUGGESTION_SCHEMA, Suggestion,
    suggest,
};

/// The only directory GitHub reads workflows from; anything else is not an input.
pub const WORKFLOW_DIRECTORY: &str = ".github/workflows";
/// Workflows one analysis may read. The three pilots have six between them.
pub const MAX_WORKFLOW_FILES: usize = 64;
/// Jobs one workflow may declare.
pub const MAX_JOBS: usize = 256;
/// Steps one job may declare.
pub const MAX_STEPS: usize = 128;
/// Triggers one workflow may declare.
pub const MAX_TRIGGERS: usize = 32;
/// Axes one matrix may declare.
pub const MAX_MATRIX_AXES: usize = 16;
/// Values one matrix axis may declare, and cells one `runs-on:` expansion may produce.
pub const MAX_MATRIX_VALUES: usize = 256;
pub const MAX_MATRIX_CELLS: usize = 256;
/// Permission scopes one job or workflow may state.
pub const MAX_PERMISSIONS: usize = 16;
/// Service containers one job may declare.
pub const MAX_SERVICES: usize = 16;
/// Secret and variable names one job may reference, and paths one cache or artifact may name.
pub const MAX_REFERENCES: usize = 64;
pub const MAX_PATHS: usize = 32;
/// Bytes one recorded name, label, path, key or event name may take.
pub const MAX_TEXT_BYTES: usize = 1024;

/// One workflow file as read at the pinned commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowFile<'a> {
    pub path: &'a str,
    pub text: &'a str,
}

/// What one analysis produced, for one commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// The commit the workflows were read at, lower-cased.
    pub revision: String,
    pub label_table: u16,
    pub rule_table: u16,
    /// Sorted by path, so the same files produce the same inventory in any order.
    pub workflows: Vec<Workflow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workflow {
    pub path: String,
    pub name: Option<String>,
    pub triggers: Vec<Trigger>,
    pub permissions: Vec<(String, String)>,
    pub concurrency: Option<Concurrency>,
    /// Environment variable names only: a value may hold a secret reference or a token.
    pub env: Vec<String>,
    pub defaults: Option<Defaults>,
    pub secrets: Vec<String>,
    pub variables: Vec<String>,
    /// The workflow-level constructs and their classification for the native path.
    pub constructs: Vec<Classified>,
    pub jobs: Vec<Job>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    pub event: String,
    pub branches: Vec<String>,
    pub branches_ignore: Vec<String>,
    pub tags: Vec<String>,
    pub tags_ignore: Vec<String>,
    pub paths: Vec<String>,
    pub paths_ignore: Vec<String>,
    pub types: Vec<String>,
    /// `schedule` entries: the cron expressions, never run here.
    pub crons: Vec<String>,
    /// `workflow_dispatch` input names.
    pub inputs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Concurrency {
    pub group: String,
    pub cancel_in_progress: bool,
    /// `cancel-in-progress` is a `${{ }}` expression: whether a run cancels is decided per event.
    pub cancel_conditional: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Defaults {
    pub shell: Option<String>,
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    pub construct: Construct,
    pub rule: Rule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub name: Option<String>,
    pub needs: Vec<String>,
    /// Whether the job states an `if:`; its text is not part of the inventory.
    pub condition: bool,
    pub timeout_minutes: Option<u64>,
    pub environment: Option<String>,
    /// Job output names only.
    pub outputs: Vec<String>,
    /// A reusable-workflow call: `jobs.<id>.uses`.
    pub reusable: Option<String>,
    pub permissions: Vec<(String, String)>,
    pub concurrency: Option<Concurrency>,
    pub env: Vec<String>,
    pub defaults: Option<Defaults>,
    pub continue_on_error: bool,
    /// `runs-on:` as written, before the label table resolves it.
    pub demand: Declared,
    pub matrix: Option<Matrix>,
    pub container: Option<Container>,
    pub services: Vec<Service>,
    pub steps: Vec<Step>,
    pub caches: Vec<CacheUse>,
    pub artifacts: Vec<ArtifactUse>,
    pub secrets: Vec<String>,
    pub variables: Vec<String>,
    /// What `runs-on:` becomes, one entry per matrix cell the labels produce.
    pub cells: Vec<Cell>,
    /// The job's own constructs and their classification for the native path.
    pub constructs: Vec<Classified>,
}

/// One `runs-on:` variant: the matrix axes the labels name, resolved, and where they go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    /// The axis values substituted into the labels, empty when the job has no matrix or its
    /// labels name no axis.
    pub axes: Vec<(String, String)>,
    /// The labels after substitution, as they are written.
    pub labels: Vec<String>,
    pub destination: Destination,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matrix {
    pub axes: Vec<Axis>,
    /// `include` entries: the values one entry adds or overrides.
    pub include: Vec<Vec<(String, String)>>,
    /// `exclude` entries: the values one entry removes from the product.
    pub exclude: Vec<Vec<(String, String)>>,
    pub fail_fast: bool,
    pub max_parallel: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Axis {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub image: String,
    /// Whether the container states `credentials:`, never the credentials themselves.
    pub credentials: bool,
    pub env: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub container: Container,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub id: Option<String>,
    pub name: Option<String>,
    pub action: Option<ActionRef>,
    pub shell: Option<String>,
    pub workdir: Option<String>,
    pub continue_on_error: bool,
    pub condition: bool,
    pub timeout_minutes: Option<u64>,
    pub env: Vec<String>,
}

/// A `uses:` reference with the version it was written at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionRef {
    Repository {
        repository: String,
        version: String,
        /// The version is a full commit id, so the action cannot move under the workflow.
        pinned: bool,
    },
    Docker {
        image: String,
    },
    Local {
        path: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheSource {
    /// `actions/cache` and the cache tools that wrap it.
    ActionsCache,
    /// A `setup-*` action caching its own tool.
    SetupCache,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheUse {
    pub source: CacheSource,
    pub key: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactDirection {
    Upload,
    Download,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactUse {
    pub direction: ArtifactDirection,
    pub name: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowError {
    /// `<path>` or `<path>:<key path>`, never a value the workflow holds.
    pub path: String,
    pub kind: WorkflowErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkflowErrorKind {
    Yaml(YamlError),
    UnknownKey(String),
    Missing,
    WrongType {
        expected: &'static str,
        found: &'static str,
    },
    Invalid(&'static str),
    TooMany {
        limit: usize,
    },
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.path)?;
        match &self.kind {
            WorkflowErrorKind::Yaml(e) => write!(f, "yaml: {e}"),
            WorkflowErrorKind::UnknownKey(k) => write!(f, "unknown key `{k}`"),
            WorkflowErrorKind::Missing => f.write_str("required"),
            WorkflowErrorKind::WrongType { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            WorkflowErrorKind::Invalid(msg) => f.write_str(msg),
            WorkflowErrorKind::TooMany { limit } => write!(f, "more than {limit} entries"),
        }
    }
}
impl std::error::Error for WorkflowError {}

type Result<T> = std::result::Result<T, WorkflowError>;

fn err(path: &str, kind: WorkflowErrorKind) -> WorkflowError {
    WorkflowError {
        path: path.to_owned(),
        kind,
    }
}

fn invalid<T>(path: &str, msg: &'static str) -> Result<T> {
    Err(err(path, WorkflowErrorKind::Invalid(msg)))
}

fn wrong<T>(path: &str, expected: &'static str, node: &Node) -> Result<T> {
    Err(err(
        path,
        WorkflowErrorKind::WrongType {
            expected,
            found: node.kind(),
        },
    ))
}

fn mapping<'a>(path: &str, node: &'a Node) -> Result<&'a [(String, Node)]> {
    match node {
        Node::Map(entries) => Ok(entries),
        other => wrong(path, "mapping", other),
    }
}

fn keys(path: &str, entries: &[(String, Node)], allowed: &[&str]) -> Result<()> {
    for (key, _) in entries {
        if !allowed.contains(&key.as_str()) {
            return Err(err(path, WorkflowErrorKind::UnknownKey(key.clone())));
        }
    }
    Ok(())
}

fn text<'a>(path: &str, node: &'a Node, max: usize) -> Result<&'a str> {
    match node {
        Node::Str(s) if s.is_empty() => invalid(path, "must not be empty"),
        Node::Str(s) if s.len() > max => invalid(path, "longer than its limit"),
        Node::Str(s) => Ok(s),
        other => wrong(path, "string", other),
    }
}

fn scalar_text(path: &str, node: &Node, max: usize) -> Result<String> {
    match node {
        Node::Str(s) if s.len() > max => invalid(path, "longer than its limit"),
        Node::Str(s) => Ok(s.clone()),
        Node::Int(i) => Ok(i.to_string()),
        Node::Bool(b) => Ok(b.to_string()),
        Node::Null => invalid(path, "must not be empty"),
        other => wrong(path, "scalar", other),
    }
}

fn boolean(path: &str, node: &Node) -> Result<bool> {
    match node {
        Node::Bool(b) => Ok(*b),
        other => wrong(path, "boolean", other),
    }
}

fn integer(path: &str, node: &Node) -> Result<u64> {
    match node {
        Node::Int(i) if *i >= 0 => Ok(*i as u64),
        Node::Int(_) => invalid(path, "must not be negative"),
        other => wrong(path, "integer", other),
    }
}

fn sequence<'a>(path: &str, node: &'a Node, max: usize) -> Result<&'a [Node]> {
    match node {
        Node::Seq(items) if items.len() > max => {
            Err(err(path, WorkflowErrorKind::TooMany { limit: max }))
        }
        Node::Seq(items) => Ok(items),
        other => wrong(path, "sequence", other),
    }
}

fn text_list(path: &str, node: &Node, max: usize, item_max: usize) -> Result<Vec<String>> {
    let items = sequence(path, node, max)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        out.push(text(&format!("{path}[{i}]"), item, item_max)?.to_owned());
    }
    Ok(out)
}

fn is_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Reads every workflow of one commit. `docker` is the deployment's own fact: whether its
/// classes run in microVM guests, which is what a job needing Docker requires.
pub fn analyze(
    revision: &str,
    files: &[WorkflowFile<'_>],
    docker: DockerHosts,
) -> Result<Inventory> {
    let valid = (revision.len() == 40 || revision.len() == 64)
        && revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return invalid(
            "revision",
            "a pinned commit is 40 or 64 lower-case hex characters",
        );
    }
    if files.len() > MAX_WORKFLOW_FILES {
        return Err(err(
            WORKFLOW_DIRECTORY,
            WorkflowErrorKind::TooMany {
                limit: MAX_WORKFLOW_FILES,
            },
        ));
    }
    let label_table = LabelTable::V1;
    let mut workflows = Vec::with_capacity(files.len());
    for file in files {
        let rest = file
            .path
            .strip_prefix(WORKFLOW_DIRECTORY)
            .and_then(|rest| rest.strip_prefix('/'));
        let shaped = rest.is_some_and(|rest| {
            !rest.is_empty()
                && !rest.contains('/')
                && (rest.ends_with(".yml") || rest.ends_with(".yaml"))
        });
        if !shaped {
            return invalid(
                file.path,
                "a workflow is a `.yml` or `.yaml` file directly under .github/workflows",
            );
        }
        let root = yaml::load(file.text).map_err(|e| err(file.path, WorkflowErrorKind::Yaml(e)))?;
        workflows.push(decode_workflow(file.path, &root, docker)?);
    }
    workflows.sort_by(|a, b| a.path.cmp(&b.path));
    for pair in workflows.windows(2) {
        if pair[0].path == pair[1].path {
            return invalid(&pair[0].path, "the same workflow was given twice");
        }
    }
    Ok(Inventory {
        revision: revision.to_ascii_lowercase(),
        label_table: label_table.version(),
        rule_table: RuleTable::V1.version(),
        workflows,
    })
}

/// The constructs one workflow or job uses, each classified once, in the order met.
struct Classifieds {
    list: Vec<Classified>,
    rules: RuleTable,
}

impl Classifieds {
    fn new() -> Self {
        Self {
            list: Vec::new(),
            rules: RuleTable::V1,
        }
    }

    fn add(&mut self, construct: Construct) {
        if self.list.iter().any(|c| c.construct == construct) {
            return;
        }
        self.list.push(Classified {
            rule: self.rules.classify(&construct),
            construct,
        });
    }

    fn finish(self) -> Vec<Classified> {
        self.list
    }
}

fn decode_workflow(path: &str, root: &Node, docker: DockerHosts) -> Result<Workflow> {
    let entries = mapping(path, root)?;
    keys(
        path,
        entries,
        &[
            "name",
            "on",
            "permissions",
            "concurrency",
            "env",
            "defaults",
            "jobs",
        ],
    )?;
    let mut constructs = Classifieds::new();
    let name = find(entries, "name")
        .map(|n| text(&child(path, "name"), n, MAX_TEXT_BYTES))
        .transpose()?
        .map(str::to_owned);
    let mut references = References::default();
    let triggers = match find(entries, "on") {
        Some(node) => decode_triggers(&child(path, "on"), node, &mut constructs)?,
        None => return Err(err(path, WorkflowErrorKind::Missing)),
    };
    let mut permissions = Vec::new();
    if let Some(node) = find(entries, "permissions") {
        permissions = decode_permissions(&child(path, "permissions"), node)?;
        constructs.add(Construct::Permissions);
    }
    let mut concurrency = None;
    if let Some(node) = find(entries, "concurrency") {
        concurrency = Some(decode_concurrency(&child(path, "concurrency"), node)?);
        constructs.add(Construct::Concurrency);
    }
    let mut env = Vec::new();
    if let Some(node) = find(entries, "env") {
        env = decode_env(&child(path, "env"), node, &mut references)?;
        constructs.add(Construct::Env);
    }
    let mut defaults = None;
    if let Some(node) = find(entries, "defaults") {
        defaults = Some(decode_defaults(&child(path, "defaults"), node)?);
        constructs.add(Construct::Defaults);
    }
    let jobs_node = find(entries, "jobs");
    let Some(jobs_node) = jobs_node else {
        return Err(err(path, WorkflowErrorKind::Missing));
    };
    let jobs_path = child(path, "jobs");
    let job_entries = mapping(&jobs_path, jobs_node)?;
    if job_entries.is_empty() {
        return invalid(&jobs_path, "at least one job is required");
    }
    if job_entries.len() > MAX_JOBS {
        return Err(err(
            &jobs_path,
            WorkflowErrorKind::TooMany { limit: MAX_JOBS },
        ));
    }
    let mut jobs = Vec::with_capacity(job_entries.len());
    for (id, node) in job_entries {
        jobs.push(decode_job(&child(&jobs_path, id), id, node, docker)?);
    }
    Ok(Workflow {
        path: path.to_owned(),
        name,
        triggers,
        permissions,
        concurrency,
        env,
        defaults,
        secrets: references.secrets,
        variables: references.variables,
        constructs: constructs.finish(),
        jobs,
    })
}

fn find<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a Node> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn child(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn decode_triggers(path: &str, node: &Node, constructs: &mut Classifieds) -> Result<Vec<Trigger>> {
    match node {
        Node::Str(event) => {
            constructs.add(Construct::Trigger {
                event: event.clone(),
            });
            Ok(vec![Trigger::new(event)])
        }
        Node::Seq(items) => {
            let events = sequence(path, node, MAX_TRIGGERS)?;
            if events.is_empty() {
                return invalid(path, "a workflow needs at least one trigger");
            }
            let mut out = Vec::with_capacity(events.len());
            for (i, item) in items.iter().enumerate() {
                let event = text(&format!("{path}[{i}]"), item, MAX_TEXT_BYTES)?;
                constructs.add(Construct::Trigger {
                    event: event.to_owned(),
                });
                out.push(Trigger::new(event));
            }
            Ok(out)
        }
        Node::Map(entries) => {
            if entries.is_empty() {
                return invalid(path, "a workflow needs at least one trigger");
            }
            if entries.len() > MAX_TRIGGERS {
                return Err(err(
                    path,
                    WorkflowErrorKind::TooMany {
                        limit: MAX_TRIGGERS,
                    },
                ));
            }
            let mut out = Vec::with_capacity(entries.len());
            for (event, config) in entries {
                constructs.add(Construct::Trigger {
                    event: event.clone(),
                });
                let event_path = child(path, event);
                let mut trigger = Trigger::new(event);
                match config {
                    Node::Null => {}
                    Node::Map(_) => {
                        decode_trigger_config(&event_path, event, config, &mut trigger)?
                    }
                    // `schedule` is the one event whose configuration is a sequence of crons.
                    Node::Seq(_) if event == "schedule" => {
                        decode_trigger_config(&event_path, event, config, &mut trigger)?;
                    }
                    other => return wrong(&event_path, "mapping", other),
                }
                out.push(trigger);
            }
            Ok(out)
        }
        other => wrong(path, "string, sequence or mapping", other),
    }
}

impl Trigger {
    fn new(event: &str) -> Self {
        Self {
            event: event.to_owned(),
            branches: Vec::new(),
            branches_ignore: Vec::new(),
            tags: Vec::new(),
            tags_ignore: Vec::new(),
            paths: Vec::new(),
            paths_ignore: Vec::new(),
            types: Vec::new(),
            crons: Vec::new(),
            inputs: Vec::new(),
        }
    }
}

fn decode_trigger_config(
    path: &str,
    event: &str,
    node: &Node,
    trigger: &mut Trigger,
) -> Result<()> {
    if event == "schedule" {
        let items = sequence(path, node, MAX_TRIGGERS)?;
        for (i, item) in items.iter().enumerate() {
            let item_path = format!("{path}[{i}]");
            let entries = mapping(&item_path, item)?;
            keys(&item_path, entries, &["cron"])?;
            let Some(cron) = find(entries, "cron") else {
                return Err(err(&item_path, WorkflowErrorKind::Missing));
            };
            trigger
                .crons
                .push(text(&child(&item_path, "cron"), cron, MAX_TEXT_BYTES)?.to_owned());
        }
        return Ok(());
    }
    let entries = mapping(path, node)?;
    keys(
        path,
        entries,
        &[
            "branches",
            "branches-ignore",
            "tags",
            "tags-ignore",
            "paths",
            "paths-ignore",
            "types",
            "inputs",
        ],
    )?;
    for (key, value) in entries {
        let key_path = child(path, key);
        match key.as_str() {
            "branches" => {
                trigger.branches = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?
            }
            "branches-ignore" => {
                trigger.branches_ignore = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?;
            }
            "tags" => trigger.tags = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?,
            "tags-ignore" => {
                trigger.tags_ignore = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?;
            }
            "paths" => trigger.paths = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?,
            "paths-ignore" => {
                trigger.paths_ignore = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?;
            }
            "types" => trigger.types = text_list(&key_path, value, MAX_PATHS, MAX_TEXT_BYTES)?,
            "inputs" => trigger.inputs = decode_inputs(&key_path, value)?,
            _ => unreachable!("keys() accepted a key this decoder does not handle"),
        }
    }
    Ok(())
}

fn decode_inputs(path: &str, node: &Node) -> Result<Vec<String>> {
    let entries = mapping(path, node)?;
    if entries.len() > MAX_REFERENCES {
        return Err(err(
            path,
            WorkflowErrorKind::TooMany {
                limit: MAX_REFERENCES,
            },
        ));
    }
    let mut names = Vec::with_capacity(entries.len());
    for (name, definition) in entries {
        if !is_name(name) || name.len() > 64 {
            return invalid(
                &child(path, name),
                "an input name is a letter or `_`, then letters, digits, `_` or `-`",
            );
        }
        if !matches!(definition, Node::Map(_)) {
            return wrong(&child(path, name), "mapping", definition);
        }
        names.push(name.clone());
    }
    Ok(names)
}

/// Scopes and accesses, as stated: `read-all`, `write-all`, or a mapping of scope to access.
fn decode_permissions(path: &str, node: &Node) -> Result<Vec<(String, String)>> {
    match node {
        Node::Str(access) if access == "read-all" || access == "write-all" => {
            let access = if access == "read-all" {
                "read"
            } else {
                "write"
            };
            Ok(vec![("all".to_owned(), access.to_owned())])
        }
        Node::Map(entries) => {
            if entries.len() > MAX_PERMISSIONS {
                return Err(err(
                    path,
                    WorkflowErrorKind::TooMany {
                        limit: MAX_PERMISSIONS,
                    },
                ));
            }
            let mut out = Vec::with_capacity(entries.len());
            for (scope, access) in entries {
                if !scope.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
                    return invalid(
                        &child(path, scope),
                        "a permission scope is lower-case and hyphenated",
                    );
                }
                let access = text(&child(path, scope), access, 16)?;
                if !matches!(access, "read" | "write" | "none") {
                    return invalid(&child(path, scope), "access is `read`, `write` or `none`");
                }
                out.push((scope.clone(), access.to_owned()));
            }
            Ok(out)
        }
        other => wrong(path, "mapping or `read-all`/`write-all`", other),
    }
}

/// Whether a scalar is one whole `${{ }}` expression, the only string form GitHub evaluates.
fn is_expression(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("${{") && value.ends_with("}}") && value.len() >= 5
}

fn decode_concurrency(path: &str, node: &Node) -> Result<Concurrency> {
    match node {
        Node::Str(group) => Ok(Concurrency {
            group: group.to_owned(),
            cancel_in_progress: false,
            cancel_conditional: false,
        }),
        Node::Map(_) => {
            let entries = mapping(path, node)?;
            keys(path, entries, &["group", "cancel-in-progress"])?;
            let Some(group) = find(entries, "group") else {
                return Err(err(path, WorkflowErrorKind::Missing));
            };
            let (cancel_in_progress, cancel_conditional) = match find(entries, "cancel-in-progress")
            {
                Some(Node::Str(s)) if s.len() <= MAX_TEXT_BYTES && is_expression(s) => {
                    (false, true)
                }
                Some(node) => (boolean(&child(path, "cancel-in-progress"), node)?, false),
                None => (false, false),
            };
            Ok(Concurrency {
                group: text(&child(path, "group"), group, MAX_TEXT_BYTES)?.to_owned(),
                cancel_in_progress,
                cancel_conditional,
            })
        }
        other => wrong(path, "string or mapping", other),
    }
}

fn decode_env(path: &str, node: &Node, references: &mut References) -> Result<Vec<String>> {
    let entries = mapping(path, node)?;
    if entries.len() > MAX_REFERENCES {
        return Err(err(
            path,
            WorkflowErrorKind::TooMany {
                limit: MAX_REFERENCES,
            },
        ));
    }
    let mut names = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        let name_path = child(path, name);
        if !is_name(name) || name.len() > 128 {
            return invalid(
                &name_path,
                "an environment variable name is a letter or `_`, then letters, digits or `_`",
            );
        }
        let value = scalar_text(&name_path, value, MAX_TEXT_BYTES)?;
        references.scan(&value, &name_path)?;
        names.push(name.clone());
    }
    Ok(names)
}

fn decode_defaults(path: &str, node: &Node) -> Result<Defaults> {
    let entries = mapping(path, node)?;
    keys(path, entries, &["run"])?;
    let mut defaults = Defaults {
        shell: None,
        working_directory: None,
    };
    if let Some(run) = find(entries, "run") {
        let run_path = child(path, "run");
        let run_entries = mapping(&run_path, run)?;
        keys(&run_path, run_entries, &["shell", "working-directory"])?;
        if let Some(shell) = find(run_entries, "shell") {
            defaults.shell = Some(text(&child(&run_path, "shell"), shell, 32)?.to_owned());
        }
        if let Some(dir) = find(run_entries, "working-directory") {
            defaults.working_directory =
                Some(text(&child(&run_path, "working-directory"), dir, MAX_TEXT_BYTES)?.to_owned());
        }
    }
    Ok(defaults)
}

/// Secret and variable names one scope references, deduplicated in the order met.
#[derive(Default)]
struct References {
    secrets: Vec<String>,
    variables: Vec<String>,
}

impl References {
    /// Every `${{ secrets.<name> }}`, `${{ secrets['<name>'] }}` and the `vars` equivalents
    /// in one string. Only the name is kept; the surrounding text never is.
    fn scan(&mut self, text: &str, path: &str) -> Result<()> {
        let mut rest = text;
        while let Some(start) = rest.find("${{") {
            let after = &rest[start + 3..];
            let Some(end) = after.find("}}") else {
                break;
            };
            let expression = after[..end].trim();
            if let Some((name, secrets)) = reference_name(expression) {
                let names = if secrets {
                    &mut self.secrets
                } else {
                    &mut self.variables
                };
                if !names.iter().any(|n| n == name) {
                    if names.len() >= MAX_REFERENCES {
                        return Err(err(
                            path,
                            WorkflowErrorKind::TooMany {
                                limit: MAX_REFERENCES,
                            },
                        ));
                    }
                    names.push(name.to_owned());
                }
            }
            rest = &after[end + 2..];
        }
        Ok(())
    }
}

/// `secrets.NAME`, `secrets['NAME']`, `vars.NAME` and `vars['NAME']`.
fn reference_name(expression: &str) -> Option<(&str, bool)> {
    for (prefix, secrets) in [("secrets", true), ("vars", false)] {
        let Some(rest) = expression
            .get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .map(|_| &expression[prefix.len()..])
        else {
            continue;
        };
        if let Some(dotted) = rest.strip_prefix('.') {
            let name = dotted.trim_end();
            if is_name(name) && name.len() <= 128 {
                return Some((name, secrets));
            }
        }
        if let Some(bracketed) = rest.trim_start().strip_prefix('[') {
            let bracketed = bracketed.trim_start();
            let quote = bracketed
                .chars()
                .next()
                .filter(|q| *q == '\'' || *q == '"')?;
            let inner = bracketed[1..].trim_end();
            let name = inner.strip_suffix(']')?.trim_end().strip_suffix(quote)?;
            let printable = !name.is_empty()
                && name.len() <= 128
                && name.bytes().all(|b| (0x20..=0x7e).contains(&b))
                && !name.contains(quote);
            if printable {
                return Some((name, secrets));
            }
        }
    }
    None
}

fn decode_job(path: &str, id: &str, node: &Node, docker: DockerHosts) -> Result<Job> {
    if !is_name(id) || id.len() > 128 {
        return invalid(
            path,
            "a job id is a letter or `_`, then letters, digits, `_` or `-`",
        );
    }
    let entries = mapping(path, node)?;
    keys(
        path,
        entries,
        &[
            "name",
            "needs",
            "if",
            "runs-on",
            "permissions",
            "environment",
            "concurrency",
            "outputs",
            "env",
            "defaults",
            "steps",
            "timeout-minutes",
            "strategy",
            "continue-on-error",
            "container",
            "services",
            "uses",
            "with",
            "secrets",
        ],
    )?;
    let mut constructs = Classifieds::new();
    let mut references = References::default();

    let name = find(entries, "name")
        .map(|n| text(&child(path, "name"), n, MAX_TEXT_BYTES))
        .transpose()?
        .map(str::to_owned);
    let needs = match find(entries, "needs") {
        None => Vec::new(),
        Some(node @ Node::Str(_)) => {
            let need = text(&child(path, "needs"), node, 128)?;
            constructs.add(Construct::Needs);
            vec![need.to_owned()]
        }
        Some(node) => {
            constructs.add(Construct::Needs);
            text_list(&child(path, "needs"), node, MAX_JOBS, 128)?
        }
    };
    let mut condition = false;
    if let Some(node) = find(entries, "if") {
        match node {
            Node::Str(s) if s.len() > MAX_TEXT_BYTES => {
                return invalid(&child(path, "if"), "longer than its limit");
            }
            Node::Bool(_) | Node::Str(_) => {}
            other => return wrong(&child(path, "if"), "string or boolean", other),
        }
        condition = true;
        constructs.add(Construct::Condition);
    }
    let timeout_minutes = match find(entries, "timeout-minutes") {
        Some(node) => {
            constructs.add(Construct::Timeout);
            Some(integer(&child(path, "timeout-minutes"), node)?)
        }
        None => None,
    };
    let mut permissions = Vec::new();
    if let Some(node) = find(entries, "permissions") {
        permissions = decode_permissions(&child(path, "permissions"), node)?;
        constructs.add(Construct::Permissions);
    }
    let mut concurrency = None;
    if let Some(node) = find(entries, "concurrency") {
        concurrency = Some(decode_concurrency(&child(path, "concurrency"), node)?);
        constructs.add(Construct::Concurrency);
    }
    let mut env = Vec::new();
    if let Some(node) = find(entries, "env") {
        env = decode_env(&child(path, "env"), node, &mut references)?;
        constructs.add(Construct::Env);
    }
    let mut defaults = None;
    if let Some(node) = find(entries, "defaults") {
        defaults = Some(decode_defaults(&child(path, "defaults"), node)?);
        constructs.add(Construct::Defaults);
    }
    let mut environment = None;
    if let Some(node) = find(entries, "environment") {
        environment = Some(decode_environment(&child(path, "environment"), node)?);
        constructs.add(Construct::Environment);
    }
    let mut outputs = Vec::new();
    if let Some(node) = find(entries, "outputs") {
        outputs = decode_outputs(&child(path, "outputs"), node, &mut references)?;
        constructs.add(Construct::Outputs);
    }
    let mut reusable = None;
    if let Some(node) = find(entries, "uses") {
        reusable = Some(text(&child(path, "uses"), node, MAX_TEXT_BYTES)?.to_owned());
        constructs.add(Construct::ReusableWorkflow);
    }
    for key in ["with", "secrets"] {
        if let Some(node) = find(entries, key) {
            let key_path = child(path, key);
            match node {
                // `secrets: inherit` passes the caller's secrets on; nothing is named.
                Node::Str(s) if s == "inherit" && key == "secrets" => {}
                Node::Map(_) => {
                    for (name, value) in mapping(&key_path, node)? {
                        if !is_name(name) || name.len() > 128 {
                            return invalid(
                                &child(&key_path, name),
                                "a name is a letter or `_`, then letters, digits, `_` or `-`",
                            );
                        }
                        let value = scalar_text(&child(&key_path, name), value, MAX_TEXT_BYTES)?;
                        references.scan(&value, &key_path)?;
                    }
                }
                other => return wrong(&key_path, "mapping", other),
            }
        }
    }
    let mut matrix = None;
    if let Some(node) = find(entries, "strategy") {
        let strategy_path = child(path, "strategy");
        let strategy = mapping(&strategy_path, node)?;
        keys(
            &strategy_path,
            strategy,
            &["matrix", "fail-fast", "max-parallel"],
        )?;
        let fail_fast = match find(strategy, "fail-fast") {
            Some(node) => boolean(&child(&strategy_path, "fail-fast"), node)?,
            None => true,
        };
        let max_parallel = match find(strategy, "max-parallel") {
            Some(node) => Some(integer(&child(&strategy_path, "max-parallel"), node)?),
            None => None,
        };
        matrix = find(strategy, "matrix")
            .map(|node| {
                let mut decoded = decode_matrix(&child(&strategy_path, "matrix"), node)?;
                decoded.fail_fast = fail_fast;
                decoded.max_parallel = max_parallel;
                Ok(decoded)
            })
            .transpose()?;
        constructs.add(Construct::Matrix);
    }
    let mut container = None;
    if let Some(node) = find(entries, "container") {
        container = Some(decode_container(
            &child(path, "container"),
            node,
            &mut references,
        )?);
        constructs.add(Construct::Container);
    }
    let mut services = Vec::new();
    if let Some(node) = find(entries, "services") {
        let services_path = child(path, "services");
        let service_entries = mapping(&services_path, node)?;
        if service_entries.len() > MAX_SERVICES {
            return Err(err(
                &services_path,
                WorkflowErrorKind::TooMany {
                    limit: MAX_SERVICES,
                },
            ));
        }
        for (service, node) in service_entries {
            let service_path = child(&services_path, service);
            if !is_name(service) || service.len() > 128 {
                return invalid(
                    &service_path,
                    "a service name is a letter or `_`, then letters, digits or `_`",
                );
            }
            services.push(Service {
                name: service.clone(),
                container: decode_container(&service_path, node, &mut references)?,
            });
        }
        constructs.add(Construct::Services);
    }
    let continue_on_error = match find(entries, "continue-on-error") {
        Some(node) => {
            constructs.add(Construct::ContinueOnError);
            boolean(&child(path, "continue-on-error"), node)?
        }
        None => false,
    };

    let demand = match find(entries, "runs-on") {
        Some(node) => decode_demand(&child(path, "runs-on"), node)?,
        None if reusable.is_some() => Declared::default(),
        None => return Err(err(&child(path, "runs-on"), WorkflowErrorKind::Missing)),
    };

    let mut caches = Vec::new();
    let mut artifacts = Vec::new();
    let steps = match find(entries, "steps") {
        Some(node) => decode_steps(
            &child(path, "steps"),
            node,
            &mut constructs,
            &mut references,
            &mut caches,
            &mut artifacts,
        )?,
        None if reusable.is_some() => Vec::new(),
        None => return Err(err(&child(path, "steps"), WorkflowErrorKind::Missing)),
    };

    let needs_docker = container.is_some()
        || !services.is_empty()
        || steps
            .iter()
            .any(|step| matches!(step.action, Some(ActionRef::Docker { .. })));
    let cells = resolve_cells(path, &demand, matrix.as_ref(), needs_docker, docker)?;

    Ok(Job {
        id: id.to_owned(),
        name,
        needs,
        condition,
        timeout_minutes,
        environment,
        outputs,
        reusable,
        permissions,
        concurrency,
        env,
        defaults,
        continue_on_error,
        demand,
        matrix,
        container,
        services,
        steps,
        caches,
        artifacts,
        secrets: references.secrets,
        variables: references.variables,
        cells,
        constructs: constructs.finish(),
    })
}

fn decode_demand(path: &str, node: &Node) -> Result<Declared> {
    let mut declared = Declared::default();
    match node {
        Node::Str(label) => declared.labels.push(label.to_owned()),
        Node::Seq(_) => declared.labels = text_list(path, node, MAX_PATHS, MAX_TEXT_BYTES)?,
        Node::Map(_) => {
            let entries = mapping(path, node)?;
            keys(path, entries, &["group", "labels"])?;
            if let Some(group) = find(entries, "group") {
                declared.group =
                    Some(text(&child(path, "group"), group, MAX_TEXT_BYTES)?.to_owned());
            }
            match find(entries, "labels") {
                Some(Node::Str(label)) => declared.labels.push(label.to_owned()),
                Some(node) => {
                    declared.labels =
                        text_list(&child(path, "labels"), node, MAX_PATHS, MAX_TEXT_BYTES)?;
                }
                None => {}
            }
        }
        other => return wrong(path, "string, sequence or mapping", other),
    }
    if declared.labels.is_empty() && declared.group.is_none() {
        return invalid(path, "at least one label or a group is required");
    }
    Ok(declared)
}

fn decode_container(path: &str, node: &Node, references: &mut References) -> Result<Container> {
    match node {
        Node::Str(image) => Ok(Container {
            image: image.to_owned(),
            credentials: false,
            env: Vec::new(),
        }),
        Node::Map(_) => {
            let entries = mapping(path, node)?;
            keys(
                path,
                entries,
                &["image", "credentials", "env", "ports", "volumes", "options"],
            )?;
            let Some(image) = find(entries, "image") else {
                return Err(err(path, WorkflowErrorKind::Missing));
            };
            let mut env = Vec::new();
            if let Some(node) = find(entries, "env") {
                env = decode_env(&child(path, "env"), node, references)?;
            }
            let credentials = match find(entries, "credentials") {
                Some(node) => {
                    let credentials_path = child(path, "credentials");
                    for (key, value) in mapping(&credentials_path, node)? {
                        let value =
                            scalar_text(&child(&credentials_path, key), value, MAX_TEXT_BYTES)?;
                        references.scan(&value, &credentials_path)?;
                    }
                    true
                }
                None => false,
            };
            Ok(Container {
                image: text(&child(path, "image"), image, MAX_TEXT_BYTES)?.to_owned(),
                credentials,
                env,
            })
        }
        other => wrong(path, "string or mapping", other),
    }
}

fn decode_environment(path: &str, node: &Node) -> Result<String> {
    match node {
        Node::Str(name) => Ok(name.to_owned()),
        Node::Map(_) => {
            let entries = mapping(path, node)?;
            keys(path, entries, &["name", "url"])?;
            let Some(name) = find(entries, "name") else {
                return Err(err(path, WorkflowErrorKind::Missing));
            };
            Ok(text(&child(path, "name"), name, MAX_TEXT_BYTES)?.to_owned())
        }
        other => wrong(path, "string or mapping", other),
    }
}

fn decode_outputs(path: &str, node: &Node, references: &mut References) -> Result<Vec<String>> {
    let entries = mapping(path, node)?;
    if entries.len() > MAX_REFERENCES {
        return Err(err(
            path,
            WorkflowErrorKind::TooMany {
                limit: MAX_REFERENCES,
            },
        ));
    }
    let mut names = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        let name_path = child(path, name);
        if !is_name(name) || name.len() > 128 {
            return invalid(
                &name_path,
                "an output name is a letter or `_`, then letters, digits, `_` or `-`",
            );
        }
        let value = scalar_text(&name_path, value, MAX_TEXT_BYTES)?;
        references.scan(&value, &name_path)?;
        names.push(name.clone());
    }
    Ok(names)
}

fn decode_matrix(path: &str, node: &Node) -> Result<Matrix> {
    let entries = mapping(path, node)?;
    if entries.len() > MAX_MATRIX_AXES + 2 {
        return Err(err(
            path,
            WorkflowErrorKind::TooMany {
                limit: MAX_MATRIX_AXES,
            },
        ));
    }
    let mut matrix = Matrix {
        fail_fast: true,
        ..Matrix::default()
    };
    for (name, value) in entries {
        let name_path = child(path, name);
        match name.as_str() {
            "include" => matrix.include = decode_matrix_entries(&name_path, value)?,
            "exclude" => matrix.exclude = decode_matrix_entries(&name_path, value)?,
            _ => {
                if matrix.axes.len() >= MAX_MATRIX_AXES {
                    return Err(err(
                        path,
                        WorkflowErrorKind::TooMany {
                            limit: MAX_MATRIX_AXES,
                        },
                    ));
                }
                if !is_name(name) || name.len() > 64 {
                    return invalid(
                        &name_path,
                        "a matrix axis name is a letter or `_`, then letters, digits or `_`",
                    );
                }
                let items = sequence(&name_path, value, MAX_MATRIX_VALUES)?;
                if items.is_empty() {
                    return invalid(&name_path, "a matrix axis needs at least one value");
                }
                let mut values = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    values.push(scalar_text(
                        &format!("{name_path}[{i}]"),
                        item,
                        MAX_TEXT_BYTES,
                    )?);
                }
                matrix.axes.push(Axis {
                    name: name.clone(),
                    values,
                });
            }
        }
    }
    if matrix.axes.is_empty() && matrix.include.is_empty() {
        return invalid(path, "a matrix needs an axis or an include entry");
    }
    Ok(matrix)
}

fn decode_matrix_entries(path: &str, node: &Node) -> Result<Vec<Vec<(String, String)>>> {
    let items = sequence(path, node, MAX_MATRIX_VALUES)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let item_path = format!("{path}[{i}]");
        let entries = mapping(&item_path, item)?;
        let mut values = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            if !is_name(name) || name.len() > 64 {
                return invalid(
                    &child(&item_path, name),
                    "a matrix key is a letter or `_`, then letters, digits or `_`",
                );
            }
            values.push((
                name.clone(),
                scalar_text(&child(&item_path, name), value, MAX_TEXT_BYTES)?,
            ));
        }
        out.push(values);
    }
    Ok(out)
}

fn decode_steps(
    path: &str,
    node: &Node,
    constructs: &mut Classifieds,
    references: &mut References,
    caches: &mut Vec<CacheUse>,
    artifacts: &mut Vec<ArtifactUse>,
) -> Result<Vec<Step>> {
    let items = sequence(path, node, MAX_STEPS)?;
    if items.is_empty() {
        return invalid(path, "a job needs at least one step");
    }
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let step_path = format!("{path}[{i}]");
        let entries = mapping(&step_path, item)?;
        keys(
            &step_path,
            entries,
            &[
                "id",
                "name",
                "uses",
                "run",
                "with",
                "env",
                "if",
                "shell",
                "working-directory",
                "continue-on-error",
                "timeout-minutes",
            ],
        )?;
        let id = find(entries, "id")
            .map(|n| text(&child(&step_path, "id"), n, 128))
            .transpose()?
            .map(str::to_owned);
        if let Some(id) = &id
            && !is_name(id)
        {
            return invalid(
                &child(&step_path, "id"),
                "a step id is a letter or `_`, then letters, digits, `_` or `-`",
            );
        }
        let name = find(entries, "name")
            .map(|n| text(&child(&step_path, "name"), n, MAX_TEXT_BYTES))
            .transpose()?
            .map(str::to_owned);
        let mut condition = false;
        if let Some(node) = find(entries, "if") {
            match node {
                Node::Str(s) if s.len() > MAX_TEXT_BYTES => {
                    return invalid(&child(&step_path, "if"), "longer than its limit");
                }
                Node::Bool(_) | Node::Str(_) => {}
                other => return wrong(&child(&step_path, "if"), "string or boolean", other),
            }
            condition = true;
            constructs.add(Construct::Condition);
        }
        let timeout_minutes = match find(entries, "timeout-minutes") {
            Some(node) => {
                constructs.add(Construct::Timeout);
                Some(integer(&child(&step_path, "timeout-minutes"), node)?)
            }
            None => None,
        };
        let continue_on_error = match find(entries, "continue-on-error") {
            Some(node) => {
                constructs.add(Construct::ContinueOnError);
                boolean(&child(&step_path, "continue-on-error"), node)?
            }
            None => false,
        };
        let mut env = Vec::new();
        if let Some(node) = find(entries, "env") {
            env = decode_env(&child(&step_path, "env"), node, references)?;
            constructs.add(Construct::Env);
        }
        let shell = match find(entries, "shell") {
            Some(node) => {
                let shell = text(&child(&step_path, "shell"), node, 32)?.to_owned();
                constructs.add(Construct::Shell {
                    shell: shell.clone(),
                });
                Some(shell)
            }
            None => None,
        };
        let action = find(entries, "uses");
        if let Some(node) = find(entries, "run") {
            if action.is_some() {
                return invalid(&step_path, "a step states `run` or `uses`, never both");
            }
            let script = text(
                &child(&step_path, "run"),
                node,
                crate::yaml::MAX_SCALAR_BYTES,
            )?;
            references.scan(script, &step_path)?;
            constructs.add(Construct::RunStep);
        }
        let workdir = match find(entries, "working-directory") {
            Some(node) => {
                constructs.add(Construct::Workdir);
                Some(
                    text(
                        &child(&step_path, "working-directory"),
                        node,
                        MAX_TEXT_BYTES,
                    )?
                    .to_owned(),
                )
            }
            None => None,
        };
        let mut step = Step {
            id,
            name,
            action: None,
            shell,
            workdir,
            continue_on_error,
            condition,
            timeout_minutes,
            env,
        };
        if let Some(node) = action {
            let uses = text(&child(&step_path, "uses"), node, MAX_TEXT_BYTES)?.to_owned();
            let reference = action_ref(&child(&step_path, "uses"), &uses)?;
            let with = match find(entries, "with") {
                Some(node) => mapping(&child(&step_path, "with"), node)?,
                None => &[],
            };
            for (key, value) in with {
                let value_path = child(&child(&step_path, "with"), key);
                let value = scalar_text(&value_path, value, MAX_TEXT_BYTES)?;
                references.scan(&value, &value_path)?;
            }
            collect_uses(&reference, &step_path, with, caches, artifacts)?;
            constructs.add(Construct::Action { uses });
            step.action = Some(reference);
        }
        out.push(step);
    }
    Ok(out)
}

fn action_ref(path: &str, uses: &str) -> Result<ActionRef> {
    if let Some(image) = uses.strip_prefix("docker://") {
        if image.is_empty() {
            return invalid(path, "a docker step names an image");
        }
        return Ok(ActionRef::Docker {
            image: image.to_owned(),
        });
    }
    if uses.starts_with("./") {
        return Ok(ActionRef::Local {
            path: uses.to_owned(),
        });
    }
    let Some((repository, version)) = uses.split_once('@') else {
        return invalid(
            path,
            "an action is `owner/repository[/path]@version`, `docker://image` or a relative path",
        );
    };
    let shaped = !version.is_empty()
        && !version.contains('/')
        && repository.split('/').count() >= 2
        && repository
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if !shaped {
        return invalid(
            path,
            "an action is `owner/repository[/path]@version`, `docker://image` or a relative path",
        );
    }
    Ok(ActionRef::Repository {
        repository: repository.to_owned(),
        version: version.to_owned(),
        pinned: is_full_sha(version),
    })
}

/// The cache and artifact inventory one step contributes.
fn collect_uses(
    reference: &ActionRef,
    step_path: &str,
    with: &[(String, Node)],
    caches: &mut Vec<CacheUse>,
    artifacts: &mut Vec<ArtifactUse>,
) -> Result<()> {
    let ActionRef::Repository { repository, .. } = reference else {
        return Ok(());
    };
    let repository = repository.to_ascii_lowercase();
    let value = |key: &str| with.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    match repository.as_str() {
        "actions/cache"
        | "actions/cache/restore"
        | "actions/cache/save"
        | "swatinem/rust-cache" => {
            let paths = match value("path") {
                Some(node) => path_list(&child(step_path, "with.path"), node)?,
                None => Vec::new(),
            };
            let key = match value("key") {
                Some(node) => Some(uses_text(&child(step_path, "with.key"), node)?),
                None => None,
            };
            caches.push(CacheUse {
                source: CacheSource::ActionsCache,
                key,
                paths,
            });
        }
        "actions/upload-artifact" | "actions/download-artifact" => {
            let direction = if repository == "actions/upload-artifact" {
                ArtifactDirection::Upload
            } else {
                ArtifactDirection::Download
            };
            let paths = match value("path").filter(|_| direction == ArtifactDirection::Upload) {
                Some(node) => path_list(&child(step_path, "with.path"), node)?,
                None => Vec::new(),
            };
            let name = match value("name") {
                Some(node) => Some(uses_text(&child(step_path, "with.name"), node)?),
                None => None,
            };
            artifacts.push(ArtifactUse {
                direction,
                name,
                paths,
            });
        }
        setup if setup.starts_with("actions/setup-") && value("cache").is_some() => {
            caches.push(CacheUse {
                source: CacheSource::SetupCache,
                key: None,
                paths: Vec::new(),
            });
        }
        _ => {}
    }
    Ok(())
}

/// A `path:` input is one path or several, one per line.
fn path_list(path: &str, node: &Node) -> Result<Vec<String>> {
    let text = uses_text(path, node)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() >= MAX_PATHS {
            return Err(err(path, WorkflowErrorKind::TooMany { limit: MAX_PATHS }));
        }
        out.push(line.to_owned());
    }
    Ok(out)
}

fn uses_text(path: &str, node: &Node) -> Result<String> {
    scalar_text(path, node, MAX_TEXT_BYTES)
}

fn resolve_cells(
    path: &str,
    demand: &Declared,
    matrix: Option<&Matrix>,
    needs_docker: bool,
    docker: DockerHosts,
) -> Result<Vec<Cell>> {
    let table = LabelTable::V1;
    let axes: Vec<&Axis> = match matrix {
        Some(matrix) => matrix
            .axes
            .iter()
            .filter(|axis| {
                demand
                    .labels
                    .iter()
                    .any(|label| names_axis(label, &axis.name))
            })
            .collect(),
        None => Vec::new(),
    };
    if axes.is_empty() {
        return Ok(vec![Cell {
            axes: Vec::new(),
            labels: demand.labels.clone(),
            destination: table.classify(demand, needs_docker, docker),
        }]);
    }
    let mut combos: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for axis in axes {
        let mut next: Vec<Vec<(String, String)>> =
            Vec::with_capacity(combos.len() * axis.values.len());
        for combo in &combos {
            for value in &axis.values {
                if next.len() >= MAX_MATRIX_CELLS {
                    return Err(err(
                        path,
                        WorkflowErrorKind::TooMany {
                            limit: MAX_MATRIX_CELLS,
                        },
                    ));
                }
                let mut cell = combo.clone();
                cell.push((axis.name.clone(), value.clone()));
                next.push(cell);
            }
        }
        combos = next;
    }
    let mut out = Vec::with_capacity(combos.len());
    for combo in combos {
        let mut labels = Vec::with_capacity(demand.labels.len());
        for label in &demand.labels {
            labels.push(substitute(label, &combo).unwrap_or_else(|| label.clone()));
        }
        let declared = Declared {
            labels,
            group: demand.group.clone(),
        };
        let destination = table.classify(&declared, needs_docker, docker);
        out.push(Cell {
            axes: combo,
            labels: declared.labels,
            destination,
        });
    }
    Ok(out)
}

/// Whether one label substitutes `matrix.<axis>`. A label that names no axis is the same
/// for every cell, so the axis does not widen the placement.
fn names_axis(label: &str, axis: &str) -> bool {
    let mut rest = label;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else {
            return false;
        };
        if let Some(name) = after[..end].trim().strip_prefix("matrix.")
            && name.trim() == axis
        {
            return true;
        }
        rest = &after[end + 2..];
    }
    false
}

/// One label with its matrix references replaced. `None` when an expression is not a
/// matrix reference this cell holds, which keeps the job on GitHub's runners.
fn substitute(label: &str, values: &[(String, String)]) -> Option<String> {
    let mut out = String::with_capacity(label.len() + 16);
    let mut rest = label;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let end = after.find("}}")?;
        let axis = after[..end].trim().strip_prefix("matrix.")?.trim();
        let (_, value) = values.iter().find(|(name, _)| name == axis)?;
        out.push_str(&rest[..start]);
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Some(out)
}
