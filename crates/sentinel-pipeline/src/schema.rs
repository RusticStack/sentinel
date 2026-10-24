use std::fmt;

use serde::{Deserialize, Serialize};

use sentinel_protocol::cache::Class;

use crate::{
    expr::{Expr, Phase, Template},
    policy::{MAX_REF_PATTERN_BYTES, MAX_REF_PATTERNS, RefFilter, Triggers, valid_pattern},
    yaml::Node,
};

pub const SCHEMA_VERSION: i64 = 1;

pub const MAX_JOBS: usize = 64;
pub const MAX_STEPS_PER_JOB: usize = 64;
pub const MAX_NEEDS: usize = 32;
pub const MAX_ENV_VARS: usize = 64;
pub const MAX_CACHES: usize = 8;
pub const MAX_ARTIFACTS: usize = 8;
pub const MAX_PATHS: usize = 32;
pub const MAX_LABELS: usize = 8;
pub const MAX_SECRETS: usize = 16;
pub const MAX_RUN_BYTES: usize = 4096;
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_JOB_TIMEOUT_SECS: u64 = 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pipeline {
    pub on: Triggers,
    pub concurrency: Option<Concurrency>,
    pub jobs: Vec<(String, Job)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Concurrency {
    pub group: Template,
    pub cancel_in_progress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub image: String,
    pub needs: Vec<String>,
    pub condition: Option<Expr>,
    pub runs_on: RunsOn,
    pub resources: Resources,
    pub timeout_secs: u64,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub steps: Vec<Step>,
    pub cache: Vec<Cache>,
    pub artifacts: Vec<Artifact>,
    /// Values never appear in YAML; the worker injects a secret only if the repository was granted it.
    pub secrets: Vec<String>,
    /// Never exposed to a step: it authorizes only this job's image pull.
    pub registry_auth: Option<String>,
}

impl Job {
    pub fn requires_secret_delivery(&self) -> bool {
        self.registry_auth.is_some()
            || self
                .steps
                .iter()
                .any(|step| !step.secrets.is_empty() || !step.secret_files.is_empty())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunsOn {
    pub arch: Option<Arch>,
    pub labels: Vec<String>,
    /// `None` keeps the pre-microVM meaning: Linux, on whatever executor the worker runs.
    pub os: Option<Os>,
    pub isolation: Option<Isolation>,
}

impl RunsOn {
    /// Whether the job states an OS or isolation; such a job needs a worker that advertises them.
    pub fn states_runtime(&self) -> bool {
        self.os.is_some() || self.isolation.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Os {
    Linux = 0,
    Windows = 1,
}

impl Os {
    pub const fn as_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Isolation {
    Container = 0,
    Microvm = 1,
    Native = 2,
}

impl Isolation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Isolation::Container => "container",
            Isolation::Microvm => "microvm",
            Isolation::Native => "native",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Arch {
    Amd64 = 0,
    Arm64 = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub run: String,
    pub condition: Option<Expr>,
    pub shell: Shell,
    pub env: Vec<(String, String)>,
    pub secrets: Vec<String>,
    pub secret_files: Vec<SecretFile>,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFile {
    pub name: String,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Shell {
    #[default]
    Sh = 0,
    Bash = 1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cache {
    pub name: String,
    pub class: Class,
    pub key: Template,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub paths: Vec<String>,
    pub when: ArtifactWhen,
    pub retain_secs: u64,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ArtifactWhen {
    #[default]
    Success = 0,
    Failure = 1,
    Always = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourcePolicy {
    pub default: Resources,
    pub min: Resources,
    pub max: Resources,
}

impl ResourcePolicy {
    pub const DEFAULT: ResourcePolicy = ResourcePolicy {
        default: Resources {
            cpu_millis: 2_000,
            memory_bytes: 4 << 30,
            disk_bytes: 10 << 30,
        },
        min: Resources {
            cpu_millis: 250,
            memory_bytes: 128 << 20,
            disk_bytes: 1 << 30,
        },
        max: Resources {
            cpu_millis: 64_000,
            memory_bytes: 256 << 30,
            disk_bytes: 1000 << 30,
        },
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError {
    pub path: String,
    pub kind: SchemaErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaErrorKind {
    UnsupportedSchema {
        found: Option<i64>,
    },
    UnknownKey(String),
    Missing,
    WrongType {
        expected: &'static str,
        found: &'static str,
    },
    Invalid(String),
    TooMany {
        limit: usize,
    },
    Empty,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.path)?;
        match &self.kind {
            SchemaErrorKind::UnsupportedSchema { found: Some(v) } => {
                write!(
                    f,
                    "schema {v} is not supported; this build accepts {SCHEMA_VERSION}"
                )
            }
            SchemaErrorKind::UnsupportedSchema { found: None } => {
                write!(f, "`schema: {SCHEMA_VERSION}` is required")
            }
            SchemaErrorKind::UnknownKey(k) => write!(f, "unknown key `{k}`"),
            SchemaErrorKind::Missing => f.write_str("required"),
            SchemaErrorKind::WrongType { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            SchemaErrorKind::Invalid(msg) => f.write_str(msg),
            SchemaErrorKind::TooMany { limit } => write!(f, "more than {limit} entries"),
            SchemaErrorKind::Empty => f.write_str("must not be empty"),
        }
    }
}
impl std::error::Error for SchemaError {}

type Result<T> = std::result::Result<T, SchemaError>;

fn err(path: &str, kind: SchemaErrorKind) -> SchemaError {
    SchemaError {
        path: path.to_owned(),
        kind,
    }
}

/// `seen` is a 64-bit set, so `Map::new` caps mappings at 64 entries.
struct Map<'a> {
    path: &'a str,
    entries: &'a [(String, Node)],
    seen: u64,
}

impl<'a> Map<'a> {
    fn new(path: &'a str, node: &'a Node) -> Result<Self> {
        match node {
            Node::Map(entries) => {
                if entries.len() > 64 {
                    return Err(err(path, SchemaErrorKind::TooMany { limit: 64 }));
                }
                Ok(Self {
                    path,
                    entries,
                    seen: 0,
                })
            }
            other => Err(err(
                path,
                SchemaErrorKind::WrongType {
                    expected: "mapping",
                    found: other.kind(),
                },
            )),
        }
    }

    fn take(&mut self, key: &str) -> Option<&'a Node> {
        let (i, entry) = self
            .entries
            .iter()
            .enumerate()
            .find(|(_, (k, _))| k == key)?;
        self.seen |= 1 << i;
        Some(&entry.1)
    }

    fn child(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{}", self.path, key)
        }
    }

    fn finish(self) -> Result<()> {
        for (i, (k, _)) in self.entries.iter().enumerate() {
            if self.seen & (1 << i) == 0 {
                return Err(err(self.path, SchemaErrorKind::UnknownKey(k.clone())));
            }
        }
        Ok(())
    }
}

fn expect_str<'a>(path: &str, node: &'a Node, max: usize) -> Result<&'a str> {
    match node {
        Node::Str(s) if s.is_empty() => Err(err(path, SchemaErrorKind::Empty)),
        Node::Str(s) if s.len() > max => Err(err(
            path,
            SchemaErrorKind::Invalid(format!("longer than {max} bytes")),
        )),
        Node::Str(s) => Ok(s),
        other => Err(err(
            path,
            SchemaErrorKind::WrongType {
                expected: "string",
                found: other.kind(),
            },
        )),
    }
}

fn expect_bool(path: &str, node: &Node) -> Result<bool> {
    match node {
        Node::Bool(b) => Ok(*b),
        other => Err(err(
            path,
            SchemaErrorKind::WrongType {
                expected: "boolean",
                found: other.kind(),
            },
        )),
    }
}

fn expect_seq<'a>(path: &str, node: &'a Node, max: usize) -> Result<&'a [Node]> {
    match node {
        Node::Seq(items) if items.is_empty() => Err(err(path, SchemaErrorKind::Empty)),
        Node::Seq(items) if items.len() > max => {
            Err(err(path, SchemaErrorKind::TooMany { limit: max }))
        }
        Node::Seq(items) => Ok(items),
        other => Err(err(
            path,
            SchemaErrorKind::WrongType {
                expected: "sequence",
                found: other.kind(),
            },
        )),
    }
}

fn string_list(path: &str, node: &Node, max: usize, item_max: usize) -> Result<Vec<String>> {
    let items = expect_seq(path, node, max)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        out.push(expect_str(&format!("{path}[{i}]"), item, item_max)?.to_owned());
    }
    Ok(out)
}

/// ```yaml
/// on: [push, tag]                    # every ref of those kinds
/// on:
///   push: {branches: [main, "release/*"]}
///   tag: {tags: ["v*"]}
///   pull_request: {branches: [main]}
///   manual: true
/// ```
fn parse_triggers(path: &str, node: &Node) -> Result<Triggers> {
    let mut triggers = Triggers::default();
    match node {
        Node::Seq(items) => {
            if items.is_empty() {
                return Err(err(path, SchemaErrorKind::Empty));
            }
            if items.len() > 4 {
                return Err(err(path, SchemaErrorKind::TooMany { limit: 4 }));
            }
            for (i, item) in items.iter().enumerate() {
                let p = format!("{path}[{i}]");
                let kind = expect_str(&p, item, 16)?;
                let kind = match kind {
                    "push" => &mut triggers.push,
                    "pull_request" => &mut triggers.pull_request,
                    "tag" => &mut triggers.tag,
                    "manual" => {
                        if triggers.manual {
                            return Err(err(
                                &p,
                                SchemaErrorKind::Invalid("duplicate trigger".into()),
                            ));
                        }
                        triggers.manual = true;
                        continue;
                    }
                    _ => {
                        return Err(err(
                            &p,
                            SchemaErrorKind::Invalid(
                                "expected push, pull_request, tag or manual".into(),
                            ),
                        ));
                    }
                };
                if kind.is_some() {
                    return Err(err(
                        &p,
                        SchemaErrorKind::Invalid("duplicate trigger".into()),
                    ));
                }
                *kind = Some(RefFilter::default());
            }
            Ok(triggers)
        }
        Node::Map(_) => {
            let mut map = Map::new(path, node)?;
            if let Some(n) = map.take("push") {
                triggers.push = Some(ref_filter(&map.child("push"), n, RefKind::Branch)?);
            }
            if let Some(n) = map.take("pull_request") {
                triggers.pull_request =
                    Some(ref_filter(&map.child("pull_request"), n, RefKind::Branch)?);
            }
            if let Some(n) = map.take("tag") {
                triggers.tag = Some(ref_filter(&map.child("tag"), n, RefKind::Tag)?);
            }
            if let Some(n) = map.take("manual") {
                let p = map.child("manual");
                if !expect_bool(&p, n)? {
                    return Err(err(
                        &p,
                        SchemaErrorKind::Invalid("`manual: true` or omit the key".into()),
                    ));
                }
                triggers.manual = true;
            }
            map.finish()?;
            if triggers.is_empty() {
                return Err(err(
                    path,
                    SchemaErrorKind::Invalid("declares no trigger".into()),
                ));
            }
            Ok(triggers)
        }
        other => Err(err(
            path,
            SchemaErrorKind::WrongType {
                expected: "sequence or mapping",
                found: other.kind(),
            },
        )),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RefKind {
    Branch,
    Tag,
}

impl RefKind {
    const fn accepted_key(self) -> &'static str {
        match self {
            Self::Branch => "branches",
            Self::Tag => "tags",
        }
    }
}

fn ref_filter(path: &str, node: &Node, kind: RefKind) -> Result<RefFilter> {
    let mut filter = RefFilter::default();
    let mut map = match node {
        Node::Null => return Ok(filter),
        Node::Map(_) => Map::new(path, node)?,
        other => {
            return Err(err(
                path,
                SchemaErrorKind::WrongType {
                    expected: "mapping",
                    found: other.kind(),
                },
            ));
        }
    };
    if let Some(n) = map.take(kind.accepted_key()) {
        let p = map.child(kind.accepted_key());
        let patterns = string_list(&p, n, MAX_REF_PATTERNS, MAX_REF_PATTERN_BYTES)?;
        for (i, pattern) in patterns.iter().enumerate() {
            valid_pattern(pattern).map_err(|why| {
                err(
                    &format!("{p}[{i}]"),
                    SchemaErrorKind::Invalid(why.to_string()),
                )
            })?;
        }
        match kind {
            RefKind::Branch => filter.branches = patterns,
            RefKind::Tag => filter.tags = patterns,
        }
    }
    map.finish()?;
    Ok(filter)
}

pub fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ID_BYTES
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn expect_id<'a>(path: &str, node: &'a Node) -> Result<&'a str> {
    let s = expect_str(path, node, MAX_ID_BYTES)?;
    if !valid_id(s) {
        return Err(err(
            path,
            SchemaErrorKind::Invalid(
                "must match [a-z0-9][a-z0-9_-]* and be at most 64 bytes".into(),
            ),
        ));
    }
    Ok(s)
}

pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut num: u64 = 0;
    let mut have_digit = false;
    let mut any = false;
    for c in s.bytes() {
        match c {
            b'0'..=b'9' => {
                num = num.checked_mul(10)?.checked_add((c - b'0') as u64)?;
                have_digit = true;
            }
            b's' | b'm' | b'h' if have_digit => {
                let mult = match c {
                    b's' => 1,
                    b'm' => 60,
                    _ => 3600,
                };
                total = total.checked_add(num.checked_mul(mult)?)?;
                num = 0;
                have_digit = false;
                any = true;
            }
            _ => return None,
        }
    }
    if have_digit || !any {
        return None;
    }
    Some(total)
}

pub fn parse_bytes(s: &str) -> Option<u64> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    let mult: u64 = match unit {
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        _ => return None,
    };
    n.checked_mul(mult)
}

fn condition(path: &str, node: &Node) -> Result<Expr> {
    let s = expect_str(path, node, crate::expr::MAX_EXPR_BYTES)?;
    let inner = s
        .trim()
        .strip_prefix("${{")
        .and_then(|r| r.strip_suffix("}}"))
        .unwrap_or(s);
    let e = Expr::parse(inner).map_err(|e| {
        err(
            path,
            SchemaErrorKind::Invalid(format!("invalid expression {e}")),
        )
    })?;
    // Type errors are rejected here, so a condition can never fail with a type error at run time.
    e.check_condition()
        .map_err(|m| err(path, SchemaErrorKind::Invalid(m.into())))?;
    Ok(e)
}

fn template(path: &str, node: &Node, max: usize) -> Result<Template> {
    let s = expect_str(path, node, max)?;
    Template::parse(s).map_err(|e| {
        err(
            path,
            SchemaErrorKind::Invalid(format!("invalid template {e}")),
        )
    })
}

fn timeout(path: &str, node: &Node) -> Result<u64> {
    let s = expect_str(path, node, 32)?;
    match parse_duration_secs(s) {
        Some(0) | None => Err(err(
            path,
            SchemaErrorKind::Invalid("expected a positive duration such as 20m or 1h30m".into()),
        )),
        Some(secs) if secs > MAX_TIMEOUT_SECS => Err(err(
            path,
            SchemaErrorKind::Invalid(format!("exceeds the maximum of {MAX_TIMEOUT_SECS} seconds")),
        )),
        Some(secs) => Ok(secs),
    }
}

fn env(path: &str, node: &Node) -> Result<Vec<(String, String)>> {
    let mut map = Map::new(path, node)?;
    if map.entries.len() > MAX_ENV_VARS {
        return Err(err(
            path,
            SchemaErrorKind::TooMany {
                limit: MAX_ENV_VARS,
            },
        ));
    }
    let mut out = Vec::with_capacity(map.entries.len());
    for (k, v) in map.entries {
        let child = map.child(k);
        let valid = !k.is_empty()
            && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !k.as_bytes()[0].is_ascii_digit();
        if !valid {
            return Err(err(
                &child,
                SchemaErrorKind::Invalid(
                    "environment names must match [A-Za-z_][A-Za-z0-9_]*".into(),
                ),
            ));
        }
        let value = match v {
            Node::Str(s) => s.clone(),
            Node::Int(i) => i.to_string(),
            Node::Bool(b) => b.to_string(),
            other => {
                return Err(err(
                    &child,
                    SchemaErrorKind::WrongType {
                        expected: "string",
                        found: other.kind(),
                    },
                ));
            }
        };
        map.take(k);
        out.push((k.clone(), value));
    }
    map.finish()?;
    Ok(out)
}

fn resources(path: &str, node: Option<&Node>, policy: &ResourcePolicy) -> Result<Resources> {
    let mut r = policy.default;
    let Some(node) = node else { return Ok(r) };
    let mut map = Map::new(path, node)?;
    if let Some(cpu) = map.take("cpu") {
        let child = map.child("cpu");
        r.cpu_millis = match cpu {
            Node::Int(n) if *n > 0 && *n <= 1024 => (*n as u32) * 1000,
            Node::Str(s) => {
                // Plain ASCII digits only: u32::from_str would accept a leading '+', and fractions must not truncate.
                let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
                let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
                let w: u32 = Some(whole)
                    .filter(|w| !w.is_empty() && digits(w))
                    .and_then(|w| w.parse().ok())
                    .filter(|w| *w <= 1024)
                    .ok_or_else(|| {
                        err(
                            &child,
                            SchemaErrorKind::Invalid("expected cores, e.g. 4 or \"0.5\"".into()),
                        )
                    })?;
                let f: u32 = if frac.is_empty() && !s.ends_with('.') {
                    0
                } else if !frac.is_empty() && frac.len() <= 3 && digits(frac) {
                    let value: u32 = frac.parse().unwrap_or(0);
                    value * 10u32.pow(3 - frac.len() as u32)
                } else {
                    return Err(err(
                        &child,
                        SchemaErrorKind::Invalid(
                            "at most millicore precision (three decimals)".into(),
                        ),
                    ));
                };
                w * 1000 + f
            }
            _ => {
                return Err(err(
                    &child,
                    SchemaErrorKind::Invalid("expected cores, e.g. 4 or \"0.5\"".into()),
                ));
            }
        };
    }
    for (key, slot) in [("memory", &mut r.memory_bytes), ("disk", &mut r.disk_bytes)] {
        if let Some(n) = map.take(key) {
            let child = map.child(key);
            let s = expect_str(&child, n, 32)?;
            *slot = parse_bytes(s).ok_or_else(|| {
                err(
                    &child,
                    SchemaErrorKind::Invalid("expected a size such as 8GiB or 512MiB".into()),
                )
            })?;
        }
    }
    map.finish()?;
    let check = |name: &str, v: u64, lo: u64, hi: u64| {
        if v < lo || v > hi {
            Err(err(
                &format!("{path}.{name}"),
                SchemaErrorKind::Invalid(format!("must be between {lo} and {hi}")),
            ))
        } else {
            Ok(())
        }
    };
    check(
        "cpu",
        r.cpu_millis as u64,
        policy.min.cpu_millis as u64,
        policy.max.cpu_millis as u64,
    )?;
    check(
        "memory",
        r.memory_bytes,
        policy.min.memory_bytes,
        policy.max.memory_bytes,
    )?;
    check(
        "disk",
        r.disk_bytes,
        policy.min.disk_bytes,
        policy.max.disk_bytes,
    )?;
    Ok(r)
}

fn step(path: &str, node: &Node) -> Result<Step> {
    let mut map = Map::new(path, node)?;
    let id = map
        .take("id")
        .ok_or_else(|| err(&format!("{path}.id"), SchemaErrorKind::Missing))
        .and_then(|n| expect_id(&map.child("id"), n))?
        .to_owned();
    let run = map
        .take("run")
        .ok_or_else(|| err(&format!("{path}.run"), SchemaErrorKind::Missing))
        .and_then(|n| expect_str(&map.child("run"), n, MAX_RUN_BYTES))?
        .to_owned();
    let condition = match map.take("if") {
        Some(n) => Some(condition(&map.child("if"), n)?),
        None => None,
    };
    let shell = match map.take("shell") {
        None => Shell::Sh,
        Some(n) => match expect_str(&map.child("shell"), n, 8)? {
            "sh" => Shell::Sh,
            "bash" => Shell::Bash,
            _ => {
                return Err(err(
                    &map.child("shell"),
                    SchemaErrorKind::Invalid("expected sh or bash".into()),
                ));
            }
        },
    };
    let env = match map.take("env") {
        Some(n) => env(&map.child("env"), n)?,
        None => Vec::new(),
    };
    let secrets = match map.take("secrets") {
        None => Vec::new(),
        Some(n) => secret_names(&map.child("secrets"), n)?,
    };
    let secret_files = match map.take("secret_files") {
        None => Vec::new(),
        Some(n) => {
            let child = map.child("secret_files");
            let entries = match n {
                Node::Map(entries) if !entries.is_empty() => entries,
                Node::Map(_) => return Err(err(&child, SchemaErrorKind::Empty)),
                other => {
                    return Err(err(
                        &child,
                        SchemaErrorKind::WrongType {
                            expected: "mapping",
                            found: other.kind(),
                        },
                    ));
                }
            };
            if entries.len() > MAX_SECRETS {
                return Err(err(&child, SchemaErrorKind::TooMany { limit: MAX_SECRETS }));
            }
            let mut files = Vec::with_capacity(entries.len());
            for (name, path_node) in entries {
                let name_path = format!("{child}.{name}");
                validate_secret_name(&name_path, name)?;
                files.push(SecretFile {
                    name: name.clone(),
                    path: relative_path(&name_path, path_node)?,
                });
            }
            files
        }
    };
    let workdir = match map.take("workdir") {
        Some(n) => Some(relative_path(&map.child("workdir"), n)?),
        None => None,
    };
    let timeout_secs = match map.take("timeout") {
        Some(n) => Some(timeout(&map.child("timeout"), n)?),
        None => None,
    };
    map.finish()?;
    Ok(Step {
        id,
        run,
        condition,
        shell,
        env,
        secrets,
        secret_files,
        workdir,
        timeout_secs,
    })
}

fn validate_secret_name(path: &str, name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ID_BYTES
        || bytes[0].is_ascii_digit()
        || name == "CI"
        || name.starts_with("SENTINEL_")
        || !bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return Err(err(
            path,
            SchemaErrorKind::Invalid("secret names must match [A-Z_][A-Z0-9_]*".into()),
        ));
    }
    Ok(())
}

fn secret_names(path: &str, node: &Node) -> Result<Vec<String>> {
    let items = expect_seq(path, node, MAX_SECRETS)?;
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let p = format!("{path}[{i}]");
        let name = expect_str(&p, item, MAX_ID_BYTES)?;
        validate_secret_name(&p, name)?;
        if out.iter().any(|existing| existing == name) {
            return Err(err(&p, SchemaErrorKind::Invalid("duplicate secret".into())));
        }
        out.push(name.to_owned());
    }
    Ok(out)
}

pub fn valid_relative_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('/')
        && !s.contains('\\')
        && !s.contains('\0')
        && !s.contains("//")
        && !s.ends_with('/')
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

pub fn valid_cache_path(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix('/') {
        !rest.is_empty() && valid_relative_path(rest)
    } else {
        valid_relative_path(s)
    }
}

fn relative_path(path: &str, node: &Node) -> Result<String> {
    let s = expect_str(path, node, 256)?;
    if !valid_relative_path(s) {
        return Err(err(
            path,
            SchemaErrorKind::Invalid("must be a normalised relative path without `..`".into()),
        ));
    }
    Ok(s.to_owned())
}

fn cache(path: &str, node: &Node) -> Result<Cache> {
    let mut map = Map::new(path, node)?;
    let name = map
        .take("name")
        .ok_or_else(|| err(&format!("{path}.name"), SchemaErrorKind::Missing))
        .and_then(|n| expect_id(&map.child("name"), n))?
        .to_owned();
    let class = match map.take("class") {
        None => Class::Dependencies,
        Some(n) => {
            let child = map.child("class");
            let s = expect_str(&child, n, 16)?;
            Class::of_name(s).ok_or_else(|| {
                err(
                    &child,
                    SchemaErrorKind::Invalid("expected downloads, dependencies or compiler".into()),
                )
            })?
        }
    };
    let key_path = map.child("key");
    let key = map
        .take("key")
        .ok_or_else(|| err(&key_path, SchemaErrorKind::Missing))
        .and_then(|n| template(&key_path, n, 256))?;
    let paths_path = map.child("paths");
    let paths = map
        .take("paths")
        .ok_or_else(|| err(&paths_path, SchemaErrorKind::Missing))
        .and_then(|n| string_list(&paths_path, n, MAX_PATHS, 256))?;
    for (i, p) in paths.iter().enumerate() {
        if !valid_cache_path(p) {
            return Err(err(
                &format!("{paths_path}[{i}]"),
                SchemaErrorKind::Invalid("must be a normalised path without `..`".into()),
            ));
        }
    }
    map.finish()?;
    Ok(Cache {
        name,
        class,
        key,
        paths,
    })
}

fn artifact(path: &str, node: &Node) -> Result<Artifact> {
    let mut map = Map::new(path, node)?;
    let name = map
        .take("name")
        .ok_or_else(|| err(&format!("{path}.name"), SchemaErrorKind::Missing))
        .and_then(|n| expect_id(&map.child("name"), n))?
        .to_owned();
    let paths_path = map.child("paths");
    let paths = map
        .take("paths")
        .ok_or_else(|| err(&paths_path, SchemaErrorKind::Missing))
        .and_then(|n| string_list(&paths_path, n, MAX_PATHS, 256))?;
    for (i, p) in paths.iter().enumerate() {
        if !valid_relative_path(p) {
            return Err(err(
                &format!("{paths_path}[{i}]"),
                SchemaErrorKind::Invalid("must be a normalised relative path without `..`".into()),
            ));
        }
    }
    let when = match map.take("when") {
        None => ArtifactWhen::Success,
        Some(n) => match expect_str(&map.child("when"), n, 8)? {
            "success" => ArtifactWhen::Success,
            "failure" => ArtifactWhen::Failure,
            "always" => ArtifactWhen::Always,
            _ => {
                return Err(err(
                    &map.child("when"),
                    SchemaErrorKind::Invalid("expected success, failure or always".into()),
                ));
            }
        },
    };
    let retain_secs = match map.take("retain") {
        None => 7 * 24 * 3600,
        Some(n) => {
            let child = map.child("retain");
            let s = expect_str(&child, n, 16)?;
            let days = s
                .strip_suffix('d')
                .and_then(|d| d.parse::<u64>().ok())
                .filter(|d| (1..=365).contains(d))
                .ok_or_else(|| {
                    err(
                        &child,
                        SchemaErrorKind::Invalid("expected 1d to 365d".into()),
                    )
                })?;
            days * 24 * 3600
        }
    };
    let required = match map.take("required") {
        None => false,
        Some(n) => expect_bool(&map.child("required"), n)?,
    };
    map.finish()?;
    Ok(Artifact {
        name,
        paths,
        when,
        retain_secs,
        required,
    })
}

fn runs_on(path: &str, node: &Node) -> Result<RunsOn> {
    let mut map = Map::new(path, node)?;
    let arch = match map.take("arch") {
        None => None,
        Some(n) => Some(match expect_str(&map.child("arch"), n, 8)? {
            "amd64" => Arch::Amd64,
            "arm64" => Arch::Arm64,
            _ => {
                return Err(err(
                    &map.child("arch"),
                    SchemaErrorKind::Invalid("expected amd64 or arm64".into()),
                ));
            }
        }),
    };
    let labels = match map.take("labels") {
        None => Vec::new(),
        Some(n) => {
            let child = map.child("labels");
            let labels = string_list(&child, n, MAX_LABELS, MAX_ID_BYTES)?;
            for (i, l) in labels.iter().enumerate() {
                if !valid_id(l) {
                    return Err(err(
                        &format!("{child}[{i}]"),
                        SchemaErrorKind::Invalid("labels must match [a-z0-9][a-z0-9_-]*".into()),
                    ));
                }
            }
            labels
        }
    };
    let os = match map.take("os") {
        None => None,
        Some(n) => Some(match expect_str(&map.child("os"), n, 8)? {
            "linux" => Os::Linux,
            "windows" => Os::Windows,
            _ => {
                return Err(err(
                    &map.child("os"),
                    SchemaErrorKind::Invalid("expected linux or windows".into()),
                ));
            }
        }),
    };
    let isolation = match map.take("isolation") {
        None => None,
        Some(n) => Some(match expect_str(&map.child("isolation"), n, 12)? {
            "container" => Isolation::Container,
            "microvm" => Isolation::Microvm,
            "native" => Isolation::Native,
            _ => {
                return Err(err(
                    &map.child("isolation"),
                    SchemaErrorKind::Invalid("expected container, microvm or native".into()),
                ));
            }
        }),
    };
    // Linux jobs run in a container or a microVM; Windows jobs in a Windows guest or natively.
    let linux = os != Some(Os::Windows);
    match isolation {
        Some(Isolation::Native) if linux => {
            return Err(err(
                &map.child("isolation"),
                SchemaErrorKind::Invalid(
                    "native isolation is for Windows jobs (os: windows)".into(),
                ),
            ));
        }
        Some(Isolation::Container) if !linux => {
            return Err(err(
                &map.child("isolation"),
                SchemaErrorKind::Invalid(
                    "Windows jobs run in a microVM or natively, not in a container".into(),
                ),
            ));
        }
        _ => {}
    }
    map.finish()?;
    Ok(RunsOn {
        arch,
        labels,
        os,
        isolation,
    })
}

pub fn valid_image(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| (0x21..=0x7E).contains(&b))
        && !s.starts_with('-')
        && !s.contains("..")
}

fn job(path: &str, node: &Node, policy: &ResourcePolicy) -> Result<Job> {
    let mut map = Map::new(path, node)?;
    let image_path = map.child("image");
    let image = map
        .take("image")
        .ok_or_else(|| err(&image_path, SchemaErrorKind::Missing))
        .and_then(|n| expect_str(&image_path, n, 256))?;
    if !valid_image(image) {
        return Err(err(
            &image_path,
            SchemaErrorKind::Invalid("must be an OCI image reference".into()),
        ));
    }
    let needs = match map.take("needs") {
        None => Vec::new(),
        Some(n) => {
            let child = map.child("needs");
            let items = expect_seq(&child, n, MAX_NEEDS)?;
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                out.push(expect_id(&format!("{child}[{i}]"), item)?.to_owned());
            }
            out
        }
    };
    let condition = match map.take("if") {
        Some(n) => Some(condition(&map.child("if"), n)?),
        None => None,
    };
    let runs_on = match map.take("runs_on") {
        None => RunsOn::default(),
        Some(n) => runs_on(&map.child("runs_on"), n)?,
    };
    let resources = resources(&map.child("resources"), map.take("resources"), policy)?;
    let timeout_secs = match map.take("timeout") {
        None => DEFAULT_JOB_TIMEOUT_SECS,
        Some(n) => timeout(&map.child("timeout"), n)?,
    };
    let env = match map.take("env") {
        Some(n) => env(&map.child("env"), n)?,
        None => Vec::new(),
    };
    let workdir = match map.take("workdir") {
        Some(n) => Some(relative_path(&map.child("workdir"), n)?),
        None => None,
    };
    let steps_path = map.child("steps");
    let steps = map
        .take("steps")
        .ok_or_else(|| err(&steps_path, SchemaErrorKind::Missing))
        .and_then(|n| expect_seq(&steps_path, n, MAX_STEPS_PER_JOB))?
        .iter()
        .enumerate()
        .map(|(i, n)| step(&format!("{steps_path}[{i}]"), n))
        .collect::<Result<Vec<_>>>()?;
    let cache = match map.take("cache") {
        None => Vec::new(),
        Some(n) => {
            let child = map.child("cache");
            expect_seq(&child, n, MAX_CACHES)?
                .iter()
                .enumerate()
                .map(|(i, n)| cache(&format!("{child}[{i}]"), n))
                .collect::<Result<Vec<_>>>()?
        }
    };
    let secrets = match map.take("secrets") {
        None => Vec::new(),
        Some(n) => secret_names(&map.child("secrets"), n)?,
    };
    let registry_auth = match map.take("registry_auth") {
        None => None,
        Some(n) => {
            let path = map.child("registry_auth");
            let name = expect_str(&path, n, MAX_ID_BYTES)?;
            validate_secret_name(&path, name)?;
            Some(name.to_owned())
        }
    };
    if registry_auth
        .as_ref()
        .is_some_and(|name| !secrets.iter().any(|declared| declared == name))
    {
        return Err(err(
            &map.child("registry_auth"),
            SchemaErrorKind::Invalid("registry_auth must be declared by the job's secrets".into()),
        ));
    }
    for (step_index, step) in steps.iter().enumerate() {
        let path = format!("{steps_path}[{step_index}]");
        for name in step
            .secrets
            .iter()
            .chain(step.secret_files.iter().map(|f| &f.name))
        {
            if !secrets.iter().any(|declared| declared == name) {
                return Err(err(
                    &path,
                    SchemaErrorKind::Invalid("step secrets must be declared by the job".into()),
                ));
            }
            if name == "CI"
                || name.starts_with("SENTINEL_")
                || job_env_has_name(&env, name)
                || step.env.iter().any(|(env_name, _)| env_name == name)
            {
                return Err(err(
                    &path,
                    SchemaErrorKind::Invalid(
                        "secret target conflicts with a reserved or ordinary environment variable"
                            .into(),
                    ),
                ));
            }
        }
        for (i, file) in step.secret_files.iter().enumerate() {
            if step.secret_files[..i].iter().any(|previous| {
                previous.path == file.path
                    || previous
                        .path
                        .strip_prefix(&file.path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                    || file
                        .path
                        .strip_prefix(&previous.path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }) {
                return Err(err(
                    &path,
                    SchemaErrorKind::Invalid("overlapping secret file paths".into()),
                ));
            }
        }
    }
    let artifacts = match map.take("artifacts") {
        None => Vec::new(),
        Some(n) => {
            let child = map.child("artifacts");
            expect_seq(&child, n, MAX_ARTIFACTS)?
                .iter()
                .enumerate()
                .map(|(i, n)| artifact(&format!("{child}[{i}]"), n))
                .collect::<Result<Vec<_>>>()?
        }
    };
    map.finish()?;
    Ok(Job {
        image: image.to_owned(),
        needs,
        condition,
        runs_on,
        resources,
        timeout_secs,
        env,
        workdir,
        steps,
        cache,
        artifacts,
        secrets,
        registry_auth,
    })
}

fn job_env_has_name(env: &[(String, String)], name: &str) -> bool {
    env.iter().any(|(env_name, _)| env_name == name)
}

pub fn decode(root: &Node, policy: &ResourcePolicy) -> Result<Pipeline> {
    let mut map = Map::new("", root)?;
    match map.take("schema") {
        Some(Node::Int(v)) if *v == SCHEMA_VERSION => {}
        Some(Node::Int(v)) => {
            return Err(err(
                "schema",
                SchemaErrorKind::UnsupportedSchema { found: Some(*v) },
            ));
        }
        _ => {
            return Err(err(
                "schema",
                SchemaErrorKind::UnsupportedSchema { found: None },
            ));
        }
    }
    let on = match map.take("on") {
        None => return Err(err("on", SchemaErrorKind::Missing)),
        Some(node) => parse_triggers("on", node)?,
    };
    let concurrency = match map.take("concurrency") {
        None => None,
        Some(n) => {
            let mut c = Map::new("concurrency", n)?;
            let group = c
                .take("group")
                .ok_or_else(|| err("concurrency.group", SchemaErrorKind::Missing))
                .and_then(|n| template("concurrency.group", n, 256))?;
            if group.min_phase() > Phase::Dispatch {
                return Err(err(
                    "concurrency.group",
                    SchemaErrorKind::Invalid(
                        "may only use event, repo and run context (no needs or hash_files)".into(),
                    ),
                ));
            }
            let cancel_in_progress = match c.take("cancel_in_progress") {
                None => false,
                Some(n) => expect_bool("concurrency.cancel_in_progress", n)?,
            };
            c.finish()?;
            Some(Concurrency {
                group,
                cancel_in_progress,
            })
        }
    };
    let jobs = match map.take("jobs") {
        None => return Err(err("jobs", SchemaErrorKind::Missing)),
        Some(n) => {
            let jobs_map = Map::new("jobs", n)?;
            if jobs_map.entries.is_empty() {
                return Err(err("jobs", SchemaErrorKind::Empty));
            }
            if jobs_map.entries.len() > MAX_JOBS {
                return Err(err("jobs", SchemaErrorKind::TooMany { limit: MAX_JOBS }));
            }
            let mut out = Vec::with_capacity(jobs_map.entries.len());
            for (name, node) in jobs_map.entries {
                let path = format!("jobs.{name}");
                if !valid_id(name) {
                    return Err(err(
                        &path,
                        SchemaErrorKind::Invalid(
                            "job names must match [a-z0-9][a-z0-9_-]* and be at most 64 bytes"
                                .into(),
                        ),
                    ));
                }
                out.push((name.clone(), job(&path, node, policy)?));
            }
            out
        }
    };
    map.finish()?;
    Ok(Pipeline {
        on,
        concurrency,
        jobs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(parse_duration_secs("20m"), Some(1200));
        assert_eq!(parse_duration_secs("1h30m"), Some(5400));
        assert_eq!(parse_duration_secs("90s"), Some(90));
        assert_eq!(parse_duration_secs("20"), None);
        assert_eq!(parse_duration_secs("m"), None);
        assert_eq!(parse_duration_secs("1d"), None);
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_bytes("8GiB"), Some(8 << 30));
        assert_eq!(parse_bytes("512MiB"), Some(512 << 20));
        assert_eq!(parse_bytes("8GB"), None);
        assert_eq!(parse_bytes("GiB"), None);
        assert_eq!(parse_bytes("99999999999999GiB"), None);
    }

    #[test]
    fn identifiers_and_paths() {
        assert!(valid_id("test-1_a"));
        assert!(!valid_id("Test"));
        assert!(!valid_id("-x"));
        assert!(!valid_id(&"a".repeat(65)));
        assert!(valid_relative_path("target/release/app"));
        assert!(!valid_relative_path("/abs"));
        assert!(!valid_relative_path("a/../b"));
        assert!(!valid_relative_path("a//b"));
        assert!(!valid_relative_path("a/"));
        assert!(!valid_relative_path("./a"));
        assert!(valid_cache_path("/usr/local/cargo/registry"));
        assert!(!valid_cache_path("/"));
        assert!(!valid_cache_path("/../etc"));
        assert!(valid_image("rust:1-bookworm"));
        assert!(valid_image("ghcr.io/o/i@sha256:abc"));
        assert!(!valid_image("a b"));
    }

    #[test]
    fn runs_on_os_and_isolation_parse_and_must_agree() {
        let doc = |runs_on: &str| {
            format!(
                "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    runs_on: {runs_on}\n    steps:\n      - id: s\n        run: echo\n"
            )
        };
        let runs_on =
            |text: &str| crate::compile_str(&doc(text)).map(|p| p.jobs[0].spec.runs_on.clone());
        let r = runs_on("{os: windows, isolation: microvm}").unwrap();
        assert_eq!(
            (r.os, r.isolation),
            (Some(Os::Windows), Some(Isolation::Microvm))
        );
        let r = runs_on("{os: windows, isolation: native}").unwrap();
        assert_eq!(r.isolation, Some(Isolation::Native));
        let r = runs_on("{isolation: container}").unwrap();
        assert_eq!((r.os, r.isolation), (None, Some(Isolation::Container)));
        assert!(r.states_runtime());
        assert!(!runs_on("{labels: [a]}").unwrap().states_runtime());
        for bad in [
            "{os: macos}",
            "{isolation: vm}",
            "{isolation: native}",
            "{os: linux, isolation: native}",
            "{os: windows, isolation: container}",
        ] {
            assert!(runs_on(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_stated_runtime_changes_the_digest_and_an_unstated_one_does_not() {
        let plain = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    runs_on: {labels: [a]}\n    steps:\n      - id: s\n        run: echo\n";
        let stated = plain.replace("{labels: [a]}", "{labels: [a], isolation: microvm}");
        let other = plain.replace("{labels: [a]}", "{labels: [a], isolation: container}");
        let d = |t: &str| crate::compile_str(t).unwrap().digest;
        assert_ne!(d(plain), d(&stated));
        assert_ne!(d(&stated), d(&other));
        assert_eq!(d(plain), d(plain));
    }

    #[test]
    fn secret_file_targets_must_not_overlap() {
        for files in [
            "        secret_files:\n          TOKEN: config\n          OTHER: config/token\n",
            "        secret_files:\n          TOKEN: config/token\n          OTHER: config\n",
        ] {
            let doc = format!(
                "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    secrets: [TOKEN, OTHER]\n    steps:\n      - id: s\n        run: echo\n{files}"
            );
            let error = crate::compile_str(&doc).unwrap_err();
            assert!(error.to_string().contains("overlapping secret file paths"));
        }
    }

    #[test]
    fn registry_auth_alone_requires_secret_delivery() {
        let pipeline = crate::compile_str(
            "schema: 1\non: [push]\njobs:\n  image:\n    image: ghcr.io/acme/app\n    secrets: [OCI_AUTH]\n    registry_auth: OCI_AUTH\n    steps:\n      - id: build\n        run: make\n",
        )
        .unwrap();
        assert!(pipeline.jobs[0].spec.requires_secret_delivery());

        let pipeline = crate::compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps:\n      - id: test\n        run: test\n",
        )
        .unwrap();
        assert!(!pipeline.jobs[0].spec.requires_secret_delivery());
    }

    #[test]
    fn a_multibyte_core_fraction_is_a_schema_error_not_a_panic() {
        let doc = |cpu: &str| {
            format!(
                "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    resources: {{ cpu: \"{cpu}\" }}\n    steps:\n      - id: s\n        run: echo\n"
            )
        };
        assert!(crate::compile_str(&doc("1.éé")).is_err());
        assert!(crate::compile_str(&doc("0.€")).is_err());
        assert!(crate::compile_str(&doc("0.5")).is_ok());
    }

    #[test]
    fn core_strings_are_plain_digits_with_at_most_millicore_precision() {
        let cpu_millis = |cpu: &str| {
            let doc = format!(
                "schema: 1
on: [push]
jobs:
  a:
    image: busybox
    resources: {{ cpu: \"{cpu}\" }}
    steps:
      - id: s
        run: echo
"
            );
            crate::compile_str(&doc).map(|p| p.jobs[0].spec.resources.cpu_millis)
        };
        for (text, millis) in [
            ("4", 4000),
            ("0.5", 500),
            ("0.25", 250),
            ("1.05", 1050),
            ("2.500", 2500),
        ] {
            assert_eq!(cpu_millis(text).unwrap(), millis, "{text}");
        }
        for text in [
            "+4", "0.+5", "0.5555", "0.2501", "1.", ".5", "-1", "0.5 ", "1_0",
        ] {
            assert!(cpu_millis(text).is_err(), "{text}");
        }
    }

    fn cache_of(text: &str) -> std::result::Result<Cache, crate::Error> {
        let doc = format!(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    cache:\n{text}    steps:\n      - id: s\n        run: echo\n"
        );
        crate::compile_str(&doc).map(|p| p.jobs[0].spec.cache[0].clone())
    }

    #[test]
    fn cache_class_parses_or_defaults() {
        let default =
            cache_of("      - name: c\n        key: k\n        paths: [target]\n").unwrap();
        assert_eq!(default.class, Class::Dependencies);
        for (word, class) in [
            ("downloads", Class::Downloads),
            ("dependencies", Class::Dependencies),
            ("compiler", Class::Compiler),
        ] {
            let c = cache_of(&format!(
                "      - name: c\n        class: {word}\n        key: k\n        paths: [target]\n"
            ))
            .unwrap();
            assert_eq!(c.class, class, "{word}");
        }
        let error = cache_of(
            "      - name: c\n        class: everything\n        key: k\n        paths: [target]\n",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("expected downloads, dependencies or compiler"),
            "{error}"
        );
        assert!(
            cache_of(
                "      - name: c\n        class: 3\n        key: k\n        paths: [target]\n"
            )
            .is_err()
        );
        let dup = cache_of(
            "      - name: c\n        class: compiler\n        class: downloads\n        key: k\n        paths: [target]\n",
        );
        assert!(dup.is_err(), "a second `class` key must not pass");
        let unknown = cache_of(
            "      - name: c\n        klass: compiler\n        key: k\n        paths: [target]\n",
        );
        assert!(
            unknown
                .unwrap_err()
                .to_string()
                .contains("unknown key `klass`")
        );
    }
}
