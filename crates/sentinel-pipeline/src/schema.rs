//! Typed `.sentinel.yml` schema version 1 and its strict decoder. Every key
//! is known, every value is typed and bounded, and every error names the
//! path that produced it. Expressions (`${{ … }}`) are kept as opaque
//! strings here; their grammar is C06.
use std::fmt;

use crate::yaml::Node;

pub const SCHEMA_VERSION: i64 = 1;

pub const MAX_JOBS: usize = 64;
pub const MAX_STEPS_PER_JOB: usize = 64;
pub const MAX_NEEDS: usize = 32;
pub const MAX_ENV_VARS: usize = 64;
pub const MAX_CACHES: usize = 8;
pub const MAX_ARTIFACTS: usize = 8;
pub const MAX_PATHS: usize = 32;
pub const MAX_LABELS: usize = 8;
pub const MAX_RUN_BYTES: usize = 4096;
pub const MAX_ID_BYTES: usize = 64;
/// One day; nothing in CI legitimately runs longer without human review.
pub const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_JOB_TIMEOUT_SECS: u64 = 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pipeline {
    pub on: Vec<Trigger>,
    pub concurrency: Option<Concurrency>,
    /// Declaration order preserved; compilation sorts deterministically.
    pub jobs: Vec<(String, Job)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Trigger {
    Push = 0,
    PullRequest = 1,
    Tag = 2,
    Manual = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Concurrency {
    pub group: String,
    pub cancel_in_progress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub image: String,
    pub needs: Vec<String>,
    pub runs_on: RunsOn,
    pub resources: Resources,
    pub timeout_secs: u64,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub steps: Vec<Step>,
    pub cache: Vec<Cache>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunsOn {
    pub arch: Option<Arch>,
    pub labels: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Arch {
    Amd64 = 0,
    Arm64 = 1,
}

/// Explicit per-job allocation. Absent fields take the policy defaults so a
/// compiled job always has a finite, enforceable budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resources {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub id: String,
    pub run: String,
    pub shell: Shell,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Shell {
    /// `/bin/sh -e -c`: fail on the first failing command.
    #[default]
    Sh = 0,
    /// `bash -eo pipefail -c`; the image must provide bash.
    Bash = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cache {
    pub name: String,
    pub key: String,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub paths: Vec<String>,
    pub when: ArtifactWhen,
    pub retain_secs: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ArtifactWhen {
    #[default]
    Success = 0,
    Failure = 1,
    Always = 2,
}

/// Resource policy: defaults for absent fields and inclusive bounds.
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
    /// Dotted path with `[i]` for sequence items, e.g. `jobs.test.steps[0].run`.
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

/// Mapping accessor that tracks which keys were consumed so unknown keys are
/// reported after all known ones are decoded (one error per unknown key,
/// deterministic: first unknown in document order).
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

/// Identifiers: `[a-z0-9][a-z0-9_-]*`, at most 64 bytes. Lowercase only so
/// names are stable across filesystems and URLs without normalisation.
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

/// Durations: an integer followed by `s`, `m` or `h`, or a sum such as `1h30m`.
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

/// Byte sizes: an integer followed by `MiB` or `GiB` (binary units only).
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
                // Allow fractional cores as strings, e.g. "0.5".
                let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
                let w: u32 = whole.parse().ok().filter(|w| *w <= 1024).ok_or_else(|| {
                    err(
                        &child,
                        SchemaErrorKind::Invalid("expected cores, e.g. 4 or \"0.5\"".into()),
                    )
                })?;
                let f: u32 = if frac.is_empty() {
                    0
                } else {
                    let padded = format!("{frac:0<3}");
                    padded[..3].parse().map_err(|_| {
                        err(
                            &child,
                            SchemaErrorKind::Invalid("at most millicore precision".into()),
                        )
                    })?
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
        shell,
        env,
        workdir,
        timeout_secs,
    })
}

/// A path inside the job workspace: relative, normalised, no `..`, no
/// backslashes, no NUL, at most 256 bytes.
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

/// A cache path may also be absolute inside the container (tool caches live
/// outside the workspace), but never a filesystem root or `..`.
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
    let key = map
        .take("key")
        .ok_or_else(|| err(&format!("{path}.key"), SchemaErrorKind::Missing))
        .and_then(|n| expect_str(&map.child("key"), n, 256))?
        .to_owned();
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
    Ok(Cache { name, key, paths })
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
    map.finish()?;
    Ok(Artifact {
        name,
        paths,
        when,
        retain_secs,
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
    map.finish()?;
    Ok(RunsOn { arch, labels })
}

/// Image references: `name[:tag][@sha256:hex]`, printable ASCII, bounded.
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
        runs_on,
        resources,
        timeout_secs,
        env,
        workdir,
        steps,
        cache,
        artifacts,
    })
}

/// Decode a loaded document into the typed schema. Structural only: DAG
/// validity and cross-job references are checked by the compiler.
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
        Some(n) => {
            let items = expect_seq("on", n, 4)?;
            let mut out: Vec<Trigger> = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let p = format!("on[{i}]");
                let t = match expect_str(&p, item, 16)? {
                    "push" => Trigger::Push,
                    "pull_request" => Trigger::PullRequest,
                    "tag" => Trigger::Tag,
                    "manual" => Trigger::Manual,
                    _ => {
                        return Err(err(
                            &p,
                            SchemaErrorKind::Invalid(
                                "expected push, pull_request, tag or manual".into(),
                            ),
                        ));
                    }
                };
                if out.contains(&t) {
                    return Err(err(
                        &p,
                        SchemaErrorKind::Invalid("duplicate trigger".into()),
                    ));
                }
                out.push(t);
            }
            out
        }
    };
    let concurrency = match map.take("concurrency") {
        None => None,
        Some(n) => {
            let mut c = Map::new("concurrency", n)?;
            let group = c
                .take("group")
                .ok_or_else(|| err("concurrency.group", SchemaErrorKind::Missing))
                .and_then(|n| expect_str("concurrency.group", n, 256))?
                .to_owned();
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
}
