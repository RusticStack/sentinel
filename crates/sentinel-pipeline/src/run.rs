//! The immutable per-run specification. A `RunSpec` binds one compiled
//! pipeline to one exact source revision and records how every image was
//! pinned. It is written once when the run is created and never edited: a
//! rerun executes the same bytes as a new attempt; a change of source or
//! pipeline is a new run. Step commands are derived from the spec so worker
//! and controller agree on argv, environment and working directory.
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    compile::CompiledPipeline,
    schema::{Job, Shell, Step},
};

/// Exact source inputs. `sha` is the commit actually checked out; `ref_name`
/// is provenance only and never used to fetch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSource {
    /// Clone URL or repository identifier as resolved by the controller.
    pub repo: String,
    /// Full 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
    pub sha: String,
    pub ref_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError {
    EmptyRepo,
    InvalidSha,
}

impl PinnedSource {
    pub fn new(repo: &str, sha: &str, ref_name: Option<&str>) -> Result<Self, SourceError> {
        if repo.is_empty() || repo.len() > 512 {
            return Err(SourceError::EmptyRepo);
        }
        let valid = (sha.len() == 40 || sha.len() == 64)
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !valid {
            return Err(SourceError::InvalidSha);
        }
        Ok(Self {
            repo: repo.to_owned(),
            sha: sha.to_owned(),
            ref_name: ref_name.map(str::to_owned),
        })
    }
}

/// An OCI image reference split into its parts. A reference is *pinned*
/// when it carries a digest; a tag-only reference is resolved to a digest by
/// the first worker that pulls it and the digest is then recorded on the run
/// so every later attempt uses the same bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    pub name: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    Empty,
    InvalidDigest,
    InvalidTag,
    InvalidName,
}

impl ImageRef {
    /// Parse `name[:tag][@sha256:hex]` as validated by the schema.
    pub fn parse(reference: &str) -> Result<Self, ImageError> {
        if reference.is_empty() {
            return Err(ImageError::Empty);
        }
        let (rest, digest) = match reference.split_once('@') {
            Some((r, d)) => {
                let hex = d.strip_prefix("sha256:").ok_or(ImageError::InvalidDigest)?;
                if hex.len() != 64
                    || !hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ImageError::InvalidDigest);
                }
                (r, Some(d.to_owned()))
            }
            None => (reference, None),
        };
        // A colon after the last slash is a tag; before it, a registry port.
        let last_slash = rest.rfind('/').map_or(0, |i| i + 1);
        let (name, tag) = match rest[last_slash..].find(':') {
            Some(i) => {
                let tag = &rest[last_slash + i + 1..];
                if tag.is_empty()
                    || tag.len() > 128
                    || !tag
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
                {
                    return Err(ImageError::InvalidTag);
                }
                (&rest[..last_slash + i], Some(tag.to_owned()))
            }
            None => (rest, None),
        };
        if name.is_empty() || name.ends_with('/') || name.starts_with('/') {
            return Err(ImageError::InvalidName);
        }
        Ok(Self {
            name: name.to_owned(),
            tag,
            digest,
        })
    }

    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// Record the digest a worker resolved. Refuses to change an existing pin.
    pub fn pin(&mut self, digest: &str) -> Result<(), ImageError> {
        if self.digest.is_some() {
            return Err(ImageError::InvalidDigest);
        }
        let parsed = ImageRef::parse(&format!("{}@{digest}", self.name))?;
        self.digest = parsed.digest;
        Ok(())
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// Everything a run needs, fixed at creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    pub source: PinnedSource,
    pub pipeline: CompiledPipeline,
    /// One entry per compiled job, same order; carries the image pin state.
    pub images: Vec<ImageRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecError {
    Image { job: usize, error: ImageError },
    Encode,
    Decode,
}

/// Bump when the encoded layout changes incompatibly; older blobs are then
/// rejected rather than misread. Format 2: `on` carries ref filters
/// (`policy::Triggers`) instead of a trigger list.
pub const SPEC_FORMAT: u8 = 2;

impl RunSpec {
    pub fn new(source: PinnedSource, pipeline: CompiledPipeline) -> Result<Self, SpecError> {
        let mut images = Vec::with_capacity(pipeline.jobs.len());
        for (i, job) in pipeline.jobs.iter().enumerate() {
            images.push(
                ImageRef::parse(&job.spec.image)
                    .map_err(|error| SpecError::Image { job: i, error })?,
            );
        }
        Ok(Self {
            source,
            pipeline,
            images,
        })
    }

    /// Compact binary form for the store: one format byte, then postcard.
    pub fn encode(&self) -> Result<Vec<u8>, SpecError> {
        let mut out = vec![SPEC_FORMAT];
        postcard::to_extend(self, out.split_off(1))
            .map(|body| {
                out.extend(body);
                out
            })
            .map_err(|_| SpecError::Encode)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SpecError> {
        match bytes.split_first() {
            Some((&SPEC_FORMAT, body)) => postcard::from_bytes(body).map_err(|_| SpecError::Decode),
            _ => Err(SpecError::Decode),
        }
    }

    /// Compile a step of a job into the exact process the worker runs.
    pub fn step_command(&self, job: usize, step: usize) -> Option<StepCommand> {
        let j = &self.pipeline.jobs.get(job)?.spec;
        let s = j.steps.get(step)?;
        Some(StepCommand::new(j, s))
    }
}

/// Failure semantics, identical for every shell: exit 0 passes; any other
/// exit status is `CommandFailed`; death by signal is `CommandSignaled`;
/// exceeding the step or job timeout is `ExecutionTimeout`; an OOM kill is
/// `OutOfMemory`. Output is captured, never interpreted, for the verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepCommand {
    /// Executable and arguments; the script is the last element.
    pub argv: Vec<String>,
    /// Job environment first, step environment overriding by name; the
    /// worker adds its own `SENTINEL_*` context variables after these so a
    /// pipeline cannot spoof them.
    pub env: Vec<(String, String)>,
    /// Relative to the workspace root; `None` means the root itself.
    pub workdir: Option<String>,
    pub timeout_secs: u64,
}

impl StepCommand {
    fn new(job: &Job, step: &Step) -> Self {
        let argv = match step.shell {
            Shell::Sh => vec!["/bin/sh".to_owned(), "-e".to_owned(), "-c".to_owned()],
            Shell::Bash => vec![
                "bash".to_owned(),
                "-e".to_owned(),
                "-o".to_owned(),
                "pipefail".to_owned(),
                "-c".to_owned(),
            ],
        };
        let mut argv = argv;
        argv.push(step.run.clone());
        let mut env: Vec<(String, String)> = job.env.clone();
        for (k, v) in &step.env {
            match env.iter_mut().find(|(name, _)| name == k) {
                Some(slot) => slot.1 = v.clone(),
                None => env.push((k.clone(), v.clone())),
            }
        }
        // Step workdir is relative to the job workdir; both were validated
        // as normalised relative paths, so joining cannot escape.
        let workdir = match (&job.workdir, &step.workdir) {
            (None, None) => None,
            (Some(j), None) => Some(j.clone()),
            (None, Some(s)) => Some(s.clone()),
            (Some(j), Some(s)) => Some(format!("{j}/{s}")),
        };
        Self {
            argv,
            env,
            workdir,
            timeout_secs: step.timeout_secs.unwrap_or(job.timeout_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_str;

    const SHA: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";

    #[test]
    fn sources_require_a_full_hex_sha() {
        assert!(PinnedSource::new("git@x:y.git", SHA, Some("main")).is_ok());
        assert_eq!(
            PinnedSource::new("", SHA, None),
            Err(SourceError::EmptyRepo)
        );
        assert_eq!(
            PinnedSource::new("r", "main", None),
            Err(SourceError::InvalidSha)
        );
        assert_eq!(
            PinnedSource::new("r", &SHA.to_uppercase(), None),
            Err(SourceError::InvalidSha)
        );
    }

    #[test]
    fn image_references_parse_and_pin_once() {
        let r = ImageRef::parse("rust:1-bookworm").unwrap();
        assert_eq!(
            (r.name.as_str(), r.tag.as_deref(), r.digest.as_deref()),
            ("rust", Some("1-bookworm"), None)
        );
        let r = ImageRef::parse("localhost:5000/org/img").unwrap();
        assert_eq!(
            (r.name.as_str(), r.tag.as_deref()),
            ("localhost:5000/org/img", None)
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut r = ImageRef::parse(&format!("ghcr.io/o/i:v1@{digest}")).unwrap();
        assert!(r.is_pinned());
        assert_eq!(r.to_string(), format!("ghcr.io/o/i:v1@{digest}"));
        assert_eq!(
            r.pin(&digest),
            Err(ImageError::InvalidDigest),
            "already pinned"
        );
        let mut t = ImageRef::parse("busybox").unwrap();
        assert!(!t.is_pinned());
        t.pin(&digest).unwrap();
        assert_eq!(t.to_string(), format!("busybox@{digest}"));
        assert_eq!(ImageRef::parse("img@md5:x"), Err(ImageError::InvalidDigest));
        assert_eq!(ImageRef::parse("img:"), Err(ImageError::InvalidTag));
        assert_eq!(ImageRef::parse("/img"), Err(ImageError::InvalidName));
    }

    #[test]
    fn run_spec_round_trips_and_derives_commands() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/pipelines/valid/full.yml"
        ))
        .unwrap();
        let pipeline = compile_str(&text).unwrap();
        let spec = RunSpec::new(PinnedSource::new("repo", SHA, None).unwrap(), pipeline).unwrap();
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], SPEC_FORMAT);
        assert_eq!(RunSpec::decode(&bytes).unwrap(), spec);
        assert_eq!(RunSpec::decode(&[9, 0]), Err(SpecError::Decode));
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() - 1]),
            Err(SpecError::Decode)
        );

        let fmt = spec.step_command(0, 0).unwrap();
        assert_eq!(
            fmt.argv,
            ["/bin/sh", "-e", "-c", "cargo fmt --all -- --check"]
        );
        assert_eq!(fmt.timeout_secs, 300);
        assert_eq!(fmt.workdir, None);
        let test = spec.step_command(0, 1).unwrap();
        assert_eq!(test.argv[..5], ["bash", "-e", "-o", "pipefail", "-c"]);
        assert_eq!(test.workdir.as_deref(), Some("crates/app"));
        assert_eq!(test.timeout_secs, 1200, "falls back to the job timeout");
        assert_eq!(test.env.len(), 2);
        assert!(spec.step_command(0, 9).is_none());
        assert!(!spec.images[0].is_pinned());
    }

    #[test]
    fn step_env_overrides_job_env_by_name() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    env: {A: job, B: job}\n    workdir: base\n    steps:\n      - id: s\n        run: echo\n        env: {B: step, C: step}\n        workdir: sub\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        let c = spec.step_command(0, 0).unwrap();
        assert_eq!(
            c.env,
            vec![
                ("A".to_owned(), "job".to_owned()),
                ("B".to_owned(), "step".to_owned()),
                ("C".to_owned(), "step".to_owned())
            ]
        );
        assert_eq!(c.workdir.as_deref(), Some("base/sub"));
        assert_eq!(c.timeout_secs, 3600);
    }
}
