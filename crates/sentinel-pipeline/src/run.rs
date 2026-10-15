use std::fmt;

use serde::{Deserialize, Serialize};

use sentinel_protocol::cache::Class;

use crate::{
    compile::{CompiledJob, CompiledPipeline},
    expr::{Expr, Template},
    policy::Triggers,
    schema::{Artifact, Cache, Concurrency, Job, Resources, RunsOn, Shell, Step},
};

/// `ref_name` is provenance only; fetches use the pinned `sha`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSource {
    pub repo: String,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    pub source: PinnedSource,
    pub pipeline: CompiledPipeline,
    pub images: Vec<ImageRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecError {
    Image { job: usize, error: ImageError },
    Encode,
    Decode,
}

pub const SPEC_FORMAT: u8 = 6;

pub const SPEC_FORMAT_READ_MIN: u8 = 3;

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
        fn whole<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, SpecError> {
            match postcard::take_from_bytes(body) {
                Ok((value, [])) => Ok(value),
                _ => Err(SpecError::Decode),
            }
        }
        match bytes.split_first() {
            Some((&SPEC_FORMAT, body)) => whole(body),
            Some((&5, body)) => whole::<RunSpecV5>(body).map(RunSpec::from),
            Some((&4, body)) => whole::<RunSpecV4>(body).map(RunSpec::from),
            Some((&3, body)) => whole::<RunSpecV3>(body).map(RunSpec::from),
            _ => Err(SpecError::Decode),
        }
    }

    pub fn step_command(&self, job: usize, step: usize) -> Option<StepCommand> {
        let j = &self.pipeline.jobs.get(job)?.spec;
        let s = j.steps.get(step)?;
        Some(StepCommand::new(j, s))
    }
}

// postcard is positional: reading an old format needs its old type graph, not serde(default).

#[derive(Debug, Serialize, Deserialize)]
struct CacheV3 {
    name: String,
    key: Template,
    paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StepV4 {
    id: String,
    run: String,
    condition: Option<Expr>,
    shell: Shell,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobV4 {
    image: String,
    needs: Vec<String>,
    condition: Option<Expr>,
    runs_on: RunsOn,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<StepV4>,
    cache: Vec<Cache>,
    artifacts: Vec<Artifact>,
    secrets: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledJobV4 {
    name: String,
    needs: Vec<u16>,
    spec: JobV4,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledPipelineV4 {
    on: Triggers,
    concurrency: Option<Concurrency>,
    jobs: Vec<CompiledJobV4>,
    digest: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV4 {
    source: PinnedSource,
    pipeline: CompiledPipelineV4,
    images: Vec<ImageRef>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobV5 {
    image: String,
    needs: Vec<String>,
    condition: Option<Expr>,
    runs_on: RunsOn,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<Step>,
    cache: Vec<Cache>,
    artifacts: Vec<Artifact>,
    secrets: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledJobV5 {
    name: String,
    needs: Vec<u16>,
    spec: JobV5,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledPipelineV5 {
    on: Triggers,
    concurrency: Option<Concurrency>,
    jobs: Vec<CompiledJobV5>,
    digest: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV5 {
    source: PinnedSource,
    pipeline: CompiledPipelineV5,
    images: Vec<ImageRef>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobV3 {
    image: String,
    needs: Vec<String>,
    condition: Option<Expr>,
    runs_on: RunsOn,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<StepV4>,
    cache: Vec<CacheV3>,
    artifacts: Vec<Artifact>,
    secrets: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledJobV3 {
    name: String,
    needs: Vec<u16>,
    spec: JobV3,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledPipelineV3 {
    on: Triggers,
    concurrency: Option<Concurrency>,
    jobs: Vec<CompiledJobV3>,
    digest: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV3 {
    source: PinnedSource,
    pipeline: CompiledPipelineV3,
    images: Vec<ImageRef>,
}

impl From<JobV3> for Job {
    fn from(v3: JobV3) -> Job {
        Job {
            image: v3.image,
            needs: v3.needs,
            condition: v3.condition,
            runs_on: v3.runs_on,
            resources: v3.resources,
            timeout_secs: v3.timeout_secs,
            env: v3.env,
            workdir: v3.workdir,
            steps: v3.steps.into_iter().map(Step::from).collect(),
            cache: v3
                .cache
                .into_iter()
                .map(|c| Cache {
                    name: c.name,
                    class: Class::Dependencies,
                    key: c.key,
                    paths: c.paths,
                })
                .collect(),
            artifacts: v3.artifacts,
            secrets: v3.secrets,
            registry_auth: None,
        }
    }
}

impl From<StepV4> for Step {
    fn from(old: StepV4) -> Step {
        Step {
            id: old.id,
            run: old.run,
            condition: old.condition,
            shell: old.shell,
            env: old.env,
            secrets: Vec::new(),
            secret_files: Vec::new(),
            workdir: old.workdir,
            timeout_secs: old.timeout_secs,
        }
    }
}

impl From<RunSpecV4> for RunSpec {
    fn from(v4: RunSpecV4) -> RunSpec {
        RunSpec {
            source: v4.source,
            pipeline: CompiledPipeline {
                on: v4.pipeline.on,
                concurrency: v4.pipeline.concurrency,
                jobs: v4
                    .pipeline
                    .jobs
                    .into_iter()
                    .map(|j| CompiledJob {
                        name: j.name,
                        needs: j.needs,
                        spec: Job {
                            image: j.spec.image,
                            needs: j.spec.needs,
                            condition: j.spec.condition,
                            runs_on: j.spec.runs_on,
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env,
                            workdir: j.spec.workdir,
                            steps: j.spec.steps.into_iter().map(Step::from).collect(),
                            cache: j.spec.cache,
                            artifacts: j.spec.artifacts,
                            secrets: j.spec.secrets,
                            registry_auth: None,
                        },
                    })
                    .collect(),
                digest: v4.pipeline.digest,
            },
            images: v4.images,
        }
    }
}

impl From<RunSpecV5> for RunSpec {
    fn from(v5: RunSpecV5) -> RunSpec {
        RunSpec {
            source: v5.source,
            pipeline: CompiledPipeline {
                on: v5.pipeline.on,
                concurrency: v5.pipeline.concurrency,
                jobs: v5
                    .pipeline
                    .jobs
                    .into_iter()
                    .map(|j| CompiledJob {
                        name: j.name,
                        needs: j.needs,
                        spec: Job {
                            image: j.spec.image,
                            needs: j.spec.needs,
                            condition: j.spec.condition,
                            runs_on: j.spec.runs_on,
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env,
                            workdir: j.spec.workdir,
                            steps: j.spec.steps,
                            cache: j.spec.cache,
                            artifacts: j.spec.artifacts,
                            secrets: j.spec.secrets,
                            registry_auth: None,
                        },
                    })
                    .collect(),
                digest: v5.pipeline.digest,
            },
            images: v5.images,
        }
    }
}

impl From<RunSpecV3> for RunSpec {
    fn from(v3: RunSpecV3) -> RunSpec {
        RunSpec {
            source: v3.source,
            pipeline: CompiledPipeline {
                on: v3.pipeline.on,
                concurrency: v3.pipeline.concurrency,
                jobs: v3
                    .pipeline
                    .jobs
                    .into_iter()
                    .map(|j| CompiledJob {
                        name: j.name,
                        needs: j.needs,
                        spec: Job::from(j.spec),
                    })
                    .collect(),
                digest: v3.pipeline.digest,
            },
            images: v3.images,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepCommand {
    pub argv: Vec<String>,
    /// Worker SENTINEL_* variables come after these so a pipeline cannot spoof them.
    pub env: Vec<(String, String)>,
    pub secrets: Vec<String>,
    pub secret_files: Vec<crate::schema::SecretFile>,
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
        // Both workdirs are validated as normalised relative paths, so joining cannot escape.
        let workdir = match (&job.workdir, &step.workdir) {
            (None, None) => None,
            (Some(j), None) => Some(j.clone()),
            (None, Some(s)) => Some(s.clone()),
            (Some(j), Some(s)) => Some(format!("{j}/{s}")),
        };
        Self {
            argv,
            env,
            secrets: step.secrets.clone(),
            secret_files: step.secret_files.clone(),
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

    fn old_step(step: &Step) -> StepV4 {
        StepV4 {
            id: step.id.clone(),
            run: step.run.clone(),
            condition: step.condition.clone(),
            shell: step.shell,
            env: step.env.clone(),
            workdir: step.workdir.clone(),
            timeout_secs: step.timeout_secs,
        }
    }

    fn encode_v3(spec: &RunSpec) -> Vec<u8> {
        let shadow = RunSpecV3 {
            source: spec.source.clone(),
            pipeline: CompiledPipelineV3 {
                on: spec.pipeline.on.clone(),
                concurrency: spec.pipeline.concurrency.clone(),
                digest: spec.pipeline.digest,
                jobs: spec
                    .pipeline
                    .jobs
                    .iter()
                    .map(|j| CompiledJobV3 {
                        name: j.name.clone(),
                        needs: j.needs.clone(),
                        spec: JobV3 {
                            image: j.spec.image.clone(),
                            needs: j.spec.needs.clone(),
                            condition: j.spec.condition.clone(),
                            runs_on: j.spec.runs_on.clone(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.iter().map(old_step).collect(),
                            cache: j
                                .spec
                                .cache
                                .iter()
                                .map(|c| CacheV3 {
                                    name: c.name.clone(),
                                    key: c.key.clone(),
                                    paths: c.paths.clone(),
                                })
                                .collect(),
                            artifacts: j.spec.artifacts.clone(),
                            secrets: j.spec.secrets.clone(),
                        },
                    })
                    .collect(),
            },
            images: spec.images.clone(),
        };
        let mut out = vec![SPEC_FORMAT_READ_MIN];
        out.extend(postcard::to_allocvec(&shadow).unwrap());
        out
    }

    fn encode_v4(spec: &RunSpec) -> Vec<u8> {
        let shadow = RunSpecV4 {
            source: spec.source.clone(),
            pipeline: CompiledPipelineV4 {
                on: spec.pipeline.on.clone(),
                concurrency: spec.pipeline.concurrency.clone(),
                digest: spec.pipeline.digest,
                jobs: spec
                    .pipeline
                    .jobs
                    .iter()
                    .map(|j| CompiledJobV4 {
                        name: j.name.clone(),
                        needs: j.needs.clone(),
                        spec: JobV4 {
                            image: j.spec.image.clone(),
                            needs: j.spec.needs.clone(),
                            condition: j.spec.condition.clone(),
                            runs_on: j.spec.runs_on.clone(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.iter().map(old_step).collect(),
                            cache: j.spec.cache.clone(),
                            artifacts: j.spec.artifacts.clone(),
                            secrets: j.spec.secrets.clone(),
                        },
                    })
                    .collect(),
            },
            images: spec.images.clone(),
        };
        let mut out = vec![4];
        out.extend(postcard::to_allocvec(&shadow).unwrap());
        out
    }

    fn encode_v5(spec: &RunSpec) -> Vec<u8> {
        let shadow = RunSpecV5 {
            source: spec.source.clone(),
            pipeline: CompiledPipelineV5 {
                on: spec.pipeline.on.clone(),
                concurrency: spec.pipeline.concurrency.clone(),
                digest: spec.pipeline.digest,
                jobs: spec
                    .pipeline
                    .jobs
                    .iter()
                    .map(|j| CompiledJobV5 {
                        name: j.name.clone(),
                        needs: j.needs.clone(),
                        spec: JobV5 {
                            image: j.spec.image.clone(),
                            needs: j.spec.needs.clone(),
                            condition: j.spec.condition.clone(),
                            runs_on: j.spec.runs_on.clone(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.clone(),
                            cache: j.spec.cache.clone(),
                            artifacts: j.spec.artifacts.clone(),
                            secrets: j.spec.secrets.clone(),
                        },
                    })
                    .collect(),
            },
            images: spec.images.clone(),
        };
        let mut out = vec![5];
        out.extend(postcard::to_allocvec(&shadow).unwrap());
        out
    }

    fn full_spec() -> RunSpec {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/pipelines/valid/full.yml"
        ))
        .unwrap();
        RunSpec::new(
            PinnedSource::new("repo", SHA, None).unwrap(),
            compile_str(&text).unwrap(),
        )
        .unwrap()
    }

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
        let spec = full_spec();
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], SPEC_FORMAT);
        assert_eq!(RunSpec::decode(&bytes).unwrap(), spec);
        for bad_format in [0u8, 1, 2, 9, 255] {
            assert_eq!(
                RunSpec::decode(&[bad_format, 0]),
                Err(SpecError::Decode),
                "format {bad_format}"
            );
        }
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() - 1]),
            Err(SpecError::Decode)
        );
        assert_eq!(RunSpec::decode(&[]), Err(SpecError::Decode));
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() / 2]),
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
    fn run_spec_v3_blobs_decode_with_default_class() {
        let spec = full_spec();
        let v3 = encode_v3(&spec);
        assert_eq!(v3[0], 3);
        let decoded = RunSpec::decode(&v3).unwrap();
        for job in &decoded.pipeline.jobs {
            for c in &job.spec.cache {
                assert_eq!(c.class, Class::Dependencies);
            }
        }
        assert_eq!(decoded, spec);
        assert_eq!(RunSpec::decode(&v3[..v3.len() - 1]), Err(SpecError::Decode));
        assert_eq!(RunSpec::decode(&v3[..4]), Err(SpecError::Decode));
        let mut corrupt = v3.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        let _ = RunSpec::decode(&corrupt);
    }

    #[test]
    fn a_blob_with_trailing_bytes_is_not_a_spec() {
        let spec = full_spec();
        for blob in [spec.encode().unwrap(), encode_v3(&spec)] {
            assert!(RunSpec::decode(&blob).is_ok());
            for tail in [&[0xAAu8][..], &[0], &blob[1..]] {
                let longer = [blob.as_slice(), tail].concat();
                assert_eq!(
                    RunSpec::decode(&longer),
                    Err(SpecError::Decode),
                    "format {} + {} bytes",
                    blob[0],
                    tail.len()
                );
            }
        }
    }

    #[test]
    fn run_spec_v6_carries_registry_auth_and_secret_targets() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    secrets: [TOKEN, REGISTRY]\n    registry_auth: REGISTRY\n    cache:\n      - name: dl\n        class: downloads\n        key: k\n        paths: [/root/.cargo/registry]\n    steps:\n      - id: s\n        run: echo hi\n        secrets: [TOKEN]\n        secret_files: {TOKEN: config/token}\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.pipeline.jobs[0].spec.cache[0].class, Class::Downloads);
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], 6);
        let decoded = RunSpec::decode(&bytes).unwrap();
        assert_eq!(decoded, spec);
        let v5 = encode_v5(&spec);
        assert_eq!(v5[0], 5);
        let previous = RunSpec::decode(&v5).unwrap();
        assert_eq!(previous.pipeline.jobs[0].spec.registry_auth, None);
        assert_eq!(
            previous.pipeline.jobs[0].spec.steps[0].secret_files,
            spec.pipeline.jobs[0].spec.steps[0].secret_files
        );
    }

    #[test]
    fn run_spec_v4_decodes_with_empty_secret_targets() {
        let spec = full_spec();
        let v4 = encode_v4(&spec);
        assert_eq!(v4[0], 4);
        assert_eq!(RunSpec::decode(&v4).unwrap(), spec);
        assert_eq!(RunSpec::decode(&v4[..v4.len() - 1]), Err(SpecError::Decode));
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
