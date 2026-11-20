use std::fmt;

use serde::{Deserialize, Serialize};

use crate::input::{InputValue, Inputs};

use sentinel_protocol::cache::Class;

use crate::{
    compile::{CompiledJob, CompiledPipeline},
    expr::{Expr, Template},
    policy::{RefFilter, Triggers},
    schema::{
        Arch, Artifact, ArtifactWhen, Cache, Concurrency, Job, Resources, Reuse, RunsOn, Shell,
        Step,
    },
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
    /// The values this run was given, ascending by name: the declarations' defaults plus whatever a
    /// manual dispatch supplied. They are not part of the digest or of any check identity.
    pub inputs: Vec<(String, InputValue)>,
    pub images: Vec<ImageRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecError {
    Image { job: usize, error: ImageError },
    Encode,
    Decode,
}

/// Format 12 adds a job's opt-in task-result reuse (`jobs.<name>.reuse`); format 11 adds a pipeline's
/// name and declared inputs with the values a run was given; format 10 adds `on.schedule`; format 9
/// adds `artifacts[].when: step:<id>`; format 8 adds `artifacts[].class`; format 7 adds `runs_on.os`
/// and `runs_on.isolation`. A spec that states none of them is written as 11, 10, 9, 8, 7 or 6, byte
/// for byte what earlier controllers wrote, so a worker that predates the newer fields keeps running it.
pub const SPEC_FORMAT: u8 = 12;

/// The format a spec that names a pipeline or states inputs takes; a worker below it refuses the spec
/// rather than run a pipeline it cannot tell apart from the unnamed one.
const SPEC_FORMAT_NAMED: u8 = 11;

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
            inputs: Vec::new(),
            images,
        })
    }

    /// The format `encode` writes for this spec: the lowest one that carries everything it states.
    pub fn format(&self) -> u8 {
        if self.pipeline.jobs.iter().any(|j| j.spec.reuse.is_some()) {
            SPEC_FORMAT
        } else if !self.inputs.is_empty()
            || self.pipeline.name.is_some()
            || !self.pipeline.inputs.is_empty()
        {
            SPEC_FORMAT_NAMED
        } else if self.pipeline.on.schedule {
            10
        } else if self
            .pipeline
            .jobs
            .iter()
            .any(|j| j.spec.artifacts.iter().any(|a| a.when.step().is_some()))
        {
            9
        } else if self
            .pipeline
            .jobs
            .iter()
            .any(|j| j.spec.artifacts.iter().any(|a| a.class.is_some()))
        {
            8
        } else if self
            .pipeline
            .jobs
            .iter()
            .any(|j| j.spec.runs_on.states_runtime())
        {
            7
        } else {
            6
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SpecError> {
        let format = self.format();
        let body = match format {
            SPEC_FORMAT => postcard::to_allocvec(&RunSpecV11::from(self)),
            6 => postcard::to_allocvec(&RunSpecV6::from(self)),
            7 => postcard::to_allocvec(&RunSpecV7::from(self)),
            10 => postcard::to_allocvec(&RunSpecV9::from(self)),
            11 => postcard::to_allocvec(&RunSpecV10::from(self)),
            _ => postcard::to_allocvec(&RunSpecV8::from(self)),
        };
        body.map(|body| {
            let mut out = Vec::with_capacity(body.len() + 1);
            out.push(format);
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
            Some((&SPEC_FORMAT, body)) => whole::<RunSpecV11>(body).map(RunSpec::from),
            Some((&SPEC_FORMAT_NAMED, body)) => whole::<RunSpecV10>(body).map(RunSpec::from),
            Some((&10, body)) => whole::<RunSpecV9>(body).map(RunSpec::from),
            // Format 9 is format 8's layout: the only difference is what `when` may hold, and this
            // reader takes both. A spec that states a newer field moves the byte, so a reader that
            // predates it refuses the spec there instead of misreading it.
            Some((&9, body)) => whole::<RunSpecV8>(body).map(RunSpec::from),
            Some((&8, body)) => whole::<RunSpecV8>(body).map(RunSpec::from),
            Some((&7, body)) => whole::<RunSpecV7>(body).map(RunSpec::from),
            Some((&6, body)) => whole::<RunSpecV6>(body).map(RunSpec::from),
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

/// `runs_on` through format 6.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunsOnV1 {
    arch: Option<Arch>,
    labels: Vec<String>,
}

impl From<RunsOnV1> for RunsOn {
    fn from(old: RunsOnV1) -> RunsOn {
        RunsOn {
            arch: old.arch,
            labels: old.labels,
            os: None,
            isolation: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JobV6 {
    image: String,
    needs: Vec<String>,
    condition: Option<Expr>,
    runs_on: RunsOnV1,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<Step>,
    cache: Vec<Cache>,
    artifacts: Vec<ArtifactV7>,
    secrets: Vec<String>,
    registry_auth: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledJobV6 {
    name: String,
    needs: Vec<u16>,
    spec: JobV6,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledPipelineV6 {
    on: TriggersV6,
    concurrency: Option<Concurrency>,
    jobs: Vec<CompiledJobV6>,
    digest: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV6 {
    source: PinnedSource,
    pipeline: CompiledPipelineV6,
    images: Vec<ImageRef>,
}

/// Only for specs that state no OS or isolation (`RunSpec::format` is 6), which lose nothing here.
impl From<&RunSpec> for RunSpecV6 {
    fn from(spec: &RunSpec) -> RunSpecV6 {
        RunSpecV6 {
            source: spec.source.clone(),
            pipeline: CompiledPipelineV6 {
                on: TriggersV6::from(&spec.pipeline.on),
                concurrency: spec.pipeline.concurrency.clone(),
                jobs: spec
                    .pipeline
                    .jobs
                    .iter()
                    .map(|j| CompiledJobV6 {
                        name: j.name.clone(),
                        needs: j.needs.clone(),
                        spec: JobV6 {
                            image: j.spec.image.clone(),
                            needs: j.spec.needs.clone(),
                            condition: j.spec.condition.clone(),
                            runs_on: RunsOnV1 {
                                arch: j.spec.runs_on.arch,
                                labels: j.spec.runs_on.labels.clone(),
                            },
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.clone(),
                            cache: j.spec.cache.clone(),
                            artifacts: j.spec.artifacts.iter().map(ArtifactV7::from).collect(),
                            secrets: j.spec.secrets.clone(),
                            registry_auth: j.spec.registry_auth.clone(),
                        },
                    })
                    .collect(),
                digest: spec.pipeline.digest,
            },
            images: spec.images.clone(),
        }
    }
}

impl From<RunSpecV6> for RunSpec {
    fn from(v6: RunSpecV6) -> RunSpec {
        RunSpec {
            inputs: Vec::new(),
            source: v6.source,
            pipeline: CompiledPipeline {
                name: None,
                inputs: Inputs::default(),
                on: v6.pipeline.on.into(),
                concurrency: v6.pipeline.concurrency,
                jobs: v6
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
                            runs_on: j.spec.runs_on.into(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env,
                            workdir: j.spec.workdir,
                            steps: j.spec.steps,
                            cache: j.spec.cache,
                            artifacts: j.spec.artifacts.into_iter().map(Artifact::from).collect(),
                            reuse: None,
                            secrets: j.spec.secrets,
                            registry_auth: j.spec.registry_auth,
                        },
                    })
                    .collect(),
                digest: v6.pipeline.digest,
            },
            images: v6.images,
        }
    }
}

/// The artifact layout of formats 3 to 7: everything a declaration stated before `class`. Its `when` never holds
/// a step trigger there: `RunSpec::format` writes such a spec as format 9, whose body a reader predating it refuses
/// at the leading byte rather than misreading the enum.
#[derive(Debug, Serialize, Deserialize)]
struct ArtifactV7 {
    name: String,
    paths: Vec<String>,
    when: ArtifactWhen,
    retain_secs: u64,
    required: bool,
}

impl From<ArtifactV7> for Artifact {
    fn from(old: ArtifactV7) -> Artifact {
        Artifact {
            name: old.name,
            paths: old.paths,
            when: old.when,
            retain_secs: old.retain_secs,
            required: old.required,
            class: None,
        }
    }
}

impl From<&Artifact> for ArtifactV7 {
    fn from(new: &Artifact) -> ArtifactV7 {
        ArtifactV7 {
            name: new.name.clone(),
            paths: new.paths.clone(),
            when: new.when,
            retain_secs: new.retain_secs,
            required: new.required,
        }
    }
}

/// Format 7: the whole spec as it stood before artifacts carried a class.
#[derive(Debug, Serialize, Deserialize)]
struct JobV7 {
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
    artifacts: Vec<ArtifactV7>,
    secrets: Vec<String>,
    registry_auth: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledJobV7 {
    name: String,
    needs: Vec<u16>,
    spec: JobV7,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledPipelineV7 {
    on: TriggersV6,
    concurrency: Option<Concurrency>,
    jobs: Vec<CompiledJobV7>,
    digest: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV7 {
    source: PinnedSource,
    pipeline: CompiledPipelineV7,
    images: Vec<ImageRef>,
}

impl From<&RunSpec> for RunSpecV7 {
    fn from(spec: &RunSpec) -> RunSpecV7 {
        RunSpecV7 {
            source: spec.source.clone(),
            pipeline: CompiledPipelineV7 {
                on: TriggersV6::from(&spec.pipeline.on),
                concurrency: spec.pipeline.concurrency.clone(),
                jobs: spec
                    .pipeline
                    .jobs
                    .iter()
                    .map(|j| CompiledJobV7 {
                        name: j.name.clone(),
                        needs: j.needs.clone(),
                        spec: JobV7 {
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
                            artifacts: j.spec.artifacts.iter().map(ArtifactV7::from).collect(),
                            secrets: j.spec.secrets.clone(),
                            registry_auth: j.spec.registry_auth.clone(),
                        },
                    })
                    .collect(),
                digest: spec.pipeline.digest,
            },
            images: spec.images.clone(),
        }
    }
}

impl From<RunSpecV7> for RunSpec {
    fn from(v7: RunSpecV7) -> RunSpec {
        RunSpec {
            inputs: Vec::new(),
            source: v7.source,
            pipeline: CompiledPipeline {
                name: None,
                inputs: Inputs::default(),
                on: v7.pipeline.on.into(),
                concurrency: v7.pipeline.concurrency,
                jobs: v7
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
                            artifacts: j.spec.artifacts.into_iter().map(Artifact::from).collect(),
                            reuse: None,
                            secrets: j.spec.secrets,
                            registry_auth: j.spec.registry_auth,
                        },
                    })
                    .collect(),
                digest: v7.pipeline.digest,
            },
            images: v7.images,
        }
    }
}

/// Format 8: the format-7 layout plus one class per artifact declaration, in order.
#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV8 {
    base: RunSpecV7,
    classes: Vec<Option<String>>,
}

impl From<&RunSpec> for RunSpecV8 {
    fn from(spec: &RunSpec) -> RunSpecV8 {
        RunSpecV8 {
            base: RunSpecV7::from(spec),
            classes: spec
                .pipeline
                .jobs
                .iter()
                .flat_map(|j| j.spec.artifacts.iter().map(|a| a.class.clone()))
                .collect(),
        }
    }
}

impl From<RunSpecV8> for RunSpec {
    fn from(v8: RunSpecV8) -> RunSpec {
        let mut spec = RunSpec::from(v8.base);
        let mut classes = v8.classes.into_iter();
        for job in &mut spec.pipeline.jobs {
            for artifact in &mut job.spec.artifacts {
                artifact.class = classes.next().flatten();
            }
        }
        spec
    }
}

/// Format 11: the format-9 layout plus the pipeline's name, its declared inputs and the values this
/// run was given. A reader that predates it refuses the leading byte instead of misreading a name.
/// Format 12: format 11's layout plus each opted-in job's reuse declaration, by job index.
///
/// The declarations ride beside the job graph rather than inside it, so the jobs themselves keep the
/// format-8 layout a worker below this format still reads. `reuse` is ascending by job index and names
/// no job twice; a spec that states none is written as format 11.
#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV11 {
    base: RunSpecV10,
    reuse: Vec<(u32, Reuse)>,
}

impl From<&RunSpec> for RunSpecV11 {
    fn from(spec: &RunSpec) -> RunSpecV11 {
        RunSpecV11 {
            base: RunSpecV10::from(spec),
            reuse: spec
                .pipeline
                .jobs
                .iter()
                .enumerate()
                .filter_map(|(index, job)| {
                    job.spec
                        .reuse
                        .clone()
                        .map(|declared| (u32::try_from(index).unwrap_or(u32::MAX), declared))
                })
                .collect(),
        }
    }
}

impl From<RunSpecV11> for RunSpec {
    fn from(v11: RunSpecV11) -> RunSpec {
        let mut spec = RunSpec::from(v11.base);
        for (index, reuse) in v11.reuse {
            if let Some(job) = spec.pipeline.jobs.get_mut(index as usize) {
                job.spec.reuse = Some(reuse);
            }
        }
        spec
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV10 {
    base: RunSpecV9,
    name: Option<String>,
    inputs: Inputs,
    values: Vec<(String, InputValue)>,
}

impl From<&RunSpec> for RunSpecV10 {
    fn from(spec: &RunSpec) -> RunSpecV10 {
        RunSpecV10 {
            base: RunSpecV9::from(spec),
            name: spec.pipeline.name.clone(),
            inputs: spec.pipeline.inputs.clone(),
            values: spec.inputs.clone(),
        }
    }
}

impl From<RunSpecV10> for RunSpec {
    fn from(v10: RunSpecV10) -> RunSpec {
        let mut spec = RunSpec::from(v10.base);
        spec.pipeline.name = v10.name;
        spec.pipeline.inputs = v10.inputs;
        spec.inputs = v10.values;
        spec
    }
}

/// Format 10: the format-8 layout plus the trigger set a scheduled pipeline states.
#[derive(Debug, Serialize, Deserialize)]
struct RunSpecV9 {
    base: RunSpecV8,
    on: Triggers,
}

impl From<&RunSpec> for RunSpecV9 {
    fn from(spec: &RunSpec) -> RunSpecV9 {
        RunSpecV9 {
            base: RunSpecV8::from(spec),
            on: spec.pipeline.on.clone(),
        }
    }
}

impl From<RunSpecV9> for RunSpec {
    fn from(v9: RunSpecV9) -> RunSpec {
        let mut spec = RunSpec::from(v9.base);
        spec.pipeline.on = v9.on;
        spec
    }
}

/// The trigger set of every format before 10: everything a pipeline could declare before `schedule`.
#[derive(Debug, Serialize, Deserialize)]
struct TriggersV6 {
    push: Option<RefFilter>,
    pull_request: Option<RefFilter>,
    merge_group: Option<RefFilter>,
    tag: Option<RefFilter>,
    manual: bool,
}

impl From<&Triggers> for TriggersV6 {
    fn from(on: &Triggers) -> TriggersV6 {
        TriggersV6 {
            push: on.push.clone(),
            pull_request: on.pull_request.clone(),
            merge_group: on.merge_group.clone(),
            tag: on.tag.clone(),
            manual: on.manual,
        }
    }
}

impl From<TriggersV6> for Triggers {
    fn from(v6: TriggersV6) -> Triggers {
        Triggers {
            push: v6.push,
            pull_request: v6.pull_request,
            merge_group: v6.merge_group,
            tag: v6.tag,
            manual: v6.manual,
            schedule: false,
        }
    }
}

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
    runs_on: RunsOnV1,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<StepV4>,
    cache: Vec<Cache>,
    artifacts: Vec<ArtifactV7>,
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
    on: TriggersV6,
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
    runs_on: RunsOnV1,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<Step>,
    cache: Vec<Cache>,
    artifacts: Vec<ArtifactV7>,
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
    on: TriggersV6,
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
    runs_on: RunsOnV1,
    resources: Resources,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    steps: Vec<StepV4>,
    cache: Vec<CacheV3>,
    artifacts: Vec<ArtifactV7>,
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
    on: TriggersV6,
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
            runs_on: v3.runs_on.into(),
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
            artifacts: v3.artifacts.into_iter().map(Artifact::from).collect(),
            secrets: v3.secrets,
            registry_auth: None,
            reuse: None,
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
            inputs: Vec::new(),
            source: v4.source,
            pipeline: CompiledPipeline {
                name: None,
                inputs: Inputs::default(),
                on: v4.pipeline.on.into(),
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
                            runs_on: j.spec.runs_on.into(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env,
                            workdir: j.spec.workdir,
                            steps: j.spec.steps.into_iter().map(Step::from).collect(),
                            cache: j.spec.cache,
                            artifacts: j.spec.artifacts.into_iter().map(Artifact::from).collect(),
                            reuse: None,
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
            inputs: Vec::new(),
            source: v5.source,
            pipeline: CompiledPipeline {
                name: None,
                inputs: Inputs::default(),
                on: v5.pipeline.on.into(),
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
                            runs_on: j.spec.runs_on.into(),
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env,
                            workdir: j.spec.workdir,
                            steps: j.spec.steps,
                            cache: j.spec.cache,
                            artifacts: j.spec.artifacts.into_iter().map(Artifact::from).collect(),
                            reuse: None,
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
            inputs: Vec::new(),
            source: v3.source,
            pipeline: CompiledPipeline {
                name: None,
                inputs: Inputs::default(),
                on: v3.pipeline.on.into(),
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
                on: TriggersV6::from(&spec.pipeline.on),
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
                            runs_on: RunsOnV1 {
                                arch: j.spec.runs_on.arch,
                                labels: j.spec.runs_on.labels.clone(),
                            },
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
                            artifacts: j.spec.artifacts.iter().map(ArtifactV7::from).collect(),
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
                on: TriggersV6::from(&spec.pipeline.on),
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
                            runs_on: RunsOnV1 {
                                arch: j.spec.runs_on.arch,
                                labels: j.spec.runs_on.labels.clone(),
                            },
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.iter().map(old_step).collect(),
                            cache: j.spec.cache.clone(),
                            artifacts: j.spec.artifacts.iter().map(ArtifactV7::from).collect(),
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
                on: TriggersV6::from(&spec.pipeline.on),
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
                            runs_on: RunsOnV1 {
                                arch: j.spec.runs_on.arch,
                                labels: j.spec.runs_on.labels.clone(),
                            },
                            resources: j.spec.resources,
                            timeout_secs: j.spec.timeout_secs,
                            env: j.spec.env.clone(),
                            workdir: j.spec.workdir.clone(),
                            steps: j.spec.steps.clone(),
                            cache: j.spec.cache.clone(),
                            artifacts: j.spec.artifacts.iter().map(ArtifactV7::from).collect(),
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

    /// The same spec as a format before 8 decodes it: the artifact classes are not in the blob.
    fn without_classes(spec: &RunSpec) -> RunSpec {
        let mut plain = spec.clone();
        for job in &mut plain.pipeline.jobs {
            for artifact in &mut job.spec.artifacts {
                artifact.class = None;
            }
        }
        plain
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
        assert_eq!(
            bytes[0], 8,
            "the fixture's artifact states a class: the newest format"
        );
        let plain = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps: [{id: s, run: 'true'}]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let plain_bytes = plain.encode().unwrap();
        assert_eq!(
            plain_bytes[0], 6,
            "no OS, isolation or artifact class stated: the format earlier workers read"
        );
        assert_eq!(RunSpec::decode(&plain_bytes).unwrap(), plain);
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
            for a in &job.spec.artifacts {
                assert_eq!(a.class, None, "a format-3 blob states no artifact class");
            }
        }
        assert_eq!(decoded, without_classes(&spec));
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
    fn a_stated_os_or_isolation_is_format_7_and_round_trips() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    runs_on: {labels: [kvm], isolation: microvm}\n    steps:\n      - id: s\n        run: echo hi\n  b:\n    image: busybox\n    steps:\n      - id: s\n        run: echo hi\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.format(), 7, "no artifact states a class");
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], 7);
        let decoded = RunSpec::decode(&bytes).unwrap();
        assert_eq!(decoded, spec);
        let a = &decoded.pipeline.jobs[0].spec.runs_on;
        assert_eq!(a.isolation, Some(crate::schema::Isolation::Microvm));
        assert_eq!(a.os, None);
        assert_eq!(a.labels, ["kvm"]);
        assert!(!decoded.pipeline.jobs[1].spec.runs_on.states_runtime());
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() - 1]),
            Err(SpecError::Decode)
        );
    }

    #[test]
    fn an_artifact_class_is_format_8_and_round_trips() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    runs_on: {labels: [kvm], isolation: microvm}\n    artifacts:\n      - {name: log, paths: [out], class: debug}\n      - {name: plain, paths: [out]}\n    steps:\n      - id: s\n        run: echo hi\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.format(), 8, "no artifact carries a step trigger");
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], 8);
        let decoded = RunSpec::decode(&bytes).unwrap();
        assert_eq!(decoded, spec);
        assert_eq!(
            decoded.pipeline.jobs[0]
                .spec
                .artifacts
                .iter()
                .map(|a| a.class.as_deref())
                .collect::<Vec<_>>(),
            [Some("debug"), None]
        );
        assert_eq!(
            decoded.pipeline.jobs[0].spec.runs_on.os, None,
            "format 8 keeps what format 7 added"
        );
        assert_eq!(
            decoded.pipeline.jobs[0].spec.runs_on.isolation,
            Some(crate::schema::Isolation::Microvm)
        );
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() - 1]),
            Err(SpecError::Decode)
        );
        let mut corrupt = bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        let _ = RunSpec::decode(&corrupt);
    }

    #[test]
    fn a_schedule_trigger_is_format_10_and_round_trips() {
        let text = "schema: 1\non: [push, schedule]\njobs:\n  a:\n    image: busybox\n    steps:\n      - id: s\n        run: echo hi\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.format(), 10);
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], 10);
        let decoded = RunSpec::decode(&bytes).unwrap();
        assert_eq!(decoded, spec);
        assert!(decoded.pipeline.on.schedule && decoded.pipeline.on.push.is_some());
        // Format 9 is format 8's layout: a reader still decodes a spec that states no schedule.
        let plain = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str("schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps:\n      - id: s\n        run: echo hi\n")
                .unwrap(),
        )
        .unwrap();
        let bytes = plain.encode().unwrap();
        assert_eq!(
            bytes[0], 6,
            "a spec that states nothing newer is written as format 6"
        );
        assert_eq!(RunSpec::decode(&bytes).unwrap(), plain);
    }

    #[test]
    fn a_step_trigger_is_format_9_and_round_trips() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    artifacts:\n      - {name: early, paths: [out], when: 'step:first'}\n      - {name: later, paths: [out], when: success, class: debug}\n    steps:\n      - id: first\n        run: echo hi\n      - id: second\n        run: echo hi\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.format(), 9);
        let bytes = spec.encode().unwrap();
        assert_eq!(bytes[0], 9);
        let decoded = RunSpec::decode(&bytes).unwrap();
        assert_eq!(decoded, spec);
        assert_eq!(
            decoded.pipeline.jobs[0]
                .spec
                .artifacts
                .iter()
                .map(|a| (a.when, a.class.as_deref()))
                .collect::<Vec<_>>(),
            [
                (ArtifactWhen::Step(0), None),
                (ArtifactWhen::Success, Some("debug"))
            ],
            "format 9 keeps what formats 7 and 8 added"
        );
        assert_eq!(
            RunSpec::decode(&bytes[..bytes.len() - 1]),
            Err(SpecError::Decode)
        );
    }

    #[test]
    fn a_stated_class_without_a_step_trigger_stays_format_8() {
        let text = "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    artifacts:\n      - {name: log, paths: [out], class: debug}\n    steps:\n      - id: s\n        run: echo hi\n";
        let spec = RunSpec::new(
            PinnedSource::new("r", SHA, None).unwrap(),
            compile_str(text).unwrap(),
        )
        .unwrap();
        assert_eq!(spec.format(), 8);
        assert_eq!(spec.encode().unwrap()[0], 8);
    }

    #[test]
    fn run_spec_v4_decodes_with_empty_secret_targets() {
        let spec = full_spec();
        let v4 = encode_v4(&spec);
        assert_eq!(v4[0], 4);
        assert_eq!(RunSpec::decode(&v4).unwrap(), without_classes(&spec));
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
