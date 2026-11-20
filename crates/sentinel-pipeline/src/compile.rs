use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    expr::{Phase, Template},
    input::Inputs,
    policy::Triggers,
    schema::{ArtifactWhen, Document, Job, Pipeline, Step},
};

pub const MAX_STEPS_TOTAL: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPipeline {
    /// `None` is the document's unnamed pipeline, whose check identity is the one schema 1 published.
    pub name: Option<String>,
    pub on: Triggers,
    pub concurrency: Option<crate::schema::Concurrency>,
    pub inputs: Inputs,
    pub jobs: Vec<CompiledJob>,
    pub digest: u128,
}

impl CompiledPipeline {
    /// The aggregate check this pipeline publishes: `sentinel / ci` unnamed, `sentinel / <name>` named.
    pub fn aggregate_check(&self) -> String {
        aggregate_check_name(self.name.as_deref())
    }

    /// One job's check. A named pipeline namespaces its jobs, so two pipelines of one repository
    /// can both have a `test` job without publishing over each other.
    pub fn job_check(&self, job: &str) -> String {
        job_check_name(self.name.as_deref(), job)
    }
}

/// `sentinel / ci` — the aggregate schema 1 has always published, kept byte for byte for a document
/// that declares no named pipelines.
pub const AGGREGATE_PREFIX: &str = "sentinel / ";
pub const DEFAULT_AGGREGATE: &str = "sentinel / ci";

pub fn aggregate_check_name(pipeline: Option<&str>) -> String {
    match pipeline {
        None => DEFAULT_AGGREGATE.to_owned(),
        Some(name) => {
            let mut out = String::with_capacity(AGGREGATE_PREFIX.len() + name.len());
            out.push_str(AGGREGATE_PREFIX);
            out.push_str(name);
            out
        }
    }
}

pub fn job_check_name(pipeline: Option<&str>, job: &str) -> String {
    let mut out = match pipeline {
        None => {
            let mut out = String::with_capacity(AGGREGATE_PREFIX.len() + job.len());
            out.push_str(AGGREGATE_PREFIX);
            out
        }
        Some(name) => {
            let mut out =
                String::with_capacity(AGGREGATE_PREFIX.len() + name.len() + job.len() + 3);
            out.push_str(AGGREGATE_PREFIX);
            out.push_str(name);
            out.push_str(" / ");
            out
        }
    };
    out.push_str(job);
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledJob {
    pub name: String,
    pub needs: Vec<u16>,
    pub spec: Job,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    UnknownDependency {
        job: String,
        needs: String,
    },
    SelfDependency {
        job: String,
    },
    DuplicateDependency {
        job: String,
        needs: String,
    },
    Cycle {
        jobs: Vec<String>,
    },
    DuplicateStepId {
        job: String,
        step: String,
    },
    DuplicateCacheName {
        job: String,
        name: String,
    },
    DuplicateArtifactName {
        job: String,
        name: String,
    },
    StepTimeoutExceedsJob {
        job: String,
        step: String,
    },
    TooManySteps {
        limit: usize,
    },
    Expression {
        path: String,
        message: String,
    },
    /// A job takes an artifact a job it does not need never declares.
    Handoff {
        job: String,
        from: String,
        artifact: String,
        reason: &'static str,
    },
    /// Canonical encoding failed. Hashing nothing instead would give two pipelines the same identity.
    Encoding,
    /// A namespace the document gives two meanings: the check a repository protects must name one.
    CheckNameConflict {
        name: String,
        first: String,
        second: String,
    },
    /// An event-driven or scheduled run cannot supply a value, so a required input would leave it invalid.
    RequiredInputWithoutDefault {
        pipeline: Option<String>,
        input: String,
    },
    /// An expression names an input its pipeline declares nothing about.
    UnknownInput {
        path: String,
        input: String,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDependency { job, needs } => {
                write!(f, "jobs.{job}.needs: `{needs}` is not a job")
            }
            Self::SelfDependency { job } => write!(f, "jobs.{job}.needs: job depends on itself"),
            Self::DuplicateDependency { job, needs } => {
                write!(f, "jobs.{job}.needs: `{needs}` listed twice")
            }
            Self::Cycle { jobs } => {
                write!(f, "jobs: dependency cycle through {}", jobs.join(" -> "))
            }
            Self::DuplicateStepId { job, step } => {
                write!(f, "jobs.{job}.steps: duplicate step id `{step}`")
            }
            Self::DuplicateCacheName { job, name } => {
                write!(f, "jobs.{job}.cache: duplicate cache name `{name}`")
            }
            Self::DuplicateArtifactName { job, name } => {
                write!(f, "jobs.{job}.artifacts: duplicate artifact name `{name}`")
            }
            Self::StepTimeoutExceedsJob { job, step } => {
                write!(
                    f,
                    "jobs.{job}.steps.{step}.timeout: exceeds the job timeout"
                )
            }
            Self::TooManySteps { limit } => write!(f, "jobs: more than {limit} steps in total"),
            Self::Handoff {
                job,
                from,
                artifact,
                reason,
            } => write!(f, "jobs.{job}.handoff: `{from}/{artifact}` {reason}"),
            Self::Expression { path, message } => write!(f, "{path}: {message}"),
            Self::Encoding => f.write_str("jobs: cannot encode the canonical form for the digest"),
            Self::CheckNameConflict {
                name,
                first,
                second,
            } => write!(
                f,
                "{second}: check `{name}` is also {first}; name one of them differently"
            ),
            Self::RequiredInputWithoutDefault { pipeline, input } => match pipeline {
                Some(p) => write!(
                    f,
                    "pipelines.{p}.inputs.{input}: a required input needs a default unless the pipeline runs only from a manual dispatch"
                ),
                None => write!(
                    f,
                    "inputs.{input}: a required input needs a default unless the pipeline runs only from a manual dispatch"
                ),
            },
            Self::UnknownInput { path, input } => {
                write!(
                    f,
                    "{path}: `inputs.{input}` names no input this pipeline declares"
                )
            }
        }
    }
}
impl std::error::Error for CompileError {}

fn check_refs(path: String, refs: &[String], needs: &[String]) -> Result<(), CompileError> {
    match refs.iter().find(|r| !needs.contains(r)) {
        None => Ok(()),
        Some(_) => Err(CompileError::Expression {
            path,
            message: "needs.<job> may only name a job listed in this job's `needs`".to_owned(),
        }),
    }
}

fn check_template(
    path: String,
    t: &Template,
    needs: &[String],
    inputs: &Inputs,
    max: Phase,
) -> Result<(), CompileError> {
    if t.min_phase() > max {
        return Err(CompileError::Expression {
            path,
            message: "uses context that is not available where this value is rendered".to_owned(),
        });
    }
    let mut refs = Vec::new();
    t.referenced_needs(&mut refs);
    check_refs(path.clone(), &refs, needs)?;
    let mut used = Vec::new();
    t.referenced_inputs(&mut used);
    if let Some(input) = used.iter().find(|name| inputs.get(name).is_none()) {
        return Err(CompileError::UnknownInput {
            path,
            input: input.clone(),
        });
    }
    Ok(())
}

fn check_job(name: &str, job: &Job, inputs: &Inputs) -> Result<(), CompileError> {
    if let Some(cond) = &job.condition {
        if cond.min_phase() > Phase::Schedule {
            return Err(CompileError::Expression {
                path: format!("jobs.{name}.if"),
                message: "job conditions cannot use hash_files; use a step condition".to_owned(),
            });
        }
        let mut refs = Vec::new();
        cond.referenced_needs(&mut refs);
        check_refs(format!("jobs.{name}.if"), &refs, &job.needs)?;
    }
    for (i, s) in job.steps.iter().enumerate() {
        if job.steps[..i].iter().any(|o| o.id == s.id) {
            return Err(CompileError::DuplicateStepId {
                job: name.into(),
                step: s.id.clone(),
            });
        }
        if let Some(cond) = &s.condition {
            let mut refs = Vec::new();
            cond.referenced_needs(&mut refs);
            check_refs(format!("jobs.{name}.steps.{}.if", s.id), &refs, &job.needs)?;
        }
        if s.timeout_secs.is_some_and(|t| t > job.timeout_secs) {
            return Err(CompileError::StepTimeoutExceedsJob {
                job: name.into(),
                step: s.id.clone(),
            });
        }
    }
    for (i, c) in job.cache.iter().enumerate() {
        check_template(
            format!("jobs.{name}.cache.{}.key", c.name),
            &c.key,
            &job.needs,
            inputs,
            Phase::Worker,
        )?;
        if job.cache[..i].iter().any(|o| o.name == c.name) {
            return Err(CompileError::DuplicateCacheName {
                job: name.into(),
                name: c.name.clone(),
            });
        }
    }
    for (i, a) in job.artifacts.iter().enumerate() {
        if job.artifacts[..i].iter().any(|o| o.name == a.name) {
            return Err(CompileError::DuplicateArtifactName {
                job: name.into(),
                name: a.name.clone(),
            });
        }
    }
    Ok(())
}

/// Every pipeline one document declares, in a fixed order: the unnamed one first, then the named
/// ones ascending by name.
pub fn compile_document(document: Document) -> Result<Vec<CompiledPipeline>, CompileError> {
    let Document { default, named } = document;
    let mut compiled: Vec<CompiledPipeline> = Vec::with_capacity(named.len() + 1);
    if let Some(pipeline) = default {
        compiled.push(compile_pipeline(None, pipeline)?);
    }
    for (name, pipeline) in named {
        compiled.push(compile_pipeline(Some(name), pipeline)?);
    }
    check_identities(&compiled)?;
    Ok(compiled)
}

/// A check name means one thing in a repository: two declarations cannot give it two meanings.
///
/// The rule reads nothing but the document. No name is reserved — a repository may call a pipeline
/// anything `[a-z0-9][a-z0-9_-]*` allows — because the only collision that exists is one the
/// document makes itself, between a named pipeline's aggregate and another pipeline's job, or
/// between the unnamed pipeline's `sentinel / ci` and a pipeline named `ci`.
fn check_identities(pipelines: &[CompiledPipeline]) -> Result<(), CompileError> {
    // The unnamed pipeline keeps the names it has always published, its own aggregate included: a
    // document that compiled before this schema reads the same way, so nothing it declared moves.
    let mut seen: Vec<(String, Option<String>, String)> = Vec::new();
    let mut record = |name: String,
                      pipeline: Option<&str>,
                      owner: String|
     -> Result<(), CompileError> {
        match seen.iter().find(|(existing, _, _)| *existing == name) {
            None => {
                seen.push((name, pipeline.map(str::to_owned), owner));
                Ok(())
            }
            Some((_, first_pipeline, first)) if *first_pipeline == pipeline.map(str::to_owned) => {
                Ok(())
            }
            Some((_, _, first)) => Err(CompileError::CheckNameConflict {
                name,
                first: first.clone(),
                second: owner,
            }),
        }
    };
    for pipeline in pipelines {
        let owner = match &pipeline.name {
            Some(name) => format!("pipelines.{name}"),
            None => "the unnamed pipeline".to_owned(),
        };
        record(
            pipeline.aggregate_check(),
            pipeline.name.as_deref(),
            owner.clone(),
        )?;
        for job in &pipeline.jobs {
            record(
                pipeline.job_check(&job.name),
                pipeline.name.as_deref(),
                format!("{owner}'s job `{}`", job.name),
            )?;
        }
    }
    Ok(())
}

pub fn compile_pipeline(
    name: Option<String>,
    pipeline: Pipeline,
) -> Result<CompiledPipeline, CompileError> {
    let Pipeline {
        on,
        concurrency,
        inputs,
        jobs,
    } = pipeline;
    // An event-driven or scheduled run has no caller to ask for a value, so a required input there
    // could only fail the run; the declaration is refused instead, before any run exists.
    if !on.manual_only()
        && let Some(input) = inputs.iter().find(|(_, spec)| spec.default.is_none())
    {
        return Err(CompileError::RequiredInputWithoutDefault {
            pipeline: name.clone(),
            input: input.0.clone(),
        });
    }
    let total_steps: usize = jobs.iter().map(|(_, j)| j.steps.len()).sum();
    if total_steps > MAX_STEPS_TOTAL {
        return Err(CompileError::TooManySteps {
            limit: MAX_STEPS_TOTAL,
        });
    }
    let mut sorted: Vec<(String, Job)> = jobs;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let index_of = |name: &str| sorted.binary_search_by(|(n, _)| n.as_str().cmp(name)).ok();

    let n = sorted.len();
    let mut needs_idx: Vec<Vec<u16>> = Vec::with_capacity(n);
    for (job_name, job) in &sorted {
        check_job(job_name, job, &inputs)?;
        let mut idx = Vec::with_capacity(job.needs.len());
        for dep in &job.needs {
            if dep == job_name {
                return Err(CompileError::SelfDependency {
                    job: job_name.clone(),
                });
            }
            let Some(i) = index_of(dep) else {
                return Err(CompileError::UnknownDependency {
                    job: job_name.clone(),
                    needs: dep.clone(),
                });
            };
            if idx.contains(&(i as u16)) {
                return Err(CompileError::DuplicateDependency {
                    job: job_name.clone(),
                    needs: dep.clone(),
                });
            }
            idx.push(i as u16);
        }
        idx.sort_unstable();
        needs_idx.push(idx);
    }

    // A handoff names an artifact of a job this job needs: the producer must have finished, and its artifact must
    // be one the schema of that job declares. A name that resolves to no declaration would deliver nothing.
    for (name, job) in &sorted {
        for handoff in &job.handoff {
            let Some(&from) = index_of(&handoff.from).as_ref() else {
                return Err(CompileError::UnknownDependency {
                    job: name.clone(),
                    needs: handoff.from.clone(),
                });
            };
            if name == &handoff.from {
                return Err(CompileError::SelfDependency { job: name.clone() });
            }
            let producer = &sorted[from].1;
            if !producer
                .artifacts
                .iter()
                .any(|a| a.name == handoff.artifact)
            {
                return Err(CompileError::Handoff {
                    job: name.clone(),
                    from: handoff.from.clone(),
                    artifact: handoff.artifact.clone(),
                    reason: "is not an artifact the producing job declares",
                });
            }
        }
    }

    // Smallest ready name first: the order is a pure function of the DAG.
    let mut indegree: Vec<u16> = needs_idx.iter().map(|d| d.len() as u16).collect();
    let mut dependents: Vec<Vec<u16>> = vec![Vec::new(); n];
    for (j, deps) in needs_idx.iter().enumerate() {
        for &d in deps {
            dependents[d as usize].push(j as u16);
        }
    }
    let mut ready: Vec<u16> = (0..n as u16)
        .filter(|&i| indegree[i as usize] == 0)
        .collect();
    ready.sort_unstable_by(|a, b| b.cmp(a));
    let mut order: Vec<u16> = Vec::with_capacity(n);
    let mut position = vec![u16::MAX; n];
    while let Some(i) = ready.pop() {
        position[i as usize] = order.len() as u16;
        order.push(i);
        let mut newly = Vec::new();
        for &d in &dependents[i as usize] {
            indegree[d as usize] -= 1;
            if indegree[d as usize] == 0 {
                newly.push(d);
            }
        }
        if !newly.is_empty() {
            ready.extend(newly);
            ready.sort_unstable_by(|a, b| b.cmp(a));
        }
    }
    if order.len() != n {
        let mut cycle: Vec<String> = sorted
            .iter()
            .enumerate()
            .filter(|(i, _)| position[*i] == u16::MAX)
            .map(|(_, (name, _))| name.clone())
            .collect();
        cycle.sort();
        return Err(CompileError::Cycle { jobs: cycle });
    }

    let mut compiled: Vec<Option<CompiledJob>> = (0..n).map(|_| None).collect();
    for (name_idx, (name, job)) in sorted.into_iter().enumerate() {
        let mut needs: Vec<u16> = needs_idx[name_idx]
            .iter()
            .map(|&d| position[d as usize])
            .collect();
        needs.sort_unstable();
        compiled[position[name_idx] as usize] = Some(CompiledJob {
            name,
            needs,
            spec: job,
        });
    }
    let jobs: Vec<CompiledJob> = compiled.into_iter().map(|j| j.expect("placed")).collect();
    let digest = digest_of(name.as_deref(), &on, concurrency.as_ref(), &inputs, &jobs)?;
    Ok(CompiledPipeline {
        name,
        on,
        concurrency,
        inputs,
        jobs,
        digest,
    })
}

/// Not cryptographic: equality of compiled specs only, never trust.
struct Digest(u128);

impl Digest {
    const fn new() -> Self {
        Self(0x6c62272e07bb014262b821756295c58d)
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        for &x in b {
            self.0 ^= x as u128;
            self.0 = self.0.wrapping_mul(0x0000000001000000000000000000013B);
        }
    }
    fn u64(&mut self, v: u64) {
        for x in v.to_le_bytes() {
            self.0 ^= x as u128;
            self.0 = self.0.wrapping_mul(0x0000000001000000000000000000013B);
        }
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn encoded<T: serde::Serialize>(&mut self, v: &T) -> Result<(), CompileError> {
        let bytes = postcard::to_allocvec(v).map_err(|_| CompileError::Encoding)?;
        self.bytes(&bytes);
        Ok(())
    }
    fn opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.u64(0),
            Some(s) => {
                self.u64(1);
                self.str(s);
            }
        }
    }
}

fn digest_step(d: &mut Digest, s: &Step) -> Result<(), CompileError> {
    d.str(&s.id);
    d.str(&s.run);
    d.encoded(&s.condition)?;
    d.u64(s.shell as u64);
    d.u64(s.env.len() as u64);
    for (k, v) in &s.env {
        d.str(k);
        d.str(v);
    }
    d.u64(s.secrets.len() as u64);
    for name in &s.secrets {
        d.str(name);
    }
    d.u64(s.secret_files.len() as u64);
    for file in &s.secret_files {
        d.str(&file.name);
        d.str(&file.path);
    }
    d.opt_str(s.workdir.as_deref());
    d.u64(s.timeout_secs.unwrap_or(0));
    // Only when stated, so the digests of pipelines written before outputs existed stay the same.
    if !s.outputs.is_empty() {
        d.str("outputs");
        d.u64(s.outputs.len() as u64);
        for name in &s.outputs {
            d.str(name);
        }
    }
    Ok(())
}

fn digest_of(
    name: Option<&str>,
    on: &Triggers,
    concurrency: Option<&crate::schema::Concurrency>,
    inputs: &Inputs,
    jobs: &[CompiledJob],
) -> Result<u128, CompileError> {
    let mut d = Digest::new();
    d.str("sentinel.pipeline/5");
    // Only when stated, so the digests a pipeline had before named pipelines stay the same.
    if let Some(name) = name {
        d.str("pipeline");
        d.str(name);
    }
    if !inputs.is_empty() {
        d.str("inputs");
        d.u64(inputs.len() as u64);
        for (input, spec) in inputs.iter() {
            d.str(input);
            d.encoded(&spec.kind)?;
            match &spec.default {
                None => d.u64(0),
                Some(value) => {
                    d.u64(1);
                    d.encoded(value)?;
                }
            }
        }
    }
    d.u64(u64::from(on.push.is_some()));
    d.u64(u64::from(on.pull_request.is_some()));
    d.u64(u64::from(on.merge_group.is_some()));
    d.u64(u64::from(on.tag.is_some()));
    d.u64(u64::from(on.manual));
    for filter in [&on.push, &on.pull_request, &on.merge_group, &on.tag]
        .into_iter()
        .flatten()
    {
        d.u64(filter.branches.len() as u64);
        for p in &filter.branches {
            d.str(p);
        }
        d.u64(filter.tags.len() as u64);
        for p in &filter.tags {
            d.str(p);
        }
    }
    match concurrency {
        None => d.u64(0),
        Some(c) => {
            d.u64(1);
            d.encoded(&c.group)?;
            d.u64(c.cancel_in_progress as u64);
        }
    }
    d.u64(jobs.len() as u64);
    for j in jobs {
        d.str(&j.name);
        d.u64(j.needs.len() as u64);
        for &n in &j.needs {
            d.u64(n as u64);
        }
        let s = &j.spec;
        d.str(&s.image);
        d.encoded(&s.condition)?;
        d.u64(s.runs_on.arch.map_or(u64::MAX, |a| a as u64));
        d.u64(s.runs_on.labels.len() as u64);
        for l in &s.runs_on.labels {
            d.str(l);
        }
        // Only when stated, so the digests of pipelines written before these fields stay the same.
        if s.runs_on.states_runtime() {
            d.str("runtime");
            d.u64(s.runs_on.os.map_or(u64::MAX, |o| o as u64));
            d.u64(s.runs_on.isolation.map_or(u64::MAX, |i| i as u64));
        }
        d.u64(s.resources.cpu_millis as u64);
        d.u64(s.resources.memory_bytes);
        d.u64(s.resources.disk_bytes);
        d.u64(s.timeout_secs);
        d.u64(s.env.len() as u64);
        for (k, v) in &s.env {
            d.str(k);
            d.str(v);
        }
        d.opt_str(s.workdir.as_deref());
        d.u64(s.steps.len() as u64);
        for st in &s.steps {
            digest_step(&mut d, st)?;
        }
        d.u64(s.cache.len() as u64);
        for c in &s.cache {
            d.str(&c.name);
            d.u64(u64::from(c.class.to_u8()));
            d.encoded(&c.key)?;
            d.u64(c.paths.len() as u64);
            for p in &c.paths {
                d.str(p);
            }
        }
        d.u64(s.secrets.len() as u64);
        for name in &s.secrets {
            d.str(name);
        }
        d.opt_str(s.registry_auth.as_deref());
        d.u64(s.artifacts.len() as u64);
        for a in &s.artifacts {
            d.str(&a.name);
            d.u64(a.paths.len() as u64);
            for p in &a.paths {
                d.str(p);
            }
            // A step trigger folds its step index into the same field, so it never collides with a verdict.
            d.u64(match a.when {
                ArtifactWhen::Success => 0,
                ArtifactWhen::Failure => 1,
                ArtifactWhen::Always => 2,
                ArtifactWhen::Step(step) => 3 + u64::from(step),
            });
            d.u64(a.retain_secs);
            d.u64(u64::from(a.required));
            d.opt_str(a.class.as_deref());
        }
        // Only when stated, so the digest of a pipeline that never opted in stays exactly as it was.
        if let Some(reuse) = &s.reuse {
            d.str("reuse");
            d.u64(reuse.inputs.len() as u64);
            for pattern in &reuse.inputs {
                d.str(pattern);
            }
            d.u64(reuse.paths.len() as u64);
            for path in &reuse.paths {
                d.str(path);
            }
        }
        if !s.outputs.is_empty() {
            d.str("job-outputs");
            d.u64(s.outputs.len() as u64);
            for name in &s.outputs {
                d.str(name);
            }
        }
        if !s.handoff.is_empty() {
            d.str("handoff");
            d.u64(s.handoff.len() as u64);
            for h in &s.handoff {
                d.str(&h.from);
                d.str(&h.artifact);
                d.str(&h.into);
            }
        }
        if let Some(f) = &s.finalize {
            d.str("finalize");
            d.str(&f.run);
            d.u64(f.shell as u64);
            d.u64(f.env.len() as u64);
            for (k, v) in &f.env {
                d.str(k);
                d.str(v);
            }
            d.opt_str(f.workdir.as_deref());
            d.u64(f.timeout_secs);
        }
    }
    Ok(d.0)
}

#[cfg(test)]
mod tests {
    use super::{CompileError, Digest};
    use serde::{Serialize, Serializer, ser::Error as _};

    #[test]
    fn serialization_failure_is_reported_as_encoding_error() {
        struct Fails;

        impl Serialize for Fails {
            fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(S::Error::custom("forced serialization failure"))
            }
        }

        let mut digest = Digest::new();
        assert_eq!(
            digest.encoded(&Fails),
            Err(CompileError::Encoding),
            "serializer failures must be encoding errors"
        );
    }
}
