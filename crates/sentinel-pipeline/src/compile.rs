//! Deterministic compilation: validates cross-job references and the DAG,
//! fixes an execution order that depends only on the document (not on hash
//! seeds or declaration whims), and computes a content digest so identical
//! input always yields an identical compiled pipeline and identical runs
//! can be recognised.
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    expr::{Phase, Template},
    policy::Triggers,
    schema::{Job, Pipeline, Step},
};

pub const MAX_STEPS_TOTAL: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPipeline {
    pub on: Triggers,
    pub concurrency: Option<crate::schema::Concurrency>,
    /// Jobs in a canonical topological order: dependencies first; ties broken
    /// by name so the order is stable across edits elsewhere in the file.
    pub jobs: Vec<CompiledJob>,
    /// 128-bit digest of the canonical form.
    pub digest: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledJob {
    pub name: String,
    /// Indices into `jobs`, ascending; every index is smaller than this job's.
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
    /// An `if` or template references a job outside `needs` or a phase it cannot reach.
    Expression {
        path: String,
        message: &'static str,
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
            Self::Expression { path, message } => write!(f, "{path}: {message}"),
        }
    }
}
impl std::error::Error for CompileError {}

fn check_refs(path: String, refs: &[String], needs: &[String]) -> Result<(), CompileError> {
    match refs.iter().find(|r| !needs.contains(r)) {
        None => Ok(()),
        Some(_) => Err(CompileError::Expression {
            path,
            message: "needs.<job> may only name a job listed in this job's `needs`",
        }),
    }
}

fn check_template(
    path: String,
    t: &Template,
    needs: &[String],
    max: Phase,
) -> Result<(), CompileError> {
    if t.min_phase() > max {
        return Err(CompileError::Expression {
            path,
            message: "uses context that is not available where this value is rendered",
        });
    }
    let mut refs = Vec::new();
    t.referenced_needs(&mut refs);
    check_refs(path, &refs, needs)
}

fn check_job(name: &str, job: &Job) -> Result<(), CompileError> {
    if let Some(cond) = &job.condition {
        if cond.min_phase() > Phase::Schedule {
            return Err(CompileError::Expression {
                path: format!("jobs.{name}.if"),
                message: "job conditions cannot use hash_files; use a step condition",
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

pub fn compile(pipeline: Pipeline) -> Result<CompiledPipeline, CompileError> {
    let Pipeline {
        on,
        concurrency,
        jobs,
    } = pipeline;
    let total_steps: usize = jobs.iter().map(|(_, j)| j.steps.len()).sum();
    if total_steps > MAX_STEPS_TOTAL {
        return Err(CompileError::TooManySteps {
            limit: MAX_STEPS_TOTAL,
        });
    }
    // Canonical name order first; indices below refer to this order.
    let mut sorted: Vec<(String, Job)> = jobs;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let index_of = |name: &str| sorted.binary_search_by(|(n, _)| n.as_str().cmp(name)).ok();

    let n = sorted.len();
    let mut needs_idx: Vec<Vec<u16>> = Vec::with_capacity(n);
    for (name, job) in &sorted {
        check_job(name, job)?;
        let mut idx = Vec::with_capacity(job.needs.len());
        for dep in &job.needs {
            if dep == name {
                return Err(CompileError::SelfDependency { job: name.clone() });
            }
            let Some(i) = index_of(dep) else {
                return Err(CompileError::UnknownDependency {
                    job: name.clone(),
                    needs: dep.clone(),
                });
            };
            if idx.contains(&(i as u16)) {
                return Err(CompileError::DuplicateDependency {
                    job: name.clone(),
                    needs: dep.clone(),
                });
            }
            idx.push(i as u16);
        }
        idx.sort_unstable();
        needs_idx.push(idx);
    }

    // Kahn's algorithm with a name-ordered ready set: the smallest ready
    // name always goes next, which makes the order a pure function of the DAG.
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
    ready.sort_unstable_by(|a, b| b.cmp(a)); // pop() yields the smallest
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
    let digest = digest_of(&on, concurrency.as_ref(), &jobs);
    Ok(CompiledPipeline {
        on,
        concurrency,
        jobs,
        digest,
    })
}

/// FNV-1a 128 over a length-prefixed canonical serialisation. Not
/// cryptographic; used for equality of compiled specs, never for trust.
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
    fn encoded<T: serde::Serialize>(&mut self, v: &T) {
        // postcard is deterministic for a given type layout.
        let bytes = postcard::to_allocvec(v).unwrap_or_default();
        self.bytes(&bytes);
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

fn digest_step(d: &mut Digest, s: &Step) {
    d.str(&s.id);
    d.str(&s.run);
    d.encoded(&s.condition);
    d.u64(s.shell as u64);
    d.u64(s.env.len() as u64);
    for (k, v) in &s.env {
        d.str(k);
        d.str(v);
    }
    d.opt_str(s.workdir.as_deref());
    d.u64(s.timeout_secs.unwrap_or(0));
}

fn digest_of(
    on: &Triggers,
    concurrency: Option<&crate::schema::Concurrency>,
    jobs: &[CompiledJob],
) -> u128 {
    let mut d = Digest::new();
    d.str("sentinel.pipeline/2");
    d.u64(u64::from(on.push.is_some()));
    d.u64(u64::from(on.pull_request.is_some()));
    d.u64(u64::from(on.tag.is_some()));
    d.u64(u64::from(on.manual));
    for filter in [&on.push, &on.pull_request, &on.tag].into_iter().flatten() {
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
            d.encoded(&c.group);
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
        d.encoded(&s.condition);
        d.u64(s.runs_on.arch.map_or(u64::MAX, |a| a as u64));
        d.u64(s.runs_on.labels.len() as u64);
        for l in &s.runs_on.labels {
            d.str(l);
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
            digest_step(&mut d, st);
        }
        d.u64(s.cache.len() as u64);
        for c in &s.cache {
            d.str(&c.name);
            d.encoded(&c.key);
            d.u64(c.paths.len() as u64);
            for p in &c.paths {
                d.str(p);
            }
        }
        d.u64(s.secrets.len() as u64);
        for name in &s.secrets {
            d.str(name);
        }
        d.u64(s.artifacts.len() as u64);
        for a in &s.artifacts {
            d.str(&a.name);
            d.u64(a.paths.len() as u64);
            for p in &a.paths {
                d.str(p);
            }
            d.u64(a.when as u64);
            d.u64(a.retain_secs);
        }
    }
    d.0
}
