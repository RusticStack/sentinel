//! The worker-phase expression context (W04): what a step's `if` and a
//! cache key can see once the pinned checkout exists.
//!
//! Every value comes from the controller's `JobContext` or the run spec;
//! `hash_files` reads the attempt's private workspace. The event facts
//! (`event.name|ref|base_ref|key|pr_number`) are recorded as the run's
//! provenance (G03); a field the event does not carry answers `null`, and a
//! field the run does not hold answers `Unresolved` so the attempt fails
//! preparation naming it rather than defaulting it.

use std::path::{Path, PathBuf};

use sentinel_link::session::JobContext;
use sentinel_pipeline::{
    RunSpec,
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase, Value},
};

pub struct WorkerContext<'a> {
    pub job: &'a JobContext,
    pub spec: &'a RunSpec,
    pub workspace: PathBuf,
}

impl<'a> WorkerContext<'a> {
    pub fn new(job: &'a JobContext, spec: &'a RunSpec, workspace: &Path) -> Self {
        WorkerContext {
            job,
            spec,
            workspace: workspace.to_path_buf(),
        }
    }
}

impl Context for WorkerContext<'_> {
    fn phase(&self) -> Phase {
        Phase::Worker
    }

    fn lookup(&self, path: &[String]) -> Lookup {
        let key: Vec<&str> = path.iter().map(String::as_str).collect();
        let event = &self.job.event;
        let value = match key.as_slice() {
            ["event", "sha"] => Value::Str(self.job.sha.clone()),
            ["event", "name"] => Value::Str(event.name.clone()),
            ["event", "ref"] => Value::Str(event.ref_name.clone()),
            ["event", "key"] => Value::Str(event.key.clone()),
            ["event", "base_ref"] => match &event.base_ref {
                Some(base) => Value::Str(base.clone()),
                None => Value::Null,
            },
            ["event", "pr_number"] => match event.pr_number {
                Some(number) => Value::Int(number as i64),
                None => Value::Null,
            },
            ["event", _] => return Lookup::Unresolved,
            ["repo", "id"] => Value::Str(self.job.repo.to_string()),
            ["repo", "name"] => Value::Str(self.job.repo_name.clone()),
            ["run", "id"] => Value::Str(self.job.run.to_string()),
            ["job", "id"] => Value::Str(self.job.job.to_string()),
            ["job", "name"] => Value::Str(self.job.job_name.clone()),
            ["needs", name, "result"] => match self.job.needs.iter().find(|(n, _)| n == name) {
                Some((_, outcome)) => Value::Str(outcome.as_str().to_owned()),
                None => return Lookup::Unresolved,
            },
            _ => return Lookup::Unresolved,
        };
        Lookup::Value(value)
    }

    fn dependency_summary(&self) -> Option<DependencySummary> {
        Some(DependencySummary {
            all_succeeded: self.job.needs.iter().all(|(_, o)| o.is_success()),
            any_failed: self.job.needs.iter().any(|(_, o)| !o.is_success()),
        })
    }

    fn cancelled(&self) -> Option<bool> {
        Some(self.job.cancelled)
    }

    fn hash_files(&self, patterns: &[&str]) -> Result<String, HashFilesError> {
        sentinel_pipeline::hash_files(&self.workspace, patterns)
    }
}
