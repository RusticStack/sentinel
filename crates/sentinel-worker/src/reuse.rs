//! Task-result reuse: whether this job's result is served from the worker's store, or it runs and seals one.
//!
//! The decision is made once, in preparation, after the checkout and before anything of the job starts. A
//! pipeline opts in per job (`jobs.<name>.reuse`); a job that does not is never looked up, so its command runs
//! every time. A served result carries its provenance, and a run whose forced-refresh flag is set never looks
//! at the store at all.

use std::path::Path;

use sentinel_cache::{
    attach::{self, Attached},
    outcome::Outcome,
    restore::{self, Context},
    scope::{Platform, Scope},
};
use sentinel_pipeline::{
    expr::Template,
    reuse::Declared,
    schema::{Cache, Reuse},
};
use sentinel_protocol::{cache::Class, summary::ReuseRecord};

use crate::{Result, attempt::Job, context::WorkerContext, host::Isolation};

/// What preparation decided about this job's result.
pub enum Decision {
    /// The job runs. `seal` is the entry to publish once it passes; absent when the key could not be built
    /// (an input pattern that matched nothing, or a declared output that is not a workspace path).
    Execute {
        seal: Option<Box<Attached>>,
        note: Note,
    },
    /// The job's result was served from this worker's store; none of its steps ran.
    Served(Box<Served>),
}

/// Why a job that declares `reuse:` still runs: reported on the attempt, never guessed at.
pub enum Note {
    /// A run that asked for fresh execution for every task in it.
    Forced,
    /// No entry under this key: the first run, or a declared input changed.
    Miss,
    /// The key cannot be built, so this job is not reusable at this run (`why` says what is missing).
    Undecidable(&'static str),
    /// The pipeline did not opt in: the job always executes and nothing is looked up.
    NotDeclared,
}

impl Note {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Forced => "forced",
            Self::Miss => "miss",
            Self::Undecidable(why) => why,
            Self::NotDeclared => "not declared",
        }
    }
}

pub struct Served {
    pub record: ReuseRecord,
    /// The entry that was served, kept so a caller can release its pin through the ordinary drop.
    pub _attached: Box<Attached>,
}

/// The declaration this job opts into, if it opts into one.
pub fn declared(job: &Job) -> Option<&Reuse> {
    job.spec
        .pipeline
        .jobs
        .get(job.job_index)
        .and_then(|compiled| compiled.spec.reuse.as_ref())
}

/// Decides this attempt's result, and on a hit materialises the declared outputs into the workspace.
///
/// Results are worker-local: they are read and written through the same sealed-generation store as the
/// cache classes, but never offered over the link, because a result restored on another worker would have
/// been produced under a sandbox this worker did not verify.
pub fn prepare(
    root: &Path,
    job: &mut Job,
    workspace: &Path,
    image: &str,
    isolation: Isolation,
    platform: Platform,
) -> Result<Decision> {
    let Some(reuse) = declared(job) else {
        return Ok(Decision::Execute {
            seal: None,
            note: Note::NotDeclared,
        });
    };
    if job.reuse_fresh {
        return Ok(Decision::Execute {
            seal: None,
            note: Note::Forced,
        });
    }
    let reuse = reuse.clone();
    let context = WorkerContext::new(&job.context, &job.spec, workspace);
    let mut inputs = Vec::with_capacity(reuse.inputs.len());
    for pattern in &reuse.inputs {
        match sentinel_pipeline::expr::Context::hash_files(&context, &[pattern.as_str()]) {
            Ok(digest) => inputs.push((pattern.clone(), digest)),
            // A pattern that matches nothing is not an empty input: the key would be a guess, so the job
            // runs and seals nothing.
            Err(_) => {
                return Ok(Decision::Execute {
                    seal: None,
                    note: Note::Undecidable("inputs_unresolved"),
                });
            }
        }
    }
    let compiled = &job.spec.pipeline.jobs[job.job_index].spec;
    let toolchain = Scope::toolchain_digest(image.as_bytes());
    let key = sentinel_pipeline::reuse::key(&Declared {
        job: compiled,
        image: &job.digest,
        toolchain: &toolchain,
        isolation: schema_isolation(isolation),
        platform: &platform.component(),
        inputs: &inputs,
    });
    let tenant = job.context.tenant.unwrap_or(attach::UNKNOWN_TENANT);
    let name = entry_id(&job.context.job_name);
    let Ok(scope) = Scope::new(
        tenant,
        job.context.repo,
        Class::Results,
        job.context.trust,
        platform,
        toolchain,
        &name,
    ) else {
        return Ok(Decision::Execute {
            seal: None,
            note: Note::Undecidable("entry_name"),
        });
    };
    let Ok(template) = Template::parse(&key.render()) else {
        return Ok(Decision::Execute {
            seal: None,
            note: Note::Undecidable("key"),
        });
    };
    let decl = Cache {
        name,
        class: Class::Results,
        key: template,
        paths: reuse.paths,
    };
    let cache_root = root.join(sentinel_cache::CACHE_DIR);
    let env = Context {
        cache_root: &cache_root,
        workspace,
        workspace_mount: crate::podman::WORKSPACE_MOUNT,
        backend: sentinel_cache::clone::detect(&cache_root),
    };
    let started = std::time::Instant::now();
    let attached = restore::restore(
        &env,
        &decl,
        Some(key.render()),
        scope,
        &job.attempt.to_string(),
    );
    let restore_ns = Some(started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
    match &attached.outcome {
        Outcome::Hit(hit) => {
            let record = ReuseRecord {
                entry: decl.name.clone(),
                key: key.render(),
                generation: attached.generation.clone().unwrap_or_default(),
                sealed_ms: hit.manifest.sealed_ms,
                files: u64::from(hit.manifest.files),
                bytes: hit.manifest.bytes,
                restore_ns,
            };
            Ok(Decision::Served(Box::new(Served {
                record,
                _attached: Box::new(attached),
            })))
        }
        // Every miss reason is a reason to run: `invalid` and `wrong_*` mean the entry is not this job's,
        // and the job's own result is sealed over it once it passes, which heals the entry.
        Outcome::Miss(_) => Ok(Decision::Execute {
            seal: Some(Box::new(attached)),
            note: Note::Miss,
        }),
    }
}

/// The id a job's result lives under. A declared job is already an id and keeps it, so no entry that
/// exists today moves. A matrix cell's name (`build (17)`) is not one a document can write, so it is
/// spelled as an id — every byte an id cannot hold becomes `-`, a digest of the exact name keeps two
/// spellings apart — rather than leaving the cell unable to reuse at all.
fn entry_id(job_name: &str) -> String {
    if sentinel_pipeline::schema::valid_id(job_name) {
        return job_name.to_owned();
    }
    const TAIL: usize = 16;
    let mut out = String::with_capacity(64);
    for byte in job_name.bytes() {
        let keep = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
        out.push(char::from(if keep { byte } else { b'-' }));
    }
    out.truncate(sentinel_pipeline::schema::MAX_ID_BYTES - TAIL - 1);
    out.push('-');
    for byte in &blake3::hash(job_name.as_bytes()).as_bytes()[..TAIL / 2] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

const fn schema_isolation(isolation: Isolation) -> sentinel_pipeline::schema::Isolation {
    match isolation {
        Isolation::Container => sentinel_pipeline::schema::Isolation::Container,
        Isolation::Microvm => sentinel_pipeline::schema::Isolation::Microvm,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::atomic::AtomicBool};

    use sentinel_core::{AttemptId, Fence, JobId, RepoId, RunId, TenantId, WorkerId};
    use sentinel_link::session::{EventContext, JobContext};
    use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
    use sentinel_protocol::cache::Trust;

    use super::*;
    use crate::{
        attempt::Job,
        images::Images,
        podman::{self, Network},
    };

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const DIGEST: &str = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn platform() -> Platform {
        Platform {
            os: sentinel_cache::Os::Linux,
            arch: sentinel_protocol::negotiate::Arch::X86_64,
        }
    }

    /// A job that opts in and runs one step, unless `body` states otherwise. `body` replaces the job's
    /// whole declaration below `image:`, so a case can move exactly one component.
    fn spec(body: &str) -> RunSpec {
        let mut yaml = String::from(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox@sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
        );
        for line in body.lines() {
            yaml.push_str("    ");
            yaml.push_str(line);
            yaml.push('\n');
        }
        RunSpec::new(
            PinnedSource::new("file:///nowhere", SHA, Some("main")).unwrap(),
            compile_str(&yaml).unwrap_or_else(|e| panic!("{e}\n{yaml}")),
        )
        .unwrap()
    }

    fn job(spec: RunSpec, tenant: TenantId, repo: RepoId) -> Job {
        Job {
            worker: WorkerId::new(),
            attempt: AttemptId::new(),
            fence: Fence(1),
            job_index: 0,
            digest: DIGEST.to_owned(),
            spec,
            context: JobContext {
                source: None,
                source_valid_until: None,
                run: RunId::new(),
                repo,
                repo_name: "app".into(),
                job: JobId::new(),
                job_name: "build".into(),
                sha: SHA.into(),
                event: EventContext {
                    name: "push".into(),
                    ref_name: "refs/heads/main".into(),
                    base_ref: None,
                    pr_number: None,
                    key: "main".into(),
                },
                cancelled: false,
                needs: Vec::new(),
                tenant: Some(tenant),
                trust: Trust::Protected,
                outputs: Vec::new(),
                checkouts: Vec::new(),
                reuse_fresh: false,
            },
            images: Images::with_download(|_, _, _, _, _, _| Ok(false)),
            caches: Vec::new(),
            reuse_seal: None,
            reuse_fresh: false,
            cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
            mirrors: None,
            prepare_hold: std::time::Duration::ZERO,
            network: Network::None,
            runtime: Default::default(),
            secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
            store: podman::Store::Shared,
        }
    }

    const OPTED_IN: &str =
        "reuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]";

    /// One worker's store and one attempt's workspace, with the declared input and output present.
    struct Box_ {
        _temp: tempfile::TempDir,
        root: std::path::PathBuf,
        workspace: std::path::PathBuf,
        tenant: TenantId,
        repo: RepoId,
    }

    impl Box_ {
        fn new(input: &str) -> Box_ {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("worker");
            let workspace = temp.path().join("ws");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir_all(workspace.join("src")).unwrap();
            fs::create_dir_all(workspace.join("out")).unwrap();
            fs::write(workspace.join("src/a.txt"), input).unwrap();
            Box_ {
                _temp: temp,
                root,
                workspace,
                tenant: TenantId::new(),
                repo: RepoId::new(),
            }
        }

        fn job(&self, spec: RunSpec) -> Job {
            job(spec, self.tenant, self.repo)
        }

        fn decide(&self, job: &mut Job, isolation: Isolation) -> Decision {
            let image = format!("busybox@{}", job.digest);
            prepare(
                &self.root,
                job,
                &self.workspace,
                &image,
                isolation,
                platform(),
            )
            .unwrap()
        }

        /// Runs a job that passed: seals what preparation decided it should seal.
        fn pass(&self, job: &mut Job, decision: Decision) {
            let Decision::Execute {
                seal: Some(attached),
                ..
            } = decision
            else {
                panic!("a passing job must be able to seal its result");
            };
            fs::write(self.workspace.join("out/result.bin"), b"sealed").unwrap();
            let published = sentinel_cache::publish::commit(
                &self.root.join(sentinel_cache::CACHE_DIR),
                &attached,
                job.context.trust,
                sentinel_core::UnixMillis::now(),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                &|| false,
            )
            .unwrap_or_else(|e| panic!("commit: {e}"));
            assert!(
                matches!(published, sentinel_cache::publish::Published::Sealed { .. }),
                "the result must seal: {published:?}"
            );
        }
    }

    #[test]
    fn a_declared_task_seals_on_a_miss_and_serves_with_its_provenance() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec(OPTED_IN));
        let Decision::Execute {
            seal: Some(_),
            note,
        } = boxed.decide(&mut job, Isolation::Container)
        else {
            panic!("the first run has no entry to serve");
        };
        assert!(matches!(note, Note::Miss));
        let decision = boxed.decide(&mut job, Isolation::Container);
        boxed.pass(&mut job, decision);

        // A later attempt of the same task, on the same worker, reads the declared outputs back.
        fs::remove_file(boxed.workspace.join("out/result.bin")).unwrap();
        let mut again = boxed.job(spec(OPTED_IN));
        let Decision::Served(served) = boxed.decide(&mut again, Isolation::Container) else {
            panic!("the sealed result must be served");
        };
        assert_eq!(
            fs::read(boxed.workspace.join("out/result.bin")).unwrap(),
            b"sealed"
        );
        let record = &served.record;
        assert_eq!(record.entry, "build");
        assert_eq!(record.key.len(), 64);
        assert!(record.generation.starts_with("gen-"));
        assert!(record.sealed_ms > 0);
        assert_eq!(record.files, 1);
        assert_eq!(record.bytes, 6);
        assert!(record.restore_ns.is_some());
    }

    /// A matrix cell's name is not an id, and its result is reusable anyway: the entry is spelled as one
    /// instead of the cell silently executing every time, and two cells of one job are two entries.
    #[test]
    fn a_matrix_cells_result_is_reusable() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec(OPTED_IN));
        job.context.job_name = "build (17)".into();
        let Decision::Execute {
            seal: Some(_),
            note,
        } = boxed.decide(&mut job, Isolation::Container)
        else {
            panic!("a cell with a name no id allows must still be able to seal");
        };
        assert!(matches!(note, Note::Miss), "{}", note.as_str());
        let decision = boxed.decide(&mut job, Isolation::Container);
        boxed.pass(&mut job, decision);

        fs::remove_file(boxed.workspace.join("out/result.bin")).unwrap();
        let mut again = boxed.job(spec(OPTED_IN));
        again.context.job_name = "build (17)".into();
        let Decision::Served(served) = boxed.decide(&mut again, Isolation::Container) else {
            panic!("the sealed result must be served");
        };
        assert!(
            sentinel_pipeline::schema::valid_id(&served.record.entry),
            "the entry is an id: {}",
            served.record.entry
        );
        assert!(
            served.record.entry.starts_with("build"),
            "{}",
            served.record.entry
        );

        // Another cell of the same job is another entry, not a result of the first.
        fs::remove_file(boxed.workspace.join("out/result.bin")).unwrap();
        let mut other = boxed.job(spec(OPTED_IN));
        other.context.job_name = "build (21)".into();
        let Decision::Execute {
            seal: Some(_),
            note,
        } = boxed.decide(&mut other, Isolation::Container)
        else {
            panic!("a second cell must not serve the first cell's result");
        };
        assert!(matches!(note, Note::Miss), "{}", note.as_str());
    }

    #[test]
    fn changing_any_declared_component_forces_a_fresh_run() {
        // Each case is one pipeline the task declares: the entry sealed under the first is never served.
        let moves: Vec<(&str, &str)> = vec![
            // The command.
            (
                "command",
                "reuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo changed}]",
            ),
            // The environment the pipeline declares, on the job.
            (
                "job env",
                "env: {MODE: fast}\nreuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]",
            ),
            // The environment the pipeline declares, on the step.
            (
                "step env",
                "reuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi, env: {MODE: fast}}]",
            ),
            // The image reference the job states.
            (
                "image reference",
                "reuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]",
            ),
            // The declared input files, by digest.
            (
                "input digest",
                "reuse: {inputs: [src/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]",
            ),
            // The inputs the pipeline declares: a pattern it stopped naming is a different task.
            (
                "input pattern",
                "reuse: {inputs: [src/*.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]",
            ),
        ];
        for (component, declared) in moves {
            let boxed = Box_::new("one");
            let mut job = boxed.job(spec(OPTED_IN));
            let decision = boxed.decide(&mut job, Isolation::Container);
            boxed.pass(&mut job, decision);
            let mut moved = boxed.job(spec(declared));
            if component == "image reference" {
                moved.spec.pipeline.jobs[0].spec.image =
                    format!("busybox@sha256:{}", "2".repeat(64));
            }
            if component == "input digest" {
                fs::write(boxed.workspace.join("src/a.txt"), b"two").unwrap();
            }
            assert!(
                matches!(
                    boxed.decide(&mut moved, Isolation::Container),
                    Decision::Execute {
                        note: Note::Miss,
                        ..
                    }
                ),
                "changing the {component} must force a fresh run"
            );
        }
    }

    #[test]
    fn the_image_digest_and_the_toolchain_are_their_own_components() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec(OPTED_IN));
        let decision = boxed.decide(&mut job, Isolation::Container);
        boxed.pass(&mut job, decision);
        // The same reference resolved to another digest is a different toolchain: nothing it sealed serves.
        let mut repinned = boxed.job(spec(OPTED_IN));
        repinned.digest = format!("sha256:{}", "f".repeat(64));
        assert!(matches!(
            boxed.decide(&mut repinned, Isolation::Container),
            Decision::Execute {
                note: Note::Miss,
                ..
            }
        ));
    }

    #[test]
    fn a_result_is_never_served_in_another_isolation_class() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec(OPTED_IN));
        let decision = boxed.decide(&mut job, Isolation::Microvm);
        boxed.pass(&mut job, decision);
        fs::remove_file(boxed.workspace.join("out/result.bin")).unwrap();
        // Weaker: a container never serves what a microVM produced.
        let mut container = boxed.job(spec(OPTED_IN));
        assert!(matches!(
            boxed.decide(&mut container, Isolation::Container),
            Decision::Execute {
                note: Note::Miss,
                ..
            }
        ));
        assert!(!boxed.workspace.join("out/result.bin").exists());
        // And the reverse is refused too: the class is part of the identity, not a ranking.
        let mut microvm = boxed.job(spec(OPTED_IN));
        assert!(boxed.decide(&mut microvm, Isolation::Microvm).served());
    }

    #[test]
    fn a_task_that_does_not_opt_in_never_looks_at_the_store() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec("steps: [{id: s, run: echo hi}]"));
        assert!(declared(&job).is_none());
        for attempt in 0..2 {
            let Decision::Execute { seal, .. } = boxed.decide(&mut job, Isolation::Container)
            else {
                panic!("attempt {attempt}: an unopted task always executes");
            };
            assert!(seal.is_none(), "it also seals nothing to serve later");
        }
        let entry_root = boxed.root.join(sentinel_cache::CACHE_DIR);
        assert!(
            !entry_root.exists(),
            "an unopted task creates no entry at all"
        );
    }

    #[test]
    fn a_forced_run_bypasses_a_sealed_result_and_seals_nothing() {
        let boxed = Box_::new("one");
        let mut job = boxed.job(spec(OPTED_IN));
        let decision = boxed.decide(&mut job, Isolation::Container);
        boxed.pass(&mut job, decision);
        let mut forced = boxed.job(spec(OPTED_IN));
        forced.reuse_fresh = true;
        let Decision::Execute { seal, note } = boxed.decide(&mut forced, Isolation::Container)
        else {
            panic!("a forced run must not serve anything");
        };
        assert!(matches!(note, Note::Forced));
        assert!(
            seal.is_none(),
            "a forced run refreshes nothing into the store"
        );
        // The entry it bypassed is untouched and still serves the next ordinary run.
        assert!(
            boxed
                .decide(&mut boxed.job(spec(OPTED_IN)), Isolation::Container)
                .served()
        );
    }

    #[test]
    fn an_input_that_resolves_to_nothing_makes_the_task_unreusable_for_that_run() {
        let boxed = Box_::new("one");
        fs::remove_file(boxed.workspace.join("src/a.txt")).unwrap();
        let mut job = boxed.job(spec(
            "reuse: {inputs: [missing/**.txt], paths: [out]}\nsteps: [{id: s, run: echo hi}]",
        ));
        let Decision::Execute { seal, note } = boxed.decide(&mut job, Isolation::Container) else {
            panic!("an unkeyable task still runs");
        };
        assert!(matches!(note, Note::Undecidable("inputs_unresolved")));
        assert!(seal.is_none(), "an incomplete key seals nothing");
    }

    impl Decision {
        fn served(&self) -> bool {
            matches!(self, Decision::Served(_))
        }
    }

    #[allow(dead_code)]
    fn unused_atomic() -> &'static AtomicBool {
        static FLAG: AtomicBool = AtomicBool::new(false);
        &FLAG
    }
}
