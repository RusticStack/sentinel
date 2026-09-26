//! K07 recipe-measurement driver (bench/k07-recipes.sh): run ONE real
//! attempt of a recipe pipeline through the worker's own path — workspace,
//! pinned checkout, digest-pinned image pull, cache restore, rootless
//! Podman execution of every declared step, and cache publication — then
//! print one JSON record on stdout describing what the attempt measured.
//!
//! The record is the attempt's own summary plus the cache carrier's
//! per-entry outcomes: lookup/clone/commit timings, hit or the stable
//! `Miss` reason, staged/reused/dirty byte split, publish answer and the
//! costly-hit flag. Nothing is simulated; a failed pull or checkout is the
//! attempt's recorded verdict, not a driver error.
//!
//! Linux only — the worker crate is empty elsewhere; the stub main on
//! other targets just refuses.

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        path::PathBuf,
        process::ExitCode,
        str::FromStr,
        sync::{Arc, Mutex, atomic::AtomicBool},
        time::Duration,
    };

    use sentinel_core::{AttemptId, Event, Fence, JobId, RepoId, RunId, WorkerId};
    use sentinel_link::session::{EventContext, JobContext};
    use sentinel_pipeline::{ImageRef, PinnedSource, RunSpec, compile_str};
    use sentinel_protocol::{
        cache::Trust,
        summary::{StepOutcome, StepRecord},
    };
    use sentinel_worker::{
        artifacts::NoSink,
        attempt::{self, CacheNote, Job, NoOutput, Output, Report, Verdict},
        images::Images,
        podman,
    };

    /// A Report that keeps the cache diagnostics the attempt emitted.
    #[derive(Default)]
    struct Notes {
        cache: Mutex<Vec<CacheNote>>,
        costly: Mutex<Vec<String>>,
    }

    impl Report for Notes {
        fn event(&self, _: AttemptId, _: Fence, _: Event) {}
        fn finish(&self, _: AttemptId, _: Fence, _: Event, _: Vec<u8>) {}
        fn cache_note(&self, _: AttemptId, note: CacheNote) {
            self.cache.lock().unwrap().push(note);
        }
        fn costly_hit(
            &self,
            _: AttemptId,
            name: &str,
            costly: sentinel_cache::Costly,
            _: &sentinel_cache::Stats,
        ) {
            self.costly
                .lock()
                .unwrap()
                .push(format!("{name}:{}", costly.as_str()));
        }
    }

    /// Step output teed to a file so the harness can show a bounded tail on
    /// failure; discarded entirely when no path was given.
    struct Tee(Option<std::fs::File>);
    impl Output for Tee {
        fn write(&self, step: u32, stream: sentinel_protocol::logs::Stream, bytes: &[u8]) {
            if let Some(f) = &self.0 {
                use std::io::Write;
                let tag = if matches!(stream, sentinel_protocol::logs::Stream::Stdout) {
                    "out"
                } else {
                    "err"
                };
                let mut f = f;
                let _ = writeln!(f, "--- step {step} {tag} ---");
                let _ = f.write_all(bytes);
            }
        }
        fn complete(&self) -> bool {
            true
        }
    }

    struct Args {
        pipeline: PathBuf,
        job: String,
        repo: PathBuf,
        sha: String,
        worker_dir: PathBuf,
        image: String,
        repo_id: RepoId,
        recipe: String,
        case: String,
        log_file: Option<PathBuf>,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            pipeline: PathBuf::new(),
            job: String::new(),
            repo: PathBuf::new(),
            sha: String::new(),
            worker_dir: PathBuf::new(),
            image: String::new(),
            repo_id: RepoId::new(),
            recipe: String::new(),
            case: String::new(),
            log_file: None,
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
            match k.as_str() {
                "--pipeline" => a.pipeline = PathBuf::from(v),
                "--job" => a.job = v,
                "--repo" => a.repo = PathBuf::from(v),
                "--sha" => a.sha = v,
                "--worker-dir" => a.worker_dir = PathBuf::from(v),
                "--image" => a.image = v,
                "--repo-id" => {
                    a.repo_id = RepoId::from_str(&v).map_err(|_| "bad --repo-id".to_owned())?
                }
                "--recipe" => a.recipe = v,
                "--case" => a.case = v,
                "--log-file" => a.log_file = Some(PathBuf::from(v)),
                _ => return Err(format!("unknown flag {k}")),
            }
        }
        for (name, empty) in [
            ("--pipeline", a.pipeline.as_os_str().is_empty()),
            ("--job", a.job.is_empty()),
            ("--repo", a.repo.as_os_str().is_empty()),
            ("--sha", a.sha.is_empty()),
            ("--worker-dir", a.worker_dir.as_os_str().is_empty()),
            ("--image", a.image.is_empty()),
            ("--recipe", a.recipe.is_empty()),
            ("--case", a.case.is_empty()),
        ] {
            if empty {
                return Err(format!("{name} is required"));
            }
        }
        Ok(a)
    }

    fn step_outcome(o: &StepOutcome) -> serde_json::Value {
        match o {
            StepOutcome::Passed => serde_json::json!("passed"),
            StepOutcome::Skipped => serde_json::json!("skipped"),
            StepOutcome::Failed { code } => serde_json::json!({ "failed": code }),
            StepOutcome::Signaled { signal } => serde_json::json!({ "signaled": signal }),
            StepOutcome::OutOfMemory => serde_json::json!("out_of_memory"),
            StepOutcome::TimedOut => serde_json::json!("timed_out"),
            StepOutcome::Runtime => serde_json::json!("runtime"),
            StepOutcome::NotRun => serde_json::json!("not_run"),
        }
    }

    fn fail(recipe: &str, case: &str, reason: String) -> ExitCode {
        println!(
            "{}",
            serde_json::json!({
                "recipe": recipe,
                "case": case,
                "status": "blocked",
                "reason": reason,
            })
        );
        ExitCode::from(2)
    }

    pub fn main() -> ExitCode {
        let args = match parse_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("k07-recipes: {e}");
                return ExitCode::from(2);
            }
        };
        let (recipe, case) = (args.recipe.as_str(), args.case.as_str());
        // The runtime must be rootless Podman on cgroup v2; probe before any
        // attempt work so a missing runtime is a driver-level blocked record.
        if let Err(e) = podman::probe() {
            return fail(recipe, case, format!("podman probe: {e}"));
        }
        let text = match std::fs::read_to_string(&args.pipeline) {
            Ok(t) => t,
            Err(e) => return fail(recipe, case, format!("pipeline read: {e}")),
        };
        let compiled = match compile_str(&text) {
            Ok(c) => c,
            Err(_) => return fail(recipe, case, "pipeline compile failed".into()),
        };
        let Some(job_index) = compiled.jobs.iter().position(|j| j.name == args.job) else {
            return fail(recipe, case, format!("job {} not in pipeline", args.job));
        };
        // The spec's image must agree in name with --image; the pin comes from
        // the flag, exactly as a controller resolves it for the run.
        let spec_image = match ImageRef::parse(&compiled.jobs[job_index].spec.image) {
            Ok(i) => i,
            Err(_) => return fail(recipe, case, "spec image unparsable".into()),
        };
        let image = match ImageRef::parse(&args.image) {
            Ok(i) => i,
            Err(_) => return fail(recipe, case, "bad --image".into()),
        };
        let Some(digest) = image.digest.clone() else {
            return fail(recipe, case, "--image must carry a sha256 digest".into());
        };
        if image.name != spec_image.name {
            return fail(
                recipe,
                case,
                format!("--image name {} != spec {}", image.name, spec_image.name),
            );
        }
        let source =
            match PinnedSource::new(args.repo.to_str().unwrap_or(""), &args.sha, Some("main")) {
                Ok(s) => s,
                Err(e) => return fail(recipe, case, format!("source: {e:?}")),
            };
        let spec = match RunSpec::new(source, compiled) {
            Ok(s) => s,
            Err(e) => return fail(recipe, case, format!("run spec: {e:?}")),
        };
        let images = match Images::for_worker_data_dir(&args.worker_dir) {
            Ok(images) => images,
            Err(e) => return fail(recipe, case, format!("image auth setup: {e}")),
        };
        let mut job = Job {
            worker: WorkerId::new(),
            attempt: AttemptId::new(),
            fence: Fence(1),
            job_index,
            digest,
            spec,
            context: JobContext {
                source: None,
                run: RunId::new(),
                repo: args.repo_id,
                repo_name: recipe.to_owned(),
                job: JobId::new(),
                job_name: args.job.clone(),
                sha: args.sha.clone(),
                event: EventContext {
                    name: "push".into(),
                    ref_name: "refs/heads/main".into(),
                    base_ref: None,
                    pr_number: None,
                    key: "k07".into(),
                },
                cancelled: false,
                needs: Vec::new(),
                tenant: None,
                trust: Trust::Protected,
            },
            images,
            caches: Vec::new(),
            secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
            mirrors: None,
            prepare_hold: Duration::ZERO,
        };
        let notes = Notes::default();
        let cancel: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let output: Arc<dyn Output> = match &args.log_file {
            Some(p) => match std::fs::File::create(p) {
                Ok(f) => Arc::new(Tee(Some(f))),
                Err(e) => return fail(recipe, case, format!("log file: {e}")),
            },
            None => Arc::new(NoOutput),
        };
        let (verdict, summary) =
            attempt::run(&args.worker_dir, &mut job, &notes, output, &NoSink, &cancel);
        let cache_notes = notes.cache.lock().unwrap().clone();
        let costly = notes.costly.lock().unwrap().clone();
        let record = serde_json::json!({
            "recipe": recipe,
            "case": case,
            "status": "measured",
            "repo_id": args.repo_id.to_string(),
            "sha": args.sha,
            "image": format!("{}@{}", image.name, job.digest),
            "verdict": match &verdict {
                Verdict::Passed => serde_json::json!("passed"),
                Verdict::Failed(c, _) => serde_json::json!({ "failed": c.as_str() }),
            },
            "detail": summary.detail,
            "timings": {
                "checkout_ns": summary.checkout_ns,
                "checkout_fetch_ns": summary.checkout_fetch_ns,
                "checkout_materialize_ns": summary.checkout_materialize_ns,
                "checkout_route": summary.checkout_route.map(|r| format!("{r:?}")),
                "image_pull_ns": summary.image_pull_ns,
                "image_present": summary.image_present,
                "container_start_ns": summary.container_start_ns,
                "steps_ns": summary.steps_ns,
                "finalize_ns": summary.finalize_ns,
            },
            "steps": summary
                .steps
                .iter()
                .map(|s: &StepRecord| serde_json::json!({
                    "id": s.id,
                    "outcome": step_outcome(&s.outcome),
                    "duration_ns": s.duration_ns,
                }))
                .collect::<Vec<_>>(),
            "caches": job
                .caches
                .iter()
                .map(|a| serde_json::json!({
                    "name": a.name,
                    "class": a.scope.class.as_str(),
                    "key": a.key,
                    "outcome": match &a.outcome {
                        sentinel_cache::Outcome::Hit(_) => "hit".to_owned(),
                        sentinel_cache::Outcome::Miss(m) => m.as_str().to_owned(),
                    },
                    "generation": a.generation.as_deref(),
                    "lookup_ns": a.stats.lookup_ns,
                    "lock_wait_ns": a.stats.lock_wait_ns,
                    "clone_ns": a.stats.clone_ns,
                    "first_touch_ns": a.stats.first_touch_ns,
                    "files": a.stats.files,
                    "bytes": a.stats.bytes,
                    "copied_bytes": a.stats.copied_bytes,
                    "reflink": a.stats.reflink,
                    "commit_ns": a.stats.commit_ns,
                    "publish": a.stats.committed.map(|c| match c {
                        sentinel_cache::attach::Committed::Sealed { .. } => "sealed".to_owned(),
                        sentinel_cache::attach::Committed::Skipped(w) => w.as_str().to_owned(),
                        sentinel_cache::attach::Committed::Failed => "failed".to_owned(),
                    }),
                    "staged_bytes": a.stats.committed.and_then(|c| match c {
                        sentinel_cache::attach::Committed::Sealed { staged_bytes, .. } => Some(staged_bytes),
                        _ => None,
                    }),
                    "reused_bytes": a.stats.committed.and_then(|c| match c {
                        sentinel_cache::attach::Committed::Sealed { reused_bytes, .. } => Some(reused_bytes),
                        _ => None,
                    }),
                    "costly_hit": a.costly_hit().map(|c| c.as_str()),
                }))
                .collect::<Vec<_>>(),
            "cache_notes": cache_notes
                .iter()
                .map(|n| serde_json::json!({
                    "name": n.name,
                    "outcome": format!("{:?}", n.outcome),
                }))
                .collect::<Vec<_>>(),
            "costly_notes": costly,
        });
        println!("{record}");
        ExitCode::SUCCESS
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("k07-recipes: the worker only runs on Linux");
    std::process::exit(2);
}
