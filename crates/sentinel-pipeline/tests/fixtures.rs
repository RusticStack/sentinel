use std::{fs, path::Path};

use sentinel_pipeline::{
    RefFilter, Triggers, compile_str,
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase, Value},
};

fn fixture_dir(sub: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pipelines")
        .join(sub)
}

fn fixtures(sub: &str) -> Vec<(String, String)> {
    let dir = fixture_dir(sub);
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures in {}", dir.display());
    out
}

#[test]
fn every_valid_fixture_compiles() {
    for (name, text) in fixtures("valid") {
        compile_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn every_invalid_fixture_fails_with_the_expected_message() {
    for (name, text) in fixtures("invalid") {
        let expect = text
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("# expect: "))
            .unwrap_or_else(|| panic!("{name}: missing `# expect:` header"));
        let err = compile_str(&text)
            .err()
            .unwrap_or_else(|| panic!("{name}: compiled unexpectedly"));
        let msg = err.to_string();
        assert!(
            msg.contains(expect),
            "{name}: expected `{expect}` in `{msg}`"
        );
    }
}

#[test]
fn full_fixture_decodes_every_field() {
    let text = fs::read_to_string(fixture_dir("valid").join("full.yml")).unwrap();
    let p = compile_str(&text).unwrap();
    assert_eq!(
        p.on,
        Triggers {
            push: Some(RefFilter::default()),
            pull_request: Some(RefFilter::default()),
            tag: None,
            manual: true,
        }
    );
    assert!(p.concurrency.as_ref().unwrap().cancel_in_progress);
    assert_eq!(p.jobs.len(), 2);
    let test = &p.jobs[0];
    assert_eq!(test.name, "test");
    assert!(test.needs.is_empty());
    assert_eq!(test.spec.resources.cpu_millis, 4000);
    assert_eq!(test.spec.resources.memory_bytes, 8 << 30);
    assert_eq!(test.spec.timeout_secs, 1200);
    assert_eq!(test.spec.steps[0].timeout_secs, Some(300));
    assert_eq!(test.spec.steps[1].workdir.as_deref(), Some("crates/app"));
    assert_eq!(
        test.spec.env[1],
        ("RUST_BACKTRACE".to_owned(), "1".to_owned())
    );
    assert_eq!(test.spec.cache[0].paths[0], "/usr/local/cargo/registry");
    let build = &p.jobs[1];
    assert_eq!(build.name, "build");
    assert_eq!(build.needs, vec![0]);
    assert_eq!(build.spec.resources.cpu_millis, 500);
    assert_eq!(build.spec.resources.memory_bytes, 512 << 20);
    assert_eq!(build.spec.resources.disk_bytes, 10 << 30, "policy default");
    assert_eq!(build.spec.timeout_secs, 5400);
    assert_eq!(build.spec.artifacts[0].retain_secs, 7 * 86_400);
}

#[test]
fn compilation_is_deterministic_and_order_is_canonical() {
    let text = fs::read_to_string(fixture_dir("valid").join("diamond.yml")).unwrap();
    let a = compile_str(&text).unwrap();
    let names: Vec<&str> = a.jobs.iter().map(|j| j.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta", "gamma", "zeta"]);
    assert_eq!(a.jobs[3].needs, vec![0, 1]);
    // Reordered declarations and reordered `needs`: same compiled pipeline, same digest.
    let reordered = "schema: 1\non: [pull_request]\njobs:\n  alpha:\n    image: busybox\n    steps: [{id: s, run: echo a}]\n  gamma:\n    needs: [alpha]\n    image: busybox\n    steps: [{id: s, run: echo g}]\n  beta:\n    needs: [alpha]\n    image: busybox\n    steps: [{id: s, run: echo b}]\n  zeta:\n    needs: [alpha, beta]\n    image: busybox\n    steps: [{id: s, run: echo z}]\n";
    let b = compile_str(reordered).unwrap();
    assert_eq!(a.digest, b.digest);
    assert_eq!(a.jobs.len(), b.jobs.len());
    // Any semantic change moves the digest.
    let changed = text.replace("echo z", "echo zz");
    assert_ne!(compile_str(&changed).unwrap().digest, a.digest);
}

struct Ctx {
    phase: Phase,
    test_passed: bool,
}

impl Context for Ctx {
    fn phase(&self) -> Phase {
        self.phase
    }
    fn lookup(&self, path: &[String]) -> Lookup {
        let key: Vec<&str> = path.iter().map(String::as_str).collect();
        match key.as_slice() {
            ["event", "ref"] => Lookup::Value(Value::Str("refs/heads/main".into())),
            ["event", "key"] => Lookup::Value(Value::Str("pr-12".into())),
            ["repo", "id"] => Lookup::Value(Value::Str("rep_x".into())),
            ["needs", "test", "result"] if self.phase >= Phase::Schedule => Lookup::Value(
                Value::Str(if self.test_passed { "passed" } else { "failed" }.into()),
            ),
            _ => Lookup::Unresolved,
        }
    }
    fn dependency_summary(&self) -> Option<DependencySummary> {
        (self.phase >= Phase::Schedule).then_some(DependencySummary {
            all_succeeded: self.test_passed,
            any_failed: !self.test_passed,
        })
    }
    fn cancelled(&self) -> Option<bool> {
        Some(false)
    }
    fn hash_files(&self, patterns: &[&str]) -> Result<String, HashFilesError> {
        Ok(format!("hash({})", patterns.join("+")))
    }
}

#[test]
fn conditions_fixture_evaluates_by_phase() {
    let text = fs::read_to_string(fixture_dir("valid").join("conditions.yml")).unwrap();
    let p = compile_str(&text).unwrap();
    let group = p.concurrency.as_ref().unwrap().group.clone();
    let dispatch = Ctx {
        phase: Phase::Dispatch,
        test_passed: false,
    };
    assert_eq!(group.render(&dispatch, 256).unwrap(), "rep_x:pr-12");

    let report = p.jobs.iter().find(|j| j.name == "report").unwrap();
    let job_if = report.spec.condition.as_ref().unwrap();
    assert!(
        job_if.eval(&dispatch).is_err(),
        "needs are unknown at dispatch"
    );
    let failed = Ctx {
        phase: Phase::Schedule,
        test_passed: false,
    };
    assert_eq!(
        job_if.eval(&failed).unwrap().as_condition(),
        Some(true),
        "always() runs on failure"
    );
    let step_if = report.spec.steps[0].condition.as_ref().unwrap();
    assert_eq!(step_if.eval(&failed).unwrap().as_condition(), Some(true));
    let passed = Ctx {
        phase: Phase::Schedule,
        test_passed: true,
    };
    assert_eq!(step_if.eval(&passed).unwrap().as_condition(), Some(false));

    let worker = Ctx {
        phase: Phase::Worker,
        test_passed: true,
    };
    let key = report.spec.cache[0].key.render(&worker, 256).unwrap();
    assert_eq!(key, "deps-hash(Cargo.lock+crates/*/Cargo.toml)");
    assert!(
        report.spec.cache[0].key.render(&passed, 256).is_err(),
        "hash_files needs the worker"
    );

    let main_only = p.jobs.iter().find(|j| j.name == "test").unwrap().spec.steps[1]
        .condition
        .as_ref()
        .unwrap();
    assert_eq!(
        main_only.eval(&dispatch).unwrap().as_condition(),
        Some(true)
    );
}
