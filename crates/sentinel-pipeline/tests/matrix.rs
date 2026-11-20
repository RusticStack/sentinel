use std::collections::HashSet;

use sentinel_pipeline::{
    CompiledPipeline, Explanation, PinnedSource, RunSpec, compile_document, compile_str,
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase},
};

fn compile(text: &str) -> CompiledPipeline {
    compile_str(text).unwrap_or_else(|e| panic!("compiles: {e}"))
}

fn error(text: &str) -> String {
    compile_str(text)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| panic!("compiled unexpectedly"))
}

fn names(p: &CompiledPipeline) -> Vec<&str> {
    p.jobs.iter().map(|j| j.name.as_str()).collect()
}

/// Enough context to evaluate a condition the way the controller does once its dependencies ended.
struct Ctx {
    phase: Phase,
}

impl Context for Ctx {
    fn phase(&self) -> Phase {
        self.phase
    }
    fn lookup(&self, _path: &[String]) -> Lookup {
        Lookup::Unresolved
    }
    fn dependency_summary(&self) -> Option<DependencySummary> {
        Some(DependencySummary {
            all_succeeded: true,
            any_failed: false,
        })
    }
    fn cancelled(&self) -> Option<bool> {
        Some(false)
    }
    fn hash_files(&self, _patterns: &[&str]) -> Result<String, HashFilesError> {
        Err(HashFilesError::UnsupportedPlatform)
    }
}

/// A matrix is one job per combination, named after the values it takes, and the check a repository
/// protects is that name on every run.
#[test]
fn a_matrix_is_one_job_per_cell_with_a_stable_check() {
    let text = "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17', '21'], os: [linux, macos]}
    image: busybox
    steps: [{id: s, run: echo}]
  deploy:
    needs: [build]
    image: busybox
    steps: [{id: s, run: echo}]
";
    let p = compile(text);
    assert_eq!(
        names(&p),
        [
            "build (17, linux)",
            "build (17, macos)",
            "build (21, linux)",
            "build (21, macos)",
            "deploy"
        ]
    );
    // The check identity is the cell's name and nothing else: no cell, no order, no run in it.
    assert_eq!(
        p.job_check("build (17, linux)"),
        "sentinel / build (17, linux)"
    );
    let again = compile(text);
    assert_eq!(again, p);
    // Every cell and the dependent see the same names, positions and digest on the second compile.
    assert_eq!(
        again.job_check("build (21, macos)"),
        p.job_check("build (21, macos)")
    );
    assert_eq!(again.digest, p.digest);
}

/// A declared job name cannot contain a space or a bracket, so no document can write a cell's name and
/// two cells — or two pipelines' cells — can never share a check.
#[test]
fn cell_names_cannot_collide_with_a_declared_job_or_each_other() {
    let text = "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17', '21']}
    image: busybox
    steps: [{id: s, run: echo}]
  build-17:
    image: busybox
    needs: [build]
    steps: [{id: s, run: echo}]
";
    let p = compile(text);
    let checks: Vec<String> = p.jobs.iter().map(|j| p.job_check(&j.name)).collect();
    let unique: HashSet<&String> = checks.iter().collect();
    assert_eq!(
        unique.len(),
        checks.len(),
        "one check name per job: {checks:?}"
    );
    assert!(names(&p).contains(&"build (17)"));
    assert!(
        names(&p).contains(&"build-17"),
        "an id is not a cell's name"
    );
    // A name that looks like a cell cannot be declared: the id charset has no space or bracket.
    let refused = error(
        "schema: 1\non: [push]\njobs:\n  \"build (17)\":\n    image: busybox\n    steps: [{id: s, run: echo}]\n",
    );
    assert!(refused.contains("job names must match"), "{refused}");
}

/// A cell is the declared job: its sandbox, resources, secrets, locks and cache scope are exactly the
/// ones the declaration states, and only the values the document renders differ.
#[test]
fn a_cell_is_exactly_the_declared_job() {
    let declared = "schema: 1
on: [push]
jobs:
  build:
    image: \"busybox:x86_64\"
    runs_on: {arch: arm64, labels: [egress]}
    resources: {cpu: 6, memory: 12GiB, disk: 40GiB}
    secrets: [REGISTRY]
    registry_auth: REGISTRY
    locks: [db/staging]
    env: {TARGET: x86_64}
    cache: [{name: cargo, class: compiler, key: \"cargo-x86_64\", paths: [/cache]}]
    steps:
      - id: test
        run: cargo test --target x86_64
        secrets: [REGISTRY]
";
    let matrix = declared
        .replace(
            "    image: \"busybox:x86_64\"",
            "    image: \"busybox:${{ matrix.target }}\"\n    matrix: {target: [x86_64]}",
        )
        .replace("TARGET: x86_64", "TARGET: \"${{ matrix.target }}\"")
        .replace("cargo-x86_64", "cargo-${{ matrix.target }}")
        .replace("--target x86_64", "--target ${{ matrix.target }}");
    let cell = compile(&matrix);
    let plain = compile(declared);
    assert_eq!(names(&cell), ["build (x86_64)"]);
    // Byte for byte the same job: same sandbox, same budget, same secrets, same cache scope, same
    // command. The cell gains nothing the declaration did not give it.
    assert_eq!(cell.jobs[0].spec, plain.jobs[0].spec);
    assert_eq!(
        cell.jobs[0].spec.secrets, plain.jobs[0].spec.secrets,
        "a matrix cannot add a secret"
    );

    // Two cells share every scope and differ only in the values the document rendered.
    let two = compile(&matrix.replace("target: [x86_64]", "target: [x86_64, aarch64]"));
    assert_eq!(two.jobs.len(), 2);
    let (a, b) = (&two.jobs[0].spec, &two.jobs[1].spec);
    assert_eq!(a.runs_on, b.runs_on);
    assert_eq!(a.resources, b.resources);
    assert_eq!(a.secrets, b.secrets);
    assert_eq!(a.locks, b.locks);
    assert_eq!(a.cache[0].name, b.cache[0].name);
    assert_eq!(a.cache[0].class, b.cache[0].class);
    assert_eq!(a.cache[0].paths, b.cache[0].paths);
    assert_ne!(a.cache[0].key, b.cache[0].key, "the key names the cell");
    assert_ne!(a.image, b.image);
}

/// A matrix needs no run spec of its own: the cells compile into plain jobs, so the spec is the format
/// a document without a matrix has, and the store, the worker and an older reader see nothing new.
#[test]
fn a_matrix_is_a_plain_run_spec() {
    let source = || PinnedSource::new("repo", &"a".repeat(40), None).unwrap();
    let matrix = compile(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17']}
    image: \"busybox:${{ matrix.jdk }}\"
    steps: [{id: s, run: \"echo ${{ matrix.jdk }}\"}]
",
    );
    let plain = compile(
        "schema: 1
on: [push]
jobs:
  build:
    image: busybox:17
    steps: [{id: s, run: echo 17}]
",
    );
    // The cell's job is the plain job: same image, same command, same bytes in the spec.
    assert_eq!(matrix.jobs[0].spec, plain.jobs[0].spec);
    assert_eq!(matrix.jobs[0].needs, plain.jobs[0].needs);
    let expanded = RunSpec::new(source(), matrix).unwrap();
    assert_eq!(expanded.format(), 6, "the format a plain pipeline has");
    let bytes = expanded.encode().unwrap();
    assert_eq!(RunSpec::decode(&bytes).unwrap(), expanded);
    assert_eq!(
        expanded.format(),
        RunSpec::new(source(), plain).unwrap().format()
    );
}

/// A job that needs a matrix waits for every cell, and a cell's place in the order is an ordinary
/// dependency: no cell starts before what the declaration needed.
#[test]
fn a_dependency_on_a_matrix_is_a_dependency_on_every_cell() {
    let p = compile(
        "schema: 1
on: [push]
jobs:
  lint:
    image: busybox
    steps: [{id: s, run: echo}]
  build:
    matrix: {jdk: ['17', '21']}
    image: busybox
    steps: [{id: s, run: echo}]
  deploy:
    needs: [lint, build]
    image: busybox
    steps: [{id: s, run: echo}]
",
    );
    assert_eq!(names(&p), ["build (17)", "build (21)", "lint", "deploy"]);
    let deploy = &p.jobs[3];
    let needs: Vec<&str> = deploy
        .needs
        .iter()
        .map(|&i| p.jobs[i as usize].name.as_str())
        .collect();
    assert_eq!(needs, ["build (17)", "build (21)", "lint"]);
    for &i in &deploy.needs {
        assert!((i as usize) < 3, "a dependency precedes its dependent");
    }
    assert!(p.jobs[0].needs.is_empty() && p.jobs[1].needs.is_empty());
}

/// A matrix value renders in a cell's condition, so a cell that does not match still runs, skips or
/// waits by exactly the rule the declaration stated.
#[test]
fn a_cell_condition_reads_its_own_value() {
    let p = compile(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17', '21']}
    image: busybox
    steps:
      - id: s
        run: echo
        if: ${{ matrix.jdk == '21' }}
",
    );
    let ctx = Ctx {
        phase: Phase::Schedule,
    };
    let decisions: Vec<bool> = p
        .jobs
        .iter()
        .map(|j| {
            j.spec.steps[0]
                .condition
                .as_ref()
                .unwrap()
                .eval(&ctx)
                .unwrap()
                .as_condition()
                .unwrap()
        })
        .collect();
    assert_eq!(decisions, [false, true], "only the 21 cell matches");
    // The stored condition holds no matrix reference: it is a value, not a lookup.
    let printed = p.jobs[1].spec.steps[0]
        .condition
        .as_ref()
        .unwrap()
        .to_string();
    assert!(!printed.contains("matrix."), "{printed}");
}

/// A matrix past the bound is refused, never cut down: a silently dropped cell is a check that would
/// never report.
#[test]
fn a_matrix_past_its_bound_is_refused_and_never_truncated() {
    let cells = |rows: &str| {
        format!(
            "schema: 1\non: [push]\njobs:\n  build:\n    matrix: {rows}\n    image: busybox\n    steps: [{{id: s, run: echo}}]\n"
        )
    };
    let refused = error(&cells("{a: [1, 2, 3, 4, 5, 6, 7], b: [1, 2, 3, 4, 5]}"));
    assert!(
        refused.contains("35 combinations exceeds the bound of 32"),
        "{refused}"
    );
    // At the bound it compiles, and every combination is a job: nothing is dropped to fit.
    let p = compile(&cells("{a: [1, 2, 3, 4, 5, 6, 7], b: [1, 2, 3, 4]}"));
    assert_eq!(p.jobs.len(), 28);
    let checks: HashSet<String> = p.jobs.iter().map(|j| p.job_check(&j.name)).collect();
    assert_eq!(checks.len(), 28);
    let refused = error(&cells(
        "{a: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]}",
    ));
    assert!(refused.contains("more than 16 entries"), "{refused}");
    let refused = error(&cells("{a: [1], b: [1], c: [1], d: [1], e: [1]}"));
    assert!(refused.contains("more than 4 entries"), "{refused}");
}

/// Expansion is bounded by the document's own job budget too, so a set of matrices cannot build a run
/// larger than one hand-written document could.
#[test]
fn expansion_past_the_job_budget_is_refused() {
    let job = |name: &str| {
        format!(
            "  {name}:\n    matrix: {{a: [1, 2, 3, 4], b: [1, 2, 3, 4, 5, 6]}}\n    image: busybox\n    steps: [{{id: s, run: echo}}]\n"
        )
    };
    let text = format!(
        "schema: 1\non: [push]\njobs:\n{}{}{}",
        job("a"),
        job("b"),
        job("c")
    );
    let refused = error(&text);
    assert!(
        refused.contains("72 jobs after expanding matrices exceeds the bound of 64"),
        "{refused}"
    );
}

/// A matrix value reaches the fields the contract names and nothing else, because a field that would
/// take one as text is a value nobody reads.
#[test]
fn a_matrix_value_reaches_only_the_fields_the_contract_names() {
    let refused = error(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17']}
    image: busybox
    steps: [{id: s, run: echo}]
    finalize: {run: \"notify ${{ matrix.jdk }}\"}
",
    );
    assert!(refused.contains("cannot be used here"), "{refused}");
    let refused = error(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17']}
    image: busybox
    secrets: [\"${{ matrix.jdk }}\"]
    steps: [{id: s, run: echo}]
",
    );
    assert!(refused.contains("secrets"), "{refused}");
    // A bare value renders; a comparison does not, because a comparison is an `if`.
    let refused = error(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17']}
    image: busybox
    steps: [{id: s, run: \"echo ${{ matrix.jdk == '17' }}\"}]
",
    );
    assert!(refused.contains("renders here only as"), "{refused}");
}

/// A job that is several jobs has no single result to read and no single artifact to take, so the
/// document is refused with the cells it could have named.
#[test]
fn a_matrix_job_is_not_one_result_or_one_artifact() {
    let base = "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17', '21']}
    image: busybox
    steps: [{id: s, run: echo}]
    artifacts: [{name: app, paths: [out]}]
";
    let refused = error(&format!(
        "{base}  deploy:\n    needs: [build]\n    if: ${{{{ needs.build.result == 'passed' }}}}\n    image: busybox\n    steps: [{{id: s, run: echo}}]\n"
    ));
    assert!(
        refused.contains("`needs.build.result` names 2 jobs: build (17), build (21)"),
        "{refused}"
    );
    let refused = error(&format!(
        "{base}  deploy:\n    needs: [build]\n    image: busybox\n    handoff: [{{from: build, artifact: app, into: dist}}]\n    steps: [{{id: s, run: echo}}]\n"
    ));
    assert!(
        refused.contains("a handoff takes one job's artifact"),
        "{refused}"
    );
    // A value no axis declares is named, not defaulted, wherever it appears.
    let refused = error(
        &base
            .replace("image: busybox", "image: \"busybox:${{ matrix.jdk }}\"")
            .replace("jdk:", "java:"),
    );
    assert!(
        refused.contains("`matrix.jdk` names no matrix axis this job declares"),
        "{refused}"
    );
}

/// Two pipelines of one repository expand into two check namespaces, and a matrix in one never
/// publishes over the other — nor does a cell's name escape its pipeline.
#[test]
fn a_matrix_in_a_named_pipeline_keeps_its_namespace() {
    let pipelines = compile_document(
        "schema: 1
pipelines:
  acceptance:
    on: [pull_request]
    jobs:
      test:
        matrix: {jdk: ['17']}
        image: busybox
        steps: [{id: s, run: echo}]
  release:
    on: [tag]
    jobs:
      test:
        matrix: {jdk: ['17']}
        image: busybox
        steps: [{id: s, run: echo}]
",
    )
    .unwrap();
    let acceptance = &pipelines[0];
    let release = &pipelines[1];
    assert_eq!(names(acceptance), ["test (17)"]);
    assert_eq!(
        acceptance.job_check("test (17)"),
        "sentinel / acceptance / test (17)"
    );
    assert_eq!(
        release.job_check("test (17)"),
        "sentinel / release / test (17)"
    );
    assert_ne!(acceptance.digest, release.digest);
}

/// The compiled view names every cell, its image and its cache, so an author reads the expansion the
/// controller will run rather than the declaration they wrote.
#[test]
fn the_explanation_shows_every_cell() {
    let p = compile(
        "schema: 1
on: [push]
jobs:
  build:
    matrix: {jdk: ['17', '21']}
    image: \"busybox:${{ matrix.jdk }}\"
    secrets: [REGISTRY]
    cache: [{name: m2, key: \"m2-${{ matrix.jdk }}\", paths: [/cache]}]
    steps: [{id: s, run: echo}]
",
    );
    let e = Explanation::of(&p);
    assert_eq!(e.jobs.len(), 2);
    assert_eq!(e.jobs[0].name, "build (17)");
    assert_eq!(e.jobs[0].image, "busybox:17");
    assert_eq!(e.jobs[1].image, "busybox:21");
    // One secret and one cache scope for the declaration, whatever the number of cells.
    assert_eq!(e.requires.secrets, ["REGISTRY"]);
    assert_eq!(e.requires.caches, ["m2"]);
    assert!(e.jobs[0].image_pinned == e.jobs[1].image_pinned);
    // The key is literal per cell: the matrix was the only thing unresolved in it.
    assert!(e.jobs[1].caches[0].key_known, "{:?}", e.jobs[1].caches[0]);
}
