//! H02's gate: every job and every construct of the fixtures is classified, and the
//! pipeline loader's limits refuse an oversized or deeply nested workflow instead of
//! reading it.

use std::fs;
use std::path::{Path, PathBuf};

use sentinel_core::runner::{RunnerClass, RunnerOs};
use sentinel_pipeline::workflow::{
    self, ActionRef, ArtifactDirection, CacheSource, Construct, Declared, Destination, DockerHosts,
    Job, KeepReason, LABEL_TABLE_VERSION, LabelTable, MAX_JOBS, MAX_MATRIX_CELLS,
    MAX_MATRIX_VALUES, MAX_WORKFLOW_FILES, RULE_TABLE_VERSION, Rule, RuleTable, WORKFLOW_DIRECTORY,
    WorkflowErrorKind, WorkflowFile, analyze,
};
use sentinel_pipeline::yaml::MAX_PIPELINE_FILE_BYTES;

const REVISION: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";

fn fixture_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/workflows")
        .join(sub)
}

/// Every fixture in a directory, by file name, as a workflow path under `.github/workflows`.
fn fixtures(sub: &str) -> Vec<(String, String)> {
    let dir = fixture_dir(sub);
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|x| x == "yml"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (
                format!("{WORKFLOW_DIRECTORY}/{name}"),
                fs::read_to_string(&path).unwrap(),
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures in {}", dir.display());
    out
}

fn try_analyze(
    files: &[(String, String)],
    docker: DockerHosts,
) -> Result<workflow::Inventory, workflow::WorkflowError> {
    let borrowed: Vec<WorkflowFile<'_>> = files
        .iter()
        .map(|(path, text)| WorkflowFile { path, text })
        .collect();
    analyze(REVISION, &borrowed, docker)
}

fn analyze_files(files: &[(String, String)], docker: DockerHosts) -> workflow::Inventory {
    try_analyze(files, docker).unwrap()
}

fn analyze_one(files: &[(String, String)], docker: DockerHosts, name: &str) -> workflow::Inventory {
    let one: Vec<(String, String)> = files
        .iter()
        .filter(|(path, _)| path.ends_with(name))
        .cloned()
        .collect();
    analyze_files(&one, docker)
}

fn classes(inventory: &workflow::Inventory) -> Vec<(String, RunnerClass)> {
    let mut out = Vec::new();
    for workflow in &inventory.workflows {
        for job in &workflow.jobs {
            for cell in &job.cells {
                if let Destination::Class(target) = cell.destination {
                    out.push((format!("{}/{}", workflow.path, job.id), target.class));
                }
            }
        }
    }
    out
}

fn keep_reasons(inventory: &workflow::Inventory) -> Vec<(String, KeepReason)> {
    let mut out = Vec::new();
    for workflow in &inventory.workflows {
        for job in &workflow.jobs {
            for cell in &job.cells {
                if let Destination::Keep(reason) = cell.destination {
                    out.push((format!("{}/{}", workflow.path, job.id), reason));
                }
            }
        }
    }
    out
}

/// Every item a job records has its construct classified, and every classification is
/// decidable: the gate's "no construct unknown" cannot be satisfied by omission.
fn assert_totality(job: &Job, where_: &str) {
    let has = |construct: &Construct| job.constructs.iter().any(|c| &c.construct == construct);
    assert!(!job.cells.is_empty(), "{where_}: no placement");
    if job.condition {
        assert!(has(&Construct::Condition), "{where_}: `if` unclassified");
    }
    if !job.permissions.is_empty() {
        assert!(
            has(&Construct::Permissions),
            "{where_}: permissions unclassified"
        );
    }
    if job.concurrency.is_some() {
        assert!(
            has(&Construct::Concurrency),
            "{where_}: concurrency unclassified"
        );
    }
    if !job.env.is_empty() {
        assert!(has(&Construct::Env), "{where_}: env unclassified");
    }
    if job.defaults.is_some() {
        assert!(has(&Construct::Defaults), "{where_}: defaults unclassified");
    }
    if !job.needs.is_empty() {
        assert!(has(&Construct::Needs), "{where_}: needs unclassified");
    }
    if job.timeout_minutes.is_some() {
        assert!(has(&Construct::Timeout), "{where_}: timeout unclassified");
    }
    if job.matrix.is_some() {
        assert!(has(&Construct::Matrix), "{where_}: matrix unclassified");
    }
    if job.container.is_some() {
        assert!(
            has(&Construct::Container),
            "{where_}: container unclassified"
        );
    }
    if !job.services.is_empty() {
        assert!(has(&Construct::Services), "{where_}: services unclassified");
    }
    if job.environment.is_some() {
        assert!(
            has(&Construct::Environment),
            "{where_}: environment unclassified"
        );
    }
    if !job.outputs.is_empty() {
        assert!(has(&Construct::Outputs), "{where_}: outputs unclassified");
    }
    if job.reusable.is_some() {
        assert!(
            has(&Construct::ReusableWorkflow),
            "{where_}: reusable call unclassified"
        );
    }
    for step in &job.steps {
        if let Some(action) = &step.action {
            let uses = match action {
                ActionRef::Repository {
                    repository,
                    version,
                    ..
                } => format!("{repository}@{version}"),
                ActionRef::Docker { image } => format!("docker://{image}"),
                ActionRef::Local { path } => path.clone(),
            };
            assert!(
                has(&Construct::Action { uses: uses.clone() }),
                "{where_}: action `{uses}` unclassified"
            );
            let rule = RuleTable::V1.classify(&Construct::Action { uses });
            assert!(!rule.as_str().is_empty());
        } else {
            assert!(has(&Construct::RunStep), "{where_}: run step unclassified");
        }
        if step.condition {
            assert!(
                has(&Construct::Condition),
                "{where_}: step `if` unclassified"
            );
        }
        if let Some(shell) = &step.shell {
            assert!(
                has(&Construct::Shell {
                    shell: shell.clone()
                }),
                "{where_}: shell `{shell}` unclassified"
            );
        }
        if step.workdir.is_some() {
            assert!(has(&Construct::Workdir), "{where_}: workdir unclassified");
        }
        if step.continue_on_error {
            assert!(
                has(&Construct::ContinueOnError),
                "{where_}: continue-on-error unclassified"
            );
        }
        if step.timeout_minutes.is_some() {
            assert!(
                has(&Construct::Timeout),
                "{where_}: step timeout unclassified"
            );
        }
    }
    for classified in &job.constructs {
        assert!(!classified.construct.name().is_empty());
        assert!(classified.rule.note().is_none_or(|note| !note.is_empty()));
    }
}

#[test]
fn the_fixture_gate_decides_every_job_and_every_construct() {
    for (path, text) in fixtures("valid") {
        for docker in [DockerHosts::MicrovmGuests, DockerHosts::ContainerOnly] {
            let inventory = analyze_files(&[(path.clone(), text.clone())], docker);
            assert_eq!(inventory.revision, REVISION);
            assert_eq!(inventory.label_table, LABEL_TABLE_VERSION);
            assert_eq!(inventory.rule_table, RULE_TABLE_VERSION);
            assert_eq!(inventory.workflows.len(), 1, "{path}");
            let workflow = &inventory.workflows[0];
            assert!(!workflow.jobs.is_empty(), "{path}: no jobs");
            for job in &workflow.jobs {
                let where_ = format!("{path}#{}", job.id);
                assert_totality(job, &where_);
                for cell in &job.cells {
                    match cell.destination {
                        Destination::Class(target) => {
                            let label = target.class.to_string();
                            assert!(label.starts_with("sentinel-"), "{where_}: {label}");
                            assert!((1..=128).contains(&target.class.vcpus), "{where_}: {label}");
                        }
                        Destination::Keep(reason) => assert!(
                            matches!(
                                reason,
                                KeepReason::MacOs
                                    | KeepReason::Gpu
                                    | KeepReason::Docker
                                    | KeepReason::Expression
                                    | KeepReason::NoClass
                            ),
                            "{where_}: {reason:?}"
                        ),
                    }
                }
            }
            for trigger in &workflow.triggers {
                assert!(
                    workflow.constructs.iter().any(|c| c.construct
                        == Construct::Trigger {
                            event: trigger.event.clone()
                        }),
                    "{path}: trigger `{}` unclassified",
                    trigger.event
                );
            }
        }
    }
}

#[test]
fn no_fixture_label_is_left_unmapped_without_a_stated_reason() {
    let inventory = analyze_files(&fixtures("valid"), DockerHosts::MicrovmGuests);
    let mut labels = Vec::new();
    for workflow in &inventory.workflows {
        for job in &workflow.jobs {
            labels.extend(job.demand.labels.iter().cloned());
        }
    }
    assert!(!labels.is_empty());
    for label in labels {
        if label.contains("${{") {
            continue;
        }
        let destination = LabelTable::V1.classify(
            &Declared {
                labels: vec![label.clone()],
                group: None,
            },
            false,
            DockerHosts::MicrovmGuests,
        );
        match destination {
            Destination::Class(target) => {
                assert_eq!(
                    RunnerClass::parse(&target.class.to_string()),
                    Some(target.class)
                )
            }
            Destination::Keep(reason) => assert!(
                matches!(
                    reason,
                    KeepReason::MacOs | KeepReason::Gpu | KeepReason::NoClass
                ),
                "`{label}`: {reason:?}"
            ),
        }
    }
}

#[test]
fn label_table_v1_maps_hosted_blacksmith_and_arm64_labels() {
    let class = |label: &str| {
        LabelTable::V1.classify(
            &Declared {
                labels: vec![label.to_owned()],
                group: None,
            },
            false,
            DockerHosts::MicrovmGuests,
        )
    };
    let target = |label: &str| match class(label) {
        Destination::Class(target) => target,
        other => panic!("`{label}`: {other:?}"),
    };
    let served = |label: &str| target(label).class.to_string();

    assert_eq!(served("ubuntu-latest"), "sentinel-4vcpu-ubuntu-2404");
    assert_eq!(served("ubuntu-24.04"), "sentinel-4vcpu-ubuntu-2404");
    assert_eq!(served("ubuntu-22.04"), "sentinel-4vcpu-ubuntu-2404");
    assert!(target("ubuntu-latest").change.is_some());
    assert!(target("ubuntu-24.04").change.is_none());
    assert!(target("ubuntu-22.04").change.is_some());
    assert_eq!(served("ubuntu-24.04-arm"), "sentinel-4vcpu-ubuntu-2404-arm");
    assert_eq!(
        served("ubuntu-24.04-arm64"),
        "sentinel-4vcpu-ubuntu-2404-arm"
    );
    assert_eq!(served("ubuntu-24.04-16core"), "sentinel-16vcpu-ubuntu-2404");
    assert_eq!(served("windows-latest"), "sentinel-4vcpu-windows-2025");
    assert_eq!(served("windows-2025"), "sentinel-4vcpu-windows-2025");
    assert!(target("windows-2022").change.is_some());
    assert_eq!(
        served("blacksmith-2vcpu-ubuntu-2404"),
        "sentinel-2vcpu-ubuntu-2404"
    );
    assert!(target("blacksmith-2vcpu-ubuntu-2404").change.is_none());
    assert_eq!(
        served("blacksmith-8vcpu-ubuntu-2204"),
        "sentinel-8vcpu-ubuntu-2404"
    );
    assert!(target("blacksmith-8vcpu-ubuntu-2204").change.is_some());
    assert_eq!(
        served("blacksmith-2vcpu-windows-2025"),
        "sentinel-2vcpu-windows-2025"
    );
    assert_eq!(
        served("sentinel-16vcpu-ubuntu-2404-arm"),
        "sentinel-16vcpu-ubuntu-2404-arm"
    );

    assert_eq!(class("macos-15"), Destination::Keep(KeepReason::MacOs));
    assert_eq!(class("macos-latest"), Destination::Keep(KeepReason::MacOs));
    assert_eq!(
        class("blacksmith-4vcpu-ubuntu-2404-gpu"),
        Destination::Keep(KeepReason::Gpu)
    );
    assert_eq!(class("self-hosted"), Destination::Keep(KeepReason::NoClass));
    assert_eq!(class("linux"), Destination::Keep(KeepReason::NoClass));
    assert_eq!(
        class("blacksmith-4vcpu-debian-12"),
        Destination::Keep(KeepReason::NoClass)
    );
    assert_eq!(
        class("${{ matrix.os }}"),
        Destination::Keep(KeepReason::Expression)
    );
    assert_eq!(
        LabelTable::V1.classify(
            &Declared {
                labels: vec!["ubuntu-latest".to_owned(), "windows-latest".to_owned()],
                group: None,
            },
            false,
            DockerHosts::MicrovmGuests
        ),
        Destination::Keep(KeepReason::NoClass)
    );
    assert_eq!(
        LabelTable::V1.classify(
            &Declared {
                labels: Vec::new(),
                group: Some("large-runners".to_owned()),
            },
            false,
            DockerHosts::MicrovmGuests
        ),
        Destination::Keep(KeepReason::NoClass)
    );
}

#[test]
fn a_job_needing_docker_needs_a_linux_microvm_guest() {
    let files = fixtures("valid");
    for docker in [DockerHosts::MicrovmGuests, DockerHosts::ContainerOnly] {
        let inventory = analyze_one(&files, docker, "blacksmith-migrated.yml");
        let workflow = &inventory.workflows[0];
        let job = |id: &str| workflow.jobs.iter().find(|job| job.id == id).unwrap();

        let container = job("docker");
        assert!(container.container.is_some());
        match (docker, container.cells[0].destination) {
            (DockerHosts::MicrovmGuests, Destination::Class(target)) => {
                assert!(target.requires_microvm);
                assert_eq!(target.class.to_string(), "sentinel-4vcpu-ubuntu-2404");
            }
            (DockerHosts::ContainerOnly, Destination::Keep(reason)) => {
                assert_eq!(reason, KeepReason::Docker);
            }
            (docker, destination) => panic!("{docker:?}: {destination:?}"),
        }
        // A job that needs no daemon keeps its class either way.
        for id in ["linux", "old-image", "arm"] {
            match job(id).cells[0].destination {
                Destination::Class(target) => assert!(!target.requires_microvm, "{id}"),
                other => panic!("{id}: {other:?}"),
            }
        }
    }
    let inventory = analyze_one(&files, DockerHosts::MicrovmGuests, "gson-build.yml");
    let build = &inventory.workflows[0].jobs[0];
    assert_eq!(build.services.len(), 1);
    assert_eq!(build.services[0].container.image, "mysql:8");
    assert_eq!(build.secrets, ["MYSQL_PASSWORD"]);
    match build.cells[0].destination {
        Destination::Class(target) => assert!(target.requires_microvm),
        other => panic!("{other:?}"),
    }
}

#[test]
fn matrix_cells_resolve_every_runs_on_label() {
    let inventory = analyze_one(
        &fixtures("valid"),
        DockerHosts::MicrovmGuests,
        "ripgrep-ci.yml",
    );
    let workflow = &inventory.workflows[0];
    let test = workflow.jobs.iter().find(|job| job.id == "test").unwrap();
    let matrix = test.matrix.as_ref().unwrap();
    assert_eq!(matrix.axes.len(), 2);
    assert_eq!(matrix.axes[0].name, "os");
    assert_eq!(matrix.axes[0].values.len(), 3);
    assert!(!matrix.fail_fast);
    assert_eq!(
        test.cells.len(),
        3,
        "only the axis the labels name widens them"
    );
    assert_eq!(
        test.cells[0].axes,
        vec![("os".to_owned(), "ubuntu-latest".to_owned())]
    );
    for cell in &test.cells {
        assert!(!cell.labels[0].contains("${{"), "{:?}", cell.labels);
    }
    assert!(matches!(test.cells[0].destination, Destination::Class(_)));
    assert_eq!(
        test.cells[1].destination,
        Destination::Keep(KeepReason::MacOs)
    );
    assert!(matches!(test.cells[2].destination, Destination::Class(_)));
    assert!(events(&inventory, "macos-latest"));
}

/// ripgrep's real `test` job has no axis: every row is an `include` entry that names its `os`.
#[test]
fn an_include_only_matrix_yields_one_cell_per_runs_on_variant() {
    let text = concat!(
        "on: [push]
",
        "jobs:
",
        "  test:
",
        "    runs-on: ${{ matrix.os }}
",
        "    strategy:
",
        "      matrix:
",
        "        include:
",
        "          - {build: stable, os: ubuntu-latest}
",
        "          - {build: beta, os: ubuntu-latest}
",
        "          - {build: macos, os: macos-latest}
",
        "          - {build: bare}
",
        "    steps:
",
        "      - run: cargo test
",
        "  lint:
",
        "    runs-on: ubuntu-latest
",
        "    strategy:
",
        "      matrix:
",
        "        include:
",
        "          - {os: macos-latest}
",
        "    steps:
",
        "      - run: cargo fmt --check
",
    );
    let inventory = analyze_files(
        &[(".github/workflows/ci.yml".to_owned(), text.to_owned())],
        DockerHosts::MicrovmGuests,
    );
    let test = &inventory.workflows[0].jobs[0];
    assert_eq!(test.cells.len(), 3, "the two Ubuntu rows are one variant");
    assert_eq!(
        test.cells[0].axes,
        vec![("os".to_owned(), "ubuntu-latest".to_owned())]
    );
    assert_eq!(test.cells[0].labels, ["ubuntu-latest"]);
    assert!(matches!(test.cells[0].destination, Destination::Class(_)));
    assert_eq!(
        test.cells[1].destination,
        Destination::Keep(KeepReason::MacOs)
    );
    // A row that does not state the key leaves the label unresolved.
    assert!(test.cells[2].axes.is_empty());
    assert_eq!(
        test.cells[2].destination,
        Destination::Keep(KeepReason::Expression)
    );
    // Labels that name no key are not widened by the entries.
    let lint = &inventory.workflows[0].jobs[1];
    assert_eq!(lint.cells.len(), 1);
    assert!(lint.cells[0].axes.is_empty());
    assert!(matches!(lint.cells[0].destination, Destination::Class(_)));
}

fn events(inventory: &workflow::Inventory, label: &str) -> bool {
    inventory.workflows[0]
        .jobs
        .iter()
        .flat_map(|job| job.cells.iter())
        .any(|cell| cell.labels.iter().any(|l| l == label))
}

#[test]
fn the_inventory_records_every_documented_construct() {
    let inventory = analyze_one(&fixtures("valid"), DockerHosts::MicrovmGuests, "full.yml");
    let workflow = &inventory.workflows[0];
    assert_eq!(workflow.name.as_deref(), Some("full"));
    assert_eq!(workflow.path, ".github/workflows/full.yml");
    assert_eq!(workflow.triggers.len(), 4);
    let push = &workflow.triggers[0];
    assert_eq!(push.event, "push");
    assert_eq!(push.branches, ["main"]);
    assert_eq!(push.tags, ["v*"]);
    assert_eq!(push.paths, ["src/**"]);
    let pull = &workflow.triggers[1];
    assert_eq!(pull.paths_ignore, ["docs/**"]);
    assert_eq!(pull.types, ["opened", "synchronize"]);
    assert_eq!(workflow.triggers[3].inputs, ["level"]);
    assert_eq!(
        workflow.permissions,
        [("contents".to_owned(), "read".to_owned())]
    );
    let concurrency = workflow.concurrency.as_ref().unwrap();
    assert!(concurrency.cancel_in_progress);
    assert_eq!(workflow.env, ["CI", "RUST_LOG"]);
    assert_eq!(workflow.variables, ["RUST_LOG"]);
    let defaults = workflow.defaults.as_ref().unwrap();
    assert_eq!(defaults.shell.as_deref(), Some("bash"));
    assert_eq!(defaults.working_directory.as_deref(), Some("./repo"));

    let build = workflow.jobs.iter().find(|job| job.id == "build").unwrap();
    assert_eq!(build.name.as_deref(), Some("build"));
    assert!(build.condition);
    assert_eq!(build.timeout_minutes, Some(20));
    assert_eq!(
        build.permissions,
        [
            ("contents".to_owned(), "read".to_owned()),
            ("checks".to_owned(), "write".to_owned())
        ]
    );
    assert!(
        build
            .concurrency
            .as_ref()
            .is_some_and(|c| !c.cancel_in_progress)
    );
    assert_eq!(build.environment.as_deref(), Some("staging"));
    assert_eq!(build.outputs, ["digest"]);
    assert_eq!(build.env, ["TOKEN"]);
    assert_eq!(build.secrets, ["BUILD_TOKEN", "STEP_TOKEN"]);
    assert_eq!(
        build.defaults.as_ref().unwrap().shell.as_deref(),
        Some("sh")
    );
    assert_eq!(build.container.as_ref().unwrap().image, "node:22");
    assert_eq!(build.services[0].name, "redis");
    assert_eq!(build.services[0].container.image, "redis:7");
    assert_eq!(build.matrix.as_ref().unwrap().max_parallel, Some(1));
    assert_eq!(build.steps.len(), 4);
    assert_eq!(build.steps[0].id.as_deref(), Some("digest"));
    assert_eq!(
        build.steps[1].action.clone().unwrap(),
        ActionRef::Repository {
            repository: "actions/cache".to_owned(),
            version: "v4".to_owned(),
            pinned: false,
        }
    );
    assert_eq!(build.caches.len(), 1);
    assert_eq!(build.caches[0].source, CacheSource::ActionsCache);
    assert_eq!(build.caches[0].paths, ["target", "~/.cargo"]);
    assert_eq!(
        build.caches[0].key.as_deref(),
        Some("cache-${{ hashFiles('Cargo.lock') }}")
    );
    assert_eq!(build.steps[2].shell.as_deref(), Some("bash"));
    assert_eq!(build.steps[2].workdir.as_deref(), Some("./repo"));
    assert!(build.steps[2].continue_on_error);
    assert_eq!(build.steps[2].timeout_minutes, Some(5));
    assert_eq!(build.steps[2].env, ["STEP_TOKEN"]);
    assert_eq!(build.artifacts.len(), 1);
    assert_eq!(build.artifacts[0].direction, ArtifactDirection::Upload);
    assert_eq!(build.artifacts[0].name.as_deref(), Some("out"));
    assert_eq!(build.artifacts[0].paths, ["out/"]);

    let call = workflow.jobs.iter().find(|job| job.id == "call").unwrap();
    assert_eq!(
        call.reusable.as_deref(),
        Some("./.github/workflows/reusable.yml")
    );
    assert_eq!(call.secrets, ["CALL_TOKEN"]);
    assert!(call.steps.is_empty());

    let rules: Vec<(String, Rule)> = workflow
        .jobs
        .iter()
        .flat_map(|job| job.constructs.iter())
        .map(|c| (c.construct.name().to_owned(), c.rule))
        .collect();
    assert!(rules.iter().any(|(name, rule)| name == "container"
        && *rule
            == Rule::Unsupported {
                reason: "a container needs a Docker daemon, which only a microVM sandbox can \
                         offer (I08)"
            }));
    assert!(rules.iter().any(|(name, rule)| name == "outputs"
        && *rule
            == Rule::WithChange {
                change: "a job's outputs become the step `outputs` that write them and the job's own \
                         `outputs`, plain text in the run's record"
            }));
}

#[test]
fn rule_table_v1_classifies_every_construct() {
    let trigger = |event: &str| {
        RuleTable::V1.classify(&Construct::Trigger {
            event: event.to_owned(),
        })
    };
    for event in ["push", "pull_request", "merge_group", "workflow_dispatch"] {
        assert_eq!(trigger(event), Rule::Translatable, "{event}");
    }
    for event in [
        "workflow_call",
        "workflow_run",
        "pull_request_target",
        "release",
        "repository_dispatch",
        "deployment",
        "issues",
    ] {
        assert!(
            matches!(trigger(event), Rule::Unsupported { .. }),
            "{event}"
        );
    }
    assert!(matches!(trigger("schedule"), Rule::WithChange { .. }));
    let action = |uses: &str| {
        RuleTable::V1.classify(&Construct::Action {
            uses: uses.to_owned(),
        })
    };
    assert_eq!(action("actions/checkout@v4"), Rule::Translatable);
    assert!(matches!(
        action("actions/cache@v4"),
        Rule::WithChange { .. }
    ));
    assert!(matches!(
        action("actions/cache/restore@v4"),
        Rule::WithChange { .. }
    ));
    assert!(matches!(
        action("actions/upload-artifact@v4"),
        Rule::WithChange { .. }
    ));
    assert!(matches!(
        action("actions/download-artifact@v4"),
        Rule::Unsupported { .. }
    ));
    assert!(matches!(
        action("actions/setup-node@v4"),
        Rule::WithChange { .. }
    ));
    assert!(matches!(
        action("Swatinem/rust-cache@v2"),
        Rule::WithChange { .. }
    ));
    assert!(matches!(
        action("docker://alpine:3"),
        Rule::Unsupported { .. }
    ));
    assert!(matches!(
        action("./.github/actions/build"),
        Rule::Unsupported { .. }
    ));
    assert!(matches!(
        action("some/third-party@v1"),
        Rule::Unsupported { .. }
    ));
    assert!(matches!(
        action("actions/checkout"),
        Rule::Unsupported { .. }
    ));
    assert_eq!(
        RuleTable::V1.classify(&Construct::Shell {
            shell: "bash".to_owned()
        }),
        Rule::Translatable
    );
    assert!(matches!(
        RuleTable::V1.classify(&Construct::Shell {
            shell: "pwsh".to_owned()
        }),
        Rule::Unsupported { .. }
    ));
    let constructs = [
        Construct::Permissions,
        Construct::Concurrency,
        Construct::Env,
        Construct::Defaults,
        Construct::Needs,
        Construct::Condition,
        Construct::Timeout,
        Construct::Matrix,
        Construct::Container,
        Construct::Services,
        Construct::Environment,
        Construct::Outputs,
        Construct::ReusableWorkflow,
        Construct::ContinueOnError,
        Construct::Workdir,
        Construct::RunStep,
    ];
    for construct in &constructs {
        let rule = RuleTable::V1.classify(construct);
        assert!(
            matches!(
                rule,
                Rule::Translatable | Rule::WithChange { .. } | Rule::Unsupported { .. }
            ),
            "{construct:?}"
        );
        assert!(!construct.name().is_empty());
        assert!(!rule.as_str().is_empty());
        if !matches!(rule, Rule::Translatable) {
            assert!(
                rule.note().is_some_and(|note| !note.is_empty()),
                "{construct:?}"
            );
        }
    }
    assert_eq!(RuleTable::V1.version(), RULE_TABLE_VERSION);
    assert_eq!(LabelTable::V1.version(), LABEL_TABLE_VERSION);
}

#[test]
fn the_loading_limits_refuse_oversized_and_deeply_nested_workflows() {
    let refused =
        |files: &[(String, String)]| try_analyze(files, DockerHosts::MicrovmGuests).unwrap_err();
    let path = format!("{WORKFLOW_DIRECTORY}/ci.yml");

    let oversized = "# ".to_owned() + &"x".repeat(MAX_PIPELINE_FILE_BYTES);
    let error = refused(&[(path.clone(), oversized)]);
    assert!(
        matches!(
            error.kind,
            WorkflowErrorKind::Yaml(ref e)
                if matches!(e.kind, sentinel_pipeline::yaml::YamlErrorKind::TooLarge { .. })
        ),
        "{error}"
    );

    let mut nested = String::from("a:\n");
    for depth in 1..40 {
        nested.push_str(&"  ".repeat(depth));
        nested.push_str("b:\n");
    }
    let error = refused(&[(path.clone(), nested)]);
    assert!(
        matches!(
            error.kind,
            WorkflowErrorKind::Yaml(ref e)
                if matches!(e.kind, sentinel_pipeline::yaml::YamlErrorKind::TooDeep { limit: 16 })
        ),
        "{error}"
    );

    let mut many_jobs = String::from("on: [push]\njobs:\n");
    for i in 0..=MAX_JOBS {
        many_jobs.push_str(&format!(
            "  job{i}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        ));
    }
    let error = refused(&[(path.clone(), many_jobs)]);
    assert_eq!(error.kind, WorkflowErrorKind::TooMany { limit: MAX_JOBS });

    let values: Vec<String> = (0..=MAX_MATRIX_VALUES).map(|i| i.to_string()).collect();
    let wide = format!(
        "on: [push]\njobs:\n  build:\n    runs-on: ${{{{ matrix.n }}}}\n    strategy:\n      matrix:\n        n: [{}]\n    steps:\n      - run: echo\n",
        values.join(", ")
    );
    let error = refused(&[(path.clone(), wide)]);
    assert_eq!(
        error.kind,
        WorkflowErrorKind::TooMany {
            limit: MAX_MATRIX_VALUES
        }
    );

    let a: Vec<String> = (0..20).map(|i| format!("a{i}")).collect();
    let b: Vec<String> = (0..20).map(|i| format!("b{i}")).collect();
    let cells = format!(
        "on: [push]\njobs:\n  build:\n    runs-on: [\"${{{{ matrix.a }}}}\", \"${{{{ matrix.b }}}}\"]\n    strategy:\n      matrix:\n        a: [{}]\n        b: [{}]\n    steps:\n      - run: echo\n",
        a.join(", "),
        b.join(", ")
    );
    let error = refused(&[(path, cells)]);
    assert_eq!(
        error.kind,
        WorkflowErrorKind::TooMany {
            limit: MAX_MATRIX_CELLS
        }
    );

    let mut many_files = Vec::new();
    for i in 0..=MAX_WORKFLOW_FILES {
        many_files.push((
            format!("{WORKFLOW_DIRECTORY}/w{i}.yml"),
            "on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
                .to_owned(),
        ));
    }
    let error = refused(&many_files);
    assert_eq!(
        error.kind,
        WorkflowErrorKind::TooMany {
            limit: MAX_WORKFLOW_FILES
        }
    );
    assert_eq!(error.path, WORKFLOW_DIRECTORY);
}

#[test]
fn every_invalid_fixture_fails_with_the_expected_message() {
    for (path, text) in fixtures("invalid") {
        let expect = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("# expect: "))
            .unwrap_or_else(|| panic!("{path}: missing `# expect:` header"));
        let error = try_analyze(&[(path.clone(), text.clone())], DockerHosts::MicrovmGuests)
            .err()
            .unwrap_or_else(|| panic!("{path}: analyzed unexpectedly"));
        let message = error.to_string();
        assert!(
            message.contains(expect),
            "{path}: expected `{expect}` in `{message}`"
        );
    }
}

#[test]
fn inputs_are_a_pinned_commit_and_the_workflow_directory() {
    let text =
        "on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n";
    let file = |path: &'static str| vec![WorkflowFile { path, text }];
    let error = analyze(
        "main",
        &file(".github/workflows/ci.yml"),
        DockerHosts::MicrovmGuests,
    )
    .err()
    .unwrap();
    assert_eq!(
        error.kind,
        WorkflowErrorKind::Invalid("a pinned commit is 40 or 64 lower-case hex characters")
    );
    let upper = REVISION.to_uppercase();
    assert!(
        analyze(
            &upper,
            &file(".github/workflows/ci.yml"),
            DockerHosts::MicrovmGuests
        )
        .is_err()
    );
    for path in [
        "ci.yml",
        ".github/workflows/ci.txt",
        ".github/workflows/nested/ci.yml",
        ".github/workflows/",
    ] {
        let error = analyze(REVISION, &file(path), DockerHosts::MicrovmGuests)
            .err()
            .unwrap();
        assert!(
            matches!(error.kind, WorkflowErrorKind::Invalid(_)),
            "{path}: {error}"
        );
    }
    let twice = [
        WorkflowFile {
            path: ".github/workflows/ci.yml",
            text,
        },
        WorkflowFile {
            path: ".github/workflows/ci.yml",
            text,
        },
    ];
    let error = analyze(REVISION, &twice, DockerHosts::MicrovmGuests)
        .err()
        .unwrap();
    assert!(
        matches!(error.kind, WorkflowErrorKind::Invalid(_)),
        "{error}"
    );
}

#[test]
fn the_inventory_holds_names_and_never_values() {
    let text = concat!(
        "on: [push]\n",
        "env:\n",
        "  DEPLOY_KEY: sntl_at_0000deadbeef\n",
        "jobs:\n",
        "  a:\n",
        "    runs-on: ubuntu-latest\n",
        "    env:\n",
        "      GH_TOKEN: ${{ secrets.GH_TOKEN }}\n",
        "      LEVEL: ${{ vars.LEVEL }}\n",
        "    steps:\n",
        "      - run: |\n",
        "          curl -H \"Authorization: ${{ secrets.API_TOKEN }}\" https://example.invalid\n",
        "      - run: |\n",
        "          echo \"${{ secrets['quoted name'] }}\"\n",
    );
    let inventory = analyze_files(
        &[(".github/workflows/ci.yml".to_owned(), text.to_owned())],
        DockerHosts::MicrovmGuests,
    );
    let job = &inventory.workflows[0].jobs[0];
    assert_eq!(job.secrets, ["GH_TOKEN", "API_TOKEN", "quoted name"]);
    assert_eq!(job.variables, ["LEVEL"]);
    assert_eq!(job.env, ["GH_TOKEN", "LEVEL"]);
    let rendered = format!("{inventory:?}");
    assert!(!rendered.contains("sntl_at_0000deadbeef"), "{rendered}");
    assert!(!rendered.contains("curl"), "{rendered}");
    assert!(!rendered.contains("example.invalid"), "{rendered}");
}

#[test]
fn the_same_files_analyze_the_same_in_any_order() {
    let files = fixtures("valid");
    let forward = analyze_files(&files, DockerHosts::MicrovmGuests);
    let mut reversed = files.clone();
    reversed.reverse();
    let backward = analyze_files(&reversed, DockerHosts::MicrovmGuests);
    assert_eq!(forward, backward);
    assert_eq!(classes(&forward), classes(&fixtures_again()));
    assert_eq!(keep_reasons(&forward), keep_reasons(&fixtures_again()));
}

fn fixtures_again() -> workflow::Inventory {
    analyze_files(&fixtures("valid"), DockerHosts::MicrovmGuests)
}

#[test]
fn the_blacksmith_fixture_keeps_what_sentinel_cannot_serve() {
    let inventory = analyze_one(
        &fixtures("valid"),
        DockerHosts::MicrovmGuests,
        "blacksmith-migrated.yml",
    );
    let workflow = &inventory.workflows[0];
    let reason =
        |id: &str| workflow.jobs.iter().find(|job| job.id == id).unwrap().cells[0].destination;
    assert_eq!(reason("gpu"), Destination::Keep(KeepReason::Gpu));
    assert_eq!(reason("mac"), Destination::Keep(KeepReason::MacOs));
    assert_eq!(
        reason("self-hosted"),
        Destination::Keep(KeepReason::NoClass)
    );
    assert!(matches!(reason("linux"), Destination::Class(_)));
    assert_eq!(classes(&inventory).len(), 5);
    assert_eq!(keep_reasons(&inventory).len(), 3);
    assert!(workflow.triggers.iter().any(|t| t.event == "schedule"));
    assert_eq!(
        workflow
            .triggers
            .iter()
            .find(|t| t.event == "schedule")
            .unwrap()
            .crons,
        ["0 3 * * 1"]
    );
    let native: Vec<(String, Rule)> = workflow
        .constructs
        .iter()
        .map(|c| (c.construct.name().to_owned(), c.rule))
        .collect();
    assert!(native.iter().any(|(name, rule)| name == "on"
        && *rule
            == Rule::WithChange {
                change: "the crons become a stored per-repository schedule; the translated \
                         pipeline accepts a scheduled run",
            }));
}

#[test]
fn an_already_migrated_workflow_analyzes_to_itself() {
    let files = fixtures("valid");
    let inventory = analyze_one(&files, DockerHosts::MicrovmGuests, "already-sentinel.yml");
    let workflow = &inventory.workflows[0];
    let test = workflow.jobs.iter().find(|job| job.id == "test").unwrap();
    match test.cells[0].destination {
        Destination::Class(target) => {
            assert_eq!(target.class.to_string(), "sentinel-8vcpu-ubuntu-2404");
            assert!(target.change.is_none());
        }
        other => panic!("{other:?}"),
    }
    let group = workflow.jobs.iter().find(|job| job.id == "group").unwrap();
    assert_eq!(
        group.cells[0].destination,
        Destination::Keep(KeepReason::NoClass)
    );
    assert_eq!(
        workflow.permissions,
        [("all".to_owned(), "read".to_owned())]
    );
}

#[test]
fn a_runner_class_is_always_one_the_worker_vocabulary_accepts() {
    let inventory = analyze_files(&fixtures("valid"), DockerHosts::ContainerOnly);
    for (_, class) in classes(&inventory) {
        let label = class.to_string();
        assert_eq!(RunnerClass::parse(&label), Some(class), "{label}");
        assert!(!class.os.is_windows() || class.os == RunnerOs::Windows2025);
    }
}
