//! The migration's other steps: the shadow that adds a non-required copy of every migrating job
//! beside its unchanged original, the switch that drops the copies and moves the labels, and the
//! native path's disable.
//!
//! Every phase's text is checked against the workflow it started from, and a switch of a
//! shadowed workflow must be the text a label plan of the unshadowed one produces — that is the
//! proof the switch drops exactly the copies and moves exactly the labels.

use std::fs;
use std::path::{Path, PathBuf};

use sentinel_pipeline::workflow::{
    self, COPY_PREFIX, DockerHosts, Images, LabelChange, Options, Phase, Plan, ShadowJob, Workflow,
    WorkflowFile, analyze, plan,
};

const REVISION: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";
const IMAGE: &str = "docker.io/library/ubuntu:24.04@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const ARM_IMAGE: &str = "docker.io/library/ubuntu:24.04@sha256:2a2c6b7de0e0f0b0acd4a4f5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f";

fn fixture_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/workflows")
        .join(sub)
}

/// Every workflow fixture in a directory, by path under `.github/workflows`.
fn fixtures(sub: &str) -> Vec<(String, String)> {
    let dir = fixture_dir(sub);
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|x| x == "yml")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".sentinel.yml"))
        })
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (
                format!("{}/{name}", workflow::WORKFLOW_DIRECTORY),
                fs::read_to_string(&path).unwrap(),
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures in {}", dir.display());
    out
}

/// Every fixture the label table can read, so each phase sees the pilots' own shapes.
fn every_fixture() -> Vec<(String, String)> {
    let mut out = fixtures("valid");
    out.extend(fixtures("native"));
    out.sort();
    out
}

fn images() -> Images<'static> {
    Images {
        linux: Some(IMAGE),
        linux_arm64: Some(ARM_IMAGE),
        windows: Some(IMAGE),
    }
}

fn plan_of(files: &[(String, String)], phase: Phase, native: bool) -> Plan {
    plan_with(files, phase, native, images())
}

fn plan_with(
    files: &[(String, String)],
    phase: Phase,
    native: bool,
    images: Images<'static>,
) -> Plan {
    let borrowed: Vec<WorkflowFile<'_>> = files
        .iter()
        .map(|(path, text)| WorkflowFile { path, text })
        .collect();
    let inventory = analyze(REVISION, &borrowed, DockerHosts::MicrovmGuests).unwrap();
    plan(
        &inventory,
        &borrowed,
        &Options {
            docker: DockerHosts::MicrovmGuests,
            native,
            images,
            phase,
        },
    )
    .unwrap()
}

fn plan_err(files: &[(String, String)], phase: Phase, native: bool) -> workflow::PlanError {
    let borrowed: Vec<WorkflowFile<'_>> = files
        .iter()
        .map(|(path, text)| WorkflowFile { path, text })
        .collect();
    let inventory = analyze(REVISION, &borrowed, DockerHosts::MicrovmGuests).unwrap();
    plan(
        &inventory,
        &borrowed,
        &Options {
            docker: DockerHosts::MicrovmGuests,
            native,
            images: images(),
            phase,
        },
    )
    .unwrap_err()
}

fn texts(files: &[(String, String)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(path, text)| (path.clone(), text.clone()))
        .collect()
}

/// A workflow of one file under the usual path.
fn one(path: &str) -> String {
    format!("{}/{path}", workflow::WORKFLOW_DIRECTORY)
}

/// Analyzes one workflow text on its own.
fn analyze_one(path: &str, text: &str) -> Workflow {
    let files = [WorkflowFile { path, text }];
    analyze(REVISION, &files, DockerHosts::MicrovmGuests)
        .unwrap()
        .workflows
        .remove(0)
}

/// The one class a job's labels resolve to, when every cell agrees: the jobs a shadow copies and
/// a switch moves.
fn class_of(job: &workflow::Job) -> Option<String> {
    let mut class: Option<String> = None;
    for cell in &job.cells {
        let workflow::Destination::Class(target) = cell.destination else {
            return None;
        };
        let label = target.class.to_string();
        match &class {
            None => class = Some(label),
            Some(first) if *first == label => {}
            Some(_) => return None,
        }
    }
    class
}

/// One hunk of a unified diff, as the lines it removes and adds.
struct Hunk {
    before_start: usize,
    lines: Vec<(char, String)>,
}

fn parse_diff(diff: &str) -> Vec<Hunk> {
    let mut hunks: Vec<Hunk> = Vec::new();
    for line in diff.lines() {
        if line.starts_with("--- ") || line.starts_with("+++ ") {
            continue;
        }
        if let Some(header) = line.strip_prefix("@@ -") {
            let before = header.split(' ').next().unwrap();
            let start: usize = before.split(',').next().unwrap().parse().unwrap();
            hunks.push(Hunk {
                before_start: start,
                lines: Vec::new(),
            });
            continue;
        }
        let hunk = hunks.last_mut().expect("a hunk before its lines");
        let mark = line.chars().next().unwrap_or(' ');
        assert!(
            matches!(mark, ' ' | '-' | '+'),
            "a diff line is context, removed or added: {line:?}"
        );
        hunk.lines.push((mark, line[1..].to_owned()));
    }
    hunks
}

/// The input with the diff applied, checking every context and removed line against it.
fn apply_diff(text: &str, hunks: &[Hunk]) -> String {
    assert!(text.ends_with('\n'), "fixtures end with a newline");
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut cursor = 0;
    for hunk in hunks {
        let start = hunk.before_start - 1;
        assert!(start >= cursor, "hunks are in order");
        out.extend(lines[cursor..start].iter().map(|l| (*l).to_owned()));
        cursor = start;
        for (mark, line) in &hunk.lines {
            match mark {
                ' ' => {
                    assert_eq!(lines[cursor], line, "context line {cursor} differs");
                    out.push(line.clone());
                    cursor += 1;
                }
                '-' => {
                    assert_eq!(lines[cursor], line, "removed line {cursor} differs");
                    cursor += 1;
                }
                '+' => out.push(line.clone()),
                _ => unreachable!(),
            }
        }
    }
    out.extend(lines[cursor..].iter().map(|l| (*l).to_owned()));
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// The text with every inserted block taken back out: what a phase added is exactly what the
/// records say it added, and the original is byte for byte the workflow the plan started from.
fn without_insertions(text: &str, changes: &[LabelChange]) -> String {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut cursor = 0;
    for change in changes {
        assert!(
            change.before.is_empty(),
            "{}: an insertion replaces nothing",
            change.job
        );
        let start = change.line as usize - 1;
        assert!(start >= cursor, "{}: the records are in order", change.job);
        let block: Vec<&str> = change.after.split_inclusive('\n').collect();
        assert_eq!(
            &lines[start..start + block.len()],
            block.as_slice(),
            "{}: the added block is not at line {}",
            change.job,
            change.line
        );
        out.extend_from_slice(&lines[cursor..start]);
        cursor = start + block.len();
    }
    out.extend_from_slice(&lines[cursor..]);
    out.concat()
}

#[test]
fn a_shadow_plan_adds_one_copy_per_migrating_job() {
    let mut copies = 0;
    let mut shaded = 0;
    for files in [every_fixture()] {
        let shadowed = plan_of(&files, Phase::Shadow, false);
        for (index, workflow) in shadowed.workflows.iter().enumerate() {
            let text = &files[index].1;
            let before = analyze_one(&workflow.path, text);
            let migrating: Vec<String> = before
                .jobs
                .iter()
                .filter(|job| class_of(job).is_some())
                .map(|job| job.id.clone())
                .collect();
            assert_eq!(
                workflow.shadow.len(),
                migrating.len(),
                "{}: one copy per migrating job",
                workflow.path
            );
            for (copy, original) in workflow.shadow.iter().zip(&migrating) {
                assert_eq!(&copy.original, original, "{}: job order", workflow.path);
                assert_eq!(copy.job, format!("sentinel-{original}"));
                let job = before.jobs.iter().find(|job| job.id == *original).unwrap();
                let name = job.name.as_deref().unwrap_or(&job.id);
                assert_eq!(copy.name, format!("{COPY_PREFIX}{name}"));
                assert_eq!(class_of(job).as_deref(), Some(copy.class.as_str()));
            }
            for job in &before.jobs {
                if class_of(job).is_some() {
                    continue;
                }
                shaded += 1;
                let kept = format!("sentinel-{}", job.id);
                assert!(
                    !workflow.shadow.iter().any(|copy| copy.job == kept),
                    "{}: {} has no class and must not be copied",
                    workflow.path,
                    job.id
                );
            }
            if workflow.shadow.is_empty() {
                assert!(workflow.changes.is_empty(), "{}", workflow.path);
                assert!(workflow.diff.is_empty(), "{}", workflow.path);
                assert_eq!(workflow.applied, None, "{}", workflow.path);
                continue;
            }
            copies += workflow.shadow.len();
            let applied = workflow.applied.as_ref().unwrap();
            // The records are the copies, and taking them out gives the input back: no original
            // line moved.
            assert_eq!(workflow.changes.len(), workflow.shadow.len());
            for (change, copy) in workflow.changes.iter().zip(&workflow.shadow) {
                assert_eq!(change.job, copy.job);
                assert!(
                    change.after.contains(&format!("name: '{COPY_PREFIX}")),
                    "{}: the copy states its name: {}",
                    workflow.path,
                    change.after
                );
                assert!(
                    change.after.contains(&format!("runs-on: {}\n", copy.class)),
                    "{}: the copy asks for its class: {}",
                    workflow.path,
                    change.after
                );
                assert!(change.after.contains(&format!("{}:", copy.job)));
            }
            assert_eq!(
                without_insertions(applied, &workflow.changes),
                *text,
                "{}: the original is not the workflow the plan started from",
                workflow.path
            );
            // The diff is those insertions, and applying it gives the same text.
            let hunks = parse_diff(&workflow.diff);
            for hunk in &hunks {
                assert!(
                    hunk.lines.iter().all(|(mark, _)| *mark != '-'),
                    "{}: a shadow removes nothing",
                    workflow.path
                );
            }
            assert_eq!(apply_diff(text, &hunks), *applied, "{}", workflow.path);
            // The copies are the jobs the plan says, with the originals' own facts.
            let after = analyze_one(&workflow.path, applied);
            assert_eq!(after.jobs.len(), before.jobs.len() + workflow.shadow.len());
            for copy in &workflow.shadow {
                let job = after
                    .jobs
                    .iter()
                    .find(|job| job.id == copy.job)
                    .unwrap_or_else(|| panic!("{}: {} is not a job", workflow.path, copy.job));
                assert_eq!(job.name.as_deref(), Some(copy.name.as_str()));
                assert_eq!(class_of(job).as_deref(), Some(copy.class.as_str()));
                let original = before
                    .jobs
                    .iter()
                    .find(|job| job.id == copy.original)
                    .unwrap();
                assert_eq!(job.steps, original.steps);
                assert_eq!(job.matrix, original.matrix);
                assert_eq!(job.constructs, original.constructs);
            }
            for original in &before.jobs {
                let job = after.jobs.iter().find(|job| job.id == original.id).unwrap();
                assert_eq!(job, original, "{}: {} moved", workflow.path, original.id);
            }
        }
    }
    assert!(copies > 8, "too few copies to be a gate: {copies}");
    assert!(shaded > 2, "no kept job went uncopied: {shaded}");
}

#[test]
fn a_copy_needs_the_copies_of_the_jobs_it_needs() {
    let text = "name: needs
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
  deploy:
    needs: [build, mac]
    runs-on: ubuntu-latest
    steps:
      - run: make deploy
  mac:
    runs-on: macos-15
    steps:
      - run: make test
";
    let path = one("needs.yml");
    let files = vec![(path.clone(), text.to_owned())];
    let planned = plan_of(&files, Phase::Shadow, false);
    let applied = planned.workflows[0].applied.as_ref().unwrap();
    let after = analyze_one(&path, applied);
    let deploy = after
        .jobs
        .iter()
        .find(|job| job.id == "sentinel-deploy")
        .expect("the deploy job's copy");
    assert_eq!(
        deploy.needs,
        vec!["sentinel-build".to_owned(), "mac".to_owned()]
    );
    // The job the table keeps is not copied, so the copy waits for it by its own id.
    assert!(after.jobs.iter().all(|job| job.id != "sentinel-mac"));
    let mac = after.jobs.iter().find(|job| job.id == "mac").unwrap();
    assert_eq!(mac.needs, Vec::<String>::new());
}

#[test]
fn shadowing_a_shadowed_workflow_adds_nothing() {
    let files = every_fixture();
    let shadowed = plan_of(&files, Phase::Shadow, false);
    let once: Vec<(String, String)> = files
        .iter()
        .zip(&shadowed.workflows)
        .map(|((path, text), workflow)| {
            (
                path.clone(),
                workflow.applied.clone().unwrap_or_else(|| text.clone()),
            )
        })
        .collect();
    let twice = plan_of(&once, Phase::Shadow, false);
    for workflow in &twice.workflows {
        assert!(
            workflow.shadow.is_empty(),
            "{}: a copy of a copy was added",
            workflow.path
        );
        assert!(workflow.changes.is_empty(), "{}", workflow.path);
        assert!(workflow.diff.is_empty(), "{}", workflow.path);
        assert_eq!(workflow.applied, None, "{}", workflow.path);
    }
}

#[test]
fn a_copy_id_some_other_job_holds_is_refused() {
    let text = "name: taken
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
  sentinel-build:
    runs-on: ubuntu-latest
    steps:
      - run: make other
";
    let files = vec![(one("taken.yml"), text.to_owned())];
    let error = plan_err(&files, Phase::Shadow, false);
    assert!(
        matches!(&error, workflow::PlanError::Copy { job, .. } if job == "sentinel-build"),
        "{error}"
    );
    assert!(error.to_string().contains("jobs.sentinel-build"), "{error}");
}

#[test]
fn a_job_the_text_does_not_hold_refuses_the_shadow() {
    // The inventory of one text, planned against another under the same path: the job is not
    // where the plan would copy it, so the phase refuses instead of copying another job.
    let path = one("swapped.yml");
    let text = "name: one\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: x\n";
    let inventory = analyze(
        REVISION,
        &[WorkflowFile { path: &path, text }],
        DockerHosts::MicrovmGuests,
    )
    .unwrap();
    let other = "name: other\non: [push]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: y\n";
    let swapped = [WorkflowFile {
        path: &path,
        text: other,
    }];
    let error = plan(
        &inventory,
        &swapped,
        &Options {
            docker: DockerHosts::MicrovmGuests,
            native: false,
            images: images(),
            phase: Phase::Shadow,
        },
    )
    .unwrap_err();
    assert!(
        matches!(&error, workflow::PlanError::Unverified { job, .. } if job == "build"),
        "{error}"
    );
}

#[test]
fn the_switch_of_a_shadowed_workflow_is_the_label_plan() {
    let files = every_fixture();
    let label = plan_of(&files, Phase::Label, false);
    let shadowed = plan_of(&files, Phase::Shadow, false);
    let copies: Vec<(String, String)> = files
        .iter()
        .zip(&shadowed.workflows)
        .map(|((path, text), workflow)| {
            (
                path.clone(),
                workflow.applied.clone().unwrap_or_else(|| text.clone()),
            )
        })
        .collect();
    assert!(
        shadowed
            .workflows
            .iter()
            .any(|workflow| !workflow.shadow.is_empty()),
        "no fixture is shadowed"
    );
    let switched = plan_of(&copies, Phase::Switch, false);
    for (index, workflow) in switched.workflows.iter().enumerate() {
        assert_eq!(workflow.kept, label.workflows[index].kept);
        let expected = label
            .workflows
            .get(index)
            .and_then(|label| label.applied.clone())
            .unwrap_or_else(|| files[index].1.clone());
        // Every copy of a job the table moved is dropped, and the records are the survivors'.
        let shadowed_copies = &shadowed.workflows[index].shadow;
        if shadowed_copies.is_empty() {
            assert!(workflow.dropped.is_empty(), "{}", workflow.path);
            assert_eq!(
                workflow.applied,
                label
                    .workflows
                    .get(index)
                    .and_then(|label| label.applied.clone()),
                "{}: an unshadowed switch is the label plan",
                workflow.path
            );
            continue;
        }
        assert_eq!(
            workflow.applied.as_deref(),
            Some(expected.as_str()),
            "{}: the switch is not the label plan",
            workflow.path
        );
        assert_eq!(
            workflow.dropped.len(),
            shadowed_copies.len(),
            "{}: a copy survived the switch",
            workflow.path
        );
        let ids: Vec<&str> = workflow
            .dropped
            .iter()
            .map(|copy| copy.job.as_str())
            .collect();
        for copy in shadowed_copies {
            assert!(
                ids.contains(&copy.job.as_str()),
                "{}: {} stayed",
                workflow.path,
                copy.job
            );
        }
        for copy in &workflow.dropped {
            let source = shadowed_copies
                .iter()
                .find(|shadow| shadow.job == copy.job)
                .unwrap();
            assert_eq!(
                copy, source,
                "{}: the dropped copy is not the one added",
                workflow.path
            );
            assert!(
                !copy.class.is_empty(),
                "{}: {} states no class",
                workflow.path,
                copy.job
            );
            assert!(
                !workflow.changes.iter().any(|change| change.job == copy.job),
                "{}: a dropped copy is not a label change",
                workflow.path
            );
            assert!(!workflow.diff.contains(&format!("+  {}:", copy.job)));
        }
        // A second switch of the switched file finds nothing left to do.
        let again = plan_of(
            &[(workflow.path.clone(), workflow.applied.clone().unwrap())],
            Phase::Switch,
            false,
        );
        assert!(again.workflows[0].dropped.is_empty(), "{}", workflow.path);
        assert_eq!(again.workflows[0].applied, None, "{}", workflow.path);
    }
}

#[test]
fn the_switch_of_an_unshadowed_workflow_is_the_label_plan() {
    let files = every_fixture();
    let label = plan_of(&files, Phase::Label, false);
    let switched = plan_of(&files, Phase::Switch, false);
    for (index, workflow) in switched.workflows.iter().enumerate() {
        assert!(workflow.dropped.is_empty(), "{}", workflow.path);
        assert_eq!(workflow.applied, label.workflows[index].applied);
        assert_eq!(workflow.changes, label.workflows[index].changes);
        assert_eq!(workflow.diff, label.workflows[index].diff);
    }
}

#[test]
fn the_switch_refuses_a_survivor_that_needs_a_copy() {
    let text = "name: needed
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
  sentinel-build:
    name: 'sentinel / build'
    runs-on: sentinel-4vcpu-ubuntu-2404
    steps:
      - run: make build
  publish:
    needs: [sentinel-build]
    runs-on: ubuntu-latest
    steps:
      - run: make publish
";
    let files = vec![(one("needed.yml"), text.to_owned())];
    let error = plan_err(&files, Phase::Switch, false);
    assert!(
        matches!(&error, workflow::PlanError::Copy { job, .. } if job == "sentinel-build"),
        "{error}"
    );
}

#[test]
fn the_switch_drops_a_copy_the_label_table_now_keeps() {
    let text = "name: kept
on: [push]
jobs:
  mac:
    runs-on: macos-15
    steps:
      - run: make test
  sentinel-mac:
    name: 'sentinel / mac'
    runs-on: sentinel-4vcpu-ubuntu-2404
    steps:
      - run: make test
";
    let files = vec![(one("kept.yml"), text.to_owned())];
    let planned = plan_of(&files, Phase::Switch, false);
    let workflow = &planned.workflows[0];
    assert_eq!(
        workflow.dropped,
        vec![ShadowJob {
            job: "sentinel-mac".to_owned(),
            original: "mac".to_owned(),
            name: format!("{COPY_PREFIX}mac"),
            class: "sentinel-4vcpu-ubuntu-2404".to_owned(),
        }]
    );
    assert!(workflow.changes.is_empty(), "{:?}", workflow.changes);
    let applied = workflow.applied.as_ref().unwrap();
    assert!(!applied.contains("sentinel-mac"));
    assert!(applied.contains("  mac:"));
    let after = analyze_one(&workflow.path, applied);
    assert_eq!(after.jobs.len(), 1);
    assert_eq!(after.jobs[0].id, "mac");
}

#[test]
fn the_disable_sets_an_always_false_condition_on_the_replaced_jobs() {
    let files = fixtures("native");
    let planned = plan_of(&files, Phase::Disable, true);
    let mut disabled = 0;
    for (index, workflow) in planned.workflows.iter().enumerate() {
        let text = &files[index].1;
        let before = analyze_one(&workflow.path, text);
        let native = workflow
            .native
            .as_ref()
            .unwrap_or_else(|| panic!("{}: {}", workflow.path, workflow.native_refused.unwrap()));
        let served: Vec<&str> = native
            .jobs
            .iter()
            .filter(|mapping| !mapping.jobs.is_empty())
            .map(|mapping| mapping.github.as_str())
            .collect();
        let expected: Vec<String> = before
            .jobs
            .iter()
            .filter(|job| served.contains(&job.id.as_str()))
            .map(|job| job.id.clone())
            .collect();
        assert_eq!(workflow.disabled, expected, "{}", workflow.path);
        let applied = workflow.applied.as_ref().unwrap();
        let after = analyze_one(&workflow.path, applied);
        assert_eq!(after.jobs.len(), before.jobs.len());
        for (job, changed) in before.jobs.iter().zip(&after.jobs) {
            assert_eq!(job.id, changed.id, "{}: a job id moved", workflow.path);
            assert_eq!(
                job.name, changed.name,
                "{}: a check name moved",
                workflow.path
            );
            if workflow.disabled.contains(&job.id) {
                assert!(
                    changed.condition,
                    "{}: {} still runs",
                    workflow.path, job.id
                );
                assert_eq!(changed.cells, job.cells);
                assert_eq!(changed.steps, job.steps);
                assert!(applied.contains("if: ${{ false }}\n"), "{}", workflow.path);
            } else {
                assert_eq!(job, changed, "{}: {} moved", workflow.path, job.id);
            }
        }
        // The diff is the `if:` lines and nothing else, and it applies to the input.
        let hunks = parse_diff(&workflow.diff);
        assert_eq!(apply_diff(text, &hunks), *applied, "{}", workflow.path);
        for hunk in &hunks {
            for (mark, line) in &hunk.lines {
                if *mark == '+' {
                    assert!(
                        line.trim_start().starts_with("if: ${{ false }}"),
                        "{}: an added line is not the condition: {line:?}",
                        workflow.path
                    );
                }
            }
        }
        disabled += workflow.disabled.len();
    }
    assert!(
        disabled >= 4,
        "too few disabled jobs to be a gate: {disabled}"
    );
}

#[test]
fn the_disable_leaves_the_jobs_a_pipeline_did_not_replace_alone() {
    let files = fixtures("native");
    let planned = plan_of(&files, Phase::Disable, true);
    let mixed = planned
        .workflows
        .iter()
        .find(|workflow| workflow.path.ends_with("/mixed.yml"))
        .unwrap();
    // `only-on-main` keeps its own `if:` because no pipeline replaced it.
    assert!(!mixed.disabled.iter().any(|job| job == "only-on-main"));
    let applied = mixed.applied.as_ref().unwrap();
    assert!(
        applied.contains("    if: github.ref == 'refs/heads/main'\n"),
        "{applied}"
    );
    assert!(applied.contains("  only-on-main:\n"));
    let after = analyze_one(&mixed.path, applied);
    let job = after
        .jobs
        .iter()
        .find(|job| job.id == "only-on-main")
        .unwrap();
    assert!(job.condition);
    assert!(!mixed.disabled.is_empty());
}

#[test]
fn the_disable_needs_the_native_plan() {
    let files = fixtures("native");
    let error = plan_err(&files, Phase::Disable, false);
    assert!(
        matches!(error, workflow::PlanError::Native { .. }),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("the disable phase needs the native plan")
    );
}

#[test]
fn identical_input_gives_byte_identical_output_for_every_phase() {
    let files = every_fixture();
    for phase in [Phase::Label, Phase::Shadow, Phase::Switch] {
        let first = plan_of(&files, phase, true);
        let second = plan_of(&files, phase, true);
        assert_eq!(first, second, "{phase:?}");
        // The same workflows in another order produce the same change.
        let mut reversed = texts(&files);
        reversed.reverse();
        let third = plan_of(&reversed, phase, true);
        for (a, b) in first.workflows.iter().zip(&third.workflows) {
            assert_eq!(a.path, b.path);
            assert_eq!(a.diff, b.diff);
            assert_eq!(a.applied, b.applied);
            assert_eq!(a.shadow, b.shadow);
            assert_eq!(a.dropped, b.dropped);
            assert_eq!(a.disabled, b.disabled);
        }
    }
    // The disable phase needs a native plan, which not every fixture can be given.
    let mut disabled = 0;
    for (path, text) in fixtures("native") {
        let one = vec![(path, text)];
        let first = plan_of(&one, Phase::Disable, true);
        let second = plan_of(&one, Phase::Disable, true);
        assert_eq!(first, second);
        disabled += 1;
    }
    assert!(disabled >= 3, "too few native fixtures: {disabled}");
}

#[test]
fn a_copy_runs_in_a_concurrency_group_of_its_own() {
    let text = "name: grouped
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    concurrency:
      group: build-${{ github.ref }}
      cancel-in-progress: true
    steps:
      - run: make build
  deploy:
    runs-on: ubuntu-latest
    concurrency: deploy
    steps:
      - run: make deploy
";
    let path = one("grouped.yml");
    let files = vec![(path.clone(), text.to_owned())];
    let shadowed = plan_of(&files, Phase::Shadow, false);
    let workflow = &shadowed.workflows[0];
    assert_eq!(workflow.shadow.len(), 2, "{:?}", workflow.shadow);

    let after = analyze_one(&path, workflow.applied.as_deref().unwrap());
    let job = |id: &str| after.jobs.iter().find(|job| job.id == id).unwrap();
    let group = |id: &str| job(id).concurrency.as_ref().unwrap().group.as_str();
    assert_eq!(group("build"), "build-${{ github.ref }}");
    assert_eq!(group("sentinel-build"), "sentinel-build-${{ github.ref }}");
    assert!(
        job("sentinel-build")
            .concurrency
            .as_ref()
            .unwrap()
            .cancel_in_progress
    );
    assert_eq!(group("deploy"), "deploy");
    assert_eq!(group("sentinel-deploy"), "sentinel-deploy");

    // Shadowing the result again adds nothing, and the switch still drops both copies.
    let again = vec![(path.clone(), workflow.applied.clone().unwrap())];
    assert!(
        plan_of(&again, Phase::Shadow, false).workflows[0]
            .shadow
            .is_empty()
    );
    let switched = plan_of(&again, Phase::Switch, false);
    let moved = plan_of(&files, Phase::Label, false);
    assert_eq!(switched.workflows[0].applied, moved.workflows[0].applied);
}
