//! H03's gate: the `runs-on:` diff changes label lines and nothing else, every generated
//! native pipeline is one the compiler accepts, and the same input produces the same bytes.

use std::fs;
use std::path::{Path, PathBuf};

use sentinel_pipeline::workflow::{
    self, DockerHosts, Images, Options, Phase, Plan, WorkflowFile, analyze, plan,
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

fn images() -> Images<'static> {
    Images {
        linux: Some(IMAGE),
        linux_arm64: Some(ARM_IMAGE),
        windows: Some(IMAGE),
    }
}

fn plan_of(files: &[(String, String)], native: bool) -> Plan {
    plan_with(files, native, images())
}

fn plan_with(files: &[(String, String)], native: bool, images: Images<'static>) -> Plan {
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
            phase: Phase::Label,
        },
    )
    .unwrap()
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

/// Analyzes one workflow text on its own.
fn analyze_one(path: &str, text: &str) -> workflow::Workflow {
    let files = [WorkflowFile { path, text }];
    analyze(REVISION, &files, DockerHosts::MicrovmGuests)
        .unwrap()
        .workflows
        .remove(0)
}

#[test]
fn the_label_diff_changes_only_runs_on_lines() {
    let mut changed_lines = 0;
    for dir in ["valid", "native"] {
        let files = fixtures(dir);
        let plan = plan_of(&files, false);
        for (index, workflow) in plan.workflows.iter().enumerate() {
            let text = &files[index].1;
            let before = text.lines().count();
            let hunks = parse_diff(&workflow.diff);
            assert_eq!(
                hunks.is_empty(),
                workflow.changes.is_empty(),
                "{}",
                workflow.path
            );
            for hunk in &hunks {
                let mut added = false;
                for (mark, line) in &hunk.lines {
                    match mark {
                        '+' => {
                            added = true;
                            changed_lines += 1;
                            let label =
                                line.trim_start()
                                    .strip_prefix("runs-on: ")
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "{}: an added line is not `runs-on:`: {line:?}",
                                            workflow.path
                                        )
                                    });
                            assert!(
                                label.starts_with("sentinel-"),
                                "{}: an added label is not a Sentinel class: {line:?}",
                                workflow.path
                            );
                        }
                        '-' => {
                            assert!(
                                line.trim_start().starts_with("runs-on")
                                    || line.trim_start().starts_with("- "),
                                "{}: a removed line is not a `runs-on:` value: {line:?}",
                                workflow.path
                            );
                        }
                        _ => {}
                    }
                }
                assert!(added, "{}: a hunk that adds nothing", workflow.path);
            }
            let after = apply_diff(text, &hunks);
            // The applied diff is exactly the plan's changes and nothing else: splicing each
            // change's lines back into the input reproduces it byte for byte.
            let mut expected: Vec<String> = text.lines().map(str::to_owned).collect();
            for change in workflow.changes.iter().rev() {
                let start = change.line as usize - 1;
                let removed = change.before.lines().count();
                assert!(
                    expected[start..start + removed]
                        .iter()
                        .map(String::as_str)
                        .eq(change.before.lines()),
                    "{}: job {}'s recorded lines are not at line {}",
                    workflow.path,
                    change.job,
                    change.line
                );
                let added: Vec<String> = change.after.lines().map(str::to_owned).collect();
                expected.splice(start..start + removed, added);
            }
            assert_eq!(
                expected,
                after.lines().map(str::to_owned).collect::<Vec<_>>(),
                "{}: the diff is not the recorded changes",
                workflow.path
            );
            // A changed line is a `runs-on:` line or one of its labels, and what replaces it
            // is one Sentinel class on the `runs-on:` line.
            for change in &workflow.changes {
                for removed in change.before.lines() {
                    let trimmed = removed.trim_start();
                    assert!(
                        trimmed.starts_with("runs-on:") || trimmed.starts_with("- "),
                        "{}: job {} removes a line that is not a label: {removed:?}",
                        workflow.path,
                        change.job
                    );
                }
                let added: Vec<&str> = change.after.lines().collect();
                assert_eq!(added.len(), 1, "{}: {}", workflow.path, change.after);
                assert!(
                    added[0].trim_start().starts_with("runs-on: sentinel-"),
                    "{}: {}",
                    workflow.path,
                    added[0]
                );
            }
            // Applying the diff leaves the jobs where the plan says they go.
            let analyzed = analyze_one(&workflow.path, &after);
            for job in &analyzed.jobs {
                for cell in &job.cells {
                    assert!(
                        matches!(cell.destination, workflow::Destination::Class(_))
                            || workflow.kept.iter().any(|kept| kept.job == job.id),
                        "{}: job {} was neither moved nor kept",
                        workflow.path,
                        job.id
                    );
                }
            }
            // A second look at the rewritten file finds nothing left to change.
            let second = plan_of(&[(workflow.path.clone(), after.clone())], false);
            assert!(
                second.workflows[0].diff.is_empty(),
                "{}: the diff does not settle: {}",
                workflow.path,
                second.workflows[0].diff
            );
            // The diff's own line arithmetic follows the file's: the rewritten text is the
            // input minus what the changes removed plus what they added.
            let delta: i64 = workflow
                .changes
                .iter()
                .map(|c| c.after.lines().count() as i64 - c.before.lines().count() as i64)
                .sum();
            assert_eq!(
                after.lines().count() as i64,
                before as i64 + delta,
                "{}: the diff's line count does not follow its changes",
                workflow.path
            );
        }
    }
    assert!(changed_lines > 0, "no fixture's labels change");
}

#[test]
fn every_native_pipeline_passes_the_compiler_and_matches_its_mapping() {
    let mut pipelines = 0;
    for dir in ["valid", "native"] {
        let files = fixtures(dir);
        let plan = plan_of(&files, true);
        for (index, workflow) in plan.workflows.iter().enumerate() {
            let text = &files[index].1;
            let before = analyze_one(&workflow.path, text);
            match &workflow.native {
                None => {
                    assert!(
                        workflow.native_refused.is_some(),
                        "{}: no native pipeline and no reason",
                        workflow.path
                    );
                    assert!(workflow.native_refused.unwrap().len() > 10);
                }
                Some(native) => {
                    pipelines += 1;
                    let compiled =
                        sentinel_pipeline::compile_str(&native.text).unwrap_or_else(|e| {
                            panic!(
                                "{}: the generated pipeline does not compile: {e}\n{}",
                                workflow.path, native.text
                            )
                        });
                    // The mapping names exactly the pipeline's jobs and every GitHub job.
                    let mut ids: Vec<String> =
                        compiled.jobs.iter().map(|job| job.name.clone()).collect();
                    let mut mapped: Vec<String> = native
                        .jobs
                        .iter()
                        .flat_map(|job| job.jobs.iter().cloned())
                        .collect();
                    ids.sort();
                    mapped.sort();
                    assert_eq!(
                        ids, mapped,
                        "{}: mapping and pipeline disagree",
                        workflow.path
                    );
                    assert_eq!(
                        native.jobs.len(),
                        before.jobs.len(),
                        "{}: a GitHub job is missing from the mapping",
                        workflow.path
                    );
                    for mapping in &native.jobs {
                        assert!(
                            mapping.jobs.is_empty() != mapping.kept.is_empty(),
                            "{}: job {} is both kept and generated",
                            workflow.path,
                            mapping.github
                        );
                    }
                    // Triggers are the workflow's own.
                    let mut events: Vec<String> = Vec::new();
                    if compiled.on.push.is_some() {
                        events.push("push".into());
                    }
                    if compiled.on.pull_request.is_some() {
                        events.push("pull_request".into());
                    }
                    if compiled.on.merge_group.is_some() {
                        events.push("merge_group".into());
                    }
                    if compiled.on.tag.is_some() {
                        events.push("tag".into());
                    }
                    if compiled.on.manual {
                        events.push("manual".into());
                    }
                    events.sort();
                    let mut expected: Vec<String> = before
                        .triggers
                        .iter()
                        .map(|trigger| match trigger.event.as_str() {
                            "workflow_dispatch" => "manual".to_owned(),
                            other => other.to_owned(),
                        })
                        .collect();
                    expected.sort();
                    assert_eq!(events, expected, "{}: triggers differ", workflow.path);
                    // The stub paths a step maps to are the ones the pipeline runs.
                    for mapping in &native.jobs {
                        for step in &mapping.steps {
                            if let Some(script) = &step.script {
                                assert!(script.starts_with(workflow::STUBS));
                                assert!(
                                    native.text.contains(&format!("sh {script}")),
                                    "{}: {} is mapped but not run",
                                    workflow.path,
                                    script
                                );
                            }
                        }
                    }
                    // The secrets to provision are the ones the pipeline declares.
                    let declared: Vec<String> = compiled
                        .jobs
                        .iter()
                        .flat_map(|job| job.spec.secrets.iter().cloned())
                        .collect();
                    for name in &native.secrets {
                        assert!(
                            declared.contains(name),
                            "{}: {name} is not declared",
                            workflow.path
                        );
                    }
                    for name in &declared {
                        assert!(
                            native.secrets.contains(name),
                            "{}: {name} is not listed",
                            workflow.path
                        );
                    }
                }
            }
        }
    }
    assert!(
        pipelines >= 4,
        "too few native pipelines to be a gate: {pipelines}"
    );
}

#[test]
fn identical_input_gives_byte_identical_output() {
    let files = fixtures("native");
    let first = plan_of(&files, true);
    let second = plan_of(&files, true);
    assert_eq!(first, second);
    // The same workflows in another order produce the same pipeline and the same diff.
    let mut reversed = files.clone();
    reversed.reverse();
    let third = plan_of(&reversed, true);
    for (a, b) in first.workflows.iter().zip(&third.workflows) {
        assert_eq!(a.path, b.path);
        assert_eq!(a.diff, b.diff);
        assert_eq!(a.native, b.native);
        assert_eq!(a.kept, b.kept);
    }
    for workflow in &first.workflows {
        if let Some(native) = &workflow.native {
            assert_eq!(
                native.text,
                plan_of(&files, true)
                    .workflows
                    .iter()
                    .find(|w| w.path == workflow.path)
                    .unwrap()
                    .native
                    .as_ref()
                    .unwrap()
                    .text
            );
        }
    }
}

#[test]
fn the_native_fixture_generates_its_recorded_pipeline() {
    let files = fixtures("native");
    let plan = plan_of(&files, true);
    let ci = plan
        .workflows
        .iter()
        .find(|w| w.path.ends_with("/ci.yml"))
        .unwrap();
    let native = ci
        .native
        .as_ref()
        .unwrap_or_else(|| panic!("{} was refused: {:?}", ci.path, ci.native_refused));
    let golden = fs::read_to_string(fixture_dir("native").join("ci.sentinel.yml")).unwrap();
    assert_eq!(native.text, golden);
    assert_eq!(native.path, ".sentinel/ci.yml");
    assert_eq!(native.secrets, vec!["CRATES_IO_TOKEN".to_owned()]);
    assert_eq!(
        native.notes,
        vec![
            workflow::NOTE_INPUTS,
            workflow::NOTE_STUBS,
            workflow::NOTE_ENV,
        ]
    );
}

#[test]
fn the_mixed_fixture_keeps_every_job_it_cannot_serve() {
    let files = fixtures("native");
    let no_windows = Images {
        windows: None,
        ..images()
    };
    let plan = plan_with(&files, true, no_windows);
    let mixed = plan
        .workflows
        .iter()
        .find(|w| w.path.ends_with("/mixed.yml"))
        .unwrap();
    // A matrix whose cells name different classes is left alone and said so.
    let cross = mixed.kept.iter().find(|kept| kept.job == "cross").unwrap();
    assert!(cross.varies);
    assert!(
        mixed.changes.iter().all(|change| change.job != "cross"),
        "a job whose cells name different classes must be left alone"
    );
    // The Windows job keeps its label: the table serves the class, this preview had no image.
    let native = mixed
        .native
        .as_ref()
        .unwrap_or_else(|| panic!("refused: {:?}", mixed.native_refused));
    let linux = native
        .jobs
        .iter()
        .find(|job| job.github == "linux")
        .unwrap();
    assert_eq!(linux.jobs, vec!["linux".to_owned()]);
    let windows = native
        .jobs
        .iter()
        .find(|job| job.github == "windows")
        .unwrap();
    assert!(windows.jobs.is_empty());
    assert_eq!(windows.kept.len(), 1);
    assert!(windows.kept[0].contains("image"));
    // `if:` is not carried, so that job stays too.
    let conditional = native
        .jobs
        .iter()
        .find(|job| job.github == "only-on-main")
        .unwrap();
    assert_eq!(conditional.kept.len(), 1);
    assert!(conditional.kept[0].contains("`if`"));
    // A matrix with an `include` entry expands differently per cell.
    let included = native
        .jobs
        .iter()
        .find(|job| job.github == "with-include")
        .unwrap();
    assert!(included.kept[0].contains("include"));
    // The GPU job is the label table's reason, not the preview's.
    let gpu = native.jobs.iter().find(|job| job.github == "gpu").unwrap();
    assert_eq!(gpu.kept, vec!["Sentinel has no GPU class"]);
    // The label diff still moves the jobs the label table serves.
    assert!(mixed.diff.contains("-    runs-on: ubuntu-latest"));
    assert!(
        mixed
            .diff
            .contains("+    runs-on: sentinel-4vcpu-ubuntu-2404")
    );
}

#[test]
fn the_plan_refuses_files_it_was_not_built_from() {
    let files = fixtures("native");
    let borrowed: Vec<WorkflowFile<'_>> = files
        .iter()
        .map(|(path, text)| WorkflowFile { path, text })
        .collect();
    let inventory = analyze(REVISION, &borrowed, DockerHosts::MicrovmGuests).unwrap();
    let options = Options {
        docker: DockerHosts::MicrovmGuests,
        native: false,
        images: Images::default(),
        phase: Phase::Label,
    };
    let fewer = plan(&inventory, &borrowed[1..], &options).unwrap_err();
    assert!(matches!(fewer, workflow::PlanError::Files));
    let mut more = borrowed.clone();
    more.push(WorkflowFile {
        path: ".github/workflows/extra.yml",
        text: "name: x\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: x\n",
    });
    let extra = plan(&inventory, &more, &options).unwrap_err();
    assert!(matches!(extra, workflow::PlanError::Files));
    // A text under a known path that does not hold that workflow's labels cannot be
    // rewritten: the plan names the job rather than emitting a diff that lands elsewhere.
    let swapped: Vec<WorkflowFile<'_>> = files
        .iter()
        .enumerate()
        .map(|(index, (path, text))| WorkflowFile {
            path,
            text: if index == 0 {
                files[1].1.as_str()
            } else {
                text
            },
        })
        .collect();
    let error = plan(&inventory, &swapped, &options).unwrap_err();
    assert!(
        matches!(
            error,
            workflow::PlanError::Rewrite { .. } | workflow::PlanError::Unverified { .. }
        ),
        "{error}"
    );
}

#[test]
fn colliding_ids_are_numbered_rather_than_duplicated() {
    let text = "name: colliding
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo one
      - run: echo two
      - id: step-2
        run: echo three
      - uses: actions/upload-artifact@v4
        with:
          name: out
          path: target/one.txt
      - uses: actions/upload-artifact@v4
        with:
          name: out
          path: target/two.txt
";
    let files = vec![(
        format!("{}/colliding.yml", workflow::WORKFLOW_DIRECTORY),
        text.to_owned(),
    )];
    let plan = plan_of(&files, true);
    let native = plan.workflows[0]
        .native
        .as_ref()
        .unwrap_or_else(|| panic!("refused: {:?}", plan.workflows[0].native_refused));
    let compiled = sentinel_pipeline::compile_str(&native.text).unwrap();
    let steps: Vec<String> = compiled.jobs[0]
        .spec
        .steps
        .iter()
        .map(|step| step.id.clone())
        .collect();
    assert_eq!(steps, vec!["step-1", "step-2", "step-2-2"]);
    let artifacts: Vec<String> = compiled.jobs[0]
        .spec
        .artifacts
        .iter()
        .map(|artifact| artifact.name.clone())
        .collect();
    assert_eq!(artifacts, vec!["out", "out-2"]);
}
