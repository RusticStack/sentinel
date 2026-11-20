//! External resources a job declares: how they parse, what they do to the digest and the spec, and
//! what the explanation tells an operator about them.

use sentinel_pipeline::{Explanation, PinnedSource, RunSpec, compile_str};

fn spec_for(text: &str) -> RunSpec {
    RunSpec::new(
        PinnedSource::new("r", &"a".repeat(40), None).unwrap(),
        compile_str(text).unwrap(),
    )
    .unwrap()
}

const BASE: &str = "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    steps: [{id: s, run: echo}]
";

#[test]
fn a_declared_resource_carries_its_bound_and_defaults_to_ten_minutes() {
    let text = "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    locks: [db/staging, {name: \"device:rig-1\", wait: 30m}]
    steps: [{id: s, run: echo}]
";
    let locks = &compile_str(text).unwrap().jobs[0].spec.locks;
    assert_eq!(locks.len(), 2);
    assert_eq!(locks[0].name, "db/staging");
    assert_eq!(
        locks[0].wait_secs,
        sentinel_pipeline::schema::DEFAULT_LOCK_WAIT_SECS,
        "the shorthand states no bound, so the default one applies"
    );
    assert_eq!(locks[1].name, "device:rig-1");
    assert_eq!(locks[1].wait_secs, 30 * 60);
}

#[test]
fn a_job_that_declares_no_resource_keeps_its_digest_and_spec_format() {
    let plain = spec_for(BASE);
    let declared = spec_for(
        "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    locks: [db/staging]
    steps: [{id: s, run: echo}]
",
    );
    assert_ne!(
        plain.pipeline.digest, declared.pipeline.digest,
        "a resource a job needs is part of what the pipeline is"
    );
    assert_eq!(
        plain.format(),
        6,
        "the digest and format of a job with no lock are unchanged"
    );
    assert_eq!(declared.format(), 13);
}

#[test]
fn a_spec_with_resources_is_format_13_and_round_trips_them() {
    let spec = spec_for(
        "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    locks: [{name: db/staging, wait: 90s}, staging/host]
    steps: [{id: s, run: echo}]
  test:
    image: busybox
    needs: [migrate]
    steps: [{id: s, run: echo}]
",
    );
    let bytes = spec.encode().unwrap();
    assert_eq!(bytes[0], 13);
    let decoded = RunSpec::decode(&bytes).unwrap();
    assert_eq!(decoded, spec);
    assert_eq!(decoded.pipeline.jobs[0].spec.locks.len(), 2);
    assert_eq!(decoded.pipeline.jobs[0].spec.locks[0].wait_secs, 90);
    assert!(
        decoded.pipeline.jobs[1].spec.locks.is_empty(),
        "a job that declares none carries none"
    );
}

#[test]
fn a_spec_whose_resource_list_does_not_match_its_jobs_is_refused() {
    let spec = spec_for(
        "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    locks: [db/staging]
    steps: [{id: s, run: echo}]
",
    );
    let bytes = spec.encode().unwrap();
    // The count is the last field of the body: a damaged spec loses the resources of a job, so the
    // reader refuses it instead of running the job without them.
    let truncated = &bytes[..bytes.len() - 1];
    assert!(RunSpec::decode(truncated).is_err());
}

#[test]
fn the_explanation_names_each_resource_and_its_bound() {
    let text = "schema: 1
on: [push]
jobs:
  migrate:
    image: busybox
    locks: [{name: db/staging, wait: 5m}]
    steps: [{id: s, run: echo}]
";
    let compilation = Explanation::of(&compile_str(text).unwrap());
    assert_eq!(compilation.jobs[0].locks.len(), 1);
    assert_eq!(compilation.jobs[0].locks[0].name, "db/staging");
    assert_eq!(compilation.jobs[0].locks[0].wait_secs, 300);
    let rendered = compilation.render_text();
    assert!(
        rendered.contains("lock db/staging (exclusive, waits at most 300s)"),
        "{rendered}"
    );
}
