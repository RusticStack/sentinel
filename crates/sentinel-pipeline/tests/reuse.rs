//! A job's opt-in reuse declaration is part of the compiled pipeline and its run spec: an older worker must
//! refuse a spec that states one rather than run it without knowing it may be served a result.

use sentinel_pipeline::{PinnedSource, RunSpec, compile_document, compile_str, run::SPEC_FORMAT};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn spec_of(yaml: &str) -> RunSpec {
    RunSpec::new(
        PinnedSource::new("file:///nowhere", SHA, Some("main")).unwrap(),
        compile_str(yaml).unwrap(),
    )
    .unwrap()
}

fn declared_yaml(inputs: &str) -> String {
    format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps: [{{id: s, run: echo hi}}]\n    reuse:\n      inputs: [{inputs}]\n      outputs: [out]\n"
    )
}

#[test]
fn a_spec_that_opts_in_round_trips_and_names_its_job() {
    let yaml = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps: [{id: s, run: echo hi}]\n    reuse: {inputs: [src/**], outputs: [out, dist]}\n  report:\n    image: busybox\n    needs: [build]\n    steps: [{id: s, run: echo done}]\n";
    let spec = spec_of(yaml);
    assert_eq!(spec.format(), SPEC_FORMAT);
    let bytes = spec.encode().unwrap();
    assert_eq!(bytes[0], SPEC_FORMAT);
    let decoded = RunSpec::decode(&bytes).unwrap();
    assert_eq!(decoded, spec);
    let build = &decoded.pipeline.jobs[0].spec.reuse;
    assert_eq!(build.as_ref().unwrap().inputs, vec!["src/**".to_string()]);
    assert_eq!(
        build.as_ref().unwrap().outputs,
        vec!["out".to_string(), "dist".to_string()]
    );
    // A job that did not opt in carries none, so nothing serves a result for it.
    assert!(decoded.pipeline.jobs[1].spec.reuse.is_none());
}

#[test]
fn a_spec_that_states_no_reuse_keeps_the_format_an_older_worker_reads() {
    let plain = spec_of(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps: [{id: s, run: echo hi}]\n",
    );
    // Format 6 is the lowest this spec needs, byte for byte what a controller wrote before any of the
    // newer fields existed; stating `reuse` is what moves it.
    assert_eq!(plain.encode().unwrap()[0], 6);
    let named = compile_document(
        "schema: 1\non: [push]\njobs:\n  ci:\n    image: busybox\n    steps: [{id: s, run: echo hi}]\npipelines:\n  acceptance:\n    on: [push]\n    jobs:\n      build:\n        image: busybox\n        steps: [{id: s, run: echo hi}]\n",
    )
    .unwrap();
    let spec = RunSpec::new(
        PinnedSource::new("file:///nowhere", SHA, None).unwrap(),
        named
            .into_iter()
            .find(|p| p.name.as_deref() == Some("acceptance"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(spec.encode().unwrap()[0], 11);
}

#[test]
fn the_declaration_is_part_of_the_compiled_digest() {
    let plain = spec_of(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox\n    steps: [{id: s, run: echo hi}]\n",
    )
    .pipeline
    .digest;
    let opted = spec_of(&declared_yaml("src/**")).pipeline.digest;
    let other = spec_of(&declared_yaml("other/**")).pipeline.digest;
    assert_ne!(plain, opted);
    assert_ne!(opted, other);
}

#[test]
fn every_refusal_names_the_shape_it_cannot_key() {
    let refused = |yaml: &str| compile_str(yaml).unwrap_err().to_string();
    // A secret has no place in the key, so a job that needs one cannot claim a complete identity.
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    secrets: [T]\n    steps: [{id: s, run: x, secrets: [T]}]\n    reuse: {inputs: [src/**], outputs: [out]}\n"
        )
        .contains("cannot declare secrets"),
    );
    // A served result evaluates nothing, so a condition could never be re-decided.
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    if: event.ref == 'refs/heads/main'\n    steps: [{id: s, run: x}]\n    reuse: {inputs: [src/**], outputs: [out]}\n"
        )
        .contains("cannot state `if`"),
    );
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps: [{id: s, run: x, if: always()}]\n    reuse: {inputs: [src/**], outputs: [out]}\n"
        )
        .contains("step `if`"),
    );
    // A step-triggered artifact publishes at a step's completion, which a served result never reaches.
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps: [{id: s, run: x}]\n    artifacts: [{name: o, paths: [out], when: 'step:s'}]\n    reuse: {inputs: [src/**], outputs: [out]}\n"
        )
        .contains("`when: step:<id>`"),
    );
    // The worker's own private directory is not a workspace directory the pipeline may claim.
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps: [{id: s, run: x}]\n    reuse: {inputs: [src/**], outputs: [.sentinel-cache/out]}\n"
        )
        .contains("which the worker owns"),
    );
    // An output is a workspace directory, never an escape or a wildcard.
    assert!(
        refused(
            "schema: 1\non: [push]\njobs:\n  a:\n    image: busybox\n    steps: [{id: s, run: x}]\n    reuse: {inputs: [src/**], outputs: [../out]}\n"
        )
        .contains("normalised relative workspace directory"),
    );
}
