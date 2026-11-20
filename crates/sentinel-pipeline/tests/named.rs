use sentinel_pipeline::{
    CompiledPipeline, Event, InputValue, PinnedSource, RunSpec,
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase},
};

fn compile(text: &str) -> Vec<CompiledPipeline> {
    sentinel_pipeline::compile_document(text).unwrap_or_else(|e| panic!("compiles: {e}"))
}

/// Just enough context to render a cache key the way a worker does.
struct Ctx<'a> {
    inputs: &'a [(String, InputValue)],
}

impl Context for Ctx<'_> {
    fn phase(&self) -> Phase {
        Phase::Worker
    }
    fn lookup(&self, path: &[String]) -> Lookup {
        match path {
            [root, name] if root == "inputs" => match self.inputs.iter().find(|(n, _)| n == name) {
                Some((_, value)) => Lookup::Value(value.expr_value()),
                None => Lookup::Unresolved,
            },
            _ => Lookup::Unresolved,
        }
    }
    fn dependency_summary(&self) -> Option<DependencySummary> {
        None
    }
    fn cancelled(&self) -> Option<bool> {
        Some(false)
    }
    fn hash_files(&self, _patterns: &[&str]) -> Result<String, HashFilesError> {
        Err(HashFilesError::UnsupportedPlatform)
    }
}

fn error(text: &str) -> String {
    sentinel_pipeline::compile_document(text)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| panic!("compiled unexpectedly"))
}

fn job(name: &str, image: &str) -> String {
    format!(
        "      {name}:\n        image: {image}\n        steps:\n          - id: s\n            run: echo\n"
    )
}

/// Two pipelines of one repository: each keeps its own triggers, its own concurrency policy and its
/// own check namespace, and neither can cancel or overwrite the other.
#[test]
fn two_named_pipelines_of_one_repository_are_independent() {
    let text = format!(
        "schema: 1
pipelines:
  alpha:
    on:
      push: {{branches: [main]}}
    concurrency: {{group: \"${{{{ repo.id }}}}:shared\", cancel_in_progress: true}}
    jobs:
{alpha}
  beta:
    on:
      pull_request: {{branches: [main]}}
    concurrency: {{group: \"${{{{ repo.id }}}}:shared\", cancel_in_progress: false}}
    jobs:
{beta}",
        alpha = job("test", "rust:1-bookworm"),
        beta = job("test", "rust:1-bookworm"),
    );
    let pipelines = compile(&text);
    assert_eq!(pipelines.len(), 2);
    let (alpha, beta) = (&pipelines[0], &pipelines[1]);
    assert_eq!(alpha.name.as_deref(), Some("alpha"));
    assert_eq!(beta.name.as_deref(), Some("beta"));

    // Triggers: each answers only the events it declares.
    assert!(alpha.on.admits(&Event::push("refs/heads/main")));
    assert!(!alpha.on.admits(&Event::pull_request("refs/heads/main")));
    assert!(beta.on.admits(&Event::pull_request("refs/heads/main")));
    assert!(!beta.on.admits(&Event::push("refs/heads/main")));

    // Concurrency: the same template, a different policy, and the pipeline name scopes each group.
    assert_eq!(
        alpha.concurrency.as_ref().map(|c| c.cancel_in_progress),
        Some(true)
    );
    assert_eq!(
        beta.concurrency.as_ref().map(|c| c.cancel_in_progress),
        Some(false)
    );

    // Check identity: disjoint namespaces over the same job name, and neither is the default's.
    assert_eq!(alpha.aggregate_check(), "sentinel / alpha");
    assert_eq!(beta.aggregate_check(), "sentinel / beta");
    assert_eq!(alpha.job_check("test"), "sentinel / alpha / test");
    assert_eq!(beta.job_check("test"), "sentinel / beta / test");
    assert_ne!(alpha.job_check("test"), beta.job_check("test"));

    // The digests differ, so a repository can tell the two compiled pipelines apart.
    assert_ne!(alpha.digest, beta.digest);

    // Recompiling the same document gives the same identities: they depend on the declaration only.
    let again = compile(&text);
    assert_eq!(again[0], *alpha);
    assert_eq!(again[1], *beta);
}

/// A document's names are the repository's; the only rule is that one name means one check.
#[test]
fn a_named_pipeline_cannot_claim_a_name_another_pipeline_publishes() {
    let conflict = error(
        "schema: 1
on: [push]
jobs:
  acceptance:
    image: busybox
    steps: [{id: s, run: echo}]
pipelines:
  acceptance:
    on: [push]
    jobs:
      suite:
        image: busybox
        steps: [{id: s, run: echo}]
",
    );
    assert!(
        conflict.contains("pipelines.acceptance: check `sentinel / acceptance` is also the unnamed pipeline's job `acceptance`"),
        "{conflict}"
    );

    // A name nothing else uses is not reserved, whatever it is called: no built-in list decides.
    for name in ["ci", "acceptance", "release", "deploy"] {
        let text = format!(
            "schema: 1
pipelines:
  {name}:
    on: [push]
    jobs:
      suite:
        image: busybox
        steps: [{{id: s, run: echo}}]
"
        );
        let pipelines = compile(&text);
        assert_eq!(pipelines.len(), 1, "{name}");
        assert_eq!(pipelines[0].aggregate_check(), format!("sentinel / {name}"));
    }

    // A job called `ci` in the unnamed pipeline publishes the name it always has: nothing an older
    // document declared changes meaning.
    let pipelines = compile(
        "schema: 1
on: [push]
jobs:
  ci:
    image: busybox
    steps: [{id: s, run: echo}]
",
    );
    assert_eq!(pipelines[0].job_check("ci"), "sentinel / ci");
    assert_eq!(pipelines[0].aggregate_check(), "sentinel / ci");
}

#[test]
fn every_input_type_refuses_a_value_it_does_not_bound() {
    let text = "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
      target: {type: string, min_length: 1, max_length: 4}
      profile: {type: choice, values: [debug, release], default: debug}
      full: {type: boolean, default: false}
      count: {type: integer, min: 1, max: 8, default: 2}
    jobs:
      suite:
        image: busybox
        steps: [{id: s, run: echo}]
";
    let pipelines = compile(text);
    let inputs = &pipelines[0].inputs;
    let resolve = |provided: &[(&str, InputValue)]| {
        let provided: Vec<(String, InputValue)> = provided
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.clone()))
            .collect();
        inputs.resolve(&provided)
    };
    // The defaults are what a run without a caller starts with, ascending by name.
    assert_eq!(
        resolve(&[("target", InputValue::Str("main".into()))]).unwrap(),
        vec![
            ("count".to_owned(), InputValue::Int(2)),
            ("full".to_owned(), InputValue::Bool(false)),
            ("profile".to_owned(), InputValue::Str("debug".to_owned())),
            ("target".to_owned(), InputValue::Str("main".to_owned())),
        ]
    );
    let refused = |provided: &[(&str, InputValue)]| resolve(provided).unwrap_err().to_string();
    let target = || ("target", InputValue::Str("main".to_owned()));
    // string: its length bound
    assert_eq!(
        refused(&[("target", InputValue::Str("release".into()))]),
        "inputs.target: 1 to 4 bytes"
    );
    // choice: its allowed values
    assert_eq!(
        refused(&[target(), ("profile", InputValue::Str("fast".into()))]),
        "inputs.profile: one of debug, release"
    );
    // boolean: a value of another type
    assert_eq!(
        refused(&[target(), ("full", InputValue::Str("yes".into()))]),
        "inputs.full: expected a boolean, found a string"
    );
    // integer: its range
    assert_eq!(
        refused(&[target(), ("count", InputValue::Int(9))]),
        "inputs.count: 1 to 8, found 9"
    );
    // missing required
    assert_eq!(refused(&[]), "inputs.target: required");
    // a name the pipeline declares nothing about
    assert_eq!(
        refused(&[target(), ("extra", InputValue::Int(1))]),
        "inputs.extra: no input of this pipeline has that name"
    );
    // the bounds hold at their edges
    assert!(
        resolve(&[
            ("target", InputValue::Str("main".into())),
            ("count", InputValue::Int(8))
        ])
        .is_ok()
    );
    assert!(resolve(&[("target", InputValue::Str("m".into()))]).is_ok());
}

#[test]
fn an_inputs_declaration_must_state_a_finite_bound() {
    let document = |inputs: &str| {
        format!(
            "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
{inputs}    jobs:
      suite:
        image: busybox
        steps: [{{id: s, run: echo}}]
"
        )
    };
    assert!(
        error(&document("      a: {type: string}\n")).contains("inputs.a.max_length: required")
    );
    assert!(
        error(&document("      a: {type: string, max_length: 0}\n"))
            .contains("inputs.a.max_length: must be between 1 and 1024")
    );
    assert!(
        error(&document("      a: {type: integer, min: 8}\n")).contains("inputs.a.max: required")
    );
    assert!(
        error(&document("      a: {type: integer, min: 8, max: 2}\n"))
            .contains("inputs.a.max: must be greater than the minimum")
    );
    assert!(error(&document("      a: {type: choice}\n")).contains("inputs.a.values: required"));
    assert!(
        error(&document("      a: {type: choice, values: [x, x]}\n"))
            .contains("inputs.a.values[1]: duplicate value")
    );
    assert!(
        error(&document(
            "      a: {type: choice, values: [x], default: y}\n"
        ))
        .contains("inputs.a.default: must be one of x")
    );
    assert!(
        error(&document("      A: {type: boolean}\n"))
            .contains("inputs.A: input names must match [a-z][a-z0-9_]*")
    );
    assert!(
        error(&document("      a: {type: boolean, values: [x]}\n"))
            .contains("inputs.a: unknown key `values`")
    );
}

#[test]
fn a_required_input_needs_a_default_unless_the_pipeline_is_manual_only() {
    let document = |on: &str| {
        format!(
            "schema: 1
pipelines:
  focus:
    on: {on}
    inputs:
      target: {{type: string, max_length: 8}}
    jobs:
      suite:
        image: busybox
        steps: [{{id: s, run: echo}}]
"
        )
    };
    for on in ["[manual]", "{manual: true}"] {
        compile(&document(on));
    }
    for on in [
        "[push]",
        "[tag]",
        "[pull_request]",
        "[schedule]",
        "[manual, push]",
        "{push: {branches: [main]}}",
    ] {
        let message = error(&document(on));
        assert!(
            message.contains(
                "pipelines.focus.inputs.target: a required input needs a default unless the pipeline runs only from a manual dispatch"
            ),
            "{on}: {message}"
        );
    }
    // A declared default makes the same pipeline runnable by any trigger.
    let with_default = "schema: 1
pipelines:
  focus:
    on: [push]
    inputs:
      target: {type: string, max_length: 8, default: main}
    jobs:
      suite:
        image: busybox
        steps: [{id: s, run: echo}]
";
    compile(with_default);
}

#[test]
fn an_input_reads_as_its_declared_type_in_a_condition() {
    let document = |condition: &str| {
        format!(
            "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
      full: {{type: boolean, default: false}}
      count: {{type: integer, min: 1, max: 8, default: 2}}
      target: {{type: string, max_length: 8, default: main}}
    jobs:
      suite:
        image: busybox
        if: ${{{{ {condition} }}}}
        steps: [{{id: s, run: echo}}]
"
        )
    };
    compile(&document("inputs.full"));
    compile(&document("inputs.count == 2"));
    compile(&document("inputs.target == 'main'"));
    compile(&document("inputs.full && inputs.target == 'main'"));
    assert!(error(&document("inputs.count")).contains("condition must be a boolean expression"));
    assert!(error(&document("inputs.count == 'x'")).contains("comparison between different types"));
    assert!(
        error(&document("inputs.verbose"))
            .contains("`inputs.verbose` names no input this pipeline declares")
    );
    // A template that names an input the pipeline does not declare is refused too.
    let unknown_in_key = "schema: 1
pipelines:
  focus:
    on: [manual]
    jobs:
      suite:
        image: busybox
        cache:
          - {name: c, key: \"c-${{ inputs.target }}\", paths: [target]}
        steps: [{id: s, run: echo}]
";
    assert!(
        error(unknown_in_key).contains(
            "jobs.suite.cache.c.key: `inputs.target` names no input this pipeline declares"
        )
    );
}

#[test]
fn the_digest_covers_the_declarations_and_not_the_values() {
    let document = |default: &str| {
        format!(
            "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
      target: {{type: string, max_length: 8, default: {default}}}
    jobs:
      suite:
        image: busybox
        steps: [{{id: s, run: echo}}]
"
        )
    };
    let a = compile(&document("main"));
    let b = compile(&document("dev"));
    // A different default is a different declaration, so the compiled pipelines differ.
    assert_ne!(a[0].digest, b[0].digest);
    // The values a run was given are not part of the digest.
    let spec = |value: &str| {
        let mut spec = RunSpec::new(
            PinnedSource::new("r", &"a".repeat(40), None).unwrap(),
            a[0].clone(),
        )
        .unwrap();
        spec.inputs = vec![("target".to_owned(), InputValue::Str(value.to_owned()))];
        spec
    };
    assert_eq!(
        spec("main").pipeline.digest,
        spec("release").pipeline.digest
    );
    assert_eq!(spec("main").inputs, spec("main").inputs);
    assert_ne!(spec("main").inputs, spec("release").inputs);
}

#[test]
fn a_cache_key_changes_with_an_input_only_when_it_names_one() {
    let document = |key: &str| {
        format!(
            "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
      target: {{type: string, max_length: 8, default: main}}
    jobs:
      suite:
        image: busybox
        cache:
          - {{name: c, key: \"{key}\", paths: [target]}}
        steps: [{{id: s, run: echo}}]
"
        )
    };
    let values = |value: &str| vec![("target".to_owned(), InputValue::Str(value.to_owned()))];
    let rendered = |text: &str, value: &str| {
        let pipelines = compile(text);
        let key = &pipelines[0].jobs[0].spec.cache[0].key;
        let inputs = values(value);
        key.render(&Ctx { inputs: &inputs }, 256).unwrap()
    };
    // Not declared: the same key whatever the value.
    let plain = document("cargo-lock");
    assert_eq!(rendered(&plain, "main"), rendered(&plain, "release"));
    // Declared: the value is part of the key, because the template names it.
    let declared = document("cargo-${{ inputs.target }}");
    assert_ne!(rendered(&declared, "main"), rendered(&declared, "release"));
    assert!(rendered(&declared, "main").contains("main"));
}

#[test]
fn a_document_without_named_pipelines_keeps_its_names_digest_and_spec_format() {
    let text = "schema: 1
on: [push]
jobs:
  test:
    image: busybox
    steps:
      - id: s
        run: echo hi
";
    let compiled = sentinel_pipeline::compile_str(text).unwrap();
    assert_eq!(compiled.name, None);
    assert_eq!(compiled.aggregate_check(), "sentinel / ci");
    assert_eq!(compiled.job_check("test"), "sentinel / test");
    assert_eq!(compiled.inputs.len(), 0);
    // The digest is the one this pipeline had before named pipelines existed: neither the name nor
    // an input list is appended when a document declares none.
    // The digest of this document before this change, computed by the release that shipped it.
    assert_eq!(compiled.digest, 61975973504121135961704583085602287749);

    let spec = RunSpec::new(
        PinnedSource::new("r", &"a".repeat(40), None).unwrap(),
        compiled,
    )
    .unwrap();
    assert!(spec.inputs.is_empty());
    assert_eq!(spec.format(), 6);
    assert_eq!(spec.encode().unwrap()[0], 6);
}

#[test]
fn a_named_pipeline_with_inputs_is_format_11_and_round_trips() {
    let text = "schema: 1
pipelines:
  focus:
    on: [manual]
    inputs:
      target: {type: string, max_length: 8}
    jobs:
      suite:
        image: busybox
        steps: [{id: s, run: echo}]
";
    let compiled = compile(text).pop().unwrap();
    let mut spec = RunSpec::new(
        PinnedSource::new("r", &"a".repeat(40), None).unwrap(),
        compiled,
    )
    .unwrap();
    spec.inputs = vec![("target".to_owned(), InputValue::Str("main".to_owned()))];
    assert_eq!(spec.format(), 11);
    let bytes = spec.encode().unwrap();
    assert_eq!(bytes[0], 11);
    let decoded = RunSpec::decode(&bytes).unwrap();
    assert_eq!(decoded, spec);
    assert_eq!(decoded.pipeline.name.as_deref(), Some("focus"));
    assert_eq!(decoded.inputs, spec.inputs);
    assert_eq!(decoded.pipeline.inputs.len(), 1);
}
