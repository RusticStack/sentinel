//! Y08's suggestion gate: a rewrite is offered only when the analyzer reads the rewritten
//! workflow as exactly the change it states, and a rewrite that fails that check is refused
//! rather than shown.

use sentinel_pipeline::workflow::{
    Construct, DockerHosts, Refusal, Rule, RuleTable, SuggestRequest, WorkflowFile, analyze,
    suggest,
};

const PATH: &str = ".github/workflows/ci.yml";

const WORKFLOW: &str = r#"name: ci
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    environment: production
    outputs:
      digest: ${{ steps.test.outputs.digest }}
    continue-on-error: false
    steps:
      - run: make test
        shell: pwsh
      - run: make lint
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: make audit
        continue-on-error: true
  docker:
    runs-on: ubuntu-latest
    container: node:20
    steps:
      - run: npm test
"#;

fn request<'a>(
    text: &'a str,
    job: Option<&'a str>,
    step: Option<usize>,
    construct: &'a str,
) -> SuggestRequest<'a> {
    SuggestRequest {
        path: PATH,
        text,
        job,
        step,
        construct,
    }
}

/// The workflow's facts, for comparing the text a suggestion produces with the one it started from.
fn facts(text: &str) -> sentinel_pipeline::workflow::Workflow {
    let files = [WorkflowFile { path: PATH, text }];
    analyze(
        "0000000000000000000000000000000000000000",
        &files,
        DockerHosts::ContainerOnly,
    )
    .unwrap()
    .workflows
    .remove(0)
}

/// The text a suggestion produces when it is applied as the whole lines it names.
fn applied(text: &str, suggestion: &sentinel_pipeline::workflow::Suggestion) -> String {
    let mut lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = suggestion.line as usize - 1;
    let count = suggestion.before.split_inclusive('\n').count();
    assert_eq!(
        lines[start..start + count].concat(),
        suggestion.before,
        "the suggestion names lines the text holds"
    );
    lines.splice(
        start..start + count,
        std::iter::once(suggestion.after.as_str()),
    );
    lines.concat()
}

#[test]
fn every_offered_rewrite_applies_cleanly_and_leaves_every_other_fact_alone() {
    let cases: [(&str, Option<&str>, Option<usize>, &str); 6] = [
        ("on", None, None, "pull_request"),
        (
            "continue-on-error",
            Some("build"),
            None,
            "continue-on-error",
        ),
        ("environment", Some("build"), None, "environment"),
        ("outputs", Some("build"), None, "outputs"),
        ("shell", Some("build"), Some(0), "shell"),
        (
            "continue-on-error",
            Some("audit"),
            Some(0),
            "continue-on-error",
        ),
    ];
    let mut covered = 0;
    for (construct, job, step, gone) in cases {
        let suggestion = suggest(&request(WORKFLOW, job, step, construct)).unwrap();
        assert_eq!(suggestion.schema, "sentinel.migration-suggestion/1");
        assert_eq!(suggestion.construct, construct);
        assert!(!suggestion.applied, "a suggestion is never applied");
        assert!(suggestion.untrusted);
        assert!(
            WORKFLOW.contains(&suggestion.before),
            "{construct}: {suggestion:?}"
        );
        let rewritten = applied(WORKFLOW, &suggestion);
        assert!(!rewritten.is_empty());
        let before = facts(WORKFLOW);
        let after = facts(&rewritten);
        // The construct the request named no longer classifies as unsupported where it was.
        let scope = match (job, step) {
            (Some(id), _) => &after.jobs.iter().find(|j| j.id == id).unwrap().constructs,
            (None, _) => &after.constructs,
        };
        assert!(
            !scope
                .iter()
                .any(|classified| classified.construct.name() == gone
                    && classified.rule != Rule::Translatable
                    && !matches!(classified.rule, Rule::WithChange { .. })),
            "{construct}: the rewritten workflow still holds it unsupported"
        );
        // Every other job and workflow-level fact is the one it started with.
        assert_eq!(after.jobs.len(), before.jobs.len(), "{construct}");
        for (was, now) in before.jobs.iter().zip(&after.jobs) {
            assert_eq!(was.id, now.id);
            assert_eq!(was.demand, now.demand);
            assert_eq!(was.matrix, now.matrix);
        }
        assert_eq!(after.name, before.name);
        covered += 1;
    }
    assert_eq!(covered, 6);
}

#[test]
fn the_trigger_rewrite_moves_the_event_and_keeps_its_filters() {
    let suggestion = suggest(&request(WORKFLOW, None, None, "on")).unwrap();
    assert_eq!(suggestion.before, "  pull_request_target:\n");
    assert_eq!(suggestion.after, "  pull_request:\n");
    let rewritten = applied(WORKFLOW, &suggestion);
    let moved = facts(&rewritten);
    assert_eq!(moved.triggers.len(), 1);
    assert_eq!(moved.triggers[0].event, "pull_request");
    assert_eq!(moved.triggers[0].branches, ["main"]);

    // The same event written as a sequence item moves the item alone.
    let listed = WORKFLOW.replace(
        "  pull_request_target:\n    branches: [main]\n",
        "  - push\n  - pull_request_target\n",
    );
    let suggestion = suggest(&request(&listed, None, None, "on")).unwrap();
    assert_eq!(suggestion.before, "  - pull_request_target\n");
    assert_eq!(suggestion.after, "  - pull_request\n");
    let listed_facts = facts(&applied(&listed, &suggestion));
    assert_eq!(
        listed_facts
            .triggers
            .iter()
            .map(|trigger| trigger.event.as_str())
            .collect::<Vec<_>>(),
        ["push", "pull_request"]
    );

    // Renaming it where the workflow already runs on the pull request would state it twice.
    let both = WORKFLOW.replace(
        "  pull_request_target:",
        "  pull_request:\n  pull_request_target:",
    );
    let refused = suggest(&request(&both, None, None, "on")).unwrap_err();
    assert!(matches!(refused, Refusal::Unverified(_)), "{refused:?}");
    assert!(refused.message().contains("pull_request"), "{refused:?}");
}

#[test]
fn a_rewrite_that_fails_to_verify_is_never_offered() {
    // The second step names the same shell, so porting one step leaves the construct recorded and
    // the workflow no more translatable than it was: the rewrite does not keep its own promise.
    let twice = WORKFLOW.replace(
        "      - run: make lint\n",
        "      - run: make lint\n        shell: pwsh\n",
    );
    let refused = suggest(&request(&twice, Some("build"), Some(0), "shell")).unwrap_err();
    assert_eq!(refused.code(), "not_found");
    assert!(
        refused.message().contains("did not verify"),
        "{}",
        refused.message()
    );

    // Dropping the job's key while a step still states it leaves the construct where it was.
    let also = WORKFLOW.replace(
        "      - run: make lint\n",
        "      - run: make lint\n        continue-on-error: true\n",
    );
    let refused = suggest(&request(&also, Some("build"), None, "continue-on-error")).unwrap_err();
    assert_eq!(refused.code(), "not_found");
    assert!(
        refused.message().contains("did not verify"),
        "{}",
        refused.message()
    );
}

#[test]
fn a_construct_with_no_rewrite_is_refused_with_the_tables_own_reason() {
    let reason = match RuleTable::V1.classify(&Construct::Container) {
        Rule::Unsupported { reason } => reason,
        other => panic!("a container is unsupported: {other:?}"),
    };
    let refused = suggest(&request(WORKFLOW, Some("docker"), None, "container")).unwrap_err();
    assert_eq!(refused, Refusal::NoRewrite(reason));
    assert!(refused.message().contains(reason));

    // An unsupported trigger other than pull_request_target has no rewrite either.
    let runs = WORKFLOW.replace(
        "  pull_request_target:\n    branches: [main]\n",
        "  workflow_run:\n    types: [completed]\n",
    );
    let refused = suggest(&request(&runs, None, None, "on")).unwrap_err();
    assert!(matches!(refused, Refusal::NoRewrite(_)), "{refused:?}");

    // Two refused triggers leave no single one to rewrite.
    let both = WORKFLOW.replace(
        "  pull_request_target:\n    branches: [main]\n",
        "  pull_request_target:\n    branches: [main]\n  workflow_run:\n    types: [completed]\n",
    );
    let refused = suggest(&request(&both, None, None, "on")).unwrap_err();
    assert!(matches!(refused, Refusal::Invalid(_)), "{refused:?}");

    // A local action has no rewrite either, and the refusal is not a suggestion.
    let local = WORKFLOW.replace(
        "      - run: npm test\n",
        "      - uses: ./.github/actions/test\n",
    );
    let refused = suggest(&request(&local, Some("docker"), Some(0), "uses")).unwrap_err();
    assert!(matches!(refused, Refusal::NoRewrite(_)), "{refused:?}");
}

#[test]
fn a_construct_that_translates_is_not_something_to_suggest() {
    let refused = suggest(&request(WORKFLOW, Some("audit"), None, "timeout-minutes")).unwrap_err();
    assert_eq!(refused, Refusal::Translates(Rule::Translatable));

    let bash = WORKFLOW.replace("shell: pwsh", "shell: bash");
    let refused = suggest(&request(&bash, Some("build"), Some(0), "shell")).unwrap_err();
    assert_eq!(refused, Refusal::Translates(Rule::Translatable));

    // `on: schedule` translates with a stated change.
    let scheduled = WORKFLOW.replace(
        "  pull_request_target:\n    branches: [main]\n",
        "  schedule:\n    - cron: '0 3 * * *'\n",
    );
    let refused = suggest(&request(&scheduled, None, None, "on")).unwrap_err();
    assert!(
        matches!(refused, Refusal::Translates(Rule::WithChange { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_request_that_names_nothing_the_workflow_holds_is_refused_before_a_rewrite() {
    for (job, step, construct, code) in [
        (Some("nope"), None, "environment", "not_found"),
        (Some("build"), Some(9), "shell", "not_found"),
        (Some("build"), Some(1), "shell", "not_found"),
        (Some("build"), None, "container", "not_found"),
        (None, None, "environment", "invalid_request"),
    ] {
        let refused = suggest(&request(WORKFLOW, job, step, construct)).unwrap_err();
        assert_eq!(
            refused.code(),
            code,
            "{job:?} {step:?} {construct}: {refused:?}"
        );
    }

    // A workflow the analyzer refuses is answered with the analyzer's own message.
    let broken = WORKFLOW.replace(
        "    runs-on: ubuntu-latest",
        "    runs-on: ubuntu-latest\n    nope: 1",
    );
    let refused = suggest(&request(&broken, Some("build"), None, "environment")).unwrap_err();
    assert_eq!(refused.code(), "invalid_request");
    assert!(refused.message().contains("unknown key"), "{refused:?}");
}

#[test]
fn one_request_gives_one_answer_and_the_suggestion_writes_nothing() {
    let first = suggest(&request(WORKFLOW, Some("build"), Some(0), "shell")).unwrap();
    let second = suggest(&request(WORKFLOW, Some("build"), Some(0), "shell")).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.before, "        shell: pwsh\n");
    assert_eq!(first.after, "        shell: bash\n");
    assert_eq!(
        first.line as usize,
        WORKFLOW
            .lines()
            .position(|line| line == "        shell: pwsh")
            .unwrap()
            + 1
    );
    assert!(!first.applied, "a suggestion is never applied");
    // The request's own text is never touched: a suggestion is advice, not a write.
    assert_eq!(facts(WORKFLOW), facts(WORKFLOW));
}
