# Flaky tests

Sentinel keeps what each named test did, attempt by attempt, from the reports a job already
publishes, and lists the tests whose own rerun proved them unreliable. The list is deterministic:
it is what the reports stated, added up. No model, prompt or inference is on this path, so the
same stored rows always give the same answer.

## What makes a test flaky

A test is flaky when it **failed on one attempt and passed on a later attempt of the same
commit**. That is the whole rule. Two consequences decide most of what an operator sees:

- A failure and a pass on **different** commits prove nothing: the commits differ, so the change
  between them may be the cause, and neither attempt contradicts the other.
- A test that **failed on every attempt** of the window is broken, not flaky. It is counted for the
  window and never listed, because a rerun never proved anything about it.

A skipped test is neither a pass nor a failure: it cannot complete a flake.

## Where the outcomes come from

The controller reads a finished attempt's own reports once, off the request path, and writes one
row per test. Two formats are read, both by the parsers that already read reports for the failure
view ([diagnostics](diagnostics.md#parser-behavior)):

| Report | Where it is read from |
|---|---|
| JUnit XML | a captured artifact named `junit.xml`, `*.junit.xml` or `TEST-*.xml` |
| Go test JSON | a captured artifact named `go-test.json` or `*.go-test.json`, or the attempt's own `go test -json` stdout |

One attempt contributes at most four report files of 4 MiB each and one 4 MiB page of its log, so a
repository cannot make the pass read an unbounded report. A file that does not parse contributes
nothing, and the attempt is not read again: the queue row that asked for it is taken in the same
transaction as the rows it produced.

A test's **identity** is its suite and name, normalised so that the same test is the same identity
across runs:

- a JUnit classname is the suite, a Go package is the suite, and the identity is `<suite>::<name>`;
- a parametrised or data-driven suffix is dropped, so `adds[case-1]` and `adds[case-2]` are
  `adds`, and `subtracts(1, 2)` is `subtracts`;
- a Go subtest is reduced to its top-level function, so `TestParse/case_one` is `TestParse`: a
  subtest that exists in one revision and not the next is still the same test.

When one attempt states an identity twice (a Go parent test and its subtests, the same class in two
files), the outcome is decided by severity alone — failed over passed over skipped — never by the
order the records arrived in.

## Bounds and retention

- **Per repository:** at most 100,000 rows. A write that would pass the cap evicts that
  repository's oldest rows first, so a repository that runs very many tests keeps its recent
  history and no other repository's rows move.
- **In time:** a row expires with the log retention the report was read beside (14 days by default,
  [retention](retention.md)), so the flaky list's history is the history the logs still cover.
- **Per read:** a report reads at most one repository's window, and at most the cap's rows.

## The list

`GET /tenants/{slug}/repos/{name}/flakes?days&limit` answers the tests that flaked in the window,
worst first ([API](api.md#routes)). The window defaults to the deployment's log retention and
accepts any number of days up to 366; `limit` is the number of tests (default 20, at most 200).
Each test states:

- `identity`, `suite` and `name`;
- `attempts`, `failed`, `passed` and `skipped` over the window;
- `commits`, the number of commits it ran in, and `flakes`, the number of those commits on which it
  failed and then passed;
- `rate_bps`, flakes per 10,000 commits the test ran in — the share of commits it flaked on;
- `last_failed_ms`, when it last failed.

The envelope also states the window (`days`, `since_ms`, `rows`, `oldest_ms`, `newest_ms`), how many
tests were **broken** and therefore not listed, and whether the scan stopped at its bound.

The web interface shows the same figures at **History → Flaky tests**
([web interface](web-ui.md#views)), and the read-only MCP tool
`list_flaky_tests` serves them as untrusted, deterministic counts ([MCP](mcp.md)).

## What is not here

Nothing on this path asks a model anything and no answer of this list is an inference. An AI
analysis of a flaky test is a summary of messages beside it, labelled as such, and never changes
what this list says ([AI](ai.md)).
