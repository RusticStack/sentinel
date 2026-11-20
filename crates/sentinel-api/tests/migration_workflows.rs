//! The workflow read the migration wizard analyses through: the bytes `.github/workflows` holds at
//! a commit, read through the App's migration token, so a client that holds no repository
//! credential of its own can still preview a migration. Nothing here reaches github.com: the fake
//! holds the workflows.

#[path = "support/migration.rs"]
mod migration;

use migration::{COMMIT, MigrationFixture, REPO, SLUG};

const PATH: &str = "/api/v1/tenants/acme/repos/widget/migration/workflows";

/// A workflow with both a job the migration moves and one it leaves on GitHub's runners.
const PLAIN: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
  mac:
    runs-on: macos-14
    steps:
      - run: cargo test
";

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
}

fn read(f: &MigrationFixture, token: &str, query: &str) -> (u16, serde_json::Value) {
    let response = agent()
        .get(&format!("{}{PATH}{query}", f.base))
        .header("authorization", format!("Bearer {token}"))
        .call()
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

#[test]
fn the_workflow_read_answers_the_bytes_the_preview_analyses() {
    let f = MigrationFixture::start(PLAIN, &["build", "mac"], None);

    // Without a commit the read starts at the default branch's head and says which it read.
    let (status, body) = read(&f, &f.token, "");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["schema"], "sentinel.migration-workflows/1");
    assert_eq!(body["branch"], "main");
    assert_eq!(body["commit"], COMMIT);
    assert_eq!(body["workflows"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["workflows"][0]["path"], ".github/workflows/ci.yml");
    assert_eq!(body["workflows"][0]["text"], PLAIN);

    // The same files at a named commit: the branch is not read, and nothing else changes.
    let (status, named) = read(&f, &f.token, &format!("?commit={COMMIT}"));
    assert_eq!(status, 200, "{named}");
    assert_eq!(named["branch"], serde_json::Value::Null);
    assert_eq!(named["commit"], COMMIT);
    assert_eq!(named["workflows"], body["workflows"]);

    // The point of the read: those bytes, posted back at the commit they were read at, are what the
    // preview analyses, and the plan names that commit.
    let response = agent()
        .post(&format!(
            "{}/api/v1/tenants/{SLUG}/repos/{REPO}/migration/preview",
            f.base
        ))
        .header("authorization", format!("Bearer {}", f.token))
        .header("content-type", "application/json")
        .send(
            serde_json::json!({"commit": named["commit"], "workflows": named["workflows"]})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.into_body().read_to_string().unwrap();
    let preview: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(preview["revision"], COMMIT);
    assert_eq!(preview["workflows"][0]["path"], ".github/workflows/ci.yml");
    assert_eq!(preview["workflows"][0]["changes"][0]["job"], "build");
    assert_eq!(preview["workflows"][0]["kept"][0]["job"], "mac");
}

#[test]
fn the_workflow_read_refuses_a_malformed_commit_and_a_credential_that_is_not_an_administrator() {
    let f = MigrationFixture::start(PLAIN, &["build"], None);
    let (status, body) = read(&f, &f.token, "?commit=abc123");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "invalid_request");

    // Reading a repository's content through the App is the tenant's administrator's work, exactly
    // as the writes beside it are.
    let reader = sentinel_store::tokens::provision(
        &f.store,
        sentinel_store::tokens::Grant {
            user: f.root,
            name: "reader",
            permissions: sentinel_core::auth::Permissions::READ,
            tenant: Some(f.tenant),
            repo: None,
            lifetime_ms: 60_000,
        },
        sentinel_core::UnixMillis::now(),
    )
    .unwrap();
    let token = sentinel_auth::token::format(&reader.secret);
    let (status, body) = read(&f, &token, "");
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "forbidden");
}
