//! Guided migration's writes against `sentinel_github::fake`: the workflows a commit holds, the
//! `sentinel/migrate` branch, and one pull request that a re-run updates instead of a second one.
//! Nothing here reaches github.com, and the branch is the only ref the client ever moves.
#![cfg(feature = "fake")]

use sentinel_github::{
    Error,
    app::App,
    fake::FakeGithub,
    migration::{self, Migrate, Outcome, Rewritten, Workflow},
};

const INSTALLATION: u64 = 41;
const ACCOUNT: u64 = 73;
const REPOSITORY: u64 = 9;
const REMOTE: &str = "https://github.com/account/app.git";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

const WORKFLOW: &str = "name: ci
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

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A throwaway RSA key, generated for this test alone: the App only signs a JWT the fake never
/// verifies.
fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

struct Fixture {
    github: FakeGithub,
    app: App,
}

impl Fixture {
    fn start() -> Fixture {
        let github = FakeGithub::start("unused-oauth-secret");
        github.add_installation(
            INSTALLATION,
            &serde_json::json!({
                "id": INSTALLATION,
                "app_id": 1,
                "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": {
                    "contents": "write",
                    "checks": "write",
                    "pull_requests": "write",
                    "workflows": "write",
                },
            })
            .to_string(),
        );
        github.add_repository(
            REPOSITORY,
            &serde_json::json!({
                "id": REPOSITORY,
                "owner": {"id": ACCOUNT},
                "clone_url": REMOTE,
                "archived": false,
            })
            .to_string(),
        );
        github.set_workflows("account", "app", COMMIT, &[("ci.yml", WORKFLOW)]);
        let app = App::new(1, test_key())
            .unwrap()
            .with_endpoint(&github.base())
            .unwrap();
        Fixture { github, app }
    }

    fn token(&self) -> sentinel_github::app::Token {
        self.app
            .migration_token(INSTALLATION, ACCOUNT, REPOSITORY, REMOTE, now_ms())
            .expect("the installation grants the migration permissions")
    }

    fn migrate(&self, text: &str) -> Result<Outcome, Error> {
        let files = [Rewritten {
            path: ".github/workflows/ci.yml",
            text,
        }];
        self.app.migrate(
            &self.token(),
            "account",
            "app",
            &Migrate {
                commit: COMMIT,
                files: &files,
                message: "Send workflow jobs to Sentinel runners\n",
                title: "Send workflow jobs to Sentinel runners",
                body: "Only the `runs-on:` lines change.\n",
            },
        )
    }
}

#[test]
fn the_workflows_a_commit_holds_are_read_at_that_commit() {
    let fixture = Fixture::start();
    let files = fixture
        .app
        .workflows(&fixture.token(), "account", "app", COMMIT)
        .unwrap();
    assert_eq!(
        files,
        [Workflow {
            path: ".github/workflows/ci.yml".into(),
            text: WORKFLOW.into(),
        }]
    );
    // A commit the fake does not hold has no workflows, which is nothing to migrate.
    assert!(
        fixture
            .app
            .workflows(&fixture.token(), "account", "app", &"a".repeat(40))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        fixture
            .app
            .workflows(&fixture.token(), "account", "app", "main"),
        Err(Error::Config("migration revision"))
    ));
}

#[test]
fn the_branch_carries_exactly_the_files_the_diff_rewrote() {
    let fixture = Fixture::start();
    let rewritten = WORKFLOW.replace(
        "runs-on: ubuntu-latest",
        "runs-on: sentinel-4vcpu-ubuntu-2404",
    );
    let outcome = fixture.migrate(&rewritten).unwrap();
    let Outcome::Opened(pull) = outcome else {
        panic!("the first run opens the pull request, got {outcome:?}");
    };
    assert_eq!(pull.number, 1);
    assert!(pull.url.starts_with("http://127.0.0.1:"));
    assert!(migration::commit_id(&pull.head));

    // One file, its whole text, and the label line is the only line that differs.
    let written = fixture.github.written();
    assert_eq!(written.len(), 1, "{written:?}");
    assert_eq!(written[0].0, ".github/workflows/ci.yml");
    assert_eq!(written[0].1, rewritten);

    // The only ref the migration moved is its own branch, never the default one.
    let refs = fixture.github.refs();
    assert_eq!(
        refs.iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/sentinel/migrate"]
    );
    assert_eq!(refs[0].1, pull.head);

    let pulls = fixture.github.pull_requests();
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].base, "main");
    assert_eq!(pulls[0].branch, "sentinel/migrate");
    assert_eq!(pulls[0].title, "Send workflow jobs to Sentinel runners");
}

#[test]
fn a_second_run_updates_the_same_branch_and_pull_request() {
    let fixture = Fixture::start();
    let first = fixture.migrate("first").unwrap();
    let second = fixture.migrate("second").unwrap();
    let (Outcome::Opened(opened), Outcome::Updated(updated)) = (first, second) else {
        panic!("the second run updates the first pull request");
    };
    assert_eq!(opened.number, updated.number);
    assert_ne!(
        opened.head, updated.head,
        "the branch moved to the new commit"
    );
    assert_eq!(fixture.github.pull_requests().len(), 1);
    assert_eq!(
        fixture.github.pull_requests()[0].body,
        "Only the `runs-on:` lines change.\n"
    );
    assert_eq!(fixture.github.refs()[0].1, updated.head);
}

#[test]
fn a_rerun_that_changes_nothing_leaves_the_branch_where_it_is() {
    let fixture = Fixture::start();
    let Outcome::Opened(opened) = fixture.migrate("same").unwrap() else {
        panic!("the first run opens the pull request");
    };
    let Outcome::Updated(updated) = fixture.migrate("same").unwrap() else {
        panic!("the second run updates the pull request");
    };
    assert_eq!(updated.number, opened.number);
    assert_eq!(
        updated.head, opened.head,
        "an unchanged analysis writes no commit"
    );
    assert_eq!(fixture.github.refs()[0].1, opened.head);
    assert_eq!(fixture.github.pull_requests().len(), 1);
}

#[test]
fn closing_leaves_the_branch_and_a_second_close_has_nothing_to_do() {
    let fixture = Fixture::start();
    let Outcome::Opened(opened) = fixture.migrate("first").unwrap() else {
        panic!("the first run opens the pull request");
    };
    let closed = fixture
        .app
        .close_migration(&fixture.token(), "account", "app")
        .unwrap();
    assert_eq!(
        closed,
        Outcome::Closed(opened.clone()),
        "closing names the pull request it closed"
    );
    assert_eq!(fixture.github.pull_requests()[0].state, "closed");
    assert!(
        !fixture.github.refs().is_empty(),
        "the branch stays, so the migration can be run again"
    );
    assert_eq!(
        fixture
            .app
            .close_migration(&fixture.token(), "account", "app")
            .unwrap(),
        Outcome::Nothing
    );
}

#[test]
fn protection_declining_the_update_is_reported_and_the_ref_is_left_alone() {
    let fixture = Fixture::start();
    let Outcome::Opened(opened) = fixture.migrate("first").unwrap() else {
        panic!("the first run opens the pull request");
    };
    fixture.github.protect("sentinel/migrate");
    assert_eq!(
        fixture.migrate("second"),
        Err(Error::Refused("branch protection"))
    );
    assert_eq!(
        fixture.github.refs()[0].1,
        opened.head,
        "the ref the protection covers is where it was"
    );
    assert_eq!(fixture.github.pull_requests().len(), 1);
}

#[test]
fn what_is_sent_is_bounded_before_a_request_is_made() {
    let fixture = Fixture::start();
    let files = [Rewritten {
        path: ".github/workflows/../escape.yml",
        text: "jobs: {}\n",
    }];
    let request = Migrate {
        commit: COMMIT,
        files: &files,
        message: "message\n",
        title: "title",
        body: "body\n",
    };
    assert_eq!(
        fixture
            .app
            .migrate(&fixture.token(), "account", "app", &request),
        Err(Error::Config("migration file"))
    );
    assert_eq!(
        fixture
            .app
            .close_migration(&fixture.token(), "account", "../app"),
        Err(Error::Config("repository"))
    );
    assert!(fixture.github.written().is_empty());
}
