//! The rollback's GitHub calls against `sentinel_github::fake`: the restore built on the default
//! branch's own head, the bytes it puts back, the files it deletes, and a branch's required status
//! checks read and put back — or refused when the App is not granted administration.
#![cfg(feature = "fake")]

use sentinel_github::{
    Error,
    app::{App, Token},
    fake::FakeGithub,
    migration::{Migrate, Outcome, Rewritten},
    rollback::{self, Protected, RequiredCheck, RequiredChecks, Restore, Set},
};

const INSTALLATION: u64 = 41;
const ADMIN: u64 = 42;
const ACCOUNT: u64 = 73;
const REPOSITORY: u64 = 9;
const REMOTE: &str = "https://github.com/account/app.git";
const BEFORE: &str = "0123456789abcdef0123456789abcdef01234567";
const HEAD: &str = "1111111111111111111111111111111111111111";

const ORIGINAL: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
";

const SWITCHED: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: sentinel-4vcpu-ubuntu-2404
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
        // The same installation once its owner has approved administration, which is the one
        // permission a settings step asks for beyond the migration's three.
        github.add_installation(
            ADMIN,
            &serde_json::json!({
                "id": ADMIN,
                "app_id": 1,
                "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": {
                    "contents": "write",
                    "checks": "write",
                    "pull_requests": "write",
                    "workflows": "write",
                    "administration": "write",
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
        github.set_workflows("account", "app", BEFORE, &[("ci.yml", ORIGINAL)]);
        github.set_workflows("account", "app", HEAD, &[("ci.yml", SWITCHED)]);
        github.set_branch("account", "app", "main", HEAD);
        let app = App::new(1, test_key())
            .unwrap()
            .with_endpoint(&github.base())
            .unwrap();
        Fixture { github, app }
    }

    fn token(&self) -> Token {
        self.app
            .migration_token(INSTALLATION, ACCOUNT, REPOSITORY, REMOTE, now_ms())
            .expect("the installation grants the migration permissions")
    }

    fn admin_token(&self) -> Token {
        self.app
            .administration_token(ADMIN, ACCOUNT, REPOSITORY, REMOTE, now_ms())
            .expect("the installation grants administration")
    }

    /// The revert: the pre-switch revision's bytes, committed on top of the default branch's head.
    fn restore(&self, files: &[Rewritten<'_>], remove: &[&str]) -> Result<Outcome, Error> {
        self.app.restore(
            &self.token(),
            "account",
            "app",
            &Restore {
                write: Migrate {
                    commit: HEAD,
                    files,
                    message: "Restore the workflows from a pre-switch revision\n",
                    title: "Roll back the migration",
                    body: "These files are restored as that revision holds them.\n",
                },
                remove,
            },
        )
    }
}

#[test]
fn the_restore_puts_the_revisions_own_bytes_back_on_the_migration_branch() {
    let fixture = Fixture::start();
    let branch = fixture
        .app
        .branch_workflows(&fixture.token(), "account", "app")
        .unwrap();
    assert_eq!(branch.name, "main");
    assert_eq!(branch.head, HEAD);
    assert_eq!(branch.workflows, [".github/workflows/ci.yml"]);

    let files = fixture
        .app
        .workflows(&fixture.token(), "account", "app", BEFORE)
        .unwrap();
    let written: Vec<Rewritten<'_>> = files
        .iter()
        .map(|file| Rewritten {
            path: &file.path,
            text: &file.text,
        })
        .collect();
    let outcome = fixture.restore(&written, &[]).unwrap();
    let Outcome::Opened(pull) = outcome else {
        panic!("a first restore opens the pull request")
    };
    assert_eq!(pull.base, "main");
    // The committed bytes are the revision's own, not a rendering of them.
    assert_eq!(
        fixture.github.written(),
        [(".github/workflows/ci.yml".into(), ORIGINAL.into())]
    );
    // The only ref the restore moved is the migration branch.
    assert_eq!(
        fixture
            .github
            .refs()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/sentinel/migrate"],
        "a rollback never pushes to a default branch"
    );
    assert_eq!(fixture.github.pull_requests().len(), 1);

    // Re-entering the same state writes no new commit: the branch keeps the commit it had and the
    // same pull request is updated rather than a second one opened.
    let outcome = fixture.restore(&written, &[]).unwrap();
    let Outcome::Updated(again) = outcome else {
        panic!("a second restore updates the pull request it found")
    };
    assert_eq!(again.number, pull.number);
    assert_eq!(
        again.head, pull.head,
        "the branch holds the commit it already had"
    );
    assert_eq!(fixture.github.pull_requests().len(), 1);
}

#[test]
fn a_workflow_the_revision_does_not_hold_is_deleted_from_the_tree() {
    let fixture = Fixture::start();
    fixture.github.set_workflows(
        "account",
        "app",
        HEAD,
        &[("ci.yml", SWITCHED), ("extra.yml", SWITCHED)],
    );
    let files = [Rewritten {
        path: ".github/workflows/ci.yml",
        text: ORIGINAL,
    }];
    fixture
        .restore(&files, &[".github/workflows/extra.yml"])
        .unwrap();
    let sent = fixture.github.received().join("\n");
    assert!(
        sent.contains(
            r#"{"mode":"100644","path":".github/workflows/extra.yml","sha":null,"type":"blob"}"#
        ) || sent.contains(
            r#""path":".github/workflows/extra.yml","mode":"100644","type":"blob","sha":null"#
        ),
        "the tree states the deletion: {sent}"
    );
}

#[test]
fn a_restore_that_states_what_it_cannot_write_is_refused_before_a_request() {
    let fixture = Fixture::start();
    let files = [Rewritten {
        path: ".github/workflows/ci.yml",
        text: ORIGINAL,
    }];
    for remove in [
        ["main.rs"].as_slice(),
        [".github/workflows/ci.yml"].as_slice(),
    ] {
        assert_eq!(
            fixture.restore(&files, remove),
            Err(Error::Config("rollback file")),
            "a path outside the workflows directory, or one both written and removed"
        );
    }
    assert!(fixture.github.refs().is_empty());
}

#[test]
fn the_required_checks_are_read_and_put_back_as_one_document() {
    let fixture = Fixture::start();
    let original = serde_json::json!({"strict": true, "checks": [
        {"context": "build", "app_id": 15368},
        {"context": "test", "app_id": 15368}
    ]});
    fixture
        .github
        .set_protection("account", "app", "main", &original);
    let token = fixture.admin_token();
    let protected = fixture
        .app
        .required_checks(&token, "account", "app", "main")
        .unwrap();
    let Protected::Checks(current) = protected else {
        panic!("the branch states its checks")
    };
    assert_eq!(
        current.checks,
        [
            RequiredCheck {
                context: "build".into(),
                app_id: Some(15368)
            },
            RequiredCheck {
                context: "test".into(),
                app_id: Some(15368)
            }
        ]
    );

    // The switch replaced `test` with its own check; the rollback states the original document.
    let switched = RequiredChecks {
        strict: true,
        checks: vec![
            RequiredCheck {
                context: "build".into(),
                app_id: Some(15368),
            },
            RequiredCheck {
                context: "sentinel / test".into(),
                app_id: Some(42),
            },
        ],
    };
    let change = switched.change_to(&current);
    assert_eq!(change.remove.len(), 1);
    assert_eq!(change.restore.len(), 1);
    assert_eq!(
        fixture
            .app
            .set_required_checks(&token, "account", "app", "main", &current)
            .unwrap(),
        Set::Applied
    );
    assert_eq!(
        fixture.github.protection("account", "app", "main"),
        Some(original),
        "the branch states exactly the document that was put back"
    );
}

#[test]
fn without_administration_the_settings_are_not_permitted() {
    let fixture = Fixture::start();
    fixture.github.set_protection(
        "account",
        "app",
        "main",
        &serde_json::json!({"strict": true, "checks": [{"context": "build", "app_id": 15368}]}),
    );
    // GitHub mints no administration for an installation that never listed it.
    assert_eq!(
        fixture
            .app
            .administration_token(INSTALLATION, ACCOUNT, REPOSITORY, REMOTE, now_ms())
            .err(),
        Some(Error::Denied("administration".into()))
    );
    // And the migration's own token may not read protection.
    assert_eq!(
        fixture
            .app
            .required_checks(&fixture.token(), "account", "app", "main")
            .unwrap(),
        Protected::NotPermitted
    );
    // Nothing was written to the branch's protection.
    let unchanged = fixture.github.protection("account", "app", "main").unwrap();
    assert_eq!(unchanged["checks"].as_array().unwrap().len(), 1);
}

#[test]
fn a_branch_with_no_protection_rule_is_answered_as_such() {
    let fixture = Fixture::start();
    assert_eq!(
        fixture
            .app
            .required_checks(&fixture.admin_token(), "account", "app", "main")
            .unwrap(),
        Protected::Unprotected
    );
    assert_eq!(
        fixture
            .app
            .set_required_checks(
                &fixture.admin_token(),
                "account",
                "app",
                "main",
                &RequiredChecks::default()
            )
            .unwrap(),
        Set::Unprotected
    );
}

#[test]
fn the_settings_step_bounds_what_it_states() {
    let fixture = Fixture::start();
    fixture.github.set_protection(
        "account",
        "app",
        "main",
        &serde_json::json!({"strict": false, "checks": []}),
    );
    let token = fixture.admin_token();
    let too_many = RequiredChecks {
        strict: false,
        checks: (0..rollback::MAX_CHECKS + 1)
            .map(|index| RequiredCheck {
                context: format!("check-{index}"),
                app_id: None,
            })
            .collect(),
    };
    assert_eq!(
        fixture
            .app
            .set_required_checks(&token, "account", "app", "main", &too_many),
        Err(Error::Config("required checks"))
    );
    let long = RequiredChecks {
        strict: false,
        checks: vec![RequiredCheck {
            context: "c".repeat(rollback::MAX_CONTEXT + 1),
            app_id: None,
        }],
    };
    assert_eq!(
        fixture
            .app
            .set_required_checks(&token, "account", "app", "main", &long),
        Err(Error::Config("required checks"))
    );
}
