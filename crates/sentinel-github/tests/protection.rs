//! Branch protection and rulesets against `sentinel_github::fake`: what a branch requires now, the
//! change a native pipeline makes to it, and the one write that applies the change. Nothing here
//! reaches github.com, and no ruleset is ever written.
#![cfg(feature = "fake")]

use sentinel_github::{
    Error,
    app::{App, Token},
    fake::FakeGithub,
    protection::{self, Required, change},
    rollback::{RequiredCheck, RequiredChecks},
};

const INSTALLATION: u64 = 41;
const ACCOUNT: u64 = 73;
const REPOSITORY: u64 = 9;
const REMOTE: &str = "https://github.com/account/app.git";

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
    fn start(administration: bool) -> Fixture {
        let github = FakeGithub::start("unused-oauth-secret");
        let mut permissions = serde_json::json!({
            "contents": "write",
            "checks": "write",
        });
        if administration {
            permissions["administration"] = serde_json::json!("write");
        }
        github.add_installation(
            INSTALLATION,
            &serde_json::json!({
                "id": INSTALLATION,
                "app_id": 1,
                "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": permissions,
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
        let app = App::new(1, test_key())
            .unwrap()
            .with_endpoint(&github.base())
            .unwrap();
        Fixture { github, app }
    }

    fn token(&self) -> Result<Token, Error> {
        self.app
            .administration_token(INSTALLATION, ACCOUNT, REPOSITORY, REMOTE, now_ms())
    }

    fn required(&self, branch: &str) -> Result<Required, Error> {
        self.app
            .protection_of(&self.token()?, "account", "app", branch)
    }

    fn set_required(&self, branch: &str, checks: &RequiredChecks) -> Result<(), Error> {
        self.app
            .set_required(&self.token()?, "account", "app", branch, checks)
    }

    /// A branch's required checks as the fake's document states them: `strict` and the contexts it
    /// waits for, in the order they are held.
    fn held(&self) -> Option<(Vec<String>, bool)> {
        let document = self.github.protection("account", "app", "main")?;
        let strict = document["strict"].as_bool().unwrap_or(false);
        let contexts = document["checks"]
            .as_array()?
            .iter()
            .filter_map(|check| check["context"].as_str().map(str::to_owned))
            .collect();
        Some((contexts, strict))
    }

    /// One branch's protection as a test sets it: `strict` and the contexts, each bound to no App.
    fn protect(&self, branch: &str, contexts: &[&str], strict: bool) {
        let checks: Vec<serde_json::Value> = contexts
            .iter()
            .map(|context| serde_json::json!({"context": context, "app_id": null}))
            .collect();
        self.github.set_protection(
            "account",
            "app",
            branch,
            &serde_json::json!({"strict": strict, "checks": checks}),
        );
    }

    fn checks(strict: bool, contexts: &[&str]) -> RequiredChecks {
        RequiredChecks {
            strict,
            checks: contexts
                .iter()
                .map(|context| RequiredCheck {
                    context: (*context).to_owned(),
                    app_id: None,
                })
                .collect(),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }
}

#[test]
fn an_unprotected_branch_requires_nothing() {
    let fixture = Fixture::start(true);
    let required = fixture.required("main").unwrap();
    assert_eq!(
        required,
        Required {
            branch: "main".to_owned(),
            contexts: Vec::new(),
            strict: false,
            protected: false,
            checks: RequiredChecks::default(),
            rulesets: Vec::new(),
            from_rulesets: Vec::new(),
        }
    );
}

#[test]
fn protection_reads_either_shape_github_states() {
    // The older document: a list of contexts and nothing else.
    let fixture = Fixture::start(true);
    fixture.github.set_protection(
        "account",
        "app",
        "main",
        &serde_json::json!({"strict": true, "contexts": ["lint", "build", "lint"]}),
    );
    let required = fixture.required("main").unwrap();
    assert_eq!(required.contexts, ["build", "lint"]);
    assert!(required.strict, "strict is carried from protection");
    assert!(required.protected);
    assert!(required.from_rulesets.is_empty());

    // The newer one: each check with the App it must be published by.
    fixture.github.set_protection(
        "account",
        "app",
        "main",
        &serde_json::json!({
            "strict": false,
            "checks": [
                {"context": "ci/external", "app_id": null},
                {"context": "build", "app_id": 7},
            ],
        }),
    );
    let required = fixture.required("main").unwrap();
    assert_eq!(required.contexts, ["build", "ci/external"]);
    assert!(!required.strict);
    let bound = required
        .checks
        .checks
        .iter()
        .find(|check| check.context == "build")
        .expect("every stated check is read");
    assert_eq!(
        bound.app_id,
        Some(7),
        "the App a check is bound to is carried, so a write keeps it"
    );
}

#[test]
fn an_active_ruleset_states_contexts_that_protection_does_not() {
    let fixture = Fixture::start(true);
    fixture.protect("main", &["build"], true);
    fixture
        .github
        .set_ruleset(7, "CI gate", &["ci/ruleset", "lint"]);
    let required = fixture.required("main").unwrap();
    assert_eq!(required.from_rulesets, ["ci/ruleset", "lint"]);
    assert_eq!(
        required.contexts,
        ["build", "ci/ruleset", "lint"],
        "the required set is the union of both sources"
    );
    assert_eq!(required.rulesets, ["CI gate"]);

    fixture.github.set_ruleset_state(7, "tag", "active");
    let retargeted = fixture.required("main").unwrap();
    assert!(retargeted.from_rulesets.is_empty(), "a tag rule is no rule");
    assert!(retargeted.rulesets.is_empty());

    fixture.github.set_ruleset_state(7, "branch", "disabled");
    let disabled = fixture.required("main").unwrap();
    assert!(disabled.from_rulesets.is_empty());
    assert!(disabled.rulesets.is_empty());
    assert_eq!(disabled.contexts, ["build"]);
}

#[test]
fn a_rule_the_listing_does_not_name_is_still_a_rule() {
    let fixture = Fixture::start(true);
    fixture.github.set_rules_json(
        r#"[{"type":"required_status_checks","ruleset_id":42,
            "parameters":{"required_status_checks":[{"context":"org/ci"}]}},
           {"type":"required_status_checks","ruleset_id":7,
            "parameters":{"required_status_checks":[{"context":"org/lint"}]}},
           {"type":"deletion","parameters":{}}]"#,
    );
    let required = fixture.required("main").unwrap();
    assert_eq!(required.from_rulesets, ["org/ci", "org/lint"]);
    assert_eq!(
        required.rulesets,
        ["#42", "#7"],
        "a ruleset the listing does not name is named by its id, never dropped"
    );
    assert_eq!(required.contexts, ["org/ci", "org/lint"]);
}

#[test]
fn a_malformed_rules_answer_is_never_a_smaller_set() {
    let fixture = Fixture::start(true);
    fixture.github.set_rules_json(
        r#"[{"type":"required_status_checks","ruleset_id":1,
            "parameters":{"required_status_checks":[{"context":"lint"},{"context":7}]}}]"#,
    );
    assert_eq!(
        fixture.required("main"),
        Err(Error::Response("branch rules"))
    );

    let long = format!(
        r#"[{{"type":"required_status_checks","ruleset_id":1,
             "parameters":{{"required_status_checks":[{{"context":"{}"}}]}}}}]"#,
        "c".repeat(protection::MAX_CONTEXT + 1)
    );
    fixture.github.set_rules_json(&long);
    assert_eq!(
        fixture.required("main"),
        Err(Error::Response("branch rules"))
    );

    // An answer that is not a list of rules at all: a set read from it would be smaller than the
    // branch's gate, so it is refused rather than read as none.
    fixture
        .github
        .set_rules_json(r#"{"type":"required_status_checks"}"#);
    assert_eq!(
        fixture.required("main"),
        Err(Error::Response("branch rules"))
    );
}

#[test]
fn the_change_swaps_a_replaced_job_and_leaves_the_external_context() {
    let fixture = Fixture::start(true);
    fixture.protect(
        "main",
        &["build (1.24)", "ci/external", "lint", "windows (2019)"],
        true,
    );
    let before = fixture.required("main").unwrap();
    let replaced = [
        ("build".to_owned(), Some("build".to_owned())),
        ("lint".to_owned(), None),
    ];
    let change = change(&before, &replaced);
    assert_eq!(
        change.contexts(),
        [
            "ci/external",
            "sentinel / build (1.24)",
            "sentinel / lint",
            "windows (2019)",
        ],
        "a matrix cell follows its job, and a job no pipeline replaced is untouched"
    );
    assert!(change.settings.strict);
    assert_eq!(
        change.replaced,
        [
            (
                "build (1.24)".to_owned(),
                "sentinel / build (1.24)".to_owned()
            ),
            ("lint".to_owned(), "sentinel / lint".to_owned()),
        ]
    );
}

#[test]
fn a_change_that_removes_a_ruleset_context_is_refused() {
    let fixture = Fixture::start(true);
    fixture.protect("main", &["build", "lint"], true);
    fixture.github.set_ruleset(4, "Org gate", &["build"]);
    let before = fixture.required("main").unwrap();
    assert_eq!(before.from_rulesets, ["build"]);
    assert_eq!(
        before.editable(&Fixture::strings(&["build"])),
        Err("ruleset"),
        "a context a ruleset states is not this deployment's to replace"
    );
    assert_eq!(
        before.editable(&Fixture::strings(&["lint"])),
        Ok(()),
        "a context only branch protection states is"
    );
}

#[test]
fn the_settings_after_the_write_equal_the_preview() {
    let fixture = Fixture::start(true);
    fixture.protect("main", &["build", "ci/external", "lint"], true);
    let before = fixture.required("main").unwrap();
    let change = change(&before, &[("build".to_owned(), Some("build".to_owned()))]);
    assert_eq!(
        change.contexts(),
        ["ci/external", "lint", "sentinel / build"]
    );
    fixture
        .set_required("main", &change.settings)
        .expect("the branch has protection to change");
    assert_eq!(
        fixture.held(),
        Some((
            Fixture::strings(&["ci/external", "lint", "sentinel / build"]),
            true
        ))
    );
    let after = fixture.required("main").unwrap();
    assert_eq!(after.contexts, change.contexts());
    assert_eq!(after.strict, change.settings.strict);
    assert!(after.from_rulesets.is_empty());
}

#[test]
fn a_write_to_an_unprotected_branch_is_denied() {
    let fixture = Fixture::start(true);
    assert_eq!(
        fixture.set_required("main", &Fixture::checks(false, &["lint"])),
        Err(Error::Denied("branch protection".into())),
        "creating protection is a person's decision, not a migration's"
    );
    assert_eq!(fixture.github.protection("account", "app", "main"), None);
}

#[test]
fn without_administration_nothing_is_read_or_written() {
    let fixture = Fixture::start(false);
    assert!(
        matches!(
            fixture.token(),
            Err(Error::Denied(permission)) if permission == "administration"
        ),
        "a token minted without the grant is the grant's answer, not a transport failure"
    );
    assert_eq!(
        fixture.required("main"),
        Err(Error::Denied("administration".into()))
    );
}

#[test]
fn what_is_written_is_bounded_before_a_request_is_made() {
    let fixture = Fixture::start(true);
    fixture.protect("main", &["lint"], false);
    let many: Vec<&str> = Vec::new();
    let _ = many;
    let contexts: Vec<String> = (0..=protection::MAX_CHECKS)
        .map(|index| format!("c{index}"))
        .collect();
    let over = RequiredChecks {
        strict: false,
        checks: contexts
            .iter()
            .map(|context| RequiredCheck {
                context: context.clone(),
                app_id: None,
            })
            .collect(),
    };
    assert_eq!(
        fixture.set_required("main", &over),
        Err(Error::Config("required checks"))
    );
    assert_eq!(
        fixture.set_required("main", &Fixture::checks(false, &["a\nb"])),
        Err(Error::Config("required checks"))
    );
    assert_eq!(
        fixture.required("../main"),
        Err(Error::Config("branch")),
        "a branch name that is not one path part is refused without a request"
    );
    assert_eq!(
        fixture
            .app
            .protection_of(&fixture.token().unwrap(), "..", "app", "main"),
        Err(Error::Config("branch"))
    );
    assert_eq!(
        fixture.held(),
        Some((Fixture::strings(&["lint"]), false)),
        "nothing a bounds check refused reached the branch"
    );
}
