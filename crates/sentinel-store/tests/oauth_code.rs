//! O01 durable half: consent choices, approval (every term re-checked in
//! the writer), and the single-use, PKCE-bound code exchange with replay
//! revocation.

use sentinel_auth::{oauth::pkce, secret::Secret};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
    oauth::{
        self, ClientSpec, GrantKind, GrantRecord,
        code::{self, Approval, CodeError},
    },
    registration::{self, Admission, Applicant, Registration},
};

const NOW: UnixMillis = UnixMillis(1_000_000);
const REDIRECT: &str = "http://127.0.0.1:49152/callback";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(NOW.0 + ms)
}

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    dev: UserId,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    other_repo: RepoId,
}

/// A super admin; `dev`, an operator of `acme` (repository `app`) only;
/// an unrelated tenant `other` with its own repository.
fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        dev: UserId::new(),
        tenant: TenantId::new(),
        other: TenantId::new(),
        repo: RepoId::new(),
        other_repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, i.root, "Root", true, NOW)?;
            provisioning::insert_human(tx, i.dev, "Dev", false, NOW)?;
            let root = Principal::new(i.root, P::ALL, None, None);
            for (tenant, slug) in [(i.tenant, "acme"), (i.other, "other")] {
                auth::create_namespace(
                    tx,
                    root,
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            auth::set_membership(tx, root, i.tenant, i.dev, Role::Operator)?;
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            auth::create_repo(tx, root, i.other, i.other_repo, "app", NOW)?;
            auth::set_repo_grant(tx, root, i.repo, i.dev, P::READ.union(P::RUN))
        })
        .unwrap();
    (dir, store, i)
}

fn privileged(i: Ids) -> Authority {
    Authority::Credential {
        principal: Principal::new(i.root, P::ALL, None, None),
        stepped_up: true,
    }
}

/// A PKCE pair: (verifier, challenge).
fn pair() -> (String, String) {
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    (verifier, challenge)
}

fn approval<'a>(user: UserId, scopes: Scopes, challenge: &'a str) -> Approval<'a> {
    Approval {
        client_id: CLI_CLIENT_ID,
        redirect_uri: REDIRECT,
        code_challenge: challenge,
        user,
        scopes,
        tenant: None,
        repo: None,
        audience: Audience::Api,
    }
}

fn exchange(
    store: &Store,
    code: &Secret,
    verifier: &str,
    now: UnixMillis,
) -> Result<oauth::Minted, CodeError> {
    code::exchange(store, CLI_CLIENT_ID, code, REDIRECT, verifier, None, now)
}

fn record(store: &Store, user: UserId, grant: sentinel_core::GrantId) -> GrantRecord {
    store
        .read(|c| oauth::grants(c, Authority::HostLocal, user, 100))
        .unwrap()
        .into_iter()
        .find(|g| g.id == grant)
        .expect("grant listed")
}

fn last_audit(store: &Store) -> local_auth::AuditRecord {
    store
        .read(|c| local_auth::recent_audit(c, 1))
        .unwrap()
        .remove(0)
}

#[test]
fn consent_offers_the_accounts_active_memberships() {
    let (_dir, store, i) = fixture();
    let choices = store.read(|c| code::consent_choices(c, i.dev)).unwrap();
    assert_eq!(choices.len(), 1);
    assert_eq!(
        (choices[0].tenant, choices[0].slug.as_str(), choices[0].role),
        (i.tenant, "acme", Role::Operator)
    );
    assert!(
        store
            .read(|c| code::consent_choices(c, i.root))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .read(|c| code::repo_named(c, i.dev, i.tenant, "app"))
            .unwrap(),
        i.repo
    );
    assert!(matches!(
        store.read(|c| code::repo_named(c, i.dev, i.tenant, "missing")),
        Err(Error::NotFound)
    ));
}

/// The consent page's repository lookup never tells a person whether a
/// name exists in a tenant they do not belong to, nor in their own tenant
/// when the repository is not theirs to see.
#[test]
fn consent_repository_lookup_hides_what_the_account_cannot_see() {
    let (_dir, store, i) = fixture();
    let foreign_existing = store.read(|c| code::repo_named(c, i.dev, i.other, "app"));
    let foreign_missing = store.read(|c| code::repo_named(c, i.dev, i.other, "missing"));
    assert!(matches!(foreign_existing, Err(Error::NotFound)));
    assert!(matches!(foreign_missing, Err(Error::NotFound)));
    // An ungranted repository of dev's own tenant is invisible to an operator.
    let hidden = RepoId::new();
    store
        .writer()
        .write(move |tx| {
            let root = Principal::new(i.root, P::ALL, None, None);
            auth::create_repo(tx, root, i.tenant, hidden, "private", NOW)
        })
        .unwrap();
    assert!(matches!(
        store.read(|c| code::repo_named(c, i.dev, i.tenant, "private")),
        Err(Error::NotFound)
    ));
}

#[test]
fn an_approved_code_exchanges_once_for_a_narrowed_code_grant() {
    let (_dir, store, i) = fixture();
    let (verifier, challenge) = pair();
    let code = code::approve(
        &store,
        &Approval {
            tenant: Some(i.tenant),
            repo: Some(i.repo),
            ..approval(i.dev, Scopes::CLI_DEFAULT, &challenge)
        },
        NOW,
    )
    .unwrap();
    let minted = exchange(&store, &code, &verifier, at(1_000)).unwrap();
    assert_eq!(minted.scopes, Scopes::CLI_DEFAULT);
    let grant = record(&store, i.dev, minted.grant);
    assert_eq!(grant.kind, GrantKind::Code);
    assert_eq!(grant.client_id, CLI_CLIENT_ID);
    assert_eq!(grant.scopes, Scopes::CLI_DEFAULT);
    assert_eq!((grant.tenant, grant.repo), (Some(i.tenant), Some(i.repo)));
    assert_eq!(
        grant.expires,
        UnixMillis(at(1_000).0 + oauth::LOGIN_GRANT_MS)
    );
    assert!(!grant.revoked);
    let audit = last_audit(&store);
    assert_eq!(audit.event, Event::OAuthGrantIssued);
    assert_eq!(audit.subject, Some(i.dev));

    let who = store
        .read(|c| oauth::authenticate_access(c, &minted.access, Audience::Api, at(2_000)))
        .unwrap();
    assert_eq!(who.principal.user, i.dev);
    assert_eq!(who.principal.tenant, Some(i.tenant));
    assert_eq!(who.principal.repo, Some(i.repo));
    store
        .read(|c| auth::require_repo(c, who.principal, i.repo, P::RUN))
        .unwrap();
}

#[test]
fn a_code_expires_after_its_lifetime_and_is_spent_by_the_attempt() {
    let (_dir, store, i) = fixture();
    let (verifier, challenge) = pair();
    let code = code::approve(&store, &approval(i.dev, Scopes::RUNS_READ, &challenge), NOW).unwrap();
    assert!(matches!(
        exchange(&store, &code, &verifier, at(oauth::CODE_LIFETIME_MS)),
        Err(CodeError::Invalid)
    ));
    // The late attempt consumed it; presenting it again is a replay with no
    // grant to revoke, still audited.
    assert!(matches!(
        exchange(&store, &code, &verifier, at(1)),
        Err(CodeError::Replay)
    ));
    assert_eq!(last_audit(&store).event, Event::OAuthCodeReplay);
    assert!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 100))
            .unwrap()
            .is_empty()
    );

    // One millisecond inside the lifetime still works.
    let code = code::approve(&store, &approval(i.dev, Scopes::RUNS_READ, &challenge), NOW).unwrap();
    assert!(exchange(&store, &code, &verifier, at(oauth::CODE_LIFETIME_MS - 1)).is_ok());
    // An unknown code is merely invalid.
    assert!(matches!(
        exchange(&store, &Secret::generate(), &verifier, NOW),
        Err(CodeError::Invalid)
    ));
}

#[test]
fn a_replayed_code_revokes_its_grant_and_is_audited() {
    let (_dir, store, i) = fixture();
    let (verifier, challenge) = pair();
    let code = code::approve(
        &store,
        &approval(i.dev, Scopes::CLI_DEFAULT, &challenge),
        NOW,
    )
    .unwrap();
    let minted = exchange(&store, &code, &verifier, at(1)).unwrap();
    assert!(matches!(
        exchange(&store, &code, &verifier, at(2)),
        Err(CodeError::Replay)
    ));
    assert!(record(&store, i.dev, minted.grant).revoked);
    let audit = last_audit(&store);
    assert_eq!(audit.event, Event::OAuthCodeReplay);
    assert_eq!(audit.subject, Some(i.dev));
    assert!(matches!(
        store.read(|c| oauth::authenticate_access(c, &minted.access, Audience::Api, at(3))),
        Err(Error::NotFound)
    ));
    assert!(oauth::refresh(&store, CLI_CLIENT_ID, &minted.refresh, None, None, at(3)).is_err());
}

#[test]
fn a_wrong_verifier_redirect_or_client_is_invalid_and_spends_the_code() {
    let (_dir, store, i) = fixture();
    oauth::register_client(
        &store,
        &ClientSpec {
            id: "other-cli",
            name: "Other",
            first_party: false,
            loopback: true,
            redirect_path: Some("/callback"),
            device: false,
            max_scopes: Scopes::ALL,
        },
        &[],
    )
    .unwrap();
    let (verifier, challenge) = pair();
    let (wrong_verifier, _) = pair();
    type Attempt = fn(&Store, &Secret, &str) -> Result<oauth::Minted, CodeError>;
    let attempts: [(&str, Attempt); 5] = [
        ("wrong verifier", |s, c, _| {
            code::exchange(s, CLI_CLIENT_ID, c, REDIRECT, &pkce::verifier(), None, NOW)
        }),
        ("malformed verifier", |s, c, _| {
            code::exchange(s, CLI_CLIENT_ID, c, REDIRECT, "short", None, NOW)
        }),
        ("the challenge itself as verifier", |s, c, v| {
            code::exchange(
                s,
                CLI_CLIENT_ID,
                c,
                REDIRECT,
                &pkce::challenge(v),
                None,
                NOW,
            )
        }),
        ("another port", |s, c, v| {
            code::exchange(
                s,
                CLI_CLIENT_ID,
                c,
                "http://127.0.0.1:49153/callback",
                v,
                None,
                NOW,
            )
        }),
        ("another client", |s, c, v| {
            code::exchange(s, "other-cli", c, REDIRECT, v, None, NOW)
        }),
    ];
    assert_ne!(verifier, wrong_verifier);
    for (what, attempt) in attempts {
        let code =
            code::approve(&store, &approval(i.dev, Scopes::RUNS_READ, &challenge), NOW).unwrap();
        assert!(
            matches!(attempt(&store, &code, &verifier), Err(CodeError::Invalid)),
            "{what}"
        );
        assert!(
            matches!(
                exchange(&store, &code, &verifier, NOW),
                Err(CodeError::Replay)
            ),
            "{what}: the code must be spent"
        );
    }
    assert!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 100))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn approval_only_narrows_what_the_account_and_client_may_hold() {
    let (_dir, store, i) = fixture();
    oauth::register_client(
        &store,
        &ClientSpec {
            id: "reader-app",
            name: "Reader",
            first_party: false,
            loopback: false,
            redirect_path: None,
            device: false,
            max_scopes: Scopes::RUNS_READ,
        },
        &["https://reader.example/cb"],
    )
    .unwrap();
    let (_, challenge) = pair();
    type Refusal<'a> = (&'a str, Approval<'a>, fn(&Error) -> bool);
    let refusals: [Refusal<'_>; 9] = [
        (
            "a tenant the account is not a member of",
            Approval {
                tenant: Some(i.other),
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            |e| matches!(e, Error::Forbidden),
        ),
        (
            "a repository outside the tenant",
            Approval {
                tenant: Some(i.tenant),
                repo: Some(i.other_repo),
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            |e| matches!(e, Error::Forbidden),
        ),
        (
            "platform administration for a non-super-admin",
            approval(i.dev, Scopes::PLATFORM_ADMIN, &challenge),
            |e| matches!(e, Error::Forbidden),
        ),
        (
            "a repository without its tenant",
            Approval {
                repo: Some(i.repo),
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            |e| matches!(e, Error::InvalidInput(_)),
        ),
        ("no scope", approval(i.dev, Scopes::NONE, &challenge), |e| {
            matches!(e, Error::InvalidInput(_))
        }),
        (
            "scopes beyond the client's ceiling",
            Approval {
                client_id: "reader-app",
                redirect_uri: "https://reader.example/cb",
                ..approval(i.dev, Scopes::CLI_DEFAULT, &challenge)
            },
            |e| matches!(e, Error::InvalidInput("scope")),
        ),
        (
            "an unregistered redirect",
            Approval {
                redirect_uri: "http://localhost:49152/callback",
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            |e| matches!(e, Error::InvalidInput("redirect_uri")),
        ),
        (
            "an unknown client",
            Approval {
                client_id: "nobody",
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            |e| matches!(e, Error::NotFound),
        ),
        (
            "a plain challenge",
            approval(i.dev, Scopes::RUNS_READ, "not-a-challenge"),
            |e| matches!(e, Error::InvalidInput("code_challenge")),
        ),
    ];
    for (what, refused, expected) in refusals {
        match code::approve(&store, &refused, NOW) {
            Err(e) => assert!(expected(&e), "{what}: {e:?}"),
            Ok(_) => panic!("{what}: approved"),
        }
    }
    // The registered exact redirect and a super admin's platform scope work.
    assert!(
        code::approve(
            &store,
            &Approval {
                client_id: "reader-app",
                redirect_uri: "https://reader.example/cb",
                ..approval(i.dev, Scopes::RUNS_READ, &challenge)
            },
            NOW,
        )
        .is_ok()
    );
    assert!(code::approve(&store, &approval(i.root, Scopes::ALL, &challenge), NOW).is_ok());
}

#[test]
fn pending_and_suspended_accounts_cannot_approve_or_redeem() {
    let (_dir, store, i) = fixture();
    let (verifier, challenge) = pair();
    // A pending applicant exists but is not active.
    store
        .writer()
        .write(move |tx| {
            let policy = registration::policy(tx)?;
            registration::set_policy(
                tx,
                privileged(i),
                registration::DeploymentPolicy {
                    registration: Registration::ApprovalRequired,
                    ..policy
                },
                NOW,
            )
        })
        .unwrap();
    let pending = match registration::register(
        &store,
        Applicant::Local {
            display_name: "Applicant",
            username: "applicant",
            password: b"a long enough password for policy",
        },
        None,
        NOW,
    )
    .unwrap()
    {
        Admission::Pending(user) => user,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        code::approve(
            &store,
            &approval(pending, Scopes::RUNS_READ, &challenge),
            NOW
        ),
        Err(Error::Forbidden)
    ));

    // Approved while active, then suspended before the exchange: no grant,
    // and the code is spent.
    let code = code::approve(&store, &approval(i.dev, Scopes::RUNS_READ, &challenge), NOW).unwrap();
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, privileged(i), i.dev, false, at(1)))
        .unwrap();
    assert!(matches!(
        code::approve(
            &store,
            &approval(i.dev, Scopes::RUNS_READ, &challenge),
            at(2)
        ),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        exchange(&store, &code, &verifier, at(2)),
        Err(CodeError::Invalid)
    ));
    assert!(matches!(
        exchange(&store, &code, &verifier, at(3)),
        Err(CodeError::Replay)
    ));
    assert!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 100))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_denial_is_audited() {
    let (_dir, store, i) = fixture();
    code::deny(&store, CLI_CLIENT_ID, i.dev).unwrap();
    let audit = last_audit(&store);
    assert_eq!(audit.event, Event::OAuthConsentDenied);
    assert_eq!((audit.actor, audit.subject), (Some(i.dev), Some(i.dev)));
}
