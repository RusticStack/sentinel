//! O03 device authorization, durable half: pending requests with unique user
//! codes, approval (with narrowing) or denial by an admitted account,
//! one-time redemption, expiry, the pending cap, and admission re-checked
//! at redemption.

use std::collections::HashSet;

use sentinel_auth::{oauth as forms, secret::Secret};
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
        self, ClientSpec, DEVICE_INTERVAL_MS, DEVICE_LIFETIME_MS, GrantKind, MAX_PENDING_DEVICE,
        device::{self, Decision, Poll},
    },
    registration::{self, Admission, Applicant},
};

const NOW: UnixMillis = UnixMillis(1_000_000);

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

/// A super admin, a developer who operates `acme` (and nothing in `other`),
/// and a repository in each tenant.
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

fn begin(store: &Store, scopes: Scopes, now: UnixMillis) -> device::DeviceStart {
    device::begin(store, CLI_CLIENT_ID, scopes, Audience::Api, now).unwrap()
}

fn poll(store: &Store, device: &Secret, now: UnixMillis) -> Result<Poll, Error> {
    device::poll(store, CLI_CLIENT_ID, device, None, now)
}

fn approve(scopes: Scopes) -> Decision {
    Decision::Approve {
        scopes,
        tenant: None,
        repo: None,
    }
}

#[test]
fn user_codes_are_unique_canonical_and_in_the_alphabet() {
    let (_dir, store, _) = fixture();
    let mut codes = HashSet::new();
    let mut devices = HashSet::new();
    for n in 0..200 {
        let start = begin(&store, Scopes::CLI_DEFAULT, at(n));
        assert_eq!(start.user_code.len(), 8);
        assert!(
            start
                .user_code
                .bytes()
                .all(|b| forms::USER_CODE_ALPHABET.contains(&b))
        );
        assert_eq!(
            forms::normalize_user_code(&forms::display_user_code(&start.user_code)).as_deref(),
            Some(start.user_code.as_str())
        );
        assert_eq!(start.expires, at(n + DEVICE_LIFETIME_MS));
        assert_eq!(start.interval_ms, DEVICE_INTERVAL_MS);
        assert!(codes.insert(start.user_code));
        assert!(devices.insert(start.device.digest().0));
    }
}

#[test]
fn an_approved_request_redeems_exactly_once() {
    let (_dir, store, i) = fixture();
    let start = begin(&store, Scopes::CLI_DEFAULT, NOW);
    assert!(matches!(
        poll(&store, &start.device, at(1)),
        Ok(Poll::Pending)
    ));
    let view = store
        .read(|c| device::view(c, &start.user_code, at(2)))
        .unwrap();
    assert_eq!(view.client_name, "Sentinel CLI");
    assert_eq!(view.scopes, Scopes::CLI_DEFAULT);
    assert_eq!(view.expires, start.expires);

    let narrowed = Scopes::RUNS_READ.union(Scopes::LOGS_READ);
    device::decide(&store, &start.user_code, i.dev, approve(narrowed), at(3)).unwrap();
    // Decided: the page no longer finds it and a second decision is refused.
    assert!(matches!(
        store.read(|c| device::view(c, &start.user_code, at(4))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        device::decide(&store, &start.user_code, i.dev, Decision::Deny, at(4)),
        Err(Error::NotFound)
    ));

    let Ok(Poll::Issued(minted)) = poll(&store, &start.device, at(5)) else {
        panic!("approved request did not issue");
    };
    assert_eq!(minted.scopes, narrowed);
    let authenticated = store
        .read(|c| oauth::authenticate_access(c, &minted.access, Audience::Api, at(6)))
        .unwrap();
    assert_eq!(authenticated.principal.user, i.dev);
    assert_eq!(authenticated.scopes, narrowed);
    let grants = store
        .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 10))
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].kind, GrantKind::Device);
    assert_eq!(grants[0].expires, at(5 + oauth::LOGIN_GRANT_MS));

    // Redeemed: never again, by any poll.
    assert!(matches!(
        poll(&store, &start.device, at(7)),
        Err(Error::NotFound)
    ));
    assert_eq!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 10))
            .unwrap()
            .len(),
        1
    );
    let audit = store.read(|c| local_auth::recent_audit(c, 2)).unwrap();
    assert_eq!(audit[0].event, Event::OAuthGrantIssued);
    assert_eq!(audit[1].event, Event::OAuthDeviceApproved);
    assert_eq!(audit[1].actor, Some(i.dev));
}

#[test]
fn unknown_and_foreign_device_codes_are_not_found() {
    let (_dir, store, _) = fixture();
    let start = begin(&store, Scopes::RUNS_READ, NOW);
    assert!(matches!(
        poll(&store, &Secret::generate(), at(1)),
        Err(Error::NotFound)
    ));
    store_client(&store, "other-device", true);
    assert!(matches!(
        device::poll(&store, "other-device", &start.device, None, at(1)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.read(|c| device::view(c, "BCDFGHJK", at(1))),
        Err(Error::NotFound)
    ));
}

fn store_client(store: &Store, id: &'static str, device: bool) {
    oauth::register_client(
        store,
        &ClientSpec {
            id,
            name: "Other",
            first_party: false,
            loopback: false,
            redirect_path: None,
            device,
            max_scopes: Scopes::CLI_DEFAULT,
        },
        &[],
    )
    .unwrap();
}

#[test]
fn clients_must_be_device_capable_and_scopes_within_their_ceiling() {
    let (_dir, store, _) = fixture();
    store_client(&store, "no-device", false);
    assert!(matches!(
        device::begin(&store, "no-device", Scopes::RUNS_READ, Audience::Api, NOW),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        device::begin(&store, "unknown", Scopes::RUNS_READ, Audience::Api, NOW),
        Err(Error::NotFound)
    ));
    store_client(&store, "narrow", true);
    assert!(matches!(
        device::begin(&store, "narrow", Scopes::SECRETS_WRITE, Audience::Api, NOW),
        Err(Error::InvalidInput("scope"))
    ));
    assert!(matches!(
        device::begin(&store, CLI_CLIENT_ID, Scopes::NONE, Audience::Api, NOW),
        Err(Error::InvalidInput("scope"))
    ));
}

#[test]
fn denial_and_expiry_are_final_answers() {
    let (_dir, store, i) = fixture();
    let denied = begin(&store, Scopes::CLI_DEFAULT, NOW);
    device::decide(&store, &denied.user_code, i.dev, Decision::Deny, at(1)).unwrap();
    assert!(matches!(
        poll(&store, &denied.device, at(2)),
        Ok(Poll::Denied)
    ));
    assert!(matches!(
        poll(&store, &denied.device, at(3)),
        Ok(Poll::Denied)
    ));
    let audit = store.read(|c| local_auth::recent_audit(c, 1)).unwrap();
    assert_eq!(audit[0].event, Event::OAuthDeviceDenied);

    // Undecided past its life: expired, and no longer approvable.
    let lapsed = begin(&store, Scopes::CLI_DEFAULT, NOW);
    assert!(matches!(
        poll(&store, &lapsed.device, at(DEVICE_LIFETIME_MS)),
        Ok(Poll::Expired)
    ));
    assert!(matches!(
        device::decide(
            &store,
            &lapsed.user_code,
            i.dev,
            approve(Scopes::RUNS_READ),
            at(DEVICE_LIFETIME_MS)
        ),
        Err(Error::NotFound)
    ));
    // Approved but never redeemed in time: expired too, and nothing issued.
    let unredeemed = begin(&store, Scopes::CLI_DEFAULT, NOW);
    device::decide(
        &store,
        &unredeemed.user_code,
        i.dev,
        approve(Scopes::RUNS_READ),
        at(1),
    )
    .unwrap();
    assert!(matches!(
        poll(&store, &unredeemed.device, at(DEVICE_LIFETIME_MS + 1)),
        Ok(Poll::Expired)
    ));
    assert!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_pending_cap_refuses_new_requests_until_old_ones_expire() {
    let (_dir, store, i) = fixture();
    let mut first = None;
    for n in 0..MAX_PENDING_DEVICE {
        let start = begin(&store, Scopes::RUNS_READ, NOW);
        if n == 0 {
            first = Some(start);
        }
    }
    assert!(matches!(
        device::begin(
            &store,
            CLI_CLIENT_ID,
            Scopes::RUNS_READ,
            Audience::Api,
            at(1)
        ),
        Err(Error::QuotaExceeded)
    ));
    // A decided request no longer counts as pending.
    let first = first.unwrap();
    device::decide(&store, &first.user_code, i.dev, Decision::Deny, at(1)).unwrap();
    begin(&store, Scopes::RUNS_READ, at(2));
    assert!(matches!(
        device::begin(
            &store,
            CLI_CLIENT_ID,
            Scopes::RUNS_READ,
            Audience::Api,
            at(3)
        ),
        Err(Error::QuotaExceeded)
    ));
    // Expired requests stop counting without any purge.
    begin(&store, Scopes::RUNS_READ, at(DEVICE_LIFETIME_MS));
}

#[test]
fn only_an_admitted_active_person_can_decide() {
    let (_dir, store, i) = fixture();
    let root = privileged(i);
    store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                root,
                registration::DeploymentPolicy {
                    registration: registration::Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                NOW,
            )
        })
        .unwrap();
    let applicant = |subject: &'static str| match registration::register(
        &store,
        Applicant::External {
            display_name: "Applicant",
            provider: "github",
            subject,
        },
        None,
        NOW,
    )
    .unwrap()
    {
        Admission::Pending(user) => user,
        other => panic!("{other:?}"),
    };
    let pending = applicant("1");
    let rejected = applicant("2");
    store
        .writer()
        .write(move |tx| registration::reject(tx, root, rejected, NOW))
        .unwrap();
    let suspended = UserId::new();
    let bot = UserId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, suspended, "Suspended", false, NOW)?;
            local_auth::set_active(tx, root, suspended, false, NOW)?;
            let admin = Principal::new(i.root, P::ALL, None, None);
            auth::create_service_account(tx, admin, i.tenant, bot, "bot", Role::Operator, NOW)
        })
        .unwrap();
    let start = begin(&store, Scopes::RUNS_READ, NOW);
    for user in [pending, rejected, suspended, bot] {
        assert!(matches!(
            device::decide(
                &store,
                &start.user_code,
                user,
                approve(Scopes::RUNS_READ),
                at(1)
            ),
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            device::decide(&store, &start.user_code, user, Decision::Deny, at(1)),
            Err(Error::Forbidden)
        ));
    }
    // Still pending for somebody who may decide.
    assert!(matches!(
        poll(&store, &start.device, at(2)),
        Ok(Poll::Pending)
    ));
}

#[test]
fn suspension_between_approval_and_poll_issues_nothing() {
    let (_dir, store, i) = fixture();
    let start = begin(&store, Scopes::CLI_DEFAULT, NOW);
    device::decide(
        &store,
        &start.user_code,
        i.dev,
        approve(Scopes::CLI_DEFAULT),
        at(1),
    )
    .unwrap();
    let root = privileged(i);
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, root, i.dev, false, at(2)))
        .unwrap();
    assert!(matches!(
        poll(&store, &start.device, at(3)),
        Ok(Poll::Denied)
    ));
    // The request is spent: reactivation does not revive it.
    store
        .writer()
        .write(move |tx| local_auth::set_active(tx, root, i.dev, true, at(4)))
        .unwrap();
    assert!(matches!(
        poll(&store, &start.device, at(5)),
        Err(Error::NotFound)
    ));
    assert!(
        store
            .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn approval_only_narrows_within_the_approvers_reach() {
    let (_dir, store, i) = fixture();
    let start = begin(
        &store,
        Scopes::CLI_DEFAULT.union(Scopes::PLATFORM_ADMIN),
        NOW,
    );
    let code = start.user_code.clone();
    let decide = |user: UserId, d: Decision| device::decide(&store, &code, user, d, at(1));
    // Wider than asked, or empty.
    assert!(matches!(
        decide(
            i.dev,
            approve(Scopes::CLI_DEFAULT.union(Scopes::SECRETS_WRITE))
        ),
        Err(Error::InvalidInput("scope"))
    ));
    assert!(matches!(
        decide(i.dev, approve(Scopes::NONE)),
        Err(Error::InvalidInput("scope"))
    ));
    // Platform administration only for a super admin.
    assert!(matches!(
        decide(i.dev, approve(Scopes::PLATFORM_ADMIN)),
        Err(Error::Forbidden)
    ));
    let narrow = |tenant, repo| Decision::Approve {
        scopes: Scopes::RUNS_READ,
        tenant,
        repo,
    };
    // A tenant the approver is not a member of, a repository outside the
    // chosen tenant, a repository without a tenant.
    assert!(matches!(
        decide(i.dev, narrow(Some(i.other), None)),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        decide(i.dev, narrow(Some(i.tenant), Some(i.other_repo))),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        decide(i.dev, narrow(None, Some(i.repo))),
        Err(Error::InvalidInput(_))
    ));
    // Nothing above spent the request; a valid narrowing is recorded.
    decide(i.dev, narrow(Some(i.tenant), Some(i.repo))).unwrap();
    let Ok(Poll::Issued(minted)) = poll(&store, &start.device, at(2)) else {
        panic!("not issued");
    };
    assert_eq!(minted.scopes, Scopes::RUNS_READ);
    let who = store
        .read(|c| oauth::authenticate_access(c, &minted.access, Audience::Api, at(3)))
        .unwrap();
    assert_eq!(who.principal.tenant, Some(i.tenant));
    assert_eq!(who.principal.repo, Some(i.repo));
    assert_eq!(who.principal.permissions, P::READ);

    // A super admin may approve platform administration.
    let admin = begin(&store, Scopes::PLATFORM_ADMIN, at(4));
    device::decide(
        &store,
        &admin.user_code,
        i.root,
        approve(Scopes::PLATFORM_ADMIN),
        at(5),
    )
    .unwrap();
    assert!(matches!(
        poll(&store, &admin.device, at(6)),
        Ok(Poll::Issued(_))
    ));
}
