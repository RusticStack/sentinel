//! `artifacts:write` (bit 1024) crosses every stored scope column migration 73 widened: a client
//! cap, an authorization code, the grant it is exchanged for, the refresh chain that renews it, a
//! device authorization requested and approved at that width, and the access token that carries it.

use sentinel_auth::{oauth::pkce, secret::Secret};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    oauth::{
        self, ClientSpec,
        code::Approval,
        device::{self, Decision, Poll},
    },
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
    repo: RepoId,
}

fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let i = Ids {
        root: UserId::new(),
        dev: UserId::new(),
        tenant: TenantId::new(),
        repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, i.root, "Root", true, NOW)?;
            provisioning::insert_human(tx, i.dev, "Dev", false, NOW)?;
            let root = Principal::new(i.root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                root,
                i.tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            auth::set_membership(tx, root, i.tenant, i.dev, Role::Operator)?;
            auth::create_repo(tx, root, i.tenant, i.repo, "app", NOW)?;
            auth::set_repo_grant(tx, root, i.repo, i.dev, P::READ.union(P::RUN))
        })
        .unwrap();
    (dir, store, i)
}

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

fn authenticated(store: &Store, access: &Secret, now: UnixMillis) -> Scopes {
    store
        .read(|c| oauth::authenticate_access(c, access, Audience::Api, now))
        .unwrap()
        .scopes
}

#[test]
fn the_cli_client_is_capped_at_every_scope_the_code_defines() {
    let (_dir, store, _) = fixture();
    let client = store.read(|c| oauth::client(c, CLI_CLIENT_ID)).unwrap();
    assert_eq!(client.max_scopes, Scopes::ALL);
    assert!(client.max_scopes.contains(Scopes::ARTIFACTS_WRITE));
}

#[test]
fn a_grant_carries_artifacts_write_through_the_code_grant_and_its_refresh_chain() {
    let (_dir, store, i) = fixture();
    let wanted = Scopes::CLI_DEFAULT.union(Scopes::ARTIFACTS_WRITE);
    let (verifier, challenge) = pair();
    let code = oauth::code::approve(&store, &approval(i.dev, wanted, &challenge), NOW).unwrap();
    let minted =
        oauth::code::exchange(&store, CLI_CLIENT_ID, &code, REDIRECT, &verifier, None, NOW)
            .unwrap();
    assert_eq!(minted.scopes, wanted);
    assert_eq!(authenticated(&store, &minted.access, NOW), wanted);

    let grant = store
        .read(|c| oauth::grants(c, Authority::HostLocal, i.dev, 100))
        .unwrap()
        .into_iter()
        .find(|g| g.id == minted.grant)
        .expect("grant listed");
    assert_eq!(grant.scopes, wanted);
    assert!(grant.scopes.contains(Scopes::ARTIFACTS_WRITE));

    let rotated =
        oauth::refresh(&store, CLI_CLIENT_ID, &minted.refresh, None, None, at(1)).unwrap();
    assert_eq!(rotated.grant, minted.grant);
    assert_eq!(rotated.scopes, wanted);
    assert_eq!(
        authenticated(&store, &rotated.access, at(1)),
        wanted,
        "the rotated access token keeps artifacts:write"
    );
    // A refresh may still narrow it away, which is the one direction the column bound never gated.
    let narrowed = oauth::refresh(
        &store,
        CLI_CLIENT_ID,
        &rotated.refresh,
        Some(Scopes::RUNS_READ),
        None,
        at(2),
    )
    .unwrap();
    assert_eq!(narrowed.scopes, Scopes::RUNS_READ);
}

#[test]
fn a_device_authorization_carries_artifacts_write_from_start_to_access_token() {
    let (_dir, store, i) = fixture();
    let wanted = Scopes::CLI_DEFAULT.union(Scopes::ARTIFACTS_WRITE);
    let start = device::begin(&store, CLI_CLIENT_ID, wanted, Audience::Api, NOW).unwrap();
    let seen = store
        .read(|c| device::view(c, &start.user_code, NOW))
        .unwrap();
    assert_eq!(seen.scopes, wanted);

    device::decide(
        &store,
        &start.user_code,
        i.dev,
        Decision::Approve {
            scopes: wanted,
            tenant: None,
            repo: None,
        },
        at(1),
    )
    .unwrap();
    let Poll::Issued(minted) =
        device::poll(&store, CLI_CLIENT_ID, &start.device, None, at(2)).unwrap()
    else {
        panic!("the approved request is redeemable");
    };
    assert_eq!(minted.scopes, wanted);
    assert_eq!(authenticated(&store, &minted.access, at(2)), wanted);

    let rotated =
        oauth::refresh(&store, CLI_CLIENT_ID, &minted.refresh, None, None, at(3)).unwrap();
    assert_eq!(rotated.scopes, wanted);
}

/// The widened column admits the bit; the client cap still decides who may hold it.
#[test]
fn a_client_capped_one_bit_narrower_is_refused_artifacts_write() {
    let (_dir, store, i) = fixture();
    oauth::register_client(
        &store,
        &ClientSpec {
            id: "narrow-cli",
            name: "Narrow",
            first_party: true,
            loopback: true,
            redirect_path: Some("/callback"),
            device: true,
            max_scopes: Scopes::CLI_DEFAULT,
        },
        &[],
    )
    .unwrap();
    let wider = Scopes::CLI_DEFAULT.union(Scopes::ARTIFACTS_WRITE);
    let (_, challenge) = pair();
    let refused = oauth::code::approve(
        &store,
        &Approval {
            client_id: "narrow-cli",
            ..approval(i.dev, wider, &challenge)
        },
        NOW,
    );
    assert!(
        matches!(refused, Err(sentinel_store::Error::InvalidInput("scope"))),
        "a cap without the bit refuses the code"
    );

    // The same client may hold it once an operator widens the cap, which the column now stores.
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE oauth_clients SET max_scopes = ?1 WHERE client_id = 'narrow-cli'",
                [Scopes::ALL.bits()],
            )?;
            Ok(())
        })
        .unwrap();
    let widened = store.read(|c| oauth::client(c, "narrow-cli")).unwrap();
    assert_eq!(widened.max_scopes, Scopes::ALL);
    assert!(
        oauth::code::approve(
            &store,
            &Approval {
                client_id: "narrow-cli",
                ..approval(i.dev, wider, &challenge)
            },
            NOW,
        )
        .is_ok()
    );
}
