//! X06 registered OAuth clients are bounded public MCP clients, independent
//! from human/service identities and their grants.

use sentinel_auth::oauth::pkce;
use sentinel_core::{
    UnixMillis, UserId,
    auth::{Audience, Scopes},
};
use sentinel_store::{
    Durability, Store,
    auth::{Authority, provisioning},
    oauth::{
        self, ClientRegistration, EVICTABLE_CLIENT_AGE_MS, MAX_MCP_CLIENTS,
        MAX_MCP_CLIENTS_PER_REGISTRANT, McpClientSpec, McpRegistrationError, McpRegistrationKind,
        UNUSED_CLIENT_TTL_MS,
        code::{self, Approval},
    },
};

#[test]
fn dcr_and_cimd_clients_are_mcp_only_refreshable_and_not_users() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();

    let dynamic_id = format!("m_{}", "a".repeat(62));
    let dynamic = McpClientSpec {
        id: &dynamic_id,
        name: "Dynamic client",
        max_scopes: Scopes::RUNS_READ.union(Scopes::LOGS_READ),
        kind: McpRegistrationKind::Dynamic,
        metadata_url: None,
    };
    oauth::register_mcp_client(&store, &dynamic, &["http://127.0.0.1:33418"]).unwrap();
    let dynamic_client = store
        .read(|connection| oauth::client(connection, &dynamic_id))
        .unwrap();
    assert_eq!(dynamic_client.name, "Dynamic client");
    assert_eq!(dynamic_client.resource, sentinel_core::auth::Audience::Mcp);
    assert_eq!(dynamic_client.max_scopes, dynamic.max_scopes);
    assert!(!dynamic_client.first_party && !dynamic_client.device);
    assert!(
        store
            .read(|connection| oauth::redirect_allowed(
                connection,
                &dynamic_client,
                "http://127.0.0.1:33418"
            ))
            .unwrap()
    );
    // RFC 8252 §7.3: a registered loopback redirect matches on any port,
    // never on another host or path.
    for (uri, allowed) in [
        ("http://127.0.0.1:33419", true),
        ("http://127.0.0.1:1/", true),
        ("http://127.0.0.1:33418/other", false),
        ("http://localhost:33418", false),
        ("http://[::1]:33418", false),
    ] {
        assert_eq!(
            store
                .read(|connection| oauth::redirect_allowed(connection, &dynamic_client, uri))
                .unwrap(),
            allowed,
            "{uri}"
        );
    }

    let metadata_url = "https://client.example.org/mcp/metadata.json";
    let metadata_id = format!("c_{}", "b".repeat(62));
    let initial = McpClientSpec {
        id: &metadata_id,
        name: "Metadata client v1",
        max_scopes: Scopes::RUNS_READ,
        kind: McpRegistrationKind::Metadata,
        metadata_url: Some(metadata_url),
    };
    oauth::register_mcp_client(
        &store,
        &initial,
        &["https://client.example.org/callback-v1"],
    )
    .unwrap();
    let refreshed = McpClientSpec {
        name: "Metadata client v2",
        max_scopes: Scopes::MCP,
        ..initial
    };
    oauth::register_mcp_client(
        &store,
        &refreshed,
        &["https://client.example.org/callback-v2"],
    )
    .unwrap();
    let metadata_client = store
        .read(|connection| oauth::client(connection, &metadata_id))
        .unwrap();
    assert_eq!(metadata_client.display_id, metadata_url);
    assert_eq!(metadata_client.name, "Metadata client v2");
    assert_eq!(metadata_client.max_scopes, Scopes::MCP);
    assert!(
        store
            .read(|connection| oauth::redirect_allowed(
                connection,
                &metadata_client,
                "https://client.example.org/callback-v2"
            ))
            .unwrap()
    );
    assert!(
        !store
            .read(|connection| oauth::redirect_allowed(
                connection,
                &metadata_client,
                "https://client.example.org/callback-v1"
            ))
            .unwrap()
    );

    let users: i64 = store
        .read(|connection| {
            Ok(connection.query_row("SELECT count(*) FROM users", [], |row| row.get(0))?)
        })
        .unwrap();
    assert_eq!(users, 0);
    let clients: i64 = store
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT count(*) FROM oauth_clients WHERE registration_kind != 0",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(clients, 2);

    // Operators disable by the CIMD URL, with no SQL.
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            oauth::set_client_disabled(tx, Authority::HostLocal, metadata_url, true, now)
        })
        .unwrap();
    assert!(matches!(
        oauth::register_mcp_client(
            &store,
            &refreshed,
            &["https://client.example.org/callback-v2"]
        ),
        Err(McpRegistrationError::Store(sentinel_store::Error::NotFound))
    ));

    let dynamic_id = dynamic_id.clone();
    assert!(
        store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "UPDATE oauth_clients SET resource = 1 WHERE client_id = ?1",
                    [&dynamic_id],
                )?;
                Ok(())
            })
            .is_err()
    );
}

const T0: UnixMillis = UnixMillis(1_700_000_000_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(T0.0 + ms)
}

fn dynamic_id(n: usize) -> String {
    format!("m_{n:062x}")
}

fn register(
    store: &Store,
    id: &str,
    registrant: Option<[u8; 16]>,
    now: UnixMillis,
) -> Result<(), McpRegistrationError> {
    oauth::register_mcp_client_from(
        store,
        &McpClientSpec {
            id,
            name: "Flood",
            max_scopes: Scopes::RUNS_READ,
            kind: McpRegistrationKind::Dynamic,
            metadata_url: None,
        },
        &["https://client.example.org/callback"],
        registrant,
        now,
    )
}

fn enabled_registrations(store: &Store) -> i64 {
    store
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT count(*) FROM oauth_clients
                 WHERE registration_kind != 0 AND disabled_ms IS NULL",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap()
}

fn exists(store: &Store, id: &str) -> bool {
    store
        .read(|connection| oauth::client(connection, id))
        .is_ok()
}

/// A grant for `client`, obtained through consent and code exchange.
fn grant_for(store: &Store, user: UserId, client: &str, now: UnixMillis) {
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let redirect = "https://client.example.org/callback";
    let secret = code::approve(
        store,
        &Approval {
            client_id: client,
            redirect_uri: redirect,
            code_challenge: &challenge,
            user,
            scopes: Scopes::RUNS_READ,
            tenant: None,
            repo: None,
            audience: Audience::Mcp,
        },
        now,
    )
    .unwrap();
    code::exchange(
        store,
        client,
        &secret,
        redirect,
        &verifier,
        Some(Audience::Mcp),
        now,
    )
    .unwrap();
}

/// P09S-2 / P11-1: a flood fills the enabled-registration cap, but it can
/// neither lock onboarding out for good nor displace a client in use.
/// Maintenance reclaims what never obtained a grant, and no SQL is needed.
#[test]
fn registration_capacity_is_reclaimed_but_granted_clients_survive() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let user = UserId::new();
    store
        .writer()
        .write(move |tx| provisioning::insert_human(tx, user, "Dev", false, T0))
        .unwrap();

    // The first registration is the one that will hold a grant: it is also
    // the oldest, so eviction must skip it on purpose, not by luck.
    let cap = usize::try_from(MAX_MCP_CLIENTS).unwrap();
    for n in 0..cap {
        register(&store, &dynamic_id(n), None, at(n as i64)).unwrap();
    }
    grant_for(&store, user, &dynamic_id(0), at(1_000));
    assert_eq!(enabled_registrations(&store), MAX_MCP_CLIENTS);

    // Full, and nothing is old enough to evict yet: refused, not grown.
    let late = dynamic_id(cap);
    assert!(matches!(
        register(&store, &late, None, at(60_000)),
        Err(McpRegistrationError::Capacity)
    ));
    assert_eq!(enabled_registrations(&store), MAX_MCP_CLIENTS);

    // Once unused rows are old enough, a newcomer displaces the oldest
    // unused one and never the granted one.
    let later = at(EVICTABLE_CLIENT_AGE_MS + cap as i64);
    register(&store, &late, None, later).unwrap();
    assert_eq!(enabled_registrations(&store), MAX_MCP_CLIENTS);
    assert!(
        exists(&store, &dynamic_id(0)),
        "a client with a grant stays"
    );
    assert!(
        !exists(&store, &dynamic_id(1)),
        "the oldest unused one went"
    );
    assert!(exists(&store, &late));

    // Maintenance deletes every registration that never obtained a grant
    // once it is a day old; the granted client and the young one stay.
    let removed =
        oauth::purge_expired(&store, at(UNUSED_CLIENT_TTL_MS + cap as i64), 1_000).unwrap();
    assert!(removed >= cap - 2, "{removed}");
    assert!(exists(&store, &dynamic_id(0)));
    assert!(exists(&store, &late));
    assert_eq!(enabled_registrations(&store), 2);
    let redirects: i64 = store
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT count(*) FROM oauth_client_redirects WHERE client_id LIKE 'm_%'",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(redirects, 2, "redirects go with their client");

    // Disabling revokes the client's grants and frees its capacity; the
    // grant's end then lets maintenance reclaim the row itself.
    let target = dynamic_id(0);
    let revoked = store
        .writer()
        .write(move |tx| oauth::set_client_disabled(tx, Authority::HostLocal, &target, true, T0))
        .unwrap();
    assert_eq!(revoked, 1);
    assert!(!exists(&store, &dynamic_id(0)));
    assert_eq!(enabled_registrations(&store), 1);
    let listed = store
        .read(|connection| oauth::registered_clients(connection, T0))
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .any(|client| client.id == dynamic_id(0) && client.disabled.is_some())
    );
    oauth::purge_expired(&store, at(2 * UNUSED_CLIENT_TTL_MS), 1_000).unwrap();
    let listed = store
        .read(|connection| oauth::registered_clients(connection, T0))
        .unwrap();
    assert_eq!(listed.len(), 0, "{listed:?}");
}

/// One address cannot take more than its share of the deployment's
/// registrations; another address is unaffected.
#[test]
fn registrations_are_bounded_per_registering_address() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let flood = oauth::registrant_digest(1);
    let other = oauth::registrant_digest(2);
    let share = usize::try_from(MAX_MCP_CLIENTS_PER_REGISTRANT).unwrap();
    for n in 0..share {
        register(&store, &dynamic_id(n), Some(flood), T0).unwrap();
    }
    assert!(matches!(
        register(&store, &dynamic_id(share), Some(flood), T0),
        Err(McpRegistrationError::Registrant)
    ));
    register(&store, &dynamic_id(share + 1), Some(other), T0).unwrap();
    // The share is of enabled registrations: reclamation returns it.
    oauth::purge_expired(&store, at(UNUSED_CLIENT_TTL_MS), 1_000).unwrap();
    register(
        &store,
        &dynamic_id(share + 2),
        Some(flood),
        at(UNUSED_CLIENT_TTL_MS),
    )
    .unwrap();
}

#[test]
fn registration_policy_defaults_to_metadata_documents_and_names_are_not_impersonated() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let policy = store.read(oauth::client_registration).unwrap();
    assert_eq!(policy, ClientRegistration::Metadata);
    assert!(policy.metadata() && !policy.dynamic());
    store
        .writer()
        .write(|tx| {
            oauth::set_client_registration(tx, Authority::HostLocal, ClientRegistration::Open, T0)
        })
        .unwrap();
    assert_eq!(
        store.read(oauth::client_registration).unwrap(),
        ClientRegistration::Open
    );

    for name in ["Sentinel CLI", "sentinel cli"] {
        let refused = oauth::register_mcp_client(
            &store,
            &McpClientSpec {
                id: &dynamic_id(7),
                name,
                max_scopes: Scopes::RUNS_READ,
                kind: McpRegistrationKind::Dynamic,
                metadata_url: None,
            },
            &["https://client.example.org/callback"],
        );
        assert!(
            matches!(
                refused,
                Err(McpRegistrationError::Store(
                    sentinel_store::Error::InvalidInput(_)
                ))
            ),
            "{name}"
        );
    }
}
