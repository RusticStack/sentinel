//! X06 registered OAuth clients are bounded public MCP clients, independent
//! from human/service identities and their grants.

use sentinel_core::{UnixMillis, auth::Scopes};
use sentinel_store::{
    Durability, Store,
    oauth::{self, McpClientSpec, McpRegistrationError, McpRegistrationKind},
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
    assert!(
        !store
            .read(|connection| oauth::redirect_allowed(
                connection,
                &dynamic_client,
                "http://127.0.0.1:33419"
            ))
            .unwrap()
    );

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

    let now = UnixMillis::now().0;
    let disabled_id = metadata_id.clone();
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE oauth_clients SET disabled_ms = ?2 WHERE client_id = ?1",
                rusqlite::params![disabled_id, now],
            )?;
            Ok(())
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
