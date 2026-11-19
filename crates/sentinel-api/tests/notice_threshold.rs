#[path = "support/web_fixture.rs"]
mod fixture;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use fixture::call;
use sentinel_core::{
    TenantId, UnixMillis,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind},
    local_auth,
    logs::LogStore,
    objects::{Expect, Objects},
    retention::Deployment,
    space,
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const QUOTA: u64 = 1_000;

struct Api {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    tenant: TenantId,
}

impl Api {
    fn serve(&mut self) {
        let server = sentinel_api::Server::start_with(
            sentinel_api::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                store: Arc::clone(&self.store),
                logs: Arc::clone(&self.logs),
                objects: Arc::clone(&self.objects),
                controller: self.controller.handle(),
                secret_key: None,
                sessions: local_auth::Policy::default(),
                github_webhook_secret: None,
                intake: None,
                public_url: None,
                github_sign_in: None,
                trusted_proxies: sentinel_api::TrustedProxy::loopback(),
            },
            sentinel_api::Options {
                notices_every: Some(Duration::from_millis(25)),
                ..sentinel_api::Options::default()
            },
        )
        .unwrap();
        self.base = format!("http://{}", server.local_addr());
        self.server = Some(server);
    }

    /// The process goes away and comes back on the same database and store.
    fn restart(&mut self) {
        self.server.take().unwrap().shutdown();
        self.serve();
    }

    fn count(&self, sql: &str) -> i64 {
        self.store
            .read(|c| Ok(c.query_row(sql, [], |r| r.get(0))?))
            .unwrap()
    }

    fn grow(&self, bytes: u64) {
        let content: Vec<u8> = (0..bytes)
            .map(|i| (i.wrapping_mul(7) % 251) as u8)
            .collect();
        let staged = self
            .objects
            .stage(self.tenant, content.as_slice(), u64::MAX, Expect::default())
            .unwrap();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
    }
}

fn start() -> (Api, Vec<(String, String)>) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    objects.set_deployment(Deployment {
        tenant_quota_bytes: QUOTA,
        ..Deployment::default()
    });
    objects.set_admission(Arc::new(
        space::Admission::with_probe(
            space::Watermarks {
                reserve: 1 << 30,
                low: 2 << 30,
                high: 4 << 30,
                floor: 1 << 27,
            },
            || Ok(1 << 50),
        )
        .unwrap(),
    ));
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        PASSWORD.as_bytes(),
        UnixMillis::now(),
    )
    .unwrap();
    let platform = Principal::new(root, P::ALL, None, None);
    let tenant = TenantId::new();
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                platform,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis::now(),
            )?;
            auth::set_membership(tx, platform, tenant, root, Role::TenantAdmin)
        })
        .unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut api = Api {
        _dir: dir,
        store,
        objects,
        logs,
        controller,
        server: None,
        base: String::new(),
        tenant,
    };
    api.serve();
    let (status, headers, body) = call(
        &api.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": "root", "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let cookie = headers
        .iter()
        .find(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.split(';').next().unwrap().to_owned())
        .expect("the sign-in sets a session cookie");
    (api, vec![("cookie".to_owned(), cookie)])
}

fn storage(api: &Api, session: &[(String, String)]) -> Value {
    let headers: Vec<(&str, &str)> = session
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let (status, _, body) = call(
        &api.base,
        "GET",
        "/api/v1/tenants/acme/storage",
        None,
        &headers,
    );
    assert_eq!(status, 200, "{body}");
    body
}

#[test]
fn a_crossing_is_told_once_on_the_storage_page_and_a_restart_tells_nobody_again() {
    let (mut api, session) = start();
    api.grow(820);
    // The crossing is found by the controller's own pass, not by the request.
    let deadline = Instant::now() + Duration::from_secs(20);
    let notice = loop {
        let body = storage(&api, &session);
        if let Some(notice) = body["notice"].as_object() {
            break notice.clone();
        }
        assert!(
            Instant::now() < deadline,
            "the crossing was never told: {body}"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        (
            notice["threshold_percent"].as_u64(),
            notice["used_bytes"].as_u64(),
            notice["limit_bytes"].as_u64(),
            notice["delivery"].as_str(),
        ),
        (Some(80), Some(820), Some(QUOTA), Some("in_app"))
    );
    assert!(notice["notified_ms"].as_i64().unwrap() > 0);
    let body = storage(&api, &session);
    assert_eq!(body["thresholds"]["state"].as_str(), Some("soft"));

    // Nothing is mailed: this deployment has no delivery configured.
    assert_eq!(api.count("SELECT COUNT(*) FROM mail_outbox"), 0);
    assert_eq!(
        api.count("SELECT COUNT(*) FROM auth_audit WHERE event = 99"),
        1
    );

    api.restart();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(api.count("SELECT COUNT(*) FROM storage_notices"), 1);
    assert_eq!(
        api.count("SELECT COUNT(*) FROM auth_audit WHERE event = 99"),
        1,
        "a restart tells nobody again"
    );
    let after = storage(&api, &session);
    assert_eq!(after["notice"], Value::Object(notice));
}
