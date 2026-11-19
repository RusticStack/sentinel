//! The storage report a tenant administrator reads: its bytes by class, the trend of daily snapshots, the heaviest
//! artifacts, what expires within 7 days, and the platform's list of tenants against their own thresholds.
//!
//! `GET /tenants/{slug}/storage` is the one figure a quota refusal and a threshold notice are measured against, so
//! these tests check the split against the quota's own totals rather than against each other.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{Fixture, call};
use sentinel_core::UnixMillis;
use sentinel_store::{classes, retention::Deployment};
use serde_json::{Value, json};

fn get(f: &Fixture, path: &str, auth: &str) -> (u16, Value) {
    let (status, _, body) = call(&f.base, "GET", path, None, &[("authorization", auth)]);
    (status, body)
}

fn send(f: &Fixture, method: &str, path: &str, body: Value, auth: &str) -> (u16, Value) {
    let (status, _, body) = call(
        &f.base,
        method,
        path,
        Some(&body),
        &[("authorization", auth)],
    );
    (status, body)
}

const DAY_MS: i64 = 86_400_000;
const CLASSES: [&str; 6] = [
    "artifacts",
    "uploads",
    "logs",
    "remote_cache",
    "actions_cache",
    "worker_cache",
];

/// Yesterday and today's snapshot, so the trend has a start and an end.
fn seed_snapshots(f: &Fixture) {
    let now = UnixMillis::now();
    let today = classes::day_of(now);
    f.store
        .writer()
        .write(move |tx| {
            for day in [today - 1, today] {
                classes::snapshot_day(tx, day, UnixMillis(day * DAY_MS), None, 64)?;
            }
            Ok(())
        })
        .unwrap();
}

/// Stamps two attempts' logs: one due inside the 7-day window, one past it.
fn stamp_logs(f: &Fixture) {
    let now = UnixMillis::now().0;
    let inside = f.attempts["alpha"].0;
    let outside = f.attempts["beta"].0;
    f.store
        .writer()
        .write(move |tx| {
            for (attempt, bytes, days) in [(inside, 4_096i64, 3), (outside, 2_048, 21)] {
                tx.execute(
                    "UPDATE attempts SET log_bytes = ?2, log_expires_ms = ?3 WHERE id = ?1",
                    (attempt.as_bytes().as_slice(), bytes, now + days * DAY_MS),
                )?;
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn the_storage_report_names_each_class_the_trend_the_largest_artifacts_and_what_expires() {
    let f = Fixture::new(1);
    f.seed_artifacts();
    stamp_logs(&f);
    seed_snapshots(&f);

    let (status, body) = get(&f, "/api/v1/tenants/acme/storage", &f.auth);
    assert_eq!(status, 200, "{body}");
    let number = |v: &Value| v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"));

    // Every class is reported, and the three the quota counts add up to the totals the page has always shown.
    let by_class = &body["classes"];
    for class in CLASSES {
        assert!(by_class[class].is_u64(), "{class} missing: {by_class}");
    }
    let artifacts = number(&by_class["artifacts"]);
    assert!(
        artifacts > 1 << 20,
        "the 1 MiB body of the seeded artifact is counted: {by_class}"
    );
    assert_eq!(number(&by_class["uploads"]), 0);
    assert_eq!(number(&by_class["logs"]), 4_096 + 2_048);
    assert_eq!(
        by_class["counted"],
        json!(["artifacts", "uploads", "logs"]),
        "the caches are reported and never part of the quota"
    );
    assert_eq!(
        number(&body["usage"]["object_bytes"]),
        artifacts + number(&by_class["uploads"])
    );
    assert_eq!(body["usage"]["log_bytes"], by_class["logs"]);

    // The trend is one snapshot per day, newest first, carrying the same split.
    let trend = body["trend"].as_array().unwrap();
    assert_eq!(trend.len(), 2, "{trend:?}");
    assert!(trend[0]["day"].as_i64() > trend[1]["day"].as_i64());
    assert_eq!(trend[0]["classes"]["artifacts"], by_class["artifacts"]);
    assert_eq!(
        number(&trend[0]["stored_bytes"]),
        artifacts + number(&by_class["logs"])
    );

    // Heaviest first, each naming the repository it counts for and the class it was stored under.
    let largest = body["largest"].as_array().unwrap();
    assert_eq!(largest[0]["name"], "reports", "{largest:?}");
    assert_eq!(largest[0]["class"], "evidence");
    assert_eq!(largest[0]["repo"], "app");
    assert_eq!(largest[0]["pinned"], false);
    assert!(number(&largest[0]["bytes"]) > 1 << 20);
    assert!(number(&largest[1]["bytes"]) < number(&largest[0]["bytes"]));
    assert!(largest[0]["expires_ms"].is_i64());

    // What expires within 7 days: one of the two stamped logs, both artifacts, and the artifacts listed by deadline.
    let expiring = &body["expiring"];
    assert_eq!(number(&expiring["window_ms"]), 7 * 86_400_000);
    assert_eq!(number(&expiring["logs"]), 1, "{expiring}");
    assert_eq!(number(&expiring["log_bytes"]), 4_096);
    assert_eq!(number(&expiring["artifacts"]), 2);
    assert_eq!(
        number(&expiring["artifact_bytes"]),
        largest.iter().map(|a| number(&a["bytes"])).sum::<u64>()
    );
    let soonest = expiring["soonest"].as_array().unwrap();
    assert_eq!(soonest.len(), 2);
    let named = |rows: &[Value]| {
        let mut out: Vec<String> = rows
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_owned())
            .collect();
        out.sort();
        out
    };
    assert_eq!(named(soonest), named(largest), "the same two artifacts");
    assert!(soonest[0]["expires_ms"].as_i64() <= soonest[1]["expires_ms"].as_i64());

    // An unlimited tenant has no threshold to be measured against and says so.
    assert_eq!(body["thresholds"]["state"], "ok");
    assert_eq!(body["effective"]["tenant_quota_bytes"], 0);
    assert_eq!(body["thresholds"]["soft_limit_bytes"], 0);
}

#[test]
fn the_trend_reads_at_most_what_the_request_asks_for_and_refuses_more() {
    let f = Fixture::new(1);
    f.seed_artifacts();
    seed_snapshots(&f);
    for path in [
        "/api/v1/tenants/acme/storage?days=0",
        "/api/v1/tenants/acme/storage?days=91",
        "/api/v1/tenants/acme/storage?days=soon",
    ] {
        let (status, body) = get(&f, path, &f.auth);
        assert_eq!(status, 400, "{path} {body}");
        assert_eq!(body["code"], "invalid_request", "{path} {body}");
    }
    let (status, body) = get(&f, "/api/v1/tenants/acme/storage?days=1", &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["trend"].as_array().unwrap().len(), 1);
    let (status, body) = get(&f, "/api/v1/tenants/acme/storage", &f.auth);
    assert_eq!(status, 200);
    assert_eq!(body["trend"].as_array().unwrap().len(), 2);
}

/// A tenant over its hard threshold is reported as such, and the platform's list carries the same percentage it is
/// measured by — the two are read from one `retention::standing`, so they cannot disagree.
#[test]
fn a_tenant_over_its_hard_threshold_is_reported_beside_the_platform_list_of_tenants() {
    let f = Fixture::new(1);
    let (objects, acme) = (Arc::clone(&f.objects), f.acme);
    f.objects.set_deployment(Deployment {
        tenant_quota_bytes: 1_000_000,
        ..Deployment::default()
    });
    // 800 000 bytes held by an open upload session: 80 % of the quota, once the thresholds are narrowed to 50 and 80.
    f.store
        .writer()
        .write(move |tx| {
            objects
                .begin_upload(tx, acme, 800_000, None, 60_000, UnixMillis::now())
                .map(|_| ())
        })
        .unwrap();
    let (status, body) = send(
        &f,
        "PUT",
        "/api/v1/admin/tenants/acme/storage",
        json!({ "soft_percent": 50, "hard_percent": 80 }),
        &f.auth,
    );
    assert_eq!(status, 200, "{body}");

    let (status, body) = get(&f, "/api/v1/tenants/acme/storage", &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["thresholds"]["state"], "hard");
    assert_eq!(body["thresholds"]["soft_limit_bytes"], 500_000);
    assert_eq!(body["thresholds"]["hard_limit_bytes"], 800_000);
    assert_eq!(body["classes"]["uploads"], 800_000);
    assert_eq!(body["classes"]["artifacts"], 0);
    assert_eq!(body["usage"]["object_bytes"], 800_000);

    let (status, body) = get(&f, "/api/v1/admin/tenants?limit=50", &f.auth);
    assert_eq!(status, 200, "{body}");
    let rows = body["tenants"].as_array().unwrap();
    let row = |slug: &str| {
        rows.iter()
            .find(|t| t["slug"] == slug)
            .unwrap_or_else(|| panic!("{slug} missing: {body}"))
            .clone()
    };
    let acme_row = row("acme");
    assert_eq!(acme_row["used_percent"], 80);
    assert_eq!(acme_row["state"], "hard");
    assert_eq!(acme_row["soft_limit_bytes"], 500_000);
    assert_eq!(acme_row["hard_limit_bytes"], 800_000);
    assert_eq!(acme_row["usage_bytes"], 800_000);
    // A tenant with nothing stored is at zero, in the same list.
    let beta_row = row("beta");
    assert_eq!(beta_row["used_percent"], 0);
    assert_eq!(beta_row["state"], "ok");
}

/// Another tenant's storage is its own: none of one tenant's artifacts, logs, trend or expiring bytes are visible
/// from another, whichever administrator asks.
#[test]
fn another_tenants_storage_reports_none_of_it() {
    let f = Fixture::new(1);
    f.seed_artifacts();
    stamp_logs(&f);
    seed_snapshots(&f);

    let (status, body) = get(&f, "/api/v1/tenants/beta/storage", &f.auth);
    assert_eq!(status, 200, "{body}");
    for class in CLASSES {
        assert_eq!(body["classes"][class], 0, "{class} leaked: {body}");
    }
    assert_eq!(body["usage"]["object_bytes"], 0);
    assert_eq!(body["usage"]["log_bytes"], 0);
    assert!(body["largest"].as_array().unwrap().is_empty(), "{body}");
    assert!(body["expiring"]["soonest"].as_array().unwrap().is_empty());
    assert_eq!(body["expiring"]["artifacts"], 0);
    assert_eq!(body["expiring"]["logs"], 0);
    assert!(body["trend"].as_array().unwrap().is_empty());

    // The account that administers both still sees each on its own: acme's figures name its artifacts and beta's name
    // none of them, so the report is read from the tenant asked for and not from the caller.
    let (_, acme) = get(&f, "/api/v1/tenants/acme/storage", &f.auth);
    assert_eq!(acme["largest"][0]["name"], "reports");
    assert!(!body.to_string().contains("reports"), "{body}");

    // An operator is not a tenant administrator and reads neither report.
    let dana = f.member(f.dana);
    assert_ne!(get(&f, "/api/v1/tenants/beta/storage", &dana).0, 200);
    assert_ne!(get(&f, "/api/v1/tenants/acme/storage", &dana).0, 200);
}
