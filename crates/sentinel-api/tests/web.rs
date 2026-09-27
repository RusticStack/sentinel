//! The routes behind the web interface (U02–U05) and how the interface
//! itself is served (U01), over real HTTP against a seeded controller.

#[path = "support/web_fixture.rs"]
mod fixture;

use fixture::{Fixture, PASSWORD, call};
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

fn ids(body: &Value) -> Vec<String> {
    body["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect()
}

/// A browser session for `username`: (cookie header, CSRF secret).
fn session(f: &Fixture, username: &str) -> (String, String) {
    let (status, headers, body) = call(
        &f.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let cookie = headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .unwrap();
    (cookie, body["csrf"].as_str().unwrap().to_owned())
}

fn with_session(
    f: &Fixture,
    method: &str,
    path: &str,
    body: Option<Value>,
    session: &(String, String),
) -> (u16, Value) {
    let (status, _, body) = call(
        &f.base,
        method,
        path,
        body.as_ref(),
        &[("cookie", &session.0), ("x-sentinel-csrf", &session.1)],
    );
    (status, body)
}

/// The sign-in page shows GitHub sign-in only when it is configured; the
/// health route says so without a credential.
#[test]
fn health_says_whether_github_sign_in_is_offered() {
    let f = Fixture::new(1);
    let (status, _, body) = call(&f.base, "GET", "/api/v1/health", None, &[]);
    assert_eq!(
        (status, body),
        (200, json!({ "ok": true, "github_sign_in": false }))
    );
}

#[test]
fn run_lists_filter_by_ref_pull_request_and_commit_prefix() {
    let f = Fixture::new(1);
    let runs = "/api/v1/tenants/acme/repos/app/runs";
    let (status, all) = get(&f, runs, &f.auth);
    assert_eq!(status, 200);
    assert_eq!(all["runs"].as_array().unwrap().len(), 4);
    let pr = all["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == f.pr_run.to_string())
        .unwrap();
    assert_eq!(
        (
            pr["trigger"].as_str(),
            pr["ref"].as_str(),
            pr["pr"].as_u64()
        ),
        (Some("pull_request"), Some("refs/heads/main"), Some(42))
    );

    // A bare branch means the branch; a full ref is taken as given.
    let (_, main) = get(&f, &format!("{runs}?ref=main"), &f.auth);
    let main = ids(&main);
    assert_eq!(main.len(), 3);
    assert!(!main.contains(&f.push_run.to_string()));
    let (_, feature) = get(&f, &format!("{runs}?ref=refs%2Fheads%2Ffeature-x"), &f.auth);
    assert_eq!(ids(&feature), vec![f.push_run.to_string()]);
    let (_, by_pr) = get(&f, &format!("{runs}?pr=42"), &f.auth);
    assert_eq!(ids(&by_pr), vec![f.pr_run.to_string()]);
    let (_, by_sha) = get(&f, &format!("{runs}?sha=3333333"), &f.auth);
    assert_eq!(ids(&by_sha), vec![f.pr_run.to_string()]);
    let (_, none) = get(&f, &format!("{runs}?sha=abcdef0"), &f.auth);
    assert!(ids(&none).is_empty());

    // A filtered page keeps the keyset contract: one run a page, no repeats.
    let mut seen = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let path = match &next {
            Some(before) => format!("{runs}?ref=main&limit=1&before={before}"),
            None => format!("{runs}?ref=main&limit=1"),
        };
        let (status, page) = get(&f, &path, &f.auth);
        assert_eq!(status, 200, "{page}");
        seen.extend(ids(&page));
        next = page["next"].as_str().map(str::to_owned);
        if next.is_none() {
            break;
        }
    }
    assert_eq!(seen, main);

    for bad in [
        "sha=333",
        "sha=zzzzzzz",
        "pr=0",
        "ref=main&pr=42",
        "pr=1&pr=2",
    ] {
        let (status, body) = get(&f, &format!("{runs}?{bad}"), &f.auth);
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{bad}"
        );
    }
    // A member of another tenant only sees nothing, filter or not.
    let (status, _) = get(
        &f,
        "/api/v1/tenants/beta/repos/site/runs?pr=42",
        &f.member(f.dana),
    );
    assert_eq!(status, 404);
}

#[test]
fn a_caller_lists_its_own_tenants_and_a_narrowed_credential_only_its_one() {
    let f = Fixture::new(1);
    let (status, body) = get(&f, "/api/v1/tenants", &f.auth);
    assert_eq!(status, 200);
    assert_eq!(
        body["tenants"],
        json!([{ "slug": "acme", "role": "admin" }, { "slug": "beta", "role": "admin" }])
    );
    assert_eq!(body["super_admin"], true);
    let dana = f.member(f.dana);
    let (_, body) = get(&f, "/api/v1/tenants", &dana);
    assert_eq!(
        body["tenants"],
        json!([{ "slug": "acme", "role": "operator" }])
    );
    // `/me` says whether a session is stepped up and whether TOTP exists.
    let (_, me) = get(&f, "/api/v1/me", &dana);
    assert_eq!(
        (me["stepped_up"].as_bool(), me["mfa"].as_bool()),
        (Some(false), Some(false))
    );
}

#[test]
fn attempt_steps_report_measured_phases_and_leave_the_unmeasured_out() {
    let f = Fixture::new(1);
    let (beta, _) = f.attempts["beta"];
    let (status, body) = get(&f, &format!("/api/v1/attempts/{beta}/steps"), &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["present"], true);
    let steps = body["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(
        (
            steps[1]["id"].as_str(),
            steps[1]["outcome"].as_str(),
            steps[1]["exit_code"].as_i64()
        ),
        (Some("unit"), Some("failed"), Some(1))
    );
    assert_eq!(steps[1]["duration_ns"], 4_000_000_000_u64);
    assert!(steps[0].get("exit_code").is_none());
    let timings = body["timings_ns"].as_object().unwrap();
    assert!(timings.contains_key("checkout") && timings.contains_key("steps"));
    assert!(
        !timings.contains_key("image_pull"),
        "never measured, never zero"
    );
    // A running attempt has not reported yet.
    let (status, body) = get(&f, &format!("/api/v1/attempts/{}/steps", f.live.2), &f.auth);
    assert_eq!((status, body["present"].as_bool()), (200, Some(false)));
    // A step-filtered log page says when the step is over.
    let (_, page) = get(&f, &format!("/api/v1/attempts/{beta}/logs?step=0"), &f.auth);
    assert_eq!(page["step_done"], true);
    let (_, page) = get(
        &f,
        &format!("/api/v1/attempts/{}/logs?step=0", f.live.2),
        &f.auth,
    );
    assert_eq!(page["step_done"], false);
}

#[test]
fn workers_report_capacity_reservations_labels_and_drain() {
    let f = Fixture::new(1);
    let (status, body) = get(&f, "/api/v1/workers?tenant=acme", &f.auth);
    assert_eq!(status, 200, "{body}");
    let worker = &body["pools"][0]["workers"][0];
    assert_eq!(worker["name"], "builder-1");
    assert_eq!(
        worker["capacity"],
        json!({ "cpu_millis": 8000, "memory_bytes": 16_u64 << 30, "disk_bytes": 100_u64 << 30 })
    );
    // Only the running job still holds its reservation.
    assert_eq!(worker["held_attempts"], 1);
    let held_cpu = worker["held"]["cpu_millis"].as_i64().unwrap();
    assert_eq!(
        worker["free"]["cpu_millis"].as_i64().unwrap(),
        8000 - held_cpu
    );
    assert_eq!(worker["labels"], json!(["linux", "ssd"]));
    assert_eq!(worker["cache_bytes"], 5_u64 << 30);
    assert_eq!(worker["host_workers"], 1);
    assert_eq!(worker["draining"], false);
    assert!(worker.get("draining_since_ms").is_none());

    let id = worker["id"].as_str().unwrap().to_owned();
    let (status, _) = send(
        &f,
        "POST",
        &format!("/api/v1/workers/{id}/drain"),
        json!({}),
        &f.auth,
    );
    assert_eq!(status, 200);
    let (_, body) = get(&f, "/api/v1/workers?tenant=acme", &f.auth);
    let worker = &body["pools"][0]["workers"][0];
    assert_eq!(worker["draining"], true);
    assert!(worker["draining_since_ms"].as_i64().is_some());
    // An operator may look but not drain.
    let dana = f.member(f.dana);
    let (status, _) = get(&f, "/api/v1/workers?tenant=acme", &dana);
    assert_eq!(status, 200);
    let (status, _) = send(
        &f,
        "POST",
        &format!("/api/v1/workers/{id}/undrain"),
        json!({}),
        &dana,
    );
    assert_eq!(status, 403);
}

#[test]
fn sync_reports_pending_check_lag_per_repository() {
    let f = Fixture::new(1);
    let (status, body) = get(&f, "/api/v1/tenants/acme/sync", &f.auth);
    assert_eq!(status, 200, "{body}");
    let repos = body["repos"].as_array().unwrap();
    let app = repos.iter().find(|r| r["name"] == "app").unwrap();
    assert_eq!(app["pending"], 1);
    let lag = body["now_ms"].as_i64().unwrap() - app["oldest_pending_ms"].as_i64().unwrap();
    assert!(lag >= 120_000, "{lag}");
    let web = repos.iter().find(|r| r["name"] == "web").unwrap();
    assert_eq!(
        (web["pending"].as_u64(), web["oldest_pending_ms"].as_i64()),
        (Some(0), None)
    );
    // Not a member: the same answer as no such tenant.
    let stranger = f.member(f.dana);
    let (status, _) = get(&f, "/api/v1/tenants/beta/sync", &stranger);
    assert_eq!(status, 404);
}

#[test]
fn tenant_members_are_administered_and_the_last_admin_keeps_the_role() {
    let f = Fixture::new(1);
    let members = "/api/v1/tenants/acme/members";
    let (status, body) = get(&f, members, &f.auth);
    assert_eq!(status, 200, "{body}");
    let listed: Vec<(String, String)> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["username"].as_str().unwrap().to_owned(),
                m["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(listed.len(), 3);
    assert!(listed.contains(&("root".into(), "admin".into())));
    assert!(listed.contains(&("dana".into(), "operator".into())));
    // An operator is not an administrator.
    let dana = f.member(f.dana);
    let (status, _) = get(&f, members, &dana);
    assert_eq!(status, 403);
    let (status, _) = send(
        &f,
        "PUT",
        &format!("{members}/rui"),
        json!({ "role": "admin" }),
        &dana,
    );
    assert_eq!(status, 403);

    // By sign-in name or id; an unknown one is not found.
    let (status, body) = send(
        &f,
        "PUT",
        &format!("{members}/rui"),
        json!({ "role": "operator" }),
        &f.auth,
    );
    assert_eq!((status, body["role"].as_str()), (200, Some("operator")));
    let (status, _) = send(
        &f,
        "PUT",
        &format!("{members}/nobody"),
        json!({ "role": "reader" }),
        &f.auth,
    );
    assert_eq!(status, 404);
    let (status, _) = send(
        &f,
        "PUT",
        &format!("{members}/rui"),
        json!({ "role": "owner" }),
        &f.auth,
    );
    assert_eq!(status, 400);

    // The last administrator cannot be demoted or removed…
    let root = f.root.to_string();
    let (status, body) = send(
        &f,
        "PUT",
        &format!("{members}/{root}"),
        json!({ "role": "reader" }),
        &f.auth,
    );
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    let (status, _) = send(
        &f,
        "DELETE",
        &format!("{members}/{root}"),
        json!({}),
        &f.auth,
    );
    assert_eq!(status, 409);
    // …until another administrator exists.
    let (status, _) = send(
        &f,
        "PUT",
        &format!("{members}/dana"),
        json!({ "role": "admin" }),
        &f.auth,
    );
    assert_eq!(status, 200);
    let (status, _) = send(
        &f,
        "PUT",
        &format!("{members}/{root}"),
        json!({ "role": "operator" }),
        &f.auth,
    );
    assert_eq!(
        status, 200,
        "a super admin still administers the tenant it no longer admins"
    );
    // Removal takes effect on the member's next request.
    let rui = f.member(f.rui);
    assert_eq!(get(&f, "/api/v1/tenants/acme/repos", &rui).0, 200);
    let (status, _) = send(&f, "DELETE", &format!("{members}/rui"), json!({}), &f.auth);
    assert_eq!(status, 200);
    assert_eq!(get(&f, "/api/v1/tenants/acme/repos", &rui).0, 404);
}

#[test]
fn platform_administration_needs_the_platform_and_privileged_changes_a_step_up() {
    let f = Fixture::new(1);
    let dana = f.member(f.dana);
    for path in [
        "/api/v1/admin/tenants",
        "/api/v1/admin/registrations",
        "/api/v1/admin/pools",
        "/api/v1/admin/audit",
        "/api/v1/admin/policy",
    ] {
        assert_eq!(get(&f, path, &dana).0, 403, "{path}");
    }
    let (status, body) = get(&f, "/api/v1/admin/tenants", &f.auth);
    assert_eq!(status, 200, "{body}");
    let slugs: Vec<&str> = body["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, ["acme", "beta"]);
    assert_eq!(body["tenants"][0]["members"], 3);

    let (status, body) = send(
        &f,
        "PUT",
        "/api/v1/admin/tenants/beta/quota",
        json!({ "bytes": 1_u64 << 30 }),
        &f.auth,
    );
    assert_eq!(
        (
            status,
            body["quota_bytes"].as_u64(),
            body["quota_set"].as_bool()
        ),
        (200, Some(1 << 30), Some(true))
    );
    let (status, body) = send(
        &f,
        "DELETE",
        "/api/v1/admin/tenants/beta/quota",
        json!({}),
        &f.auth,
    );
    assert_eq!((status, body["quota_set"].as_bool()), (200, Some(false)));

    // A bearer can never step up, so suspension is refused with the reason.
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/admin/tenants/beta/suspend",
        json!({}),
        &f.auth,
    );
    assert_eq!(
        (status, body["details"]["step_up"].as_bool()),
        (403, Some(true)),
        "{body}"
    );
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/step-up",
        json!({ "method": "password", "code": PASSWORD }),
        &f.auth,
    );
    assert_eq!(status, 400, "{body}");

    // A session steps up with its password (no TOTP enrolled), then may.
    let root = session(&f, "root");
    let (status, body) = with_session(
        &f,
        "POST",
        "/api/v1/admin/tenants/beta/suspend",
        Some(json!({})),
        &root,
    );
    assert_eq!(
        (status, body["details"]["step_up"].as_bool()),
        (403, Some(true))
    );
    let (status, _) = with_session(
        &f,
        "POST",
        "/api/v1/step-up",
        Some(json!({ "method": "password", "code": "wrong" })),
        &root,
    );
    assert_eq!(status, 403);
    let (status, body) = with_session(
        &f,
        "POST",
        "/api/v1/step-up",
        Some(json!({ "method": "password", "code": PASSWORD })),
        &root,
    );
    assert_eq!(status, 200, "{body}");
    let (_, me) = with_session(&f, "GET", "/api/v1/me", None, &root);
    assert_eq!(me["stepped_up"], true);
    let (status, body) = with_session(
        &f,
        "POST",
        "/api/v1/admin/tenants/beta/suspend",
        Some(json!({})),
        &root,
    );
    assert_eq!(
        (status, body["active"].as_bool()),
        (200, Some(false)),
        "{body}"
    );
    let (_, body) = get(&f, "/api/v1/admin/tenants", &f.auth);
    assert_eq!(body["tenants"][1]["active"], false);
    let (status, _) = with_session(
        &f,
        "POST",
        "/api/v1/admin/tenants/beta/reactivate",
        Some(json!({})),
        &root,
    );
    assert_eq!(status, 200);

    // Policy: readable by the platform, changed only when stepped up.
    let (status, policy) = get(&f, "/api/v1/admin/policy", &f.auth);
    assert_eq!(
        (status, policy["registration"].as_str()),
        (200, Some("approval_required"))
    );
    let closed = json!({ "registration": "closed", "tenant_creation": "super_admin_only", "installation_binding": "super_admin_only" });
    assert_eq!(
        send(&f, "PUT", "/api/v1/admin/policy", closed.clone(), &f.auth).0,
        403
    );
    let (status, body) = with_session(&f, "PUT", "/api/v1/admin/policy", Some(closed), &root);
    assert_eq!(
        (status, body["registration"].as_str()),
        (200, Some("closed"))
    );

    // Registrations: the applicant waits until approved.
    let (_, body) = get(&f, "/api/v1/admin/registrations", &f.auth);
    assert_eq!(body["pending"][0]["user"], f.pat.to_string());
    let (status, _) = send(
        &f,
        "POST",
        &format!("/api/v1/admin/registrations/{}/approve", f.pat),
        json!({}),
        &f.auth,
    );
    assert_eq!(status, 200);
    let (_, body) = get(&f, "/api/v1/admin/registrations", &f.auth);
    assert!(body["pending"].as_array().unwrap().is_empty());

    // Tenants and pools.
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/admin/tenants",
        json!({ "slug": "gamma" }),
        &f.auth,
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/admin/tenants",
            json!({ "slug": "gamma" }),
            &f.auth
        )
        .0,
        409
    );
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/admin/tenants",
            json!({ "slug": "Bad Slug" }),
            &f.auth
        )
        .0,
        400
    );
    let (status, pool) = send(
        &f,
        "POST",
        "/api/v1/admin/pools",
        json!({ "name": "shared-arm", "kind": "shared" }),
        &f.auth,
    );
    assert_eq!(status, 201, "{pool}");
    let pool = pool["id"].as_str().unwrap();
    assert_eq!(
        send(
            &f,
            "PUT",
            &format!("/api/v1/admin/pools/{pool}/grants/beta"),
            json!({}),
            &f.auth
        )
        .0,
        200
    );
    let (_, pools) = get(&f, "/api/v1/admin/pools", &f.auth);
    let listed = pools["pools"].as_array().unwrap();
    let builders = listed.iter().find(|p| p["name"] == "builders").unwrap();
    assert_eq!(
        (builders["owner"].as_str(), builders["workers"].as_u64()),
        (Some("acme"), Some(1))
    );
    let shared = listed.iter().find(|p| p["name"] == "shared-arm").unwrap();
    assert_eq!(shared["grants"], json!(["beta"]));
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/admin/pools",
            json!({ "name": "x", "kind": "dedicated" }),
            &f.auth
        )
        .0,
        400
    );

    // The audit trail pages back through what just happened.
    let (_, first) = get(&f, "/api/v1/admin/audit?limit=3", &f.auth);
    let events = first["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["event"], "pool-granted");
    let before = first["next"].as_i64().unwrap();
    let (_, older) = get(
        &f,
        &format!("/api/v1/admin/audit?limit=100&before={before}"),
        &f.auth,
    );
    let names: Vec<&str> = older["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"tenant-suspended")
            && names.contains(&"stepped-up")
            && names.contains(&"account-approved"),
        "{names:?}"
    );
    assert!(
        older["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["seq"].as_i64().unwrap() < before)
    );
}

#[test]
fn repositories_are_created_and_described_without_any_credential() {
    let f = Fixture::new(1);
    let (status, body) = send(
        &f,
        "POST",
        "/api/v1/tenants/acme/repos",
        json!({ "name": "api" }),
        &f.auth,
    );
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/tenants/acme/repos",
            json!({ "name": "api" }),
            &f.auth
        )
        .0,
        409
    );
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/tenants/acme/repos",
            json!({ "name": "../x" }),
            &f.auth
        )
        .0,
        400
    );
    let dana = f.member(f.dana);
    assert_eq!(
        send(
            &f,
            "POST",
            "/api/v1/tenants/acme/repos",
            json!({ "name": "other" }),
            &dana
        )
        .0,
        403
    );
    let (_, repos) = get(&f, "/api/v1/tenants/acme/repos", &f.auth);
    assert!(
        repos["repos"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "api")
    );
    // Without a grant on the repository an operator cannot see it at all.
    let source = "/api/v1/tenants/acme/repos/app/source";
    assert_eq!(get(&f, source, &dana).0, 404);
    assert_eq!(
        send(
            &f,
            "PUT",
            "/api/v1/tenants/acme/repos/app/grants/dana",
            json!({ "access": ["read", "run"] }),
            &f.auth
        )
        .0,
        200
    );
    let (status, body) = get(&f, source, &dana);
    assert_eq!((status, body), (200, json!({ "bound": false })));
    // Grants: read and run for a member, withdrawn with an empty list.
    let (status, body) = send(
        &f,
        "PUT",
        "/api/v1/tenants/acme/repos/api/grants/rui",
        json!({ "access": ["read"] }),
        &f.auth,
    );
    assert_eq!((status, body["access"].clone()), (200, json!(["read"])));
    assert_eq!(
        send(
            &f,
            "PUT",
            "/api/v1/tenants/acme/repos/api/grants/rui",
            json!({ "access": ["root"] }),
            &f.auth
        )
        .0,
        400
    );
    assert_eq!(
        send(
            &f,
            "PUT",
            "/api/v1/tenants/acme/repos/api/grants/rui",
            json!({ "access": [] }),
            &f.auth
        )
        .0,
        200
    );
}

#[test]
fn tenant_audit_pages_run_control_actions() {
    let f = Fixture::new(1);
    let (status, _) = send(
        &f,
        "POST",
        &format!("/api/v1/runs/{}/cancel", f.stuck_run),
        json!({}),
        &f.auth,
    );
    assert_eq!(status, 200);
    let (status, _) = send(
        &f,
        "POST",
        &format!("/api/v1/jobs/{}/rerun", f.jobs["beta"]),
        json!({}),
        &f.auth,
    );
    assert_eq!(status, 200);
    let (status, body) = get(&f, "/api/v1/tenants/acme/audit?limit=1", &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events"][0]["action"], "rerun_job");
    assert_eq!(body["events"][0]["target"], f.jobs["beta"].to_string());
    assert_eq!(body["events"][0]["via"], "credential");
    let before = body["next"].as_i64().unwrap();
    let (_, older) = get(
        &f,
        &format!("/api/v1/tenants/acme/audit?before={before}"),
        &f.auth,
    );
    assert_eq!(older["events"][0]["action"], "cancel_run");
    assert_eq!(older["events"][0]["target"], f.stuck_run.to_string());
    let dana = f.member(f.dana);
    assert_eq!(get(&f, "/api/v1/tenants/acme/audit", &dana).0, 403);
}

/// A page left open keeps a run wait or a log poll parked; removing the
/// person from the tenant ends both at once with the same `not_found` a
/// fresh request gets, not when their 25 s run out.
#[test]
fn a_parked_poll_ends_as_soon_as_its_reader_loses_the_tenant() {
    let f = Fixture::new(1);
    let grant = send(
        &f,
        "PUT",
        "/api/v1/tenants/acme/repos/app/grants/dana",
        json!({ "access": ["read"] }),
        &f.auth,
    );
    assert_eq!(grant.0, 200);
    let dana = f.member(f.dana);
    let (_, now) = get(&f, &format!("/api/v1/runs/{}/wait", f.diamond), &dana);
    let version = now["version"].as_str().unwrap().to_owned();
    let (_, page) = get(&f, &format!("/api/v1/attempts/{}/logs", f.live.2), &dana);
    let after = page["next_after"]
        .as_u64()
        .or_else(|| {
            page["frames"]
                .as_array()
                .unwrap()
                .last()
                .and_then(|fr| fr["seq"].as_u64())
        })
        .unwrap();
    let park = |path: String| {
        let (base, dana) = (f.base.clone(), dana.clone());
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let (status, _, body) = call(&base, "GET", &path, None, &[("authorization", &dana)]);
            (status, body, started.elapsed())
        })
    };
    let run_wait = park(format!(
        "/api/v1/runs/{}/wait?since={version}&timeout_ms=20000",
        f.diamond
    ));
    let log_wait = park(format!(
        "/api/v1/attempts/{}/logs?after={after}&wait=1",
        f.live.2
    ));
    std::thread::sleep(std::time::Duration::from_millis(600));
    let removed = send(
        &f,
        "DELETE",
        "/api/v1/tenants/acme/members/dana",
        json!({}),
        &f.auth,
    );
    assert_eq!(removed.0, 200);
    for handle in [run_wait, log_wait] {
        let (status, body, elapsed) = handle.join().unwrap();
        assert_eq!(
            (status, body["code"].as_str()),
            (404, Some("not_found")),
            "{body}"
        );
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }
}

/// A parked poll whose client hung up gives its subscriber slot back at
/// once: a person clicking from one run page to the next (each page's web
/// server stream aborting its upstream wait) never runs out of their share.
#[test]
fn a_parked_poll_whose_client_left_frees_its_slot() {
    use std::io::Write;
    let f = Fixture::new(1);
    let (_, now) = get(&f, &format!("/api/v1/runs/{}/wait", f.diamond), &f.auth);
    let version = now["version"].as_str().unwrap().to_owned();
    let addr = f.base.trim_start_matches("http://").to_owned();
    let wait = format!(
        "/api/v1/runs/{}/wait?since={version}&timeout_ms=20000",
        f.diamond
    );
    // Parked waits hold this user's whole share…
    let mut parked = Vec::new();
    for _ in 0..sentinel_api::SUBSCRIBERS_PER_USER {
        let mut s = std::net::TcpStream::connect(&addr).unwrap();
        write!(
            s,
            "GET {wait} HTTP/1.1\r\nhost: x\r\nauthorization: {}\r\n\r\n",
            f.auth
        )
        .unwrap();
        parked.push(s);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let quick = format!(
        "/api/v1/runs/{}/wait?since={version}&timeout_ms=100",
        f.diamond
    );
    let (status, _) = get(&f, &quick, &f.auth);
    assert_eq!(status, 429, "the share is held");
    // …until their clients leave.
    drop(parked);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let (status, body) = get(
            &f,
            &format!(
                "/api/v1/runs/{}/wait?since={version}&timeout_ms=50",
                f.diamond
            ),
            &f.auth,
        );
        if status == 200 {
            assert_eq!(body["changed"], false);
            break;
        }
        assert_eq!(status, 429);
        assert!(
            std::time::Instant::now() < deadline,
            "the slots were not given back"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Parked polls hold no handler permit: with three people's whole shares
/// parked — three times the handler permits — sign-ins, reads and writes
/// are still answered at once. Waiting is not work.
#[test]
fn parked_polls_leave_every_handler_for_work() {
    use std::io::Write;
    let f = Fixture::new(1);
    for who in ["dana", "rui"] {
        let path = format!("/api/v1/tenants/acme/repos/app/grants/{who}");
        assert_eq!(
            send(&f, "PUT", &path, json!({ "access": ["read"] }), &f.auth).0,
            200
        );
    }
    let (_, now) = get(&f, &format!("/api/v1/runs/{}/wait", f.diamond), &f.auth);
    let version = now["version"].as_str().unwrap().to_owned();
    let addr = f.base.trim_start_matches("http://").to_owned();
    let people = [f.auth.clone(), f.member(f.dana), f.member(f.rui)];
    assert!(people.len() * sentinel_api::SUBSCRIBERS_PER_USER > sentinel_api::WORKERS);
    let mut parked = Vec::new();
    for auth in &people {
        for _ in 0..sentinel_api::SUBSCRIBERS_PER_USER {
            let mut s = std::net::TcpStream::connect(&addr).unwrap();
            write!(
                s,
                "GET /api/v1/runs/{}/wait?since={version}&timeout_ms=20000 HTTP/1.1\r\nhost: x\r\nauthorization: {auth}\r\n\r\n",
                f.diamond
            )
            .unwrap();
            parked.push(s);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(700));
    // They are all parked: each person's share is full…
    let quick = format!(
        "/api/v1/runs/{}/wait?since={version}&timeout_ms=100",
        f.diamond
    );
    for auth in &people {
        assert_eq!(get(&f, &quick, auth).0, 429, "the share is parked");
    }
    // …and requests doing work are served straight away.
    for _ in 0..(2 * sentinel_api::WORKERS) {
        let started = std::time::Instant::now();
        let (status, _) = get(&f, "/api/v1/me", &f.auth);
        assert_eq!(status, 200);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
    let cancel = format!("/api/v1/runs/{}/cancel", f.stuck_run);
    assert_eq!(send(&f, "POST", &cancel, json!({}), &f.auth).0, 200);
    drop(parked);
}
