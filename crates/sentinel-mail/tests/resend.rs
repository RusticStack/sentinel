use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use sentinel_core::{MailId, UnixMillis};
use sentinel_mail::{ApiKey, Failure, Mail, Resend, Sender, Transport};

const KEY: &str = "re_testkey_0123456789";

enum Script {
    Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    Hang,
}

fn reply(status: u16, body: &str) -> Script {
    Script::Reply {
        status,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

struct Seen {
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

fn serve(script: Vec<Script>) -> (String, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/emails", listener.local_addr().unwrap());
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    thread::spawn(move || {
        for script in script {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, length) = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (raw.len(), 0);
                }
                raw.extend_from_slice(&chunk[..n]);
                if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (end + 4, length);
                }
            };
            while raw.len() < head_end + length {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&raw[..head_end.saturating_sub(4)]).into_owned();
            let headers = head
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .map(|(n, v)| (n.trim().to_lowercase(), v.trim().to_owned()))
                .collect();
            let body = String::from_utf8_lossy(&raw[head_end.min(raw.len())..]).into_owned();
            seen.lock().unwrap().push(Seen { headers, body });
            match script {
                Script::Hang => thread::sleep(Duration::from_secs(5)),
                Script::Reply {
                    status,
                    headers,
                    body,
                } => {
                    let mut out = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    for (name, value) in headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    // The client may hang up on an oversize body.
                    let _ = stream.write_all(out.as_bytes());
                    let _ = stream.write_all(&body);
                }
            }
        }
    });
    (url, log)
}

fn client(url: &str) -> Resend {
    Resend::with_endpoint(
        ApiKey::new(KEY.as_bytes().to_vec()).unwrap(),
        Sender::parse("Sentinel <ci@example.com>").unwrap(),
        url,
    )
}

fn mail(id: MailId) -> Mail<'static> {
    Mail {
        id,
        to: "ada@example.com",
        subject: "Verify your address",
        body: "Open https://ci.example.com/verify#token=SECRETTOKEN to verify.\n",
        now: UnixMillis::now(),
    }
}

fn failure(result: Result<(), Failure>) -> Failure {
    let failure = result.unwrap_err();
    let text = format!("{failure:?}");
    for secret in [KEY, "SECRETTOKEN", "ada@example.com"] {
        assert!(!text.contains(secret), "{secret} leaked into {text}");
    }
    failure
}

#[test]
fn a_message_is_one_authenticated_json_post_with_an_idempotency_key() {
    let (url, log) = serve(vec![reply(200, r#"{"id":"abc"}"#)]);
    let id = MailId::new();
    client(&url).deliver(&mail(id)).unwrap();
    let log = log.lock().unwrap();
    let seen = &log[0];
    assert_eq!(
        seen.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(
        seen.header("idempotency-key"),
        Some(format!("sentinel-mail-{id}").as_str())
    );
    assert!(
        seen.header("user-agent")
            .is_some_and(|ua| ua.starts_with("sentinel/"))
    );
    let body: serde_json::Value = serde_json::from_str(&seen.body).unwrap();
    assert_eq!(body["from"], "Sentinel <ci@example.com>");
    assert_eq!(body["to"], serde_json::json!(["ada@example.com"]));
    assert_eq!(body["subject"], "Verify your address");
    assert!(body["text"].as_str().unwrap().contains("SECRETTOKEN"));
    assert!(body["html"].as_str().unwrap().contains("<br>"));
}

#[test]
fn rejected_messages_are_permanent() {
    for (status, body) in [
        (403, r#"{"name":"forbidden_resource","message":"x"}"#),
        (403, "not json"),
        (400, r#"{"name":"invalid_from_address","message":"x"}"#),
        (
            422,
            r#"{"name":"validation_error","message":"The to field ada@example.com is invalid"}"#,
        ),
        (404, "not json"),
    ] {
        let (url, _) = serve(vec![reply(status, body)]);
        let failure = failure(client(&url).deliver(&mail(MailId::new())));
        let Failure::Permanent(why) = failure else {
            panic!("{status} must be permanent");
        };
        assert!(why.contains(&status.to_string()), "{why}");
    }
    let (url, _) = serve(vec![reply(
        422,
        r#"{"name":"validation_error","message":"nope"}"#,
    )]);
    let Failure::Permanent(why) = failure(client(&url).deliver(&mail(MailId::new()))) else {
        panic!()
    };
    assert!(
        why.contains("validation_error"),
        "the error name is kept: {why}"
    );
    assert!(!why.contains("nope"), "the service's message is not: {why}");
}

#[test]
fn throttling_carries_the_retry_after_and_server_errors_are_transient() {
    let (url, _) = serve(vec![Script::Reply {
        status: 429,
        headers: vec![("retry-after", "7".into())],
        body: br#"{"name":"rate_limit_exceeded","message":"x"}"#.to_vec(),
    }]);
    assert_eq!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Transient {
            why: "resend throttled the request (429 rate_limit_exceeded)".into(),
            retry_after: Some(Duration::from_secs(7)),
        }
    );
    for status in [500, 502, 503] {
        let (url, _) = serve(vec![reply(status, "")]);
        assert!(
            matches!(
                failure(client(&url).deliver(&mail(MailId::new()))),
                Failure::Transient {
                    retry_after: None,
                    ..
                }
            ),
            "{status}"
        );
    }
    let (url, _) = serve(vec![reply(
        409,
        r#"{"name":"concurrent_idempotent_requests","message":"x"}"#,
    )]);
    assert!(matches!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Transient { .. }
    ));
    let (url, _) = serve(vec![reply(
        409,
        r#"{"name":"invalid_idempotent_request","message":"x"}"#,
    )]);
    assert!(matches!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Permanent(_)
    ));
}

#[test]
fn a_retry_after_a_server_error_reuses_the_idempotency_key() {
    let (url, log) = serve(vec![reply(503, ""), reply(200, "{}")]);
    let mut sender = client(&url);
    let id = MailId::new();
    assert!(matches!(
        sender.send(&mail(id)),
        Err(Failure::Transient { .. })
    ));
    sender.send(&mail(id)).unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(
        log[0].header("idempotency-key"),
        log[1].header("idempotency-key")
    );
    drop(log);
    let (url, log) = serve(vec![reply(200, "{}"), reply(200, "{}")]);
    let sender = client(&url);
    sender.deliver(&mail(MailId::new())).unwrap();
    sender.deliver(&mail(MailId::new())).unwrap();
    let log = log.lock().unwrap();
    assert_ne!(
        log[0].header("idempotency-key"),
        log[1].header("idempotency-key")
    );
}

#[test]
fn a_silent_service_times_out_as_a_transient_failure() {
    let (url, _) = serve(vec![Script::Hang]);
    let sender = client(&url).with_total_timeout(Duration::from_millis(400));
    let started = std::time::Instant::now();
    let Failure::Transient { why, .. } = failure(sender.deliver(&mail(MailId::new()))) else {
        panic!("a timeout is transient");
    };
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(why.contains("in time"), "{why}");
}

#[test]
fn an_oversize_response_is_bounded_and_only_the_status_counts() {
    let huge = vec![b'x'; 2 << 20];
    let big = |status| Script::Reply {
        status,
        headers: Vec::new(),
        body: huge.clone(),
    };
    let (url, _) = serve(vec![big(500)]);
    assert!(matches!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Transient { .. }
    ));
    let (url, _) = serve(vec![big(422)]);
    assert!(matches!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Permanent(_)
    ));
    let (url, _) = serve(vec![big(200)]);
    client(&url).deliver(&mail(MailId::new())).unwrap();
}

#[test]
fn a_redirect_is_not_followed_and_the_key_goes_nowhere_else() {
    let (url, log) = serve(vec![
        Script::Reply {
            status: 302,
            headers: vec![("location", "http://127.0.0.1:9/elsewhere".into())],
            body: Vec::new(),
        },
        reply(200, "{}"),
    ]);
    assert!(matches!(
        failure(client(&url).deliver(&mail(MailId::new()))),
        Failure::Transient { .. }
    ));
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn an_unacceptable_message_never_leaves_the_process() {
    let (url, log) = serve(vec![reply(200, "{}")]);
    let sender = client(&url);
    let id = MailId::new();
    let with = |to: &'static str, subject: &'static str| Mail {
        to,
        subject,
        ..mail(id)
    };
    for bad in [
        with("ada@example.com", "Hi\r\nBcc: eve@example.com"),
        with("ada@example.com", ""),
        with("ada example@com", "Hi"),
        with("ada@example.com,eve@example.com", "Hi"),
    ] {
        assert!(matches!(
            failure(sender.deliver(&bad)),
            Failure::Permanent(_)
        ));
    }
    let long = "s".repeat(201);
    let subject: &'static str = Box::leak(long.into_boxed_str());
    assert!(sender.deliver(&with("ada@example.com", subject)).is_err());
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn the_key_file_is_read_like_the_other_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resend-key");
    let write = |bytes: &[u8]| {
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    write(b"re_abc\n");
    assert!(ApiKey::from_file(&path).is_ok());
    write(b"re abc\n");
    assert!(ApiKey::from_file(&path).is_err());
    write(&vec![b'a'; 5000]);
    assert!(ApiKey::from_file(&path).is_err());
    write(b"");
    assert!(ApiKey::from_file(&path).is_err());
    assert!(ApiKey::from_file(&dir.path().join("missing")).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        write(b"re_abc\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = ApiKey::from_file(&path).unwrap_err();
        assert!(!error.contains("resend-key"), "the path is not echoed");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(ApiKey::from_file(&link).is_err());
    }
}

#[test]
fn key_and_sender_problems_belong_to_the_service_not_to_the_message() {
    for (status, body) in [
        (
            401,
            r#"{"name":"missing_api_key","message":"ada@example.com"}"#,
        ),
        (401, "not json"),
        (403, r#"{"name":"restricted_api_key","message":"x"}"#),
        (403, r#"{"name":"invalid_api_key","message":"x"}"#),
        (
            403,
            r#"{"name":"validation_error","message":"The example.com domain is not verified"}"#,
        ),
    ] {
        let (url, _) = serve(vec![reply(status, body)]);
        let failure = failure(client(&url).deliver(&mail(MailId::new())));
        let Failure::Service(why) = failure else {
            panic!("{status} {body} must be the service's");
        };
        assert!(why.contains(&status.to_string()), "{why}");
        assert!(
            !why.contains("ada@example.com"),
            "the message is not kept: {why}"
        );
    }
}
