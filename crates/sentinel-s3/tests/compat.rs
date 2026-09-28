//! The named endpoint compatibility matrix (R02/R03): every case against
//! every S3 service listed in `$SENTINEL_S3_ENDPOINTS` (written by
//! `tests/endpoints.sh`; see [docs/s3.md](../../../docs/s3.md)). Without the
//! variable it reports that it was skipped, never a false pass.

use std::io::Read;

use sentinel_s3::{Client, Config, Credentials, Error, Part};

struct Endpoint {
    name: String,
    endpoint: String,
    region: String,
    bucket: String,
    path_style: bool,
    credentials: std::path::PathBuf,
}

fn endpoints() -> Option<Vec<Endpoint>> {
    let list = std::env::var_os("SENTINEL_S3_ENDPOINTS")?;
    let only = std::env::var("SENTINEL_S3_ONLY").ok();
    let text = std::fs::read_to_string(list).expect("read the endpoint list");
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                Endpoint {
                    name: f[0].into(),
                    endpoint: f[1].into(),
                    region: f[2].into(),
                    bucket: f[3].into(),
                    path_style: f[4] == "true",
                    credentials: f[5].into(),
                }
            })
            .filter(|e| {
                only.as_ref()
                    .is_none_or(|o| o.split(',').any(|n| n == e.name))
            })
            .collect(),
    )
}

fn client(e: &Endpoint, prefix: &str, secret: Option<&[u8]>) -> Client {
    let mut credentials = Credentials::from_file(&e.credentials).unwrap();
    if let Some(secret) = secret {
        credentials =
            Credentials::new(credentials.access_key_id.clone(), secret.to_vec(), None).unwrap();
    }
    let (connect, read) = sentinel_s3::client::default_timeouts();
    Client::new(Config {
        endpoint: e.endpoint.clone(),
        region: e.region.clone(),
        bucket: e.bucket.clone(),
        prefix: prefix.into(),
        path_style: e.path_style,
        ca_file: None,
        credentials,
        connect_timeout: connect,
        read_timeout: read,
    })
    .unwrap()
}

fn read_all(r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let mut r = r;
    r.read_to_end(&mut out).unwrap();
    out
}

type Case = fn(&Endpoint, &str) -> Result<(), String>;

fn check(what: &str, ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.into()) }
}

fn roundtrip(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, None);
    let key = c.key("objects/aa/round trip+&.bin");
    let body: Vec<u8> = (0..70_000u32).map(|i| (i * 7 % 251) as u8).collect();
    c.put_object(&key, &body, &[("blake3", "abc123")])
        .map_err(|x| x.to_string())?;
    let head = c
        .head_object(&key)
        .map_err(|x| x.to_string())?
        .ok_or("head: missing")?;
    check("head length", head.len == body.len() as u64)?;
    check(
        "metadata round-trips",
        head.meta("blake3") == Some("abc123"),
    )?;
    let (len, r) = c.get_object(&key, None).map_err(|x| x.to_string())?;
    check("full read", len == body.len() as u64 && read_all(r) == body)?;
    let (len, r) = c
        .get_object(&key, Some((1_000, 1_999)))
        .map_err(|x| x.to_string())?;
    check(
        "range read",
        len == 1_000 && read_all(r) == body[1_000..2_000],
    )?;
    let page = c
        .list_objects(&c.key("objects/"), None)
        .map_err(|x| x.to_string())?;
    check(
        "listing",
        page.objects
            .iter()
            .any(|(k, l)| *k == key && *l == body.len() as u64),
    )?;
    c.delete_object(&key).map_err(|x| x.to_string())?;
    check(
        "gone after delete",
        c.head_object(&key).map_err(|x| x.to_string())?.is_none(),
    )?;
    check(
        "a missing key reads as not found",
        matches!(c.get_object(&key, None), Err(Error::NotFound(_))),
    )?;
    c.delete_object(&key)
        .map_err(|x| format!("a second delete: {x}"))
}

fn multipart_resume(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, None);
    let key = c.key("objects/bb/multipart.bin");
    let first: Vec<u8> = (0..(5u32 << 20)).map(|i| (i % 253) as u8).collect();
    let second: Vec<u8> = (0..4_097u32).map(|i| (i % 7) as u8).collect();
    let id = c
        .create_multipart(&key, &[("blake3", "def")])
        .map_err(|x| x.to_string())?;
    let e1 = c
        .upload_part(&key, &id, 1, &first)
        .map_err(|x| x.to_string())?;
    // A restart: a fresh client learns what the upload already holds.
    let c = client(e, prefix, None);
    let held = c.list_parts(&key, &id).map_err(|x| x.to_string())?;
    check(
        "the listed part matches the upload",
        held.len() == 1
            && held[0].number == 1
            && held[0].etag == e1
            && held[0].len == first.len() as u64,
    )?;
    let e2 = c
        .upload_part(&key, &id, 2, &second)
        .map_err(|x| x.to_string())?;
    let mut parts = held;
    parts.push(Part {
        number: 2,
        etag: e2,
        len: second.len() as u64,
    });
    c.complete_multipart(&key, &id, &parts)
        .map_err(|x| x.to_string())?;
    let head = c
        .head_object(&key)
        .map_err(|x| x.to_string())?
        .ok_or("missing after complete")?;
    check(
        "assembled length",
        head.len == (first.len() + second.len()) as u64,
    )?;
    check(
        "metadata survives multipart",
        head.meta("blake3") == Some("def"),
    )?;
    let at = first.len() as u64;
    let (_, r) = c
        .get_object(&key, Some((at - 3, at + 3)))
        .map_err(|x| x.to_string())?;
    let mut expect = first[first.len() - 3..].to_vec();
    expect.extend_from_slice(&second[..4]);
    check("a range across the part boundary", read_all(r) == expect)?;
    c.delete_object(&key).map_err(|x| x.to_string())
}

fn abort_cleanup(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, None);
    let key = c.key("objects/cc/aborted.bin");
    let id = c.create_multipart(&key, &[]).map_err(|x| x.to_string())?;
    c.upload_part(&key, &id, 1, &vec![9u8; 5 << 20])
        .map_err(|x| x.to_string())?;
    let (listed, _) = c
        .list_multipart_uploads(&c.key(""), None)
        .map_err(|x| x.to_string())?;
    check(
        "the open upload is listed",
        listed.iter().any(|u| u.upload_id == id && u.key == key),
    )?;
    c.abort_multipart(&key, &id).map_err(|x| x.to_string())?;
    let (listed, _) = c
        .list_multipart_uploads(&c.key(""), None)
        .map_err(|x| x.to_string())?;
    check(
        "the aborted upload is gone",
        !listed.iter().any(|u| u.upload_id == id),
    )?;
    check(
        "its parts are gone",
        matches!(c.list_parts(&key, &id), Err(Error::NotFound(_))),
    )?;
    check(
        "nothing was stored",
        c.head_object(&key).map_err(|x| x.to_string())?.is_none(),
    )?;
    c.abort_multipart(&key, &id)
        .map_err(|x| format!("a second abort: {x}"))
}

fn payload_hash_verified(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, None);
    let key = c.key("objects/dd/corrupt.bin");
    let claimed = sentinel_s3::sigv4::sha256_hex(b"what was meant");
    let refused = c.put_object_claiming(&key, b"what arrived", &claimed, None);
    check(
        "a body that does not match its signed hash is refused",
        matches!(refused, Err(Error::Refused { .. })),
    )?;
    check(
        "and not stored",
        c.head_object(&key).map_err(|x| x.to_string())?.is_none(),
    )
}

fn content_md5_verified(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, None);
    let key = c.key("objects/ee/corrupt.bin");
    let arrived = b"what arrived";
    let md5 = sentinel_s3::client::content_md5(b"what was meant");
    let sha = sentinel_s3::sigv4::sha256_hex(arrived);
    let refused = c.put_object_claiming(&key, arrived, &sha, Some(&md5));
    check(
        "a body that does not match its Content-MD5 is refused",
        matches!(refused, Err(Error::Refused { .. })),
    )?;
    check(
        "and not stored",
        c.head_object(&key).map_err(|x| x.to_string())?.is_none(),
    )
}

fn wrong_secret(e: &Endpoint, prefix: &str) -> Result<(), String> {
    let c = client(e, prefix, Some(b"not-the-secret-at-all-000000000000000000"));
    match c.check() {
        Err(Error::Refused { code, .. }) => check(
            "the refusal never carries the secret",
            !code.contains("not-the-secret"),
        ),
        other => Err(format!("a wrong secret was not refused: {other:?}")),
    }
}

#[test]
fn compatibility_matrix() {
    let Some(endpoints) = endpoints() else {
        eprintln!("skipped: set SENTINEL_S3_ENDPOINTS (tests/endpoints.sh writes it)");
        return;
    };
    // (name, case, required): an optional case records what the service
    // does without failing the matrix — only `Content-MD5` is relied on for
    // transport integrity, the signed payload hash is a second check some
    // services skip.
    let cases: [(&str, Case, bool); 6] = [
        ("roundtrip", roundtrip, true),
        ("multipart_resume", multipart_resume, true),
        ("abort_cleanup", abort_cleanup, true),
        ("payload_hash", payload_hash_verified, false),
        ("content_md5", content_md5_verified, true),
        ("wrong_secret", wrong_secret, true),
    ];
    let run = format!("compat-{}/", std::process::id());
    let mut failures = Vec::new();
    let mut rows = Vec::new();
    for e in &endpoints {
        let setup = client(e, &run, None);
        if let Err(err) = setup.create_bucket() {
            failures.push(format!("{}: create bucket: {err}", e.name));
        }
        let mut row = vec![e.name.clone()];
        for (name, case, required) in cases {
            match (case(e, &run), required) {
                (Ok(()), true) => row.push("pass".into()),
                (Ok(()), false) => row.push("checked".into()),
                (Err(_), false) => row.push("ignored".into()),
                (Err(why), true) => {
                    row.push("FAIL".into());
                    failures.push(format!("{} {name}: {why}", e.name));
                }
            }
        }
        rows.push(row);
    }
    let header: Vec<&str> = std::iter::once("endpoint")
        .chain(cases.iter().map(|(n, _, _)| *n))
        .collect();
    println!("| {} |", header.join(" | "));
    for row in &rows {
        println!("| {} |", row.join(" | "));
    }
    if let Some(out) = std::env::var_os("SENTINEL_S3_MATRIX_OUT") {
        let json: Vec<String> = rows
            .iter()
            .map(|r| {
                let cells: Vec<String> = header
                    .iter()
                    .zip(r)
                    .map(|(h, v)| format!("\"{h}\":\"{v}\""))
                    .collect();
                format!("{{{}}}", cells.join(","))
            })
            .collect();
        std::fs::write(out, json.join("\n") + "\n").unwrap();
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
