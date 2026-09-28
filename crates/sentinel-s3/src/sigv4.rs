//! AWS Signature Version 4 for S3, header form.
//!
//! The payload hash is always the real SHA-256 of the body: the service then
//! verifies every byte it received against the signed request, so a part
//! corrupted in transit is refused rather than stored.

use ring::{digest, hmac};

/// `UNSIGNED-PAYLOAD` is never used; an empty body hashes to this.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn hmac(key: &[u8], data: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
}

/// RFC 3986 encoding as SigV4 wants it: unreserved characters kept, every
/// other byte `%XX` upper-case; `/` kept only when `keep_slash`.
pub fn uri_encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => {
                const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(DIGITS[(b >> 4) as usize] as char);
                out.push(DIGITS[(b & 15) as usize] as char);
            }
        }
    }
    out
}

/// A UTC instant as SigV4 writes it: `(20130524T000000Z, 20130524)`.
pub fn timestamp(unix_secs: u64) -> (String, String) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let time = format!(
        "{date}T{:02}{:02}{:02}Z",
        rem / 3_600,
        (rem / 60) % 60,
        rem % 60
    );
    (time, date)
}

/// What one request's signature covers.
pub struct Request<'a> {
    pub method: &'a str,
    /// The encoded path, starting with `/`.
    pub path: &'a str,
    /// Query parameters, unencoded; sorted here.
    pub query: &'a [(&'a str, &'a str)],
    /// Headers to sign, names lower-case; `host`, `x-amz-date` and
    /// `x-amz-content-sha256` must be among them.
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
}

/// The canonical query string: parameters encoded, sorted by name then
/// value.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Authorization` header value for `request`, signed at `amz_date`
/// (`20130524T000000Z`) in `region` with the given credentials.
pub fn authorization(
    request: &Request<'_>,
    amz_date: &str,
    region: &str,
    access_key: &str,
    secret_key: &[u8],
) -> String {
    let mut headers: Vec<(&str, String)> = request
        .headers
        .iter()
        .map(|(k, v)| (*k, v.trim().to_owned()))
        .collect();
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let signed: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
    let signed = signed.join(";");
    let mut canonical = String::new();
    canonical.push_str(request.method);
    canonical.push('\n');
    canonical.push_str(request.path);
    canonical.push('\n');
    canonical.push_str(&canonical_query(request.query));
    canonical.push('\n');
    for (k, v) in &headers {
        canonical.push_str(k);
        canonical.push(':');
        canonical.push_str(v);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed);
    canonical.push('\n');
    canonical.push_str(request.payload_sha256);
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut secret = Vec::with_capacity(4 + secret_key.len());
    secret.extend_from_slice(b"AWS4");
    secret.extend_from_slice(secret_key);
    let k_date = hmac(&secret, date.as_bytes());
    zeroize::Zeroize::zeroize(&mut secret);
    let k_region = hmac(k_date.as_ref(), region.as_bytes());
    let k_service = hmac(k_region.as_ref(), b"s3");
    let k_signing = hmac(k_service.as_ref(), b"aws4_request");
    let signature = hex(hmac(k_signing.as_ref(), to_sign.as_bytes()).as_ref());
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in AWS's S3 Signature V4 documentation ("GET
    /// Object"): a range read of `test.txt` from `examplebucket`.
    #[test]
    fn the_published_get_object_example_signs_identically() {
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ];
        let auth = authorization(
            &Request {
                method: "GET",
                path: "/test.txt",
                query: &[],
                headers: &headers,
                payload_sha256: EMPTY_SHA256,
            },
            "20130524T000000Z",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn timestamps_and_encoding_follow_the_specification() {
        assert_eq!(
            timestamp(1_369_353_600),
            ("20130524T000000Z".into(), "20130524".into())
        );
        assert_eq!(timestamp(951_827_696).0, "20000229T123456Z");
        assert_eq!(timestamp(0).0, "19700101T000000Z");
        assert_eq!(uri_encode("a b/c~d+é", true), "a%20b/c~d%2B%C3%A9");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(
            canonical_query(&[("uploadId", "x y"), ("partNumber", "2")]),
            "partNumber=2&uploadId=x%20y"
        );
    }
}
