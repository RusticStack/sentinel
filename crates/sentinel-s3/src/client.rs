//! The S3 operations: single and multipart uploads (with resume and abort),
//! range reads, head, delete and listing.

use std::{
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Config, Error, Result, sigv4, xml};

/// Largest body read for anything but an object's own bytes.
const MAX_RESPONSE: u64 = 4 << 20;
const MAX_HEADERS: usize = 32 * 1024;
/// S3's own bounds on multipart uploads.
pub const MIN_PART_BYTES: u64 = 5 << 20;
pub const MAX_PART_BYTES: u64 = 5 << 30;
pub const MAX_PARTS: u32 = 10_000;
/// User metadata one object may carry here.
const MAX_METADATA: usize = 8;

/// What `HEAD` reports about an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub len: u64,
    pub etag: String,
    /// `x-amz-meta-*` values, by the name after the prefix, lower-case.
    pub metadata: Vec<(String, String)>,
}

impl Head {
    pub fn meta(&self, name: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One uploaded part of a multipart upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub number: u32,
    pub etag: String,
    pub len: u64,
}

/// An unfinished multipart upload the bucket still holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartUpload {
    /// The full key, prefix included.
    pub key: String,
    pub upload_id: String,
    /// `2026-09-28T12:00:00.000Z`, as the service wrote it.
    pub initiated: String,
}

/// One page of a listing: full keys and sizes, and where the next starts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectPage {
    pub objects: Vec<(String, u64)>,
    pub next: Option<String>,
}

pub struct Client {
    agent: ureq::Agent,
    config: Arc<Config>,
    scheme: &'static str,
    host: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.config.endpoint)
            .field("bucket", &self.config.bucket)
            .field("prefix", &self.config.prefix)
            .finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Strip the quotes S3 wraps an ETag in.
fn etag(value: &str) -> String {
    value.trim().trim_matches('"').to_owned()
}

impl Client {
    pub fn new(config: Config) -> Result<Client> {
        config.validate()?;
        let (scheme, host) = match config.endpoint.split_once("://") {
            // A default port is dropped: the signed host must be the one the
            // transport sends, which omits it.
            Some(("https", host)) => ("https", host.trim_end_matches(":443").to_owned()),
            Some(("http", host)) => ("http", host.trim_end_matches(":80").to_owned()),
            _ => return Err(Error::Config("endpoint scheme".into())),
        };
        let mut tls = ureq::tls::TlsConfig::builder();
        if let Some(path) = &config.ca_file {
            let pem = std::fs::read(path)
                .map_err(|_| Error::Config(format!("cannot read ca_file {}", path.display())))?;
            let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                return Err(Error::Config(format!(
                    "ca_file {} holds no PEM certificate",
                    path.display()
                )));
            }
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
        }
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_connect(Some(config.connect_timeout))
                .timeout_recv_response(Some(config.read_timeout))
                .timeout_recv_body(Some(config.read_timeout))
                .timeout_send_body(Some(config.read_timeout))
                .max_redirects(0)
                .max_response_header_size(MAX_HEADERS)
                .http_status_as_error(false)
                .tls_config(tls.build())
                .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
                .build(),
        );
        Ok(Client {
            agent,
            config: Arc::new(config),
            scheme,
            host,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The full key for a path under the configured prefix.
    pub fn key(&self, path: &str) -> String {
        format!("{}{}", self.config.prefix, path)
    }

    /// The host header and encoded path for a full key (`None`: the bucket).
    fn locate(&self, key: Option<&str>) -> (String, String) {
        let encoded = key.map(|k| sigv4::uri_encode(k, true)).unwrap_or_default();
        if self.config.path_style {
            (
                self.host.clone(),
                format!("/{}/{}", self.config.bucket, encoded),
            )
        } else {
            (
                format!("{}.{}", self.config.bucket, self.host),
                format!("/{encoded}"),
            )
        }
    }

    /// Sign and send one request. `body` is sent as is and hashed into the
    /// signature; `extra` headers are signed too.
    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let (host, path) = self.locate(key);
        let payload = if body.is_empty() {
            sigv4::EMPTY_SHA256.to_owned()
        } else {
            sigv4::sha256_hex(body)
        };
        let (amz_date, _) = sigv4::timestamp(now_secs());
        let creds = &self.config.credentials;
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", &host),
            ("x-amz-content-sha256", &payload),
            ("x-amz-date", &amz_date),
        ];
        if let Some(token) = &creds.session_token {
            headers.push(("x-amz-security-token", token));
        }
        headers.extend_from_slice(extra);
        let authorization = sigv4::authorization(
            &sigv4::Request {
                method,
                path: &path,
                query,
                headers: &headers,
                payload_sha256: &payload,
            },
            &amz_date,
            &self.config.region,
            &creds.access_key_id,
            creds.secret(),
        );
        let query_string = sigv4::canonical_query(query);
        let url = if query_string.is_empty() {
            format!("{}://{}{}", self.scheme, host, path)
        } else {
            format!("{}://{}{}?{}", self.scheme, host, path, query_string)
        };
        let mut request = ureq::http::Request::builder().method(method).uri(&url);
        for (name, value) in &headers {
            if *name != "host" {
                request = request.header(*name, *value);
            }
        }
        request = request.header("authorization", &authorization);
        let request = request
            .body(body)
            .map_err(|_| Error::Config("request shape".into()))?;
        self.agent
            .run(request)
            .map_err(|e| Error::Transient(transport(&e)))
    }

    /// The service's refusal, classified; never includes the request.
    fn refusal(status: u16, mut response: ureq::http::Response<ureq::Body>) -> Error {
        let body = response
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_vec()
            .unwrap_or_default();
        let code = xml::field(&body, "Code")
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("http_{status}"));
        let request_id = xml::field(&body, "RequestId").ok().flatten();
        let code = match request_id {
            Some(id) if id.len() <= 128 => format!("{code} (request {id})"),
            _ => code,
        };
        match status {
            404 => Error::NotFound(code),
            429 | 500..=599 => Error::Transient(code),
            _ if code.starts_with("SlowDown") || code.starts_with("RequestTimeout") => {
                Error::Transient(code)
            }
            _ => Error::Refused { status, code },
        }
    }

    fn ok(response: ureq::http::Response<ureq::Body>) -> Result<ureq::http::Response<ureq::Body>> {
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(response)
        } else {
            Err(Self::refusal(status, response))
        }
    }

    fn body(mut response: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
        response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| Error::Transient(transport(&e)))
    }

    fn header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    fn metadata_headers(metadata: &[(&str, &str)]) -> Result<Vec<(String, String)>> {
        if metadata.len() > MAX_METADATA {
            return Err(Error::Config("too much object metadata".into()));
        }
        metadata
            .iter()
            .map(|(k, v)| {
                if k.is_empty()
                    || !k
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || !v.bytes().all(|b| (0x20..0x7f).contains(&b))
                    || v.len() > 256
                {
                    return Err(Error::Config(
                        "object metadata must be short printable ASCII".into(),
                    ));
                }
                Ok((format!("x-amz-meta-{k}"), (*v).to_owned()))
            })
            .collect()
    }

    /// Store `body` at `key` in one request (up to [`MAX_PART_BYTES`]).
    /// Returns the ETag.
    pub fn put_object(&self, key: &str, body: &[u8], metadata: &[(&str, &str)]) -> Result<String> {
        if body.len() as u64 > MAX_PART_BYTES {
            return Err(Error::Config("single upload above 5 GiB".into()));
        }
        let meta = Self::metadata_headers(metadata)?;
        let md5 = content_md5(body);
        let mut extra: Vec<(&str, &str)> =
            meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        extra.push(("content-md5", &md5));
        let response = Self::ok(self.send("PUT", Some(key), &[], &extra, body)?)?;
        Ok(etag(&Self::header(&response, "etag").unwrap_or_default()))
    }

    /// Begin a multipart upload; the caller records the id to resume or
    /// abort it after a restart.
    pub fn create_multipart(&self, key: &str, metadata: &[(&str, &str)]) -> Result<String> {
        let meta = Self::metadata_headers(metadata)?;
        let extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let response = Self::ok(self.send("POST", Some(key), &[("uploads", "")], &extra, &[])?)?;
        xml::field(&Self::body(response)?, "UploadId")?
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or_else(|| Error::Protocol("no UploadId".into()))
    }

    /// Upload one part (1-based `number`); its `Content-MD5` (and, where the
    /// service checks it, the signed payload hash) makes the service verify
    /// it. Returns the part's ETag.
    pub fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        number: u32,
        body: &[u8],
    ) -> Result<String> {
        if !(1..=MAX_PARTS).contains(&number) || body.len() as u64 > MAX_PART_BYTES {
            return Err(Error::Config("part number or size out of range".into()));
        }
        let n = number.to_string();
        let md5 = content_md5(body);
        let response = Self::ok(self.send(
            "PUT",
            Some(key),
            &[("partNumber", &n), ("uploadId", upload_id)],
            &[("content-md5", &md5)],
            body,
        )?)?;
        Self::header(&response, "etag")
            .map(|e| etag(&e))
            .filter(|e| !e.is_empty())
            .ok_or_else(|| Error::Protocol("part without an ETag".into()))
    }

    /// Finish a multipart upload from its parts in order.
    pub fn complete_multipart(&self, key: &str, upload_id: &str, parts: &[Part]) -> Result<String> {
        if parts.is_empty() || parts.windows(2).any(|w| w[1].number <= w[0].number) {
            return Err(Error::Config(
                "parts must be non-empty and ascending".into(),
            ));
        }
        let mut body = String::from("<CompleteMultipartUpload>");
        for part in parts {
            body.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>\"{}\"</ETag></Part>",
                part.number,
                part.etag.replace(['<', '>', '&', '"'], "")
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let response = Self::ok(self.send(
            "POST",
            Some(key),
            &[("uploadId", upload_id)],
            &[("content-type", "application/xml")],
            body.as_bytes(),
        )?)?;
        // A 200 can still carry an error document (S3 streams whitespace
        // while it assembles, then reports).
        let answer = Self::body(response)?;
        if let Some(code) = xml::field(&answer, "Code")? {
            return Err(if code == "InternalError" || code == "SlowDown" {
                Error::Transient(code)
            } else {
                Error::Refused { status: 200, code }
            });
        }
        Ok(xml::field(&answer, "ETag")?
            .map(|e| etag(&e))
            .unwrap_or_default())
    }

    /// Abandon a multipart upload and free its parts. An upload already gone
    /// is not an error.
    pub fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        match Self::ok(self.send("DELETE", Some(key), &[("uploadId", upload_id)], &[], &[])?) {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The parts an unfinished upload already holds — what a resumed upload
    /// need not send again.
    pub fn list_parts(&self, key: &str, upload_id: &str) -> Result<Vec<Part>> {
        let mut out = Vec::new();
        let mut marker = String::new();
        loop {
            let mut query = vec![("uploadId", upload_id), ("max-parts", "1000")];
            if !marker.is_empty() {
                query.push(("part-number-marker", marker.as_str()));
            }
            let body = Self::body(Self::ok(self.send("GET", Some(key), &query, &[], &[])?)?)?;
            for fields in xml::records(&body, "Part")? {
                let number = xml::get(&fields, "PartNumber").and_then(|n| n.parse().ok());
                let len = xml::get(&fields, "Size").and_then(|n| n.parse().ok());
                match (number, xml::get(&fields, "ETag"), len) {
                    (Some(number), Some(e), Some(len)) => out.push(Part {
                        number,
                        etag: etag(e),
                        len,
                    }),
                    _ => return Err(Error::Protocol("malformed part listing".into())),
                }
            }
            let truncated = xml::field(&body, "IsTruncated")?.as_deref() == Some("true");
            match xml::field(&body, "NextPartNumberMarker")? {
                Some(next) if truncated && next != marker && out.len() < MAX_PARTS as usize => {
                    marker = next
                }
                _ => return Ok(out),
            }
        }
    }

    /// Unfinished multipart uploads under `prefix` (a full key prefix), a
    /// page at a time — what abort cleanup walks.
    pub fn list_multipart_uploads(
        &self,
        prefix: &str,
        after: Option<(&str, &str)>,
    ) -> Result<(Vec<MultipartUpload>, Option<(String, String)>)> {
        let mut query = vec![("uploads", ""), ("prefix", prefix), ("max-uploads", "1000")];
        if let Some((key, id)) = after {
            query.push(("key-marker", key));
            query.push(("upload-id-marker", id));
        }
        let body = Self::body(Self::ok(self.send("GET", None, &query, &[], &[])?)?)?;
        let mut uploads = Vec::new();
        for fields in xml::records(&body, "Upload")? {
            match (xml::get(&fields, "Key"), xml::get(&fields, "UploadId")) {
                (Some(key), Some(id)) => uploads.push(MultipartUpload {
                    key: key.to_owned(),
                    upload_id: id.to_owned(),
                    initiated: xml::get(&fields, "Initiated")
                        .unwrap_or_default()
                        .to_owned(),
                }),
                _ => return Err(Error::Protocol("malformed upload listing".into())),
            }
        }
        let truncated = xml::field(&body, "IsTruncated")?.as_deref() == Some("true");
        let next = match (
            xml::field(&body, "NextKeyMarker")?,
            xml::field(&body, "NextUploadIdMarker")?,
        ) {
            (Some(k), Some(u)) if truncated && !k.is_empty() => Some((k, u)),
            _ => None,
        };
        Ok((uploads, next))
    }

    /// An object's size, ETag and metadata; `None` when there is none.
    pub fn head_object(&self, key: &str) -> Result<Option<Head>> {
        let response = self.send("HEAD", Some(key), &[], &[], &[])?;
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            // HEAD answers carry no body: classify by status alone.
            return Err(match status {
                429 | 500..=599 => Error::Transient(format!("http_{status}")),
                _ => Error::Refused {
                    status,
                    code: format!("http_{status}"),
                },
            });
        }
        let len = Self::header(&response, "content-length")
            .and_then(|l| l.parse().ok())
            .ok_or_else(|| Error::Protocol("HEAD without a length".into()))?;
        let metadata = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                let name = name.as_str().strip_prefix("x-amz-meta-")?;
                Some((name.to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect();
        Ok(Some(Head {
            len,
            etag: etag(&Self::header(&response, "etag").unwrap_or_default()),
            metadata,
        }))
    }

    /// Read an object, or `range` (`start..=end`) of it, as a stream bounded
    /// by the answer's `Content-Length`.
    pub fn get_object(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> Result<(u64, impl Read + use<>)> {
        let header = range.map(|(a, b)| format!("bytes={a}-{b}"));
        let extra: Vec<(&str, &str)> = header.iter().map(|h| ("range", h.as_str())).collect();
        let response = Self::ok(self.send("GET", Some(key), &[], &extra, &[])?)?;
        let len: u64 = Self::header(&response, "content-length")
            .and_then(|l| l.parse().ok())
            .ok_or_else(|| Error::Protocol("GET without a length".into()))?;
        if let Some((a, b)) = range
            && len != b - a + 1
        {
            return Err(Error::Protocol("range answered with another length".into()));
        }
        // The transport already stops at `Content-Length`; ureq's limit
        // counts reaching it as exceeding it, so it sits one past.
        let reader = response
            .into_body()
            .into_with_config()
            .limit(len.saturating_add(1))
            .reader();
        Ok((len, reader))
    }

    /// Delete an object; one already gone is not an error.
    pub fn delete_object(&self, key: &str) -> Result<()> {
        match Self::ok(self.send("DELETE", Some(key), &[], &[], &[])?) {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// One page (≤ 1,000) of the keys under `prefix`, after `continuation`.
    pub fn list_objects(&self, prefix: &str, continuation: Option<&str>) -> Result<ObjectPage> {
        let mut query = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
        if let Some(token) = continuation {
            query.push(("continuation-token", token));
        }
        let body = Self::body(Self::ok(self.send("GET", None, &query, &[], &[])?)?)?;
        let mut page = ObjectPage::default();
        for fields in xml::records(&body, "Contents")? {
            match (
                xml::get(&fields, "Key"),
                xml::get(&fields, "Size").and_then(|s| s.parse().ok()),
            ) {
                (Some(key), Some(len)) => page.objects.push((key.to_owned(), len)),
                _ => return Err(Error::Protocol("malformed object listing".into())),
            }
        }
        if xml::field(&body, "IsTruncated")?.as_deref() == Some("true") {
            page.next = xml::field(&body, "NextContinuationToken")?;
        }
        Ok(page)
    }

    /// Create the configured bucket (an operator's setup step, and the
    /// compatibility tests'); one that already exists and is ours is fine.
    pub fn create_bucket(&self) -> Result<()> {
        let body = if self.config.region == "us-east-1" {
            String::new()
        } else {
            format!(
                "<CreateBucketConfiguration><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                self.config.region
            )
        };
        match Self::ok(self.send("PUT", None, &[], &[], body.as_bytes())?) {
            Ok(_) => Ok(()),
            Err(Error::Refused { code, .. }) if code.starts_with("BucketAlreadyOwnedByYou") => {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Store `body` while claiming `claimed_sha256` as its hash — only for
    /// proving that an endpoint verifies the signed payload hash.
    #[doc(hidden)]
    pub fn put_object_claiming(
        &self,
        key: &str,
        body: &[u8],
        claimed_sha256: &str,
        claimed_md5: Option<&str>,
    ) -> Result<()> {
        let (host, path) = self.locate(Some(key));
        let (amz_date, _) = sigv4::timestamp(now_secs());
        let creds = &self.config.credentials;
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", &host),
            ("x-amz-content-sha256", claimed_sha256),
            ("x-amz-date", &amz_date),
        ];
        if let Some(md5) = claimed_md5 {
            headers.push(("content-md5", md5));
        }
        let authorization = sigv4::authorization(
            &sigv4::Request {
                method: "PUT",
                path: &path,
                query: &[],
                headers: &headers,
                payload_sha256: claimed_sha256,
            },
            &amz_date,
            &self.config.region,
            &creds.access_key_id,
            creds.secret(),
        );
        let mut request = ureq::http::Request::builder()
            .method("PUT")
            .uri(format!("{}://{}{}", self.scheme, host, path))
            .header("x-amz-content-sha256", claimed_sha256)
            .header("x-amz-date", &amz_date)
            .header("authorization", &authorization);
        if let Some(md5) = claimed_md5 {
            request = request.header("content-md5", md5);
        }
        let request = request
            .body(body)
            .map_err(|_| Error::Config("request shape".into()))?;
        let response = self
            .agent
            .run(request)
            .map_err(|e| Error::Transient(transport(&e)))?;
        Self::ok(response).map(|_| ())
    }

    /// A cheap reachability and authority check: list at most one key under
    /// the prefix.
    pub fn check(&self) -> Result<()> {
        let prefix = self.config.prefix.clone();
        let query = vec![
            ("list-type", "2"),
            ("prefix", prefix.as_str()),
            ("max-keys", "1"),
        ];
        Self::body(Self::ok(self.send("GET", None, &query, &[], &[])?)?).map(|_| ())
    }
}

/// A transport failure described without the URL (which could carry a
/// presigned query) or any header.
fn transport(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timed out".into(),
        ureq::Error::Io(e) => format!("i/o: {}", e.kind()),
        ureq::Error::HostNotFound => "host not found".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::BodyExceedsLimit(_) => "response too large".into(),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS failure".into(),
        _ => "transport failure".into(),
    }
}

/// `Content-MD5` of a body: base64 of its MD5, which the service must check
/// and refuse on mismatch.
pub fn content_md5(body: &[u8]) -> String {
    use base64::Engine as _;
    use md5::Digest as _;
    base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(body))
}

/// A default timeout pair: 10 s to connect, 60 s per read.
pub fn default_timeouts() -> (Duration, Duration) {
    (Duration::from_secs(10), Duration::from_secs(60))
}
