use std::{
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{Config, Error, Result, sigv4, xml};

const MAX_RESPONSE: u64 = 4 << 20;
const MAX_HEADERS: usize = 32 * 1024;
pub const MIN_PART_BYTES: u64 = 5 << 20;
pub const MAX_PART_BYTES: u64 = 5 << 30;
pub const MAX_PARTS: u32 = 10_000;
const MAX_METADATA: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub len: u64,
    pub etag: String,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub number: u32,
    pub etag: String,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartUpload {
    pub key: String,
    pub upload_id: String,
    pub initiated: String,
}

pub type UploadPage = (Vec<MultipartUpload>, Option<(String, String)>);

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

const MAX_CODE: usize = 64;
const MAX_REQUEST_ID: usize = 64;

fn identifier(text: &str, max: usize) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    .then(|| text.to_owned())
}

fn range_len(a: u64, b: u64) -> Option<u64> {
    b.checked_sub(a)?.checked_add(1)
}

fn etag(value: &str) -> String {
    value.trim().trim_matches('"').to_owned()
}

/// The slowest sustained upload the client waits for. Below it a part times out.
pub const MIN_SEND_BYTES_PER_SEC: u64 = 4 << 20;

/// Bytes one ranged read asks for. Each read has its own timeout budget, so the limit on an object's size is not the link speed times one timeout.
pub const READ_CHUNK_BYTES: u64 = 32 << 20;

/// `None` while the configured timeout already covers the body at the minimum rate.
fn send_budget(len: u64, base: Duration) -> Option<Duration> {
    let needed = Duration::from_secs(len.div_ceil(MIN_SEND_BYTES_PER_SEC));
    (needed > base).then_some(needed)
}

/// A refusal that means the thing a delete or an abort targeted is already gone.
/// Any other 404, such as a missing bucket or a proxy's bare answer, is not success.
fn already_gone(result: Result<()>, expected: &str) -> Result<()> {
    match result {
        Err(Error::NotFound(code)) if !code.starts_with(expected) => {
            Err(Error::Refused { status: 404, code })
        }
        Err(Error::NotFound(_)) | Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `bytes a-b/total` from a `Content-Range` header.
fn content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, total) = value.trim().strip_prefix("bytes ")?.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?, total.parse().ok()?))
}

impl Client {
    pub fn new(config: Config) -> Result<Client> {
        config.validate()?;
        let (scheme, host) = match config.endpoint.split_once("://") {
            // The signed host must match what the transport sends, which omits a default port.
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

    pub fn key(&self, path: &str) -> String {
        format!("{}{}", self.config.prefix, path)
    }

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

    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let payload = if body.is_empty() {
            sigv4::EMPTY_SHA256.to_owned()
        } else {
            sigv4::sha256_hex(body)
        };
        self.send_hashed(method, key, query, extra, body, &payload)
    }

    fn send_hashed(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: &[u8],
        payload: &str,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let (host, path) = self.locate(key);
        let (amz_date, _) = sigv4::timestamp(now_secs());
        let creds = &self.config.credentials;
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", &host),
            ("x-amz-content-sha256", payload),
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
                payload_sha256: payload,
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
        // The send budget is a total for the whole body, so a large part gets time in proportion to its size.
        let response = match send_budget(body.len() as u64, self.config.read_timeout) {
            Some(budget) => self.agent.run(
                self.agent
                    .configure_request(request)
                    .timeout_send_body(Some(budget))
                    .build(),
            ),
            None => self.agent.run(request),
        };
        response.map_err(|e| Error::Transient(transport(&e)))
    }

    fn refusal(status: u16, mut response: ureq::http::Response<ureq::Body>) -> Error {
        let body = response
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_vec()
            .unwrap_or_default();
        // Remote text is untrusted: only a short identifier survives, so it cannot inject text into errors.
        let code = xml::field(&body, "Code")
            .ok()
            .flatten()
            .and_then(|code| identifier(&code, MAX_CODE))
            .unwrap_or_else(|| format!("http_{status}"));
        let request_id = xml::field(&body, "RequestId")
            .ok()
            .flatten()
            .and_then(|id| identifier(&id, MAX_REQUEST_ID));
        let code = match request_id {
            Some(id) => format!("{code} (request {id})"),
            None => code,
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

    pub fn put_object(&self, key: &str, body: &[u8], metadata: &[(&str, &str)]) -> Result<String> {
        if body.len() as u64 > MAX_PART_BYTES {
            return Err(Error::Config("single upload above 5 GiB".into()));
        }
        let meta = Self::metadata_headers(metadata)?;
        let (sha256, md5) = body_hashes(body);
        let mut extra: Vec<(&str, &str)> =
            meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        extra.push(("content-md5", &md5));
        let response = Self::ok(self.send_hashed("PUT", Some(key), &[], &extra, body, &sha256)?)?;
        Ok(etag(&Self::header(&response, "etag").unwrap_or_default()))
    }

    pub fn create_multipart(&self, key: &str, metadata: &[(&str, &str)]) -> Result<String> {
        let meta = Self::metadata_headers(metadata)?;
        let extra: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let response = Self::ok(self.send("POST", Some(key), &[("uploads", "")], &extra, &[])?)?;
        xml::field(&Self::body(response)?, "UploadId")?
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or_else(|| Error::Protocol("no UploadId".into()))
    }

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
        let (sha256, md5) = body_hashes(body);
        let response = Self::ok(self.send_hashed(
            "PUT",
            Some(key),
            &[("partNumber", &n), ("uploadId", upload_id)],
            &[("content-md5", &md5)],
            body,
            &sha256,
        )?)?;
        Self::header(&response, "etag")
            .map(|e| etag(&e))
            .filter(|e| !e.is_empty())
            .ok_or_else(|| Error::Protocol("part without an ETag".into()))
    }

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

    pub fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        already_gone(
            Self::ok(self.send("DELETE", Some(key), &[("uploadId", upload_id)], &[], &[])?)
                .map(|_| ()),
            "NoSuchUpload",
        )
    }

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

    pub fn list_multipart_uploads(
        &self,
        prefix: &str,
        after: Option<(&str, &str)>,
    ) -> Result<UploadPage> {
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

    pub fn head_object(&self, key: &str) -> Result<Option<Head>> {
        let response = self.send("HEAD", Some(key), &[], &[], &[])?;
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
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

    pub fn get_object(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> Result<(u64, impl Read + use<>)> {
        let expected = range
            .map(|(a, b)| range_len(a, b).ok_or_else(|| Error::Config("invalid byte range".into())))
            .transpose()?;
        let header = range.map(|(a, b)| format!("bytes={a}-{b}"));
        let extra: Vec<(&str, &str)> = header.iter().map(|h| ("range", h.as_str())).collect();
        let response = Self::ok(self.send("GET", Some(key), &[], &extra, &[])?)?;
        let len: u64 = Self::header(&response, "content-length")
            .and_then(|l| l.parse().ok())
            .ok_or_else(|| Error::Protocol("GET without a length".into()))?;
        if expected.is_some_and(|expected| len != expected) {
            return Err(Error::Protocol("range answered with another length".into()));
        }
        let reader = response
            .into_body()
            .into_with_config()
            .limit(len.saturating_add(1))
            .reader();
        Ok((len, reader))
    }

    pub fn delete_object(&self, key: &str) -> Result<()> {
        already_gone(
            Self::ok(self.send("DELETE", Some(key), &[], &[], &[])?).map(|_| ()),
            "NoSuchKey",
        )
    }

    /// Streams the object into `out` in ranged reads of at most `chunk` bytes, each with its own timeout budget.
    /// Returns the object's length. A server that ignores `Range` answers the first read with the whole body, which is accepted.
    pub fn read_object(&self, key: &str, out: &mut dyn std::io::Write, chunk: u64) -> Result<u64> {
        let chunk = chunk.max(1);
        let mut offset = 0u64;
        loop {
            let last = offset.saturating_add(chunk - 1);
            let (total, len, mut reader) = match self.get_range(key, offset, last) {
                // An empty object has no satisfiable range; a plain read returns its empty body.
                Err(Error::Refused { status: 416, .. }) if offset == 0 => {
                    let (len, reader) = self.get_object(key, None)?;
                    (len, len, Box::new(reader) as Box<dyn Read>)
                }
                other => {
                    let (total, len, reader) = other?;
                    (total, len, Box::new(reader) as Box<dyn Read>)
                }
            };
            let copied = std::io::copy(&mut reader, out)
                .map_err(|e| Error::Transient(format!("read: {}", e.kind())))?;
            if copied != len {
                return Err(Error::Transient("read ended short".into()));
            }
            offset = offset.saturating_add(len);
            if offset >= total {
                return Ok(offset);
            }
            if len == 0 {
                return Err(Error::Protocol("range answered with no bytes".into()));
            }
        }
    }

    /// One ranged read. Returns the object's total length, this answer's length and its body.
    fn get_range(&self, key: &str, first: u64, last: u64) -> Result<(u64, u64, impl Read + use<>)> {
        let header = format!("bytes={first}-{last}");
        let response = Self::ok(self.send("GET", Some(key), &[], &[("range", &header)], &[])?)?;
        let len: u64 = Self::header(&response, "content-length")
            .and_then(|l| l.parse().ok())
            .ok_or_else(|| Error::Protocol("GET without a length".into()))?;
        let total = if response.status().as_u16() == 206 {
            let (a, b, total) = Self::header(&response, "content-range")
                .and_then(|v| content_range(&v))
                .ok_or_else(|| Error::Protocol("range answered without a Content-Range".into()))?;
            if a != first || range_len(a, b) != Some(len) || b >= total {
                return Err(Error::Protocol("range answered with another span".into()));
            }
            total
        } else if first == 0 {
            len
        } else {
            return Err(Error::Protocol("range ignored past the first read".into()));
        };
        let reader = response
            .into_body()
            .into_with_config()
            .limit(len.saturating_add(1))
            .reader();
        Ok((total, len, reader))
    }

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

pub fn content_md5(body: &[u8]) -> String {
    use base64::Engine as _;
    use md5::Digest as _;
    base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(body))
}

pub fn body_hashes(body: &[u8]) -> (String, String) {
    use base64::Engine as _;
    use md5::Digest as _;
    const CHUNK: usize = 64 << 10;
    let mut sha = ring::digest::Context::new(&ring::digest::SHA256);
    let mut md5 = md5::Md5::new();
    for chunk in body.chunks(CHUNK) {
        sha.update(chunk);
        md5.update(chunk);
    }
    (
        sigv4::hex(sha.finish().as_ref()),
        base64::engine::general_purpose::STANDARD.encode(md5.finalize()),
    )
}

pub fn default_timeouts() -> (Duration, Duration) {
    (Duration::from_secs(10), Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_walk_gives_the_same_hashes_as_two() {
        for len in [0usize, 1, 1000, 64 << 10, (64 << 10) + 1, 300_000] {
            let body: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            assert_eq!(
                body_hashes(&body),
                (sigv4::sha256_hex(&body), content_md5(&body)),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn a_part_gets_send_time_in_proportion_to_its_size() {
        let base = Duration::from_secs(60);
        assert_eq!(send_budget(16 << 20, base), None, "the default part fits");
        assert_eq!(send_budget(240 << 20, base), None, "exactly the base");
        assert_eq!(
            send_budget(512 << 20, base),
            Some(Duration::from_secs(128)),
            "the largest configurable part"
        );
        assert_eq!(send_budget(0, base), None);
    }

    #[test]
    fn content_ranges_parse_and_refuse_anything_else() {
        assert_eq!(content_range("bytes 0-99/1000"), Some((0, 99, 1000)));
        assert_eq!(content_range(" bytes 5-5/6 "), Some((5, 5, 6)));
        for bad in [
            "bytes 0-99/*",
            "items 0-1/2",
            "bytes 0-1",
            "bytes a-b/c",
            "",
        ] {
            assert_eq!(content_range(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_the_named_missing_thing_counts_as_already_gone() {
        let gone =
            |code: &str, expected: &str| already_gone(Err(Error::NotFound(code.into())), expected);
        assert!(gone("NoSuchKey (request AB12)", "NoSuchKey").is_ok());
        assert!(gone("NoSuchUpload", "NoSuchUpload").is_ok());
        for wrong in ["NoSuchBucket (request AB12)", "http_404", "NoSuchUpload"] {
            assert!(
                matches!(
                    gone(wrong, "NoSuchKey"),
                    Err(Error::Refused { status: 404, .. })
                ),
                "{wrong}"
            );
        }
        assert!(already_gone(Ok(()), "NoSuchKey").is_ok());
        assert!(matches!(
            already_gone(Err(Error::Transient("x".into())), "NoSuchKey"),
            Err(Error::Transient(_))
        ));
    }

    #[test]
    fn ranges_count_their_bytes_and_refuse_to_wrap() {
        assert_eq!(range_len(0, 0), Some(1));
        assert_eq!(range_len(1_000, 1_999), Some(1_000));
        assert_eq!(range_len(5, 4), None, "an inverted range");
        assert_eq!(range_len(0, u64::MAX), None, "one past what u64 counts");
        assert_eq!(range_len(1, u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn only_short_identifiers_survive_from_a_refusal() {
        assert_eq!(
            identifier("NoSuchUpload", MAX_CODE).as_deref(),
            Some("NoSuchUpload")
        );
        assert_eq!(
            identifier(" 4442587FB7D0A2F9 ", MAX_REQUEST_ID).as_deref(),
            Some("4442587FB7D0A2F9")
        );
        assert_eq!(identifier("", MAX_CODE), None);
        assert_eq!(identifier(&"A".repeat(MAX_CODE + 1), MAX_CODE), None);
        for hostile in [
            "Access Denied for key secret",
            "<script>",
            "Slow\nDown",
            "a/b",
            "caf\u{e9}",
        ] {
            assert_eq!(identifier(hostile, MAX_CODE), None, "{hostile:?}");
        }
    }
}
