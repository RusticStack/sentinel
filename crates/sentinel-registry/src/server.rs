//! The loopback endpoint: HTTP/1.1, one request per connection, `GET` and `HEAD` only.
//!
//! A hit is answered from disk. A miss is fetched from the upstream registry, verified, stored and then
//! answered from the stored copy, so what a client receives is always the copy the cache verified. Every
//! blob response is chunked and its terminating chunk is written only after the body hashes to the
//! digest it was requested by: a mismatched or truncated body ends the response without a complete
//! message, which the client reports as a failed pull, and the file is removed so the next pull fetches
//! it again.

use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    Error, Inner, Result,
    spec::{self, Digest, Reference, Route},
    store::{self, MAX_MANIFEST_BYTES},
};

const MAX_HEAD_BYTES: usize = 16 << 10;
const READ_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Connections served at once. A worker pulls a handful of images at a time; the rest wait in the queue
/// and the acceptor closes a connection it cannot queue rather than growing threads.
const HANDLERS: usize = 8;
const QUEUE: usize = 64;
const CHUNK: usize = 64 << 10;

const ACCEPT_INDEX: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

pub(crate) fn bind() -> Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", 0)).map_err(Error::Io)
}

/// The running endpoint. Dropping it stops the acceptor and the handlers.
pub struct Listener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    acceptor: Option<JoinHandle<()>>,
    handlers: Vec<JoinHandle<()>>,
}

impl Listener {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn start(
        listener: TcpListener,
        addr: SocketAddr,
        serve: impl Fn(TcpStream) + Send + Sync + 'static,
    ) -> Result<Listener> {
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(Queue::default());
        let serve = Arc::new(serve);
        let mut handlers = Vec::with_capacity(HANDLERS);
        for _ in 0..HANDLERS {
            let queue = Arc::clone(&queue);
            let serve = Arc::clone(&serve);
            handlers.push(thread::Builder::new().spawn(move || {
                while let Some(stream) = queue.take() {
                    serve(stream);
                }
            })?);
        }
        let acceptor = {
            let stop = Arc::clone(&stop);
            thread::Builder::new().spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = stream else {
                        break;
                    };
                    queue.put(stream);
                }
                queue.close();
            })?
        };
        Ok(Listener {
            addr,
            stop,
            acceptor: Some(acceptor),
            handlers,
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // The acceptor is blocked in `accept`: one connection of our own wakes it.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        // The acceptor closed the queue on its way out, so the handlers drain what is left and return.
        for handler in self.handlers.drain(..) {
            let _ = handler.join();
        }
    }
}

/// Connections waiting for a handler. A connection that arrives while every slot is taken is served
/// once a handler is free, up to [`QUEUE`]; past that the acceptor closes it rather than growing memory.
#[derive(Default)]
struct Queue {
    items: Mutex<VecDeque<TcpStream>>,
    wake: Condvar,
    closed: AtomicBool,
}

impl Queue {
    fn put(&self, stream: TcpStream) {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        if items.len() >= QUEUE {
            return;
        }
        items.push_back(stream);
        drop(items);
        self.wake.notify_one();
    }

    fn take(&self) -> Option<TcpStream> {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(stream) = items.pop_front() {
                return Some(stream);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            items = self.wake.wait(items).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_all();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Head,
}

#[derive(Debug)]
struct Request<'a> {
    method: Method,
    path: &'a str,
    authorization: Option<&'a str>,
    accept: Option<&'a str>,
    range: Option<&'a str>,
}

pub(crate) fn serve(inner: &Arc<Inner>, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut stream = stream;
    let Ok(head) = read_head(&mut stream) else {
        return;
    };
    let Some(request) = parse(&head) else {
        let _ = error_response(&mut stream, 400, "UNSUPPORTED", "malformed request");
        return;
    };
    let outcome = match spec::route(request.path) {
        Route::Ping => ping(&mut stream),
        Route::Refused { why, status } => error_response(&mut stream, status, "UNSUPPORTED", why),
        Route::Manifest {
            token,
            host,
            repo,
            reference,
        } => manifest(inner, &mut stream, &request, token, host, repo, reference),
        Route::Blob {
            token,
            host,
            repo,
            digest,
        } => blob(inner, &mut stream, &request, token, host, repo, digest),
    };
    if let Err(error) = outcome {
        // The status a client needs to see, when nothing has been written yet.
        let (status, code) = match &error {
            Error::OverBudget { .. } => (507, "DENIED"),
            Error::Corrupt(_) => (502, "DIGEST_INVALID"),
            Error::Upstream(_) => (502, "UNKNOWN"),
            Error::Io(_) | Error::Config(_) | Error::Refused(_) => (500, "UNKNOWN"),
        };
        let _ = error_response(&mut stream, status, code, &error.to_string());
    }
}

/// Resolves the scope token and the upstream registry a request names. A token this process did not
/// mint, or a registry the worker does not cache, is refused before anything is fetched.
fn target<'a>(
    inner: &Inner,
    token: &'a str,
    host: &str,
) -> std::result::Result<&'a str, &'static str> {
    if inner.scope_of(token).is_none() {
        return Err("the scope is not one this worker serves");
    }
    if inner.registry(host).is_none() {
        return Err("this registry is not one the worker caches");
    }
    Ok(token)
}

fn manifest(
    inner: &Arc<Inner>,
    stream: &mut TcpStream,
    request: &Request<'_>,
    token: &str,
    host: &str,
    repo: &str,
    reference: Reference<'_>,
) -> Result<()> {
    let Ok(token) = target(inner, token, host) else {
        return error_response(
            stream,
            404,
            "NAME_UNKNOWN",
            "this registry is not cached by the worker",
        );
    };
    match reference {
        Reference::Digest(digest) => {
            if let Some(entry) = inner.store.manifest(token, &digest) {
                return send_manifest(
                    stream,
                    request.method,
                    &entry.bytes,
                    &entry.media_type,
                    digest,
                );
            }
            fetch_manifest(inner, stream, request, token, host, repo, reference)
        }
        Reference::Tag(tag) => {
            if let Some(record) = inner.store.tag(token, repo, tag)
                && inner.store.fresh(&record, store::now_ms())
                && let Some(entry) = inner.store.manifest(token, &record.digest)
            {
                return send_manifest(
                    stream,
                    request.method,
                    &entry.bytes,
                    &entry.media_type,
                    record.digest,
                );
            }
            fetch_manifest(inner, stream, request, token, host, repo, reference)
        }
    }
}

fn fetch_manifest(
    inner: &Arc<Inner>,
    stream: &mut TcpStream,
    request: &Request<'_>,
    token: &str,
    host: &str,
    repo: &str,
    reference: Reference<'_>,
) -> Result<()> {
    let Some(registry) = inner.registry(host) else {
        return error_response(
            stream,
            404,
            "NAME_UNKNOWN",
            "this registry is not cached by the worker",
        );
    };
    let url = format!(
        "{}/v2/{}/manifests/{}",
        registry.upstream,
        repo,
        reference.text()
    );
    let fetched = inner
        .upstream
        .get("GET", &url, request.authorization, Some(ACCEPT_INDEX))?;
    match fetched.status {
        200 => {
            let mut body = Vec::with_capacity(4096);
            let declared_type = fetched.content_type.clone();
            fetched
                .into_reader()
                .take(MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|error| Error::Upstream(format!("manifest body: {}", error.kind())))?;
            if body.len() as u64 > MAX_MANIFEST_BYTES {
                return Err(Error::Upstream(
                    "the manifest is larger than the cache stores".into(),
                ));
            }
            let digest = Digest::of(&body);
            if let Reference::Digest(expected) = reference
                && expected != digest
            {
                return error_response(
                    stream,
                    502,
                    "DIGEST_INVALID",
                    "the upstream manifest does not hash to the digest it was requested by",
                );
            }
            let media_type = media_type(declared_type.as_deref(), &body);
            inner
                .store
                .put_manifest(token, &digest, &media_type, &body)?;
            if let Reference::Tag(tag) = reference {
                inner.store.put_tag(token, repo, tag, &digest)?;
            }
            send_manifest(stream, request.method, &body, &media_type, digest)
        }
        401 | 403 => relay_refusal(stream, fetched.status, fetched.challenge.as_deref()),
        404 => error_response(
            stream,
            404,
            "MANIFEST_UNKNOWN",
            "the upstream registry has no such manifest",
        ),
        status => Err(Error::Upstream(format!("answered {status} for a manifest"))),
    }
}

fn send_manifest(
    stream: &mut TcpStream,
    method: Method,
    body: &[u8],
    media_type: &str,
    digest: Digest,
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {media_type}\r\ncontent-length: {}\r\ndocker-content-digest: {digest}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    if method == Method::Get {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

fn blob(
    inner: &Arc<Inner>,
    stream: &mut TcpStream,
    request: &Request<'_>,
    token: &str,
    host: &str,
    repo: &str,
    digest: Digest,
) -> Result<()> {
    let Ok(token) = target(inner, token, host) else {
        return error_response(
            stream,
            404,
            "NAME_UNKNOWN",
            "this registry is not cached by the worker",
        );
    };
    match inner.store.blob(token, &digest) {
        Some((path, size)) => serve_blob(stream, request, &path, digest, size),
        None => fetch_blob(inner, stream, request, token, host, repo, digest),
    }
}

fn fetch_blob(
    inner: &Arc<Inner>,
    stream: &mut TcpStream,
    request: &Request<'_>,
    token: &str,
    host: &str,
    repo: &str,
    digest: Digest,
) -> Result<()> {
    let Some(registry) = inner.registry(host) else {
        return error_response(
            stream,
            404,
            "NAME_UNKNOWN",
            "this registry is not cached by the worker",
        );
    };
    let url = format!("{}/v2/{}/blobs/{}", registry.upstream, repo, digest);
    let fetched = inner
        .upstream
        .get("GET", &url, request.authorization, None)?;
    match fetched.status {
        200 => {
            let mut staging =
                inner
                    .store
                    .begin(token, digest, fetched.content_length, &part_name())?;
            let mut reader = fetched.into_reader();
            let mut chunk = vec![0u8; CHUNK];
            loop {
                let read = reader
                    .read(&mut chunk)
                    .map_err(|error| Error::Upstream(format!("blob body: {}", error.kind())))?;
                if read == 0 {
                    break;
                }
                staging.write(&chunk[..read])?;
            }
            let path = staging.commit()?;
            let size = std::fs::symlink_metadata(&path)?.len();
            serve_blob(stream, request, &path, digest, size)
        }
        401 | 403 => relay_refusal(stream, fetched.status, fetched.challenge.as_deref()),
        404 => error_response(
            stream,
            404,
            "BLOB_UNKNOWN",
            "the upstream registry has no such blob",
        ),
        status => Err(Error::Upstream(format!("answered {status} for a blob"))),
    }
}

fn serve_blob(
    stream: &mut TcpStream,
    request: &Request<'_>,
    path: &Path,
    digest: Digest,
    size: u64,
) -> Result<()> {
    if request.method == Method::Head {
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {size}\r\ndocker-content-digest: {digest}\r\nconnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes())?;
        stream.flush()?;
        return Ok(());
    }
    let Some(range) = request.range else {
        return send_blob_verified(stream, path, digest, size);
    };
    // A range names part of a body, so the file is verified whole first: the bytes handed out are then
    // known to belong to the digest, not merely to the file they were cut from.
    verify_file(path, digest)?;
    let Some((start, length)) = parse_range(range, size) else {
        let head = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\ncontent-range: bytes */{size}\r\nconnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes())?;
        return Ok(());
    };
    let mut file = File::open(path)?;
    use std::io::Seek as _;
    file.seek(io::SeekFrom::Start(start))?;
    let head = format!(
        "HTTP/1.1 206 Partial Content\r\ncontent-type: application/octet-stream\r\ncontent-length: {length}\r\ncontent-range: bytes {start}-{}/{size}\r\ndocker-content-digest: {digest}\r\nconnection: close\r\n\r\n",
        start + length - 1
    );
    stream.write_all(head.as_bytes())?;
    let copied = io::copy(&mut file.take(length), stream)?;
    if copied != length {
        return Err(Error::Corrupt(
            "the stored blob is shorter than its length".into(),
        ));
    }
    stream.flush()?;
    Ok(())
}

/// Streams a whole blob, hashing what it sends. The terminating chunk is withheld when the body does not
/// hash to `digest`, so the client sees an incomplete response instead of a body it might accept.
fn send_blob_verified(
    stream: &mut TcpStream,
    path: &Path,
    digest: Digest,
    size: u64,
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ntransfer-encoding: chunked\r\ndocker-content-digest: {digest}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes())?;
    let mut file = File::open(path)?;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    let mut chunk = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        sent += read as u64;
        if sent > size {
            return Err(Error::Corrupt(
                "the stored blob is longer than its length".into(),
            ));
        }
        hasher.update(&chunk[..read]);
        write_chunk(stream, &chunk[..read])?;
    }
    if Digest::of_finished(&hasher) != digest || sent != size {
        let _ = std::fs::remove_file(path);
        return Err(Error::Corrupt(
            "the stored blob no longer matches the digest it is stored under".into(),
        ));
    }
    let _ = File::open(path).and_then(|file| file.set_modified(std::time::SystemTime::now()));
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

fn verify_file(path: &Path, digest: Digest) -> Result<()> {
    let mut file = File::open(path)?;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    if Digest::of_finished(&hasher) == digest {
        return Ok(());
    }
    let _ = std::fs::remove_file(path);
    Err(Error::Corrupt(format!("the stored blob {digest}")))
}

fn write_chunk(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    // One small allocation per 64 KiB chunk: the hex length is the only variable-size part of the frame.
    let mut frame = Vec::with_capacity(9);
    write!(frame, "{:x}\r\n", bytes.len())?;
    stream.write_all(&frame)?;
    stream.write_all(bytes)?;
    stream.write_all(b"\r\n")
}

/// `bytes=a-b`, `bytes=a-`, `bytes=-n`, single range only.
fn parse_range(text: &str, size: u64) -> Option<(u64, u64)> {
    let spec = text.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (from, to) = spec.split_once('-')?;
    let (start, end) = match (from.trim(), to.trim()) {
        ("", "") => return None,
        ("", suffix) => {
            let suffix: u64 = suffix.parse().ok()?;
            if suffix == 0 {
                return None;
            }
            (size.saturating_sub(suffix), size)
        }
        (start, "") => (start.parse().ok()?, size),
        (start, end) => {
            let start: u64 = start.parse().ok()?;
            let end: u64 = end.parse().ok()?;
            if end < start {
                return None;
            }
            (start, (end + 1).min(size))
        }
    };
    (start < size && start < end).then(|| (start, end - start))
}

fn ping(stream: &mut TcpStream) -> Result<()> {
    let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\ndocker-distribution-api-version: registry/2.0\r\nconnection: close\r\n\r\n{}";
    stream.write_all(head.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn relay_refusal(stream: &mut TcpStream, status: u16, challenge: Option<&str>) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-length: 0\r\nconnection: close\r\n",
        reason(status)
    );
    if let Some(challenge) = challenge {
        // The client answers this challenge itself: a bearer token comes from the registry's token
        // service, so the cache never sees a credential it would have to keep.
        if !challenge
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b.is_ascii_control())
        {
            head.push_str("www-authenticate: ");
            head.push_str(challenge);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn error_response(stream: &mut TcpStream, status: u16, code: &str, message: &str) -> Result<()> {
    let body = oci_error(code, message);
    let head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn oci_error(code: &str, message: &str) -> Vec<u8> {
    let mut out = String::with_capacity(64 + message.len());
    out.push_str("{\"errors\":[{\"code\":\"");
    out.push_str(code);
    out.push_str("\",\"message\":\"");
    for ch in message.chars().take(256) {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            other if other.is_control() => out.push(' '),
            other => out.push(other),
        }
    }
    out.push_str("\"}]}");
    out.into_bytes()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        507 => "Insufficient Storage",
        _ => "Error",
    }
}

fn media_type(declared: Option<&str>, body: &[u8]) -> String {
    if let Some(declared) = declared {
        let trimmed = declared.trim();
        if !trimmed.is_empty() && !trimmed.contains(' ') {
            return trimmed.to_owned();
        }
    }
    // An upstream that states no media type still has to be answered with one the client accepts.
    let text = String::from_utf8_lossy(&body[..body.len().min(4096)]);
    if text.contains("\"manifests\"") {
        "application/vnd.oci.image.index.v1+json".to_owned()
    } else {
        "application/vnd.oci.image.manifest.v1+json".to_owned()
    }
}

fn part_name() -> String {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        return format!("part-{}", std::process::id());
    }
    Digest::of(&bytes).hex()
}

fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while buffer.len() < MAX_HEAD_BYTES {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buffer).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "request head is not utf-8")
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "request head is incomplete",
    ))
}

fn parse(head: &str) -> Option<Request<'_>> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = match parts.next()? {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        _ => return None,
    };
    let path = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return None;
    }
    let mut request = Request {
        method,
        path,
        authorization: None,
        accept: None,
        range: None,
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "authorization" => request.authorization = Some(value),
            "accept" => request.accept = Some(value),
            "range" => request.range = Some(value),
            _ => {}
        }
    }
    Some(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_name_one_slice_or_nothing() {
        assert_eq!(parse_range("bytes=0-9", 100), Some((0, 10)));
        assert_eq!(parse_range("bytes=90-", 100), Some((90, 10)));
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 10)));
        assert_eq!(parse_range("bytes=0-1000", 100), Some((0, 100)));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(parse_range("bytes=5-4", 100), None);
        assert_eq!(parse_range("bytes=0-1,4-5", 100), None);
        assert_eq!(parse_range("items=0-9", 100), None);
        assert_eq!(parse_range("bytes=0-9", 0), None);
    }

    #[test]
    fn a_request_names_its_method_path_and_the_headers_the_pull_needs() {
        let head = "GET /v2/aa/docker.io/x/y/manifests/1.0 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\nRange: bytes=0-1\r\n\r\n";
        let request = parse(head).unwrap();
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.authorization, Some("Bearer t"));
        assert_eq!(request.range, Some("bytes=0-1"));
        assert!(parse("PUT / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse("GET / HTTP/2\r\n\r\n").is_none());
        assert!(parse("GET /").is_none());
    }

    #[test]
    fn an_error_body_is_json_a_client_can_read_and_carries_no_control_bytes() {
        let body = oci_error("NAME_UNKNOWN", "a \"quoted\" name\nwith a newline");
        let text = String::from_utf8(body).unwrap();
        assert_eq!(
            text,
            "{\"errors\":[{\"code\":\"NAME_UNKNOWN\",\"message\":\"a \\\"quoted\\\" name with a newline\"}]}"
        );
    }
}
