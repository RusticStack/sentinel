//! The HTTP/1.1 the pinned clients speak, and nothing more: one request at a time on a kept-alive
//! connection, a head bounded long before it could hold a body, a body streamed into the store as it
//! arrives, and responses that always state their length so a client's keep-alive agent never waits.
//!
//! The clients this exists for are `@actions/http-client` (JSON bodies, streamed `PATCH` chunks sent
//! with chunked transfer encoding) and `@azure/storage-blob` (block uploads with `Content-Length`), so
//! both framings are read, and nothing else is invented.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

pub const MAX_HEAD: usize = 32 << 10;
/// The most a JSON body may occupy: every request the services send as JSON is far below this.
pub const MAX_JSON_BODY: usize = 1 << 20;
const BUFFER: usize = 64 << 10;

pub struct Conn<S> {
    stream: S,
    buf: Vec<u8>,
    at: usize,
    end: usize,
}

impl<S: Read + Write> Conn<S> {
    pub fn new(stream: S) -> Conn<S> {
        Conn {
            stream,
            buf: vec![0u8; BUFFER],
            at: 0,
            end: 0,
        }
    }

    fn fill(&mut self) -> io::Result<usize> {
        if self.at > 0 && self.at == self.end {
            self.at = 0;
            self.end = 0;
        }
        if self.at > 0 && self.end == self.buf.len() {
            self.buf.copy_within(self.at..self.end, 0);
            self.end -= self.at;
            self.at = 0;
        }
        let read = self.stream.read(&mut self.buf[self.end..])?;
        self.end += read;
        Ok(read)
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    /// Reads one request head. `Ok(None)` is a connection a client closed between requests.
    pub fn head(&mut self) -> io::Result<Option<String>> {
        loop {
            if let Some(end) = find_head(&self.buf[self.at..self.end]) {
                let text = String::from_utf8_lossy(&self.buf[self.at..self.at + end]).into_owned();
                self.at += end;
                return Ok(Some(text));
            }
            if self.end - self.at > MAX_HEAD {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if self.fill()? == 0 {
                return Ok(None);
            }
        }
    }

    pub fn read_into(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.end && self.fill()? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let take = out.len().min(self.end - self.at);
        out[..take].copy_from_slice(&self.buf[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }

    /// Reads a line terminated by CRLF, bounded: a chunk size line is 20 bytes and anything near the
    /// bound is not one.
    fn line(&mut self) -> io::Result<String> {
        let mut out = Vec::with_capacity(24);
        loop {
            if self.at == self.end && self.fill()? == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            while self.at < self.end {
                let byte = self.buf[self.at];
                self.at += 1;
                if byte == b'\n' {
                    if out.last() == Some(&b'\r') {
                        out.pop();
                    }
                    return String::from_utf8(out)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
                }
                out.push(byte);
                if out.len() > 512 {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
            }
        }
    }
}

/// One parsed request: the head's facts and a body that is read on demand.
pub struct Request<'a, S: Read + Write> {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: String,
    pub version: (u8, u8),
    pub headers: Vec<(String, String)>,
    pub body: Body<'a, S>,
}

impl<'a, S: Read + Write> Request<'a, S> {
    pub fn parse(conn: &'a mut Conn<S>, head: &str) -> Option<Request<'a, S>> {
        let mut lines = head.split("\r\n");
        let mut line = lines.next()?.split(' ');
        let method = line.next()?.to_owned();
        let target = line.next()?.to_owned();
        let version = match line.next()? {
            "HTTP/1.1" => (1, 1),
            "HTTP/1.0" => (1, 0),
            _ => return None,
        };
        if method.is_empty() || method.len() > 16 {
            return None;
        }
        let mut headers = Vec::with_capacity(8);
        for header in lines {
            if header.is_empty() {
                continue;
            }
            let (name, value) = header.split_once(':')?;
            if name.len() > 64 || value.len() > 8 << 10 {
                return None;
            }
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path.to_owned(), query.to_owned()),
            None => (target.clone(), String::new()),
        };
        let chunked = headers.iter().any(|(name, value)| {
            name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked")
        });
        let remaining = if chunked {
            None
        } else {
            let stated = headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .map(|(_, value)| value.parse::<u64>().ok());
            match stated {
                Some(Some(len)) => Some(len),
                Some(None) => return None,
                None => Some(0),
            }
        };
        Some(Request {
            method,
            target,
            path,
            query,
            version,
            headers,
            body: Body {
                conn,
                remaining,
                chunked,
                done: false,
            },
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn keep_alive(&self) -> bool {
        let stated = self
            .header("connection")
            .map(|value| value.to_ascii_lowercase());
        match stated.as_deref() {
            Some("close") => false,
            Some("keep-alive") => true,
            _ => self.version >= (1, 1),
        }
    }

    /// The query's named parameter, percent-decoded. A parameter stated twice is the first one, as the
    /// services parse it.
    pub fn param(&self, name: &str) -> Option<String> {
        for pair in self.query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if percent_decode(key) == name {
                return Some(percent_decode(value));
            }
        }
        None
    }
}

/// A request body: `Content-Length` framed, chunked, or absent.
pub struct Body<'a, S: Read + Write> {
    conn: &'a mut Conn<S>,
    remaining: Option<u64>,
    /// Whether the body is framed by chunk sizes: `remaining` is the current chunk's, or `None` for
    /// a length-framed body.
    chunked: bool,
    done: bool,
}

impl<S: Read + Write> Body<'_, S> {
    /// The body's declared length, when it is framed by one.
    pub fn declared(&self) -> Option<u64> {
        if self.chunked { None } else { self.remaining }
    }

    /// Whether the body arrives in chunks, as the cache client's streamed upload does.
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// Reads what has arrived into `out`, `Ok(0)` at the end of the body.
    pub fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        if let Some(remaining) = self.remaining {
            if remaining == 0 {
                self.done = true;
                return Ok(0);
            }
            let take = out.len().min(remaining as usize);
            let read = self.conn.read_into(&mut out[..take])?;
            self.remaining = Some(remaining - read as u64);
            return Ok(read);
        }
        // Chunked: size line, data, CRLF, until a zero chunk.
        let size = loop {
            let line = self.conn.line()?;
            if line.is_empty() {
                continue;
            }
            let digits = line.split(';').next().unwrap_or("").trim();
            break usize::from_str_radix(digits, 16)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        };
        if size == 0 {
            // Trailer headers end at an empty line.
            while !self.conn.line()?.is_empty() {}
            self.done = true;
            return Ok(0);
        }
        let take = out.len().min(size);
        let read = self.conn.read_into(&mut out[..take])?;
        if read < size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if read == size {
            let _ = self.conn.line()?;
        }
        Ok(read)
    }

    /// Reads the whole body, refusing one larger than `max`.
    pub fn read_all(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.declared().unwrap_or(0).min(max as u64) as usize);
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let read = self.read(&mut buf)?;
            if read == 0 {
                return Ok(out);
            }
            if out.len() + read > max {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            out.extend_from_slice(&buf[..read]);
        }
    }

    /// Streams the body into `sink` in arrival order, answering the bytes taken.
    pub fn stream<F>(&mut self, mut sink: F) -> io::Result<u64>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut buf = vec![0u8; BUFFER];
        let mut total = 0u64;
        loop {
            let read = self.read(&mut buf)?;
            if read == 0 {
                return Ok(total);
            }
            sink(&buf[..read])?;
            total += read as u64;
        }
    }

    /// Reads and drops the body, so a kept-alive connection starts its next request where the next
    /// head begins.
    pub fn discard(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        while self.read(&mut buf)? != 0 {}
        Ok(())
    }
}

#[derive(Debug)]
pub enum Payload {
    Bytes(Vec<u8>),
    File { path: PathBuf, len: u64 },
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Payload,
}

impl Response {
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Vec::with_capacity(3),
            body: Payload::Bytes(Vec::new()),
        }
    }

    pub fn bytes(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: Vec::with_capacity(3),
            body: Payload::Bytes(body.into()),
        }
    }

    pub fn json(status: u16, body: &serde_json::Value) -> Response {
        let mut response = Response::bytes(status, serde_json::to_vec(body).unwrap_or_default());
        response
            .headers
            .push(("Content-Type", "application/json".to_owned()));
        response
    }

    pub fn file(status: u16, path: PathBuf, len: u64) -> Response {
        Response {
            status,
            headers: Vec::with_capacity(3),
            body: Payload::File { path, len },
        }
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Response {
        self.headers.push((name, value.into()));
        self
    }

    pub fn write<S: Read + Write>(&self, conn: &mut Conn<S>, head: bool) -> io::Result<()> {
        let mut out = Vec::with_capacity(192);
        let reason = reason(self.status);
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(reason.as_bytes());
        out.extend_from_slice(b"\r\n");
        let len = match &self.body {
            Payload::Bytes(bytes) => bytes.len() as u64,
            Payload::File { len, .. } => *len,
        };
        if head {
            out.extend_from_slice(format!("Content-Length: {len}\r\n").as_bytes());
        } else {
            out.extend_from_slice(b"Connection: close\r\nContent-Length: 0\r\n");
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        conn.write_all(&out)?;
        if !head {
            return Ok(());
        }
        match &self.body {
            Payload::Bytes(bytes) => conn.write_all(bytes),
            Payload::File { path, .. } => {
                let mut file = File::open(path)?;
                let mut buf = vec![0u8; BUFFER];
                loop {
                    match file.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Ok(n) => conn.write_all(&buf[..n])?,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Percent-decoding of a query component: `%XX` and `+` as a space, as a form query spells them.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' if at + 2 < bytes.len() => {
                let high = hex_value(bytes[at + 1]);
                let low = hex_value(bytes[at + 2]);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        at += 3;
                    }
                    _ => {
                        out.push(b'%');
                        at += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    Some(match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => return None,
    })
}

/// The offset in `bytes` just past the blank line that ends a head.
fn find_head(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn parse(raw: &[u8]) -> (String, String, String, Vec<u8>) {
        let mut conn = Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let mut request = Request::parse(&mut conn, &head).unwrap();
        let body = request.body.read_all(1 << 20).unwrap();
        (request.method, request.path, request.query, body)
    }

    #[test]
    fn a_json_post_with_a_length_reads_whole() {
        let raw = format!(
            "POST /twirp/x/CreateArtifact HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"name\":\"logs\",\"version\":4}}",
            "{\"name\":\"logs\",\"version\":4}".len()
        );
        let raw = raw.as_bytes();
        let (method, path, query, body) = parse(raw);
        assert_eq!(
            (method.as_str(), path.as_str(), query.as_str()),
            ("POST", "/twirp/x/CreateArtifact", "")
        );
        assert_eq!(body, b"{\"name\":\"logs\",\"version\":4}");
    }

    /// The pinned cache client streams its chunk with chunked transfer encoding, so that framing is
    /// read rather than refused.
    #[test]
    fn a_chunked_patch_reads_its_chunks_in_order() {
        let raw = b"PATCH /_apis/artifactcache/caches/7 HTTP/1.1\r\nContent-Range: bytes 0-7/*\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n";
        let (method, path, _, body) = parse(raw);
        assert_eq!(method, "PATCH");
        assert_eq!(path, "/_apis/artifactcache/caches/7");
        assert_eq!(body, b"ABCDEFGH");
    }

    #[test]
    fn the_query_is_percent_decoded_as_the_cache_client_encodes_it() {
        let mut conn = Conn::new(Cursor::new(
            b"GET /_apis/artifactcache/cache?keys=cargo-main%2Cfallback&version=abc HTTP/1.1\r\n\r\n"
                .to_vec(),
        ));
        let head = conn.head().unwrap().unwrap();
        let request = Request::parse(&mut conn, &head).unwrap();
        assert_eq!(
            request.param("keys").as_deref(),
            Some("cargo-main,fallback")
        );
        assert_eq!(request.param("version").as_deref(), Some("abc"));
        assert!(request.param("missing").is_none());
    }

    #[test]
    fn two_requests_on_one_connection_keep_their_bodies_apart() {
        let raw = b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let mut conn = Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let mut first = Request::parse(&mut conn, &head).unwrap();
        assert_eq!(first.body.read_all(16).unwrap(), b"abc");
        drop(first);
        let head = conn.head().unwrap().unwrap();
        let request = Request::parse(&mut conn, &head).unwrap();
        assert_eq!(request.path, "/b");
        assert!(request.keep_alive());
    }

    #[test]
    fn a_head_without_a_length_carries_no_body_and_a_close_is_honoured() {
        let raw = b"GET /_apis/artifactcache/cache?keys=a HTTP/1.0\r\nConnection: close\r\n\r\n";
        let mut conn = Conn::new(Cursor::new(raw.to_vec()));
        let head = conn.head().unwrap().unwrap();
        let request = Request::parse(&mut conn, &head).unwrap();
        assert!(!request.keep_alive());
        assert_eq!(request.body.declared(), Some(0));
    }

    #[test]
    fn a_response_states_its_length_and_a_file_is_streamed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive");
        std::fs::write(&path, b"payload").unwrap();
        let mut conn = Conn::new(Cursor::new(Vec::new()));
        Response::file(200, path, 7).write(&mut conn, true).unwrap();
        let written = conn.stream.into_inner();
        assert!(written.starts_with(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"));
        assert!(written.ends_with(b"payload"));
    }
}
