use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    io::{self, BufRead, BufReader, Cursor, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::oauth::limit::{TrustedProxy, client_key, is_proxy};

#[derive(Clone, Copy)]
pub(crate) struct Tune {
    pub connections: usize,
    pub handlers: usize,
    pub head_bytes: usize,
    pub head_time: Duration,
    pub body_time: Duration,
    pub public_bodies: usize,
    pub public_body_time: Duration,
    pub per_peer: usize,
    pub write_stall: Duration,
    pub poll: Duration,
}

impl Tune {
    pub(crate) const DEFAULT: Tune = Tune {
        connections: crate::CONNECTIONS,
        handlers: crate::WORKERS,
        head_bytes: 16 << 10,
        head_time: Duration::from_secs(15),
        body_time: Duration::from_secs(120),
        public_bodies: crate::PUBLIC_BODIES,
        public_body_time: Duration::from_secs(10),
        per_peer: crate::CONNECTIONS_PER_PEER,
        write_stall: Duration::from_secs(60),
        poll: Duration::from_millis(100),
    };
}

struct Pool {
    free: Mutex<usize>,
    total: usize,
    wake: Condvar,
}

impl Pool {
    fn new(count: usize) -> Arc<Pool> {
        Arc::new(Pool {
            free: Mutex::new(count),
            total: count,
            wake: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>, stop: &AtomicBool, poll: Duration) -> Option<Permit> {
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *free > 0 {
                *free -= 1;
                return Some(Permit(Arc::clone(self)));
            }
            if stop.load(Ordering::Acquire) {
                return None;
            }
            let (guard, _) = self
                .wake
                .wait_timeout(free, poll)
                .unwrap_or_else(|e| e.into_inner());
            free = guard;
        }
    }

    fn acquire_until(
        self: &Arc<Self>,
        stop: &AtomicBool,
        poll: Duration,
        until: Instant,
    ) -> Option<Permit> {
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *free > 0 {
                *free -= 1;
                return Some(Permit(Arc::clone(self)));
            }
            let left = until.checked_duration_since(Instant::now())?;
            if stop.load(Ordering::Acquire) {
                return None;
            }
            let (guard, _) = self
                .wake
                .wait_timeout(free, left.min(poll))
                .unwrap_or_else(|e| e.into_inner());
            free = guard;
        }
    }

    fn wait_full(&self, poll: Duration) {
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        while *free != self.total {
            let (guard, _) = self
                .wake
                .wait_timeout(free, poll)
                .unwrap_or_else(|e| e.into_inner());
            free = guard;
        }
    }
}

struct Gate {
    handlers: Arc<Pool>,
    bodies: Arc<Pool>,
    body_time: Duration,
    readers: Arc<Mutex<HashSet<u128>>>,
    trusted: Vec<TrustedProxy>,
}

struct ReaderKey {
    readers: Arc<Mutex<HashSet<u128>>>,
    key: u128,
}

impl ReaderKey {
    fn take(readers: &Arc<Mutex<HashSet<u128>>>, key: u128) -> Option<ReaderKey> {
        let mut held = readers.lock().unwrap_or_else(|e| e.into_inner());
        held.insert(key).then(|| ReaderKey {
            readers: Arc::clone(readers),
            key,
        })
    }
}

impl Drop for ReaderKey {
    fn drop(&mut self) {
        self.readers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

struct Permit(Arc<Pool>);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut free = self.0.free.lock().unwrap_or_else(|e| e.into_inner());
        *free += 1;
        drop(free);
        self.0.wake.notify_all();
    }
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct Field(String);

impl Field {
    pub(crate) fn equiv(&self, name: &str) -> bool {
        self.0.eq_ignore_ascii_case(name)
    }
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct Value(String);

impl Value {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg_attr(test, derive(Debug))]
pub(crate) struct Header {
    pub(crate) field: Field,
    pub(crate) value: Value,
}

impl Header {
    pub(crate) fn from_bytes(name: &[u8], value: &[u8]) -> Option<Header> {
        let name = std::str::from_utf8(name).ok()?;
        if name.is_empty() || !name.bytes().all(token) {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return None;
        }
        Some(Header {
            field: Field(name.to_owned()),
            value: Value(value.to_owned()),
        })
    }
}

fn token(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

pub(crate) struct StatusCode(pub u16);

pub(crate) struct Response {
    status: u16,
    headers: Vec<Header>,
    data: Box<dyn Read + Send>,
    len: Option<u64>,
}

impl Response {
    pub(crate) fn from_string(body: impl Into<String>) -> Response {
        let body = body.into();
        Response {
            status: 200,
            headers: Vec::new(),
            len: Some(body.len() as u64),
            data: Box::new(io::Cursor::new(body.into_bytes())),
        }
    }

    pub(crate) fn new<R: Read + Send + 'static>(
        status: StatusCode,
        headers: Vec<Header>,
        data: R,
        len: Option<usize>,
        content_type: Option<Header>,
    ) -> Response {
        let mut headers = headers;
        if let Some(h) = content_type {
            headers.push(h);
        }
        Response {
            status: status.0,
            headers,
            data: Box::new(data),
            len: len.map(|n| n as u64),
        }
    }

    pub(crate) fn with_status_code(mut self, code: StatusCode) -> Response {
        self.status = code.0;
        self
    }

    pub(crate) fn with_header(mut self, header: Header) -> Response {
        self.headers.push(header);
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        302 => "Found",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Large",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => "Status",
    }
}

/// Windows: a shutdown does not reliably wake a timed recv, so the timeout itself is the wakeup.
fn rearm(socket: &TcpStream, deadline: Instant, poll: Duration) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline"));
    }
    socket.set_read_timeout(Some(left.min(poll)))
}

fn timed_out(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
}

fn timed_read(
    r: &mut (impl Read + ?Sized),
    socket: &TcpStream,
    stop: &AtomicBool,
    poll: Duration,
    deadline: Instant,
    buf: &mut [u8],
) -> io::Result<usize> {
    loop {
        rearm(socket, deadline, poll)?;
        match r.read(buf) {
            Err(e) if timed_out(&e) => {
                if stop.load(Ordering::Acquire) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "stopping"));
                }
            }
            other => return other,
        }
    }
}

fn bounded_line(
    r: &mut dyn BufRead,
    socket: &TcpStream,
    cap: usize,
    deadline: Instant,
    stop: &AtomicBool,
    poll: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        if buf.len() > cap {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        rearm(socket, deadline, poll)?;
        match r
            .take((cap + 1 - buf.len()) as u64)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) => {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "line"))
                };
            }
            Ok(_) => {
                if buf.ends_with(b"\n") {
                    return Ok(Some(buf));
                }
            }
            Err(e) if timed_out(&e) => {
                if stop.load(Ordering::Acquire) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "stopping"));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

enum Body<'a> {
    Empty,
    Fixed(Limited<'a>),
    Chunked(Chunked<'a>),
    Internal(Cursor<Vec<u8>>),
}

impl Body<'_> {
    fn cap_deadline(&mut self, deadline: Instant) {
        match self {
            Body::Fixed(f) => f.deadline = f.deadline.min(deadline),
            Body::Chunked(c) => c.l.deadline = c.l.deadline.min(deadline),
            Body::Empty | Body::Internal(_) => {}
        }
    }

    fn drained(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Fixed(f) => f.left == 0,
            Body::Chunked(c) => c.done,
            Body::Internal(c) => c.position() == c.get_ref().len() as u64,
        }
    }
}

impl Read for Body<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Empty => Ok(0),
            Body::Fixed(f) => f.read(buf),
            Body::Chunked(c) => c.read(buf),
            Body::Internal(c) => c.read(buf),
        }
    }
}

struct Limited<'a> {
    r: &'a mut dyn BufRead,
    socket: &'a TcpStream,
    stop: &'a AtomicBool,
    poll: Duration,
    left: u64,
    deadline: Instant,
}

impl Read for Limited<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let mut take = self.r.take(self.left);
        let n = timed_read(
            &mut take,
            self.socket,
            self.stop,
            self.poll,
            self.deadline,
            buf,
        )?;
        self.left -= n as u64;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "body shorter than content-length",
            ));
        }
        Ok(n)
    }
}

struct Chunked<'a> {
    l: Limited<'a>,
    state: u8,
    trailers: usize,
    done: bool,
}

impl Chunked<'_> {
    fn eof() -> io::Error {
        io::Error::new(io::ErrorKind::UnexpectedEof, "chunked body")
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                0 => {
                    let line = bounded_line(
                        self.l.r,
                        self.l.socket,
                        64,
                        self.l.deadline,
                        self.l.stop,
                        self.l.poll,
                    )?
                    .ok_or_else(Self::eof)?;
                    let size = std::str::from_utf8(&line)
                        .ok()
                        .and_then(|l| l.trim_end().split(';').next())
                        .and_then(|s| parse_digits(s, 16))
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "bad chunk size")
                        })?;
                    if size == 0 {
                        self.state = 3;
                    } else {
                        self.l.left = size;
                        self.state = 1;
                    }
                }
                1 => {
                    let mut take = self.l.r.take(self.l.left);
                    let n = timed_read(
                        &mut take,
                        self.l.socket,
                        self.l.stop,
                        self.l.poll,
                        self.l.deadline,
                        buf,
                    )?;
                    if n == 0 {
                        return Err(Self::eof());
                    }
                    self.l.left -= n as u64;
                    if self.l.left == 0 {
                        self.state = 2;
                    }
                    return Ok(n);
                }
                2 => {
                    let mut crlf = [0u8; 2];
                    let mut got = 0;
                    while got < 2 {
                        match timed_read(
                            self.l.r,
                            self.l.socket,
                            self.l.stop,
                            self.l.poll,
                            self.l.deadline,
                            &mut crlf[got..],
                        )? {
                            0 => return Err(Self::eof()),
                            n => got += n,
                        }
                    }
                    if &crlf != b"\r\n" {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk CRLF"));
                    }
                    self.state = 0;
                }
                _ => match bounded_line(
                    self.l.r,
                    self.l.socket,
                    8 << 10,
                    self.l.deadline,
                    self.l.stop,
                    self.l.poll,
                )? {
                    Some(line) if line == b"\r\n" => {
                        self.done = true;
                        return Ok(0);
                    }
                    Some(line) => {
                        self.trailers += line.len();
                        if self.trailers > 8 << 10 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "trailers too long",
                            ));
                        }
                    }
                    None => return Err(Self::eof()),
                },
            }
        }
    }
}

#[cfg_attr(test, derive(Debug))]
enum HeadErr {
    Closed,
    Timeout,
    Status(u16),
}

fn head_line(
    r: &mut dyn BufRead,
    socket: &TcpStream,
    budget: usize,
    deadline: Instant,
    stop: &AtomicBool,
    poll: Duration,
) -> Result<Vec<u8>, HeadErr> {
    match bounded_line(r, socket, budget, deadline, stop, poll) {
        Ok(Some(line)) => Ok(line),
        Ok(None) => Err(HeadErr::Closed),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(HeadErr::Status(431)),
        Err(e) if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => {
            Err(HeadErr::Timeout)
        }
        Err(_) => Err(HeadErr::Closed),
    }
}

#[cfg_attr(test, derive(Debug))]
struct Head {
    method: String,
    url: String,
    headers: Vec<Header>,
    length: Option<u64>,
    chunked: bool,
    close: bool,
    expect_continue: bool,
}

fn head(
    r: &mut BufReader<&TcpStream>,
    socket: &TcpStream,
    tune: Tune,
    stop: &AtomicBool,
) -> Result<Head, HeadErr> {
    let deadline = Instant::now() + tune.head_time;
    let mut total = 0usize;
    let mut next = |r: &mut dyn BufRead| -> Result<Vec<u8>, HeadErr> {
        let line = head_line(
            r,
            socket,
            tune.head_bytes.saturating_sub(total),
            deadline,
            stop,
            tune.poll,
        )?;
        total += line.len();
        Ok(line)
    };

    let mut first = next(r)?;
    while first == b"\r\n" {
        first = next(r)?;
    }
    if !first.ends_with(b"\r\n") {
        return Err(HeadErr::Status(400));
    }
    let request =
        std::str::from_utf8(&first[..first.len() - 2]).map_err(|_| HeadErr::Status(400))?;
    let mut parts = request.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None)
            if !m.is_empty() && m.len() <= 64 && m.bytes().all(token) =>
        {
            (m.to_owned(), t.to_owned(), v)
        }
        _ => return Err(HeadErr::Status(400)),
    };
    let mut close = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(HeadErr::Status(505)),
    };
    let url = if target.starts_with('/') {
        target
    } else if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(at) => rest[at..].to_owned(),
            None => "/".to_owned(),
        }
    } else {
        return Err(HeadErr::Status(400));
    };

    let mut headers = Vec::new();
    let mut length: Option<u64> = None;
    let mut lengths = 0usize;
    let mut chunked = false;
    let mut expect_continue = false;
    let mut host = false;
    let mut keep_alive = false;
    loop {
        let raw = next(r)?;
        if raw == b"\r\n" {
            break;
        }
        if !raw.ends_with(b"\r\n") || raw[0].is_ascii_whitespace() {
            return Err(HeadErr::Status(400));
        }
        let text = std::str::from_utf8(&raw[..raw.len() - 2]).map_err(|_| HeadErr::Status(400))?;
        let (name, value) = text.split_once(':').ok_or(HeadErr::Status(400))?;
        let value = value.trim_matches([' ', '\t']);
        let header =
            Header::from_bytes(name.as_bytes(), value.as_bytes()).ok_or(HeadErr::Status(400))?;
        if header.field.equiv("content-length") {
            lengths += 1;
            length = Some(parse_digits(value, 10).ok_or(HeadErr::Status(400))?);
        } else if header.field.equiv("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(HeadErr::Status(400));
            }
            chunked = true;
        } else if header.field.equiv("connection") {
            for token in value.split(',') {
                if token.trim().eq_ignore_ascii_case("close") {
                    close = true;
                } else if token.trim().eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            }
        } else if header.field.equiv("expect") {
            if !value.eq_ignore_ascii_case("100-continue") {
                return Err(HeadErr::Status(417));
            }
            expect_continue = true;
        } else if header.field.equiv("host") {
            host = true;
        }
        headers.push(header);
    }
    if lengths > 1 || (chunked && length.is_some()) {
        // Duplicate or conflicting length signals are the request-smuggling shape: refuse, never pick one.
        return Err(HeadErr::Status(400));
    }
    if version == "HTTP/1.1" && !host {
        return Err(HeadErr::Status(400));
    }
    if keep_alive {
        close = false;
    }
    Ok(Head {
        method,
        url,
        headers,
        length,
        chunked,
        close,
        expect_continue,
    })
}

/// Digits only: u64::from_str accepts a leading '+', which RFC 9110 forbids in lengths and chunk sizes.
fn parse_digits(text: &str, radix: u32) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| (b as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(text, radix).ok()
}

struct Stall<'a> {
    w: &'a TcpStream,
    stop: &'a AtomicBool,
    poll: Duration,
    stall: Duration,
    progress: Instant,
}

impl Write for Stall<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let stalled = self.progress.elapsed();
            if stalled >= self.stall {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "write stall"));
            }
            self.w
                .set_write_timeout(Some((self.stall - stalled).min(self.poll)))?;
            match self.w.write(buf) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write")),
                Ok(n) => {
                    self.progress = Instant::now();
                    return Ok(n);
                }
                Err(e) if timed_out(&e) => {
                    if self.stop.load(Ordering::Acquire) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "stopping"));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Request<'a> {
    method: String,
    url: String,
    headers: Vec<Header>,
    length: Option<u64>,
    body: Body<'a>,
    writer: &'a TcpStream,
    stop: &'a AtomicBool,
    poll: Duration,
    stall: Duration,
    close: bool,
    responded: bool,
    /// Set only on a child request made after the outer MCP bearer was checked; network requests never set it.
    trusted_identity: Option<crate::auth::Identity>,
    handler: Option<Permit>,
    gate: Option<&'a Gate>,
    ready: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BodyErr {
    TooLarge,
    Busy,
    Unreadable,
}

impl Request<'_> {
    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub(crate) fn peer(&self) -> Option<std::net::IpAddr> {
        self.writer.peer_addr().ok().map(|addr| addr.ip())
    }

    pub(crate) fn peer_gone(&self) -> bool {
        if self.writer.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let gone = match self.writer.peek(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => e.kind() != io::ErrorKind::WouldBlock,
        };
        let _ = self.writer.set_nonblocking(false);
        gone
    }

    pub(crate) fn yield_handler(&mut self) {
        self.handler = None;
    }

    pub(crate) fn public_body(&mut self, limit: usize) -> Result<Vec<u8>, BodyErr> {
        if self.length.is_some_and(|n| n > limit as u64) {
            return Err(BodyErr::TooLarge);
        }
        let mut slot = None;
        if let (false, Some(gate)) = (self.ready, self.gate) {
            let deadline = Instant::now() + gate.body_time;
            self.handler = None;
            let forwarded = self
                .headers
                .iter()
                .find(|h| h.field.equiv("x-forwarded-for"))
                .map(|h| h.value.as_str());
            let key = client_key(self.peer(), forwarded, &gate.trusted);
            let Some(reader) = ReaderKey::take(&gate.readers, key) else {
                self.restore_handler(gate)?;
                return Err(BodyErr::Busy);
            };
            let Some(permit) = gate.bodies.acquire_until(self.stop, self.poll, deadline) else {
                drop(reader);
                self.restore_handler(gate)?;
                return Err(BodyErr::Busy);
            };
            slot = Some((permit, reader));
            self.body.cap_deadline(deadline);
        }
        let mut bytes = Vec::new();
        let read = (&mut self.body)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        drop(slot);
        if let Some(gate) = self.gate {
            self.restore_handler(gate)?;
        }
        read.map_err(|_| BodyErr::Unreadable)?;
        if bytes.len() > limit {
            return Err(BodyErr::TooLarge);
        }
        Ok(bytes)
    }

    fn restore_handler(&mut self, gate: &Gate) -> Result<(), BodyErr> {
        if self.handler.is_none() {
            self.handler = Some(
                gate.handlers
                    .acquire(self.stop, self.poll)
                    .ok_or(BodyErr::Unreadable)?,
            );
        }
        Ok(())
    }

    pub(crate) fn body_length(&self) -> Option<usize> {
        self.length
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
    }

    pub(crate) fn trusted_identity(&self) -> Option<crate::auth::Identity> {
        self.trusted_identity
    }

    pub(crate) fn internal(
        &self,
        method: String,
        url: String,
        headers: Vec<Header>,
        body: Vec<u8>,
        identity: crate::auth::Identity,
    ) -> Request<'_> {
        let length = body.len() as u64;
        Request {
            method,
            url,
            headers,
            length: Some(length),
            body: Body::Internal(Cursor::new(body)),
            writer: self.writer,
            stop: self.stop,
            poll: self.poll,
            stall: self.stall,
            close: true,
            responded: false,
            trusted_identity: Some(identity),
            handler: None,
            gate: None,
            ready: true,
        }
    }

    pub(crate) fn as_reader(&mut self) -> &mut dyn Read {
        &mut self.body
    }

    pub(crate) fn respond(&mut self, response: Response) -> io::Result<()> {
        if self.responded {
            return Err(io::Error::other("responded twice"));
        }
        self.responded = true;
        let close = self.must_close() || response.len.is_none();
        let mut head = String::with_capacity(256);
        let _ = write!(
            head,
            "HTTP/1.1 {} {}\r\n",
            response.status,
            reason(response.status)
        );
        for h in &response.headers {
            let _ = write!(head, "{}: {}\r\n", h.field.0, h.value.0);
        }
        if let Some(len) = response.len {
            let _ = write!(head, "content-length: {len}\r\n");
        }
        if close {
            head.push_str("connection: close\r\n");
        }
        head.push_str("\r\n");
        let mut writer = Stall {
            w: self.writer,
            stop: self.stop,
            poll: self.poll,
            stall: self.stall,
            progress: Instant::now(),
        };
        writer.write_all(head.as_bytes())?;
        if self.method != "HEAD" {
            let mut data = response.data;
            let copied = match response.len {
                Some(len) => io::copy(&mut data.by_ref().take(len), &mut writer),
                None => io::copy(&mut data, &mut writer),
            };
            let copied = match copied {
                Ok(copied) => copied,
                Err(e) => {
                    self.close = true;
                    let _ = self.writer.shutdown(Shutdown::Both);
                    return Err(e);
                }
            };
            writer.flush()?;
            if response.len.is_some_and(|len| copied != len) {
                self.close = true;
            }
        }
        if close || self.close {
            let _ = self.writer.shutdown(Shutdown::Write);
            self.close = true;
        }
        Ok(())
    }

    fn must_close(&self) -> bool {
        self.close || !self.body.drained()
    }
}

fn refuse(stream: &TcpStream, status: u16) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let mut w = stream;
    let _ = w.write_all(
        format!(
            "HTTP/1.1 {status} {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            reason(status)
        )
        .as_bytes(),
    );
    let _ = stream.shutdown(Shutdown::Write);
}

pub(crate) struct Conns {
    stop: Arc<AtomicBool>,
    sockets: Arc<Mutex<BTreeMap<u64, TcpStream>>>,
    permits: Arc<Pool>,
    poll: Duration,
    wake: SocketAddr,
    acceptor: Option<JoinHandle<()>>,
}

impl Conns {
    pub(crate) fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        for socket in self
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(acceptor) = self.acceptor.take() {
            let target = match self.wake.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => {
                    SocketAddr::from((Ipv4Addr::LOCALHOST, self.wake.port()))
                }
                IpAddr::V6(ip) if ip.is_unspecified() => {
                    SocketAddr::from((Ipv6Addr::LOCALHOST, self.wake.port()))
                }
                _ => self.wake,
            };
            for _ in 0..50 {
                if acceptor.is_finished() {
                    break;
                }
                let _ = TcpStream::connect_timeout(&target, Duration::from_millis(100));
                for _ in 0..20 {
                    if acceptor.is_finished() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
            if acceptor.is_finished() {
                let _ = acceptor.join();
            }
        }
        self.permits.wait_full(self.poll);
    }
}

impl Drop for Conns {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) fn listen(
    listener: TcpListener,
    serve: Arc<dyn Fn(&mut Request) + Send + Sync>,
    stop: Arc<AtomicBool>,
    tune: Tune,
    exempt: Vec<TrustedProxy>,
) -> io::Result<Conns> {
    listener.set_nonblocking(false)?;
    let wake = listener.local_addr()?;
    let (sockets, permits) = (
        Arc::new(Mutex::new(BTreeMap::new())),
        Pool::new(tune.connections),
    );
    let gate = Arc::new(Gate {
        handlers: Pool::new(tune.handlers),
        bodies: Pool::new(tune.public_bodies),
        body_time: tune.public_body_time,
        readers: Arc::new(Mutex::new(HashSet::new())),
        trusted: exempt.clone(),
    });
    let peers = Arc::new(Peers {
        cap: tune.per_peer,
        exempt,
        held: Mutex::new(HashMap::new()),
    });
    let acceptor = thread::Builder::new()
        .name("sentinel-api-accept".into())
        .spawn({
            let (stop, sockets, permits) = (
                Arc::clone(&stop),
                Arc::clone(&sockets),
                Arc::clone(&permits),
            );
            move || accept_loop(listener, serve, stop, sockets, permits, gate, peers, tune)
        })?;
    Ok(Conns {
        stop,
        sockets,
        permits,
        poll: tune.poll,
        wake,
        acceptor: Some(acceptor),
    })
}

static CONN: AtomicU64 = AtomicU64::new(0);

struct Peers {
    cap: usize,
    exempt: Vec<TrustedProxy>,
    held: Mutex<HashMap<u128, usize>>,
}

struct PeerSlot {
    peers: Arc<Peers>,
    key: u128,
}

impl Peers {
    fn admit(self: &Arc<Self>, peer: IpAddr) -> Option<Option<PeerSlot>> {
        if is_proxy(peer, &self.exempt) {
            return Some(None);
        }
        let key = client_key(Some(peer), None, &[]);
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let count = held.entry(key).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(Some(PeerSlot {
            peers: Arc::clone(self),
            key,
        }))
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut held = self.peers.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

#[expect(clippy::too_many_arguments, reason = "the acceptor's whole state")]
fn accept_loop(
    listener: TcpListener,
    serve: Arc<dyn Fn(&mut Request) + Send + Sync>,
    stop: Arc<AtomicBool>,
    sockets: Arc<Mutex<BTreeMap<u64, TcpStream>>>,
    connections: Arc<Pool>,
    gate: Arc<Gate>,
    peers: Arc<Peers>,
    tune: Tune,
) {
    while !stop.load(Ordering::Acquire) {
        let Some(slot) = connections.acquire(&stop, tune.poll) else {
            break;
        };
        match listener.accept() {
            Ok((stream, addr)) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Some(peer_slot) = peers.admit(addr.ip()) else {
                    continue;
                };
                let Ok(registered) = stream.try_clone() else {
                    continue;
                };
                let id = CONN.fetch_add(1, Ordering::Relaxed);
                sockets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, registered);
                let (serve, gate, stop, registry) = (
                    Arc::clone(&serve),
                    Arc::clone(&gate),
                    Arc::clone(&stop),
                    Arc::clone(&sockets),
                );
                if thread::Builder::new()
                    .name("sentinel-api-conn".into())
                    .spawn(move || {
                        connection(stream, &*serve, &gate, &stop, tune);
                        // Released last: wait_full must not return while a reader still holds State through serve.
                        drop(serve);
                        drop(gate);
                        drop(peer_slot);
                        registry
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&id);
                        drop(registry);
                        drop(slot);
                    })
                    .is_err()
                {
                    sockets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&id);
                }
            }
            Err(_) => thread::sleep(tune.poll),
        }
    }
}

fn connection(
    stream: TcpStream,
    serve: &dyn Fn(&mut Request),
    gate: &Gate,
    stop: &AtomicBool,
    tune: Tune,
) {
    // Accepted sockets inherit the listener's nonblocking mode on Windows; deadlines need blocking reads.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let stream = &stream;
    let mut reader = BufReader::with_capacity(8 << 10, stream);
    while !stop.load(Ordering::Acquire) {
        let head = match head(&mut reader, stream, tune, stop) {
            Ok(head) => head,
            Err(HeadErr::Closed | HeadErr::Timeout) => break,
            Err(HeadErr::Status(status)) => {
                refuse(stream, status);
                break;
            }
        };
        if head.expect_continue
            && (Stall {
                w: stream,
                stop,
                poll: tune.poll,
                stall: tune.write_stall,
                progress: Instant::now(),
            })
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .is_err()
        {
            break;
        }
        let Some(handler) = gate.handlers.acquire(stop, tune.poll) else {
            break;
        };
        let ready = !head.chunked
            && head
                .length
                .is_none_or(|n| n as usize <= reader.buffer().len());
        let body_deadline = Instant::now() + tune.body_time;
        let body = if head.chunked {
            Body::Chunked(Chunked {
                l: Limited {
                    r: &mut reader,
                    socket: stream,
                    stop,
                    poll: tune.poll,
                    left: 0,
                    deadline: body_deadline,
                },
                state: 0,
                trailers: 0,
                done: false,
            })
        } else {
            match head.length {
                Some(0) | None => Body::Empty,
                Some(left) => Body::Fixed(Limited {
                    r: &mut reader,
                    socket: stream,
                    stop,
                    poll: tune.poll,
                    left,
                    deadline: body_deadline,
                }),
            }
        };
        let mut request = Request {
            method: head.method,
            url: head.url,
            headers: head.headers,
            length: head.length,
            body,
            writer: stream,
            stop,
            poll: tune.poll,
            stall: tune.write_stall,
            close: head.close,
            responded: false,
            trusted_identity: None,
            handler: Some(handler),
            gate: Some(gate),
            ready,
        };
        let panicked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve(&mut request))).is_err();
        if panicked || !request.responded {
            let _ = request
                .respond(Response::from_string(String::new()).with_status_code(StatusCode(500)));
            break;
        }
        if request.must_close() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn tune() -> Tune {
        Tune {
            connections: 2,
            handlers: 1,
            head_bytes: 1 << 10,
            head_time: Duration::from_millis(800),
            body_time: Duration::from_millis(300),
            public_bodies: 1,
            public_body_time: Duration::from_millis(300),
            per_peer: 16,
            write_stall: Duration::from_secs(1),
            poll: Duration::from_millis(10),
        }
    }

    fn parse(wire: &[u8], tune: Tune) -> Result<Head, HeadErr> {
        let (mut client, server) = pair();
        client.write_all(wire).unwrap();
        let stop = AtomicBool::new(false);
        let mut reader = BufReader::with_capacity(1024, &server);
        head(&mut reader, &server, tune, &stop)
    }

    fn limited<'a>(
        r: &'a mut dyn BufRead,
        socket: &'a TcpStream,
        stop: &'a AtomicBool,
        left: u64,
    ) -> Limited<'a> {
        Limited {
            r,
            socket,
            stop,
            poll: Duration::from_millis(10),
            left,
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    #[test]
    fn head_accepts_origin_and_absolute_forms() {
        let got = parse(b"GET /a?b=c HTTP/1.1\r\nhost: h\r\nx-a: 1\r\n\r\n", tune()).unwrap();
        assert_eq!(got.method, "GET");
        assert_eq!(got.url, "/a?b=c");
        assert!(!got.close && !got.chunked && got.length.is_none());
        assert!(
            got.headers
                .iter()
                .any(|h| h.field.equiv("X-A") && h.value.as_str() == "1")
        );

        let got = parse(b"GET http://ex.com/p?q=1 HTTP/1.0\r\n\r\n", tune()).unwrap();
        assert_eq!(got.url, "/p?q=1");
        assert!(got.close);
    }

    #[test]
    fn head_refuses_smuggling_shapes() {
        for wire in [
            &b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nhost: h\r\ntransfer-encoding: gzip\r\n\r\n",
            b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: +5\r\n\r\n",
            b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: -0\r\n\r\n",
            b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length:\r\n\r\n",
        ] {
            match parse(wire, tune()) {
                Err(HeadErr::Status(400)) => {}
                other => panic!("expected 400, got {other:?}"),
            }
        }
        match parse(
            b"GET / HTTP/1.1\r\nhost: h\r\nexpect: magic\r\n\r\n",
            tune(),
        ) {
            Err(HeadErr::Status(417)) => {}
            other => panic!("expected 417, got {other:?}"),
        }
        for (wire, want) in [
            (&b"GET / HTTP/1.1\r\n\r\n"[..], 400),
            (b"GET / HTTP/9.9\r\nhost: h\r\n\r\n", 505),
            (b"GET / HTTP/1.1\r\nhost: h\r\n folded\r\n\r\n", 400),
        ] {
            match parse(wire, tune()) {
                Err(HeadErr::Status(got)) => assert_eq!(got, want),
                other => panic!("expected {want}, got {other:?}"),
            }
        }
    }

    #[test]
    fn head_byte_cap_is_cumulative() {
        let mut wire = b"GET / HTTP/1.1\r\nhost: h\r\n".to_vec();
        while wire.len() <= 1024 {
            wire.extend_from_slice(
                b"x-pad: ..........................................................\r\n",
            );
        }
        wire.extend_from_slice(b"\r\n");
        match parse(&wire, tune()) {
            Err(HeadErr::Status(431)) => {}
            other => panic!("expected 431, got {other:?}"),
        }
    }

    #[test]
    fn head_stall_times_out() {
        let (_client, server) = pair();
        let stop = AtomicBool::new(false);
        let mut reader = BufReader::with_capacity(1024, &server);
        match head(&mut reader, &server, tune(), &stop) {
            Err(HeadErr::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn fixed_body_is_exact_and_short_eof_errors() {
        let (mut client, server) = pair();
        client.write_all(b"abcdef").unwrap();
        let stop = AtomicBool::new(false);
        let mut reader = BufReader::with_capacity(1024, &server);
        let mut got = Vec::new();
        limited(&mut reader, &server, &stop, 4)
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"abcd");

        drop(client);
        assert_eq!(
            limited(&mut reader, &server, &stop, 10)
                .read_to_end(&mut Vec::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn chunked_decodes_and_bounds_trailers() {
        let (mut client, server) = pair();
        client
            .write_all(b"4\r\nabcd\r\n3\r\nefg\r\n0\r\nx-t: y\r\n\r\n")
            .unwrap();
        let stop = AtomicBool::new(false);
        let mut reader = BufReader::with_capacity(1024, &server);
        let mut body = Chunked {
            l: limited(&mut reader, &server, &stop, 0),
            state: 0,
            trailers: 0,
            done: false,
        };
        let mut got = Vec::new();
        body.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"abcdefg");
        assert!(body.done);

        let (mut client, server) = pair();
        let mut wire = b"1\r\na\r\n0\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; (8 << 10) + 16]);
        wire.extend_from_slice(b"\r\n\r\n");
        client.write_all(&wire).unwrap();
        let mut reader = BufReader::with_capacity(1024, &server);
        let mut body = Chunked {
            l: limited(&mut reader, &server, &stop, 0),
            state: 0,
            trailers: 0,
            done: false,
        };
        let mut got = Vec::new();
        assert_eq!(
            body.read_to_end(&mut got).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn chunked_rejects_bad_size_and_short_eof() {
        let stop = AtomicBool::new(false);
        for wire in [&b"zz\r\n"[..], b"4\r\nab", b"+4\r\nabcd\r\n0\r\n\r\n"] {
            let (mut client, server) = pair();
            client.write_all(wire).unwrap();
            drop(client);
            let mut reader = BufReader::with_capacity(1024, &server);
            let mut body = Chunked {
                l: limited(&mut reader, &server, &stop, 0),
                state: 0,
                trailers: 0,
                done: false,
            };
            assert!(body.read_to_end(&mut Vec::new()).is_err());
        }
    }

    #[test]
    fn respond_sets_length_and_closes_on_undrained_body() {
        let (client, server) = pair();
        let stop = AtomicBool::new(false);
        let mut request = Request {
            method: "GET".into(),
            url: "/".into(),
            headers: Vec::new(),
            length: None,
            body: Body::Empty,
            writer: &server,
            stop: &stop,
            poll: Duration::from_millis(10),
            stall: Duration::from_secs(1),
            close: false,
            responded: false,
            trusted_identity: None,
            handler: None,
            gate: None,
            ready: true,
        };
        request.respond(Response::from_string("hi")).unwrap();
        drop(server);
        let mut wire = String::new();
        let mut client = client;
        client.read_to_string(&mut wire).unwrap();
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("content-length: 2\r\n"));
        assert!(wire.ends_with("\r\n\r\nhi"));
        assert!(!wire.contains("connection: close"));

        let (client, server) = pair();
        let mut reader = BufReader::with_capacity(1024, &server);
        let mut request = Request {
            method: "POST".into(),
            url: "/".into(),
            headers: Vec::new(),
            length: Some(5),
            body: Body::Fixed(limited(&mut reader, &server, &stop, 5)),
            writer: &server,
            stop: &stop,
            poll: Duration::from_millis(10),
            stall: Duration::from_secs(1),
            close: false,
            responded: false,
            trusted_identity: None,
            handler: None,
            gate: None,
            ready: false,
        };
        request.respond(Response::from_string("no")).unwrap();
        assert!(request.must_close());
        drop(server);
        let mut wire = String::new();
        let mut client = client;
        client.read_to_string(&mut wire).unwrap();
        assert!(wire.contains("connection: close\r\n"));
    }

    #[test]
    fn a_new_connection_is_served_without_waiting_for_a_poll() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = listen(
            listener,
            Arc::new(|request: &mut Request| {
                let _ = request.respond(Response::from_string("ok"));
            }),
            Arc::new(AtomicBool::new(false)),
            Tune {
                connections: 8,
                handlers: 4,
                poll: Duration::from_millis(100),
                ..tune()
            },
            Vec::new(),
        )
        .unwrap();
        let mut taken: Vec<Duration> = Vec::new();
        for _ in 0..15 {
            let started = Instant::now();
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n")
                .unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut wire = Vec::new();
            client.read_to_end(&mut wire).unwrap();
            assert!(wire.starts_with(b"HTTP/1.1 200"), "{wire:?}");
            taken.push(started.elapsed());
            thread::sleep(Duration::from_millis(7));
        }
        taken.sort();
        assert!(
            taken[taken.len() / 2] < Duration::from_millis(50),
            "median {:?} of {taken:?}",
            taken[taken.len() / 2]
        );
        conns.close();
    }

    #[test]
    fn closing_an_idle_server_wakes_its_blocked_acceptor() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let conns = listen(
            listener,
            Arc::new(|_: &mut Request| {}),
            Arc::new(AtomicBool::new(false)),
            tune(),
            Vec::new(),
        )
        .unwrap();
        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        conns.close();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "shutdown took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn server_caps_connections_and_parks_overflow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = listen(
            listener,
            Arc::new(|request: &mut Request| {
                let _ = request.respond(Response::from_string("ok"));
            }),
            stop,
            tune(),
            Vec::new(),
        )
        .unwrap();

        let _a = TcpStream::connect(addr).unwrap();
        let _b = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(150));

        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nhost: h\r\n\r\n").unwrap();
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(c.read(&mut buf).is_err(), "overflow conn must wait");

        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0 && buf.starts_with(b"HTTP/1.1 200"));
        conns.close();
    }

    #[test]
    fn server_bounds_handlers_and_kills_stalled_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicU64::new(0));
        let (gate, wait) = mpsc::channel::<()>();
        let wait = Mutex::new(wait);
        let conns = listen(
            listener,
            Arc::new(move |request: &mut Request| {
                if entered.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = wait
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .recv_timeout(Duration::from_secs(5));
                } else {
                    let _ = io::copy(request.as_reader(), &mut io::sink());
                }
                let _ = request.respond(Response::from_string("ok"));
            }),
            stop,
            tune(),
            Vec::new(),
        )
        .unwrap();

        let mut one = TcpStream::connect(addr).unwrap();
        one.write_all(b"GET /one HTTP/1.1\r\nhost: h\r\n\r\n")
            .unwrap();
        let mut two = TcpStream::connect(addr).unwrap();
        two.write_all(b"POST /two HTTP/1.1\r\nhost: h\r\ncontent-length: 100\r\n\r\nx")
            .unwrap();
        thread::sleep(Duration::from_millis(150));

        two.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(two.read(&mut buf).is_err(), "second request must wait");
        gate.send(()).unwrap();
        one.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let n = one.read(&mut buf).unwrap();
        assert!(n > 0 && buf.starts_with(b"HTTP/1.1 200"));

        two.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut all = Vec::new();
        two.read_to_end(&mut all).unwrap();
        assert!(all.starts_with(b"HTTP/1.1 200"), "got {all:?}");
        conns.close();
    }

    #[test]
    fn stalled_public_bodies_hold_no_handler_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = listen(
            listener,
            Arc::new(|request: &mut Request| {
                let outcome = if request.url() == "/public" {
                    request.public_body(1024).map(|b| b.len())
                } else {
                    Ok(0)
                };
                let status = if outcome.is_ok() { 200 } else { 400 };
                let _ = request.respond(
                    Response::from_string(String::new()).with_status_code(StatusCode(status)),
                );
            }),
            Arc::new(AtomicBool::new(false)),
            Tune {
                connections: 4,
                public_body_time: Duration::from_millis(600),
                ..tune()
            },
            Vec::new(),
        )
        .unwrap();
        let mut slow = TcpStream::connect(addr).unwrap();
        slow.write_all(b"POST /public HTTP/1.1\r\nhost: h\r\ncontent-length: 100\r\n\r\nx")
            .unwrap();
        thread::sleep(Duration::from_millis(150));

        let mut fast = TcpStream::connect(addr).unwrap();
        fast.write_all(b"GET /fast HTTP/1.1\r\nhost: h\r\n\r\n")
            .unwrap();
        fast.set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = fast.read(&mut buf).expect("served while a body trickles");
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));

        slow.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut all = Vec::new();
        let _ = slow.read_to_end(&mut all);
        assert!(all.starts_with(b"HTTP/1.1 400"), "got {all:?}");
        conns.close();
    }

    #[test]
    fn a_client_holds_one_public_body_slot_and_others_still_get_theirs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = listen(
            listener,
            Arc::new(|request: &mut Request| {
                let outcome = request.public_body(1024).map(|b| b.len());
                let status = if outcome.is_ok() { 200 } else { 400 };
                let _ = request.respond(
                    Response::from_string(String::new()).with_status_code(StatusCode(status)),
                );
            }),
            Arc::new(AtomicBool::new(false)),
            Tune {
                connections: 6,
                handlers: 4,
                public_bodies: 2,
                public_body_time: Duration::from_secs(3),
                ..tune()
            },
            TrustedProxy::loopback(),
        )
        .unwrap();
        let post = |client: &str, body: &str, declared: usize| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .write_all(
                    format!(
                        "POST /p HTTP/1.1\r\nhost: h\r\nx-forwarded-for: {client}\r\ncontent-length: {declared}\r\n\r\n{body}"
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream
        };
        let status = |mut stream: TcpStream| {
            stream
                .set_read_timeout(Some(Duration::from_millis(1500)))
                .unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).expect("answered in time");
            buf[..n].to_vec()
        };
        let _slow = post("198.51.100.1", "x", 100);
        thread::sleep(Duration::from_millis(150));

        let same = status(post("198.51.100.1", "o", 2));
        assert!(same.starts_with(b"HTTP/1.1 400"), "got {same:?}");
        let mut other = post("198.51.100.2", "o", 2);
        thread::sleep(Duration::from_millis(100));
        other.write_all(b"k").unwrap();
        let other = status(other);
        assert!(other.starts_with(b"HTTP/1.1 200"), "got {other:?}");
        conns.close();
    }

    #[test]
    fn a_peer_is_capped_unless_it_is_a_trusted_proxy() {
        for (exempt, capped) in [(Vec::new(), true), (TrustedProxy::loopback(), false)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let conns = listen(
                listener,
                Arc::new(|request: &mut Request| {
                    let _ = request.respond(Response::from_string("ok"));
                }),
                Arc::new(AtomicBool::new(false)),
                Tune {
                    connections: 8,
                    per_peer: 2,
                    head_time: Duration::from_secs(5),
                    ..tune()
                },
                exempt,
            )
            .unwrap();
            let held: Vec<TcpStream> = (0..3).map(|_| TcpStream::connect(addr).unwrap()).collect();
            thread::sleep(Duration::from_millis(150));
            let mut third = &held[2];
            let _ = third.write_all(b"GET / HTTP/1.1\r\nhost: h\r\n\r\n");
            third
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 16];
            let n = third.read(&mut buf).unwrap_or(0);
            assert_eq!(n == 0, capped, "capped={capped}");
            conns.close();
        }
    }

    #[test]
    fn close_wakes_parked_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = listen(
            listener,
            Arc::new(|request: &mut Request| {
                let _ = request.respond(Response::from_string("ok"));
            }),
            stop,
            Tune {
                head_time: Duration::from_secs(30),
                ..tune()
            },
            Vec::new(),
        )
        .unwrap();
        let mut idle = TcpStream::connect(addr).unwrap();
        idle.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        conns.close();
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut buf = [0u8; 8];
        assert!(idle.read(&mut buf).unwrap_or(0) == 0);
    }
}
