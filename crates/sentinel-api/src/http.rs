//! The API's bounded HTTP/1.1 layer. One acceptor thread hands accepted
//! sockets to at most `Tune::connections` reader threads; each connection
//! parses a head, then takes one of `Tune::handlers` permits before any
//! route work — so request concurrency is `handlers`, reader threads are
//! `connections`, and nothing else spawns. Heads and client bodies are
//! deadline-bounded; a stalled write fails its syscall instead of holding
//! a handler permit forever. Responses always carry an explicit
//! `content-length` (routes know their lengths) or close the connection.
//!
//! `Conns::close` stops the acceptor, force-closes live sockets so parked
//! reads fail at once, and waits for every connection permit to come back
//! — a reader thread still inside a route holds `State`, so shutdown does
//! not return while one can still touch the store.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The server's resource bounds and timeouts; `Tune::DEFAULT` is what
/// `Server` uses — tests inject smaller values.
#[derive(Clone, Copy)]
pub(crate) struct Tune {
    /// Accepted connections held at once; further handshakes wait in the
    /// listener backlog until a slot frees.
    pub connections: usize,
    /// Requests being handled at once — the `WORKERS` bound.
    pub handlers: usize,
    /// Request line plus headers, bytes in total.
    pub head_bytes: usize,
    /// Total time allowed for one head — also the keep-alive idle window.
    pub head_time: Duration,
    /// Total time allowed for one client body.
    pub body_time: Duration,
    /// Longest a single socket write may stall.
    pub write_stall: Duration,
    /// Poll granularity for the nonblocking accept and permit waits.
    pub poll: Duration,
}

impl Tune {
    pub(crate) const DEFAULT: Tune = Tune {
        connections: 64,
        handlers: crate::WORKERS,
        head_bytes: 16 << 10,
        head_time: Duration::from_secs(15),
        body_time: Duration::from_secs(120),
        write_stall: Duration::from_secs(60),
        poll: Duration::from_millis(100),
    };
}

/// A counting semaphore whose permits release on drop; doubles as the
/// liveness check for the threads that hold them.
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

    /// Take a slot; `None` when `stop` is set while parked.
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

    /// Wait until every issued permit has been dropped.
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

struct Permit(Arc<Pool>);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut free = self.0.free.lock().unwrap_or_else(|e| e.into_inner());
        *free += 1;
        drop(free);
        self.0.wake.notify_all();
    }
}

/// A header name; `equiv` matches ASCII-insensitively.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Field(String);

impl Field {
    pub(crate) fn equiv(&self, name: &str) -> bool {
        self.0.eq_ignore_ascii_case(name)
    }
}

/// A header value; head parsing already required valid UTF-8.
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
    /// Header names are tokens and values UTF-8 without CR/LF — the
    /// response head is built by interpolation, so nothing may inject a
    /// line.
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

/// What a route answers. `len` is declared up front: the wire response is
/// never chunked, and `None` means the body ends at close.
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

/// Re-arm the socket's read timeout for the time left before `deadline`,
/// clamped to `poll` so a `stop` during the wait is seen promptly — a
/// `shutdown` from `Conns::close` does not reliably wake a timed `recv`
/// on Windows, so the timeout itself is the wakeup.
fn rearm(socket: &TcpStream, deadline: Instant, poll: Duration) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline"));
    }
    socket.set_read_timeout(Some(left.min(poll)))
}

/// `true` for the errors a timed read produces on expiry; on Windows a
/// timed-out blocking read reports `WouldBlock`.
fn timed_out(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
}

/// One socket read bounded by `deadline`, retried every `poll` until
/// bytes arrive, `stop` is set, or the deadline passes.
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

/// One bounded, deadline-armed CRLF-terminated line. `Ok(None)` is a
/// clean EOF before any byte; a partial line at EOF is `UnexpectedEof`.
/// Reads retry every `poll` so `stop` ends a parked read without
/// waiting out the deadline.
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

/// A body the route reads through `Request::as_reader`: absent, a
/// declared `content-length`, or `chunked`.
enum Body<'a> {
    Empty,
    Fixed(Limited<'a>),
    Chunked(Chunked<'a>),
}

impl Body<'_> {
    fn drained(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Fixed(f) => f.left == 0,
            Body::Chunked(c) => c.done,
        }
    }
}

impl Read for Body<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Empty => Ok(0),
            Body::Fixed(f) => f.read(buf),
            Body::Chunked(c) => c.read(buf),
        }
    }
}

/// A `content-length` body: at most `left` bytes before `deadline`. The
/// reader is type-erased so the borrow's region is just this request —
/// a `BufReader<&TcpStream>` field would pin the socket's lifetime and
/// hold the buffer mutable for the whole connection loop.
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

/// `transfer-encoding: chunked`, decoded in place; the trailer section
/// is bounded and discarded. A socket EOF anywhere mid-body is an error
/// — a truncated stream must not read as a short-but-valid body.
struct Chunked<'a> {
    l: Limited<'a>,
    /// 0 = at a size line, 1 = inside chunk data, 2 = data just ended and
    /// its CRLF is owed, 3 = reading trailers.
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
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
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

/// Why a head failed; `Status` writes a canned refusal then closes, the
/// others close silently.
#[cfg_attr(test, derive(Debug))]
enum HeadErr {
    Closed,
    Timeout,
    Status(u16),
}

/// One head line under the remaining byte budget; any EOF is `Closed` —
/// a peer that went away mid-head gets no diagnostic it cannot read.
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

/// Read one request head under `tune.head_bytes`/`tune.head_time`.
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

    // A client may precede the request with blank lines; skip them.
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
    // Origin-form first; absolute-form (a fronting proxy may send it)
    // strips scheme and authority down to the path.
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
            // A bare-LF line or an obs-fold continuation is not a header.
            return Err(HeadErr::Status(400));
        }
        let text = std::str::from_utf8(&raw[..raw.len() - 2]).map_err(|_| HeadErr::Status(400))?;
        let (name, value) = text.split_once(':').ok_or(HeadErr::Status(400))?;
        let value = value.trim_matches([' ', '\t']);
        let header =
            Header::from_bytes(name.as_bytes(), value.as_bytes()).ok_or(HeadErr::Status(400))?;
        if header.field.equiv("content-length") {
            lengths += 1;
            length = Some(value.parse().map_err(|_| HeadErr::Status(400))?);
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
        // Duplicate or conflicting length signals are the classic
        // request-smuggling shape; refuse rather than pick one.
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

/// A socket writer whose individual syscalls retry every `poll` and
/// whose total stall — time without a successful write — is bounded by
/// `stall`. Keeps a blocked client from holding a handler permit past
/// the stall budget and lets `stop` end a parked write promptly.
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

/// One parsed request head plus its bounded body reader. Borrows the
/// connection's buffer and write half; the owning connection thread runs
/// the keep-alive loop, so nothing here crosses a thread boundary.
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

    pub(crate) fn body_length(&self) -> Option<usize> {
        self.length
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
    }

    pub(crate) fn as_reader(&mut self) -> &mut dyn Read {
        &mut self.body
    }

    /// Write the response. A body the route never read, an explicit
    /// `connection: close`, or a close-delimited response all end the
    /// connection — bytes left unread would desync the next head.
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
                Some(len) => io::copy(&mut data.by_ref().take(len), &mut writer)?,
                None => io::copy(&mut data, &mut writer)?,
            };
            writer.flush()?;
            // A stream that ended early desyncs the client; close rather
            // than let its next read land on a short body.
            if response.len.is_some_and(|len| copied != len) {
                self.close = true;
            }
        }
        if close || self.close {
            // FIN after the response, so a refused-body reply survives
            // the unread bytes the close is about to abandon.
            let _ = self.writer.shutdown(Shutdown::Write);
            self.close = true;
        }
        Ok(())
    }

    fn must_close(&self) -> bool {
        self.close || !self.body.drained()
    }
}

/// Best-effort canned refusal for an unparseable head, then close. The
/// write timeout is small: a client we are refusing does not get to
/// park a connection thread on a stalled send.
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

/// The live side of `listen`: the acceptor plus every open connection's
/// socket, so `close` can fail parked reads instead of waiting out the
/// head deadline.
pub(crate) struct Conns {
    stop: Arc<AtomicBool>,
    sockets: Arc<Mutex<BTreeMap<u64, TcpStream>>>,
    permits: Arc<Pool>,
    poll: Duration,
    acceptor: Option<JoinHandle<()>>,
}

impl Conns {
    /// Stop accepting, force-close every open connection, and wait for
    /// the reader threads to release their permits.
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
            let _ = acceptor.join();
        }
        self.permits.wait_full(self.poll);
    }
}

impl Drop for Conns {
    /// A `Server` dropped without `shutdown` still owes its threads a
    /// stop; the steps are idempotent after `close`.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Serve `listener` until the returned `Conns` is closed. `stop` is
/// shared with the rest of the API so routes' long polls end when the
/// server does. Saturated connection permits park the acceptor so the
/// kernel backlog — not our memory — absorbs the flood.
pub(crate) fn listen(
    listener: TcpListener,
    serve: Arc<dyn Fn(&mut Request) + Send + Sync>,
    stop: Arc<AtomicBool>,
    tune: Tune,
) -> io::Result<Conns> {
    listener.set_nonblocking(true)?;
    let (sockets, permits, handlers) = (
        Arc::new(Mutex::new(BTreeMap::new())),
        Pool::new(tune.connections),
        Pool::new(tune.handlers),
    );
    let acceptor = thread::Builder::new()
        .name("sentinel-api-accept".into())
        .spawn({
            let (stop, sockets, permits) = (
                Arc::clone(&stop),
                Arc::clone(&sockets),
                Arc::clone(&permits),
            );
            move || accept_loop(listener, serve, stop, sockets, permits, handlers, tune)
        })?;
    Ok(Conns {
        stop,
        sockets,
        permits,
        poll: tune.poll,
        acceptor: Some(acceptor),
    })
}

static CONN: AtomicU64 = AtomicU64::new(0);

fn accept_loop(
    listener: TcpListener,
    serve: Arc<dyn Fn(&mut Request) + Send + Sync>,
    stop: Arc<AtomicBool>,
    sockets: Arc<Mutex<BTreeMap<u64, TcpStream>>>,
    connections: Arc<Pool>,
    handlers: Arc<Pool>,
    tune: Tune,
) {
    while !stop.load(Ordering::Acquire) {
        let Some(slot) = connections.acquire(&stop, tune.poll) else {
            break;
        };
        match listener.accept() {
            Ok((stream, _)) => {
                let Ok(registered) = stream.try_clone() else {
                    // A connection the close path cannot supervise is one
                    // we must not keep.
                    continue;
                };
                let id = CONN.fetch_add(1, Ordering::Relaxed);
                sockets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, registered);
                let (serve, handlers, stop, registry) = (
                    Arc::clone(&serve),
                    Arc::clone(&handlers),
                    Arc::clone(&stop),
                    Arc::clone(&sockets),
                );
                if thread::Builder::new()
                    .name("sentinel-api-conn".into())
                    .spawn(move || {
                        connection(stream, &*serve, &handlers, &stop, tune);
                        // Released last: `close`'s `wait_full` must not
                        // return while a reader still holds `serve` — and
                        // through it `State` and the store.
                        drop(serve);
                        drop(handlers);
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
            // WouldBlock is the nonblocking poll; the rest is descriptor
            // exhaustion or peers resetting mid-handshake — either way,
            // back off a poll and keep accepting.
            Err(_) => thread::sleep(tune.poll),
        }
    }
}

/// One connection's keep-alive loop: head, handler permit, serve, repeat
/// until close, error, or `stop`.
fn connection(
    stream: TcpStream,
    serve: &dyn Fn(&mut Request),
    handlers: &Arc<Pool>,
    stop: &AtomicBool,
    tune: Tune,
) {
    // Accepted sockets inherit the listener's nonblocking mode on
    // Windows (POSIX does not inherit); deadlines need blocking reads.
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
        let Some(_handler) = handlers.acquire(stop, tune.poll) else {
            break;
        };
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
        };
        let panicked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve(&mut request))).is_err();
        if panicked || !request.responded {
            // A route fault — or a handler that never answered — still
            // owes what can still be written, then closes.
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

    /// A connected client/server socket pair on loopback.
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
            write_stall: Duration::from_secs(1),
            poll: Duration::from_millis(10),
        }
    }

    /// Parse one head from wire bytes; the client half stays open so the
    /// server's reads see a live socket.
    fn parse(wire: &[u8], tune: Tune) -> Result<Head, HeadErr> {
        let (mut client, server) = pair();
        client.write_all(wire).unwrap();
        let stop = AtomicBool::new(false);
        let mut reader = BufReader::with_capacity(1024, &server);
        head(&mut reader, &server, tune, &stop)
    }

    /// A `Limited` over the buffered half of a socket pair.
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
        assert!(got.close); // HTTP/1.0 defaults to close
    }

    #[test]
    fn head_refuses_smuggling_shapes() {
        // Two content-lengths, or chunked+length, are refused outright.
        for wire in [
            &b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nhost: h\r\ntransfer-encoding: gzip\r\n\r\n",
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
        // HTTP/1.1 without Host; an unknown version; an obs-fold line.
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
        // Each line is well under the cap; together they exceed it.
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

        // Declared longer than the peer ever sends: EOF mid-body errors.
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

        // A trailer section past the cap is refused, not buffered.
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
        for wire in [&b"zz\r\n"[..], b"4\r\nab"] {
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

        // An unread request body forces the connection closed.
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
            tune(), // connections: 2
        )
        .unwrap();

        // Two idle clients hold both connection permits.
        let _a = TcpStream::connect(addr).unwrap();
        let _b = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(150));

        // A third connects at the kernel but waits for a permit.
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nhost: h\r\n\r\n").unwrap();
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(c.read(&mut buf).is_err(), "overflow conn must wait");

        // The idle conns' head deadline frees permits; the queued
        // request is then served.
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
                // First handler call parks until released; while it holds
                // the only handler permit a second request must wait.
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
            tune(), // handlers: 1
        )
        .unwrap();

        let mut one = TcpStream::connect(addr).unwrap();
        one.write_all(b"GET /one HTTP/1.1\r\nhost: h\r\n\r\n")
            .unwrap();
        let mut two = TcpStream::connect(addr).unwrap();
        two.write_all(b"POST /two HTTP/1.1\r\nhost: h\r\ncontent-length: 100\r\n\r\nx")
            .unwrap();
        thread::sleep(Duration::from_millis(150));

        // `two` cannot get a handler permit while `one` is parked.
        two.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(two.read(&mut buf).is_err(), "second request must wait");
        gate.send(()).unwrap();
        one.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let n = one.read(&mut buf).unwrap();
        assert!(n > 0 && buf.starts_with(b"HTTP/1.1 200"));

        // `two` then runs, but its body stalls past `body_time` — the
        // connection dies rather than parking the handler forever. The
        // response says close and the socket reaches EOF.
        two.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut all = Vec::new();
        two.read_to_end(&mut all).unwrap();
        assert!(all.starts_with(b"HTTP/1.1 200"), "got {all:?}");
        conns.close();
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
        )
        .unwrap();
        let mut idle = TcpStream::connect(addr).unwrap();
        idle.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        conns.close();
        assert!(start.elapsed() < Duration::from_secs(2));
        // The force-closed socket fails the client's parked read at once.
        let mut buf = [0u8; 8];
        assert!(idle.read(&mut buf).unwrap_or(0) == 0);
    }
}
