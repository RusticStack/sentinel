//! The single-use loopback listener the browser sign-in redirects to (O04,
//! RFC 8252 §7.3): bound to `127.0.0.1:0`, the whole wait bounded (five
//! minutes), each request head at most 8 KiB, only `GET /callback`
//! considered — any other path is answered `404` and the wait goes on. The
//! first `/callback` decides: its `state` must equal this login's (constant
//! time) and its `iss` the issuer (RFC 9207), otherwise the login stops.
//! The browser gets a static page either way; nothing from the request is
//! echoed.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_protocol::oauth::CLI_REDIRECT_PATH;

use crate::client::{Error, Exit};

/// How long a browser sign-in may take.
pub const WAIT: Duration = Duration::from_secs(5 * 60);
/// The largest request head read.
pub const MAX_HEAD: usize = 8 << 10;
/// How long one connection may take to send its head.
const PER_REQUEST: Duration = Duration::from_secs(10);

const DONE_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sentinel sign-in</title></head>\
<body><p>Sentinel sign-in is complete. You can close this window and return to the terminal.</p></body></html>";
const FAILED_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sentinel sign-in</title></head>\
<body><p>Sentinel sign-in did not complete. Return to the terminal for details.</p></body></html>";

/// The listening socket of one browser sign-in.
pub struct Listener {
    listener: TcpListener,
    addr: SocketAddr,
}

/// What a callback carried, once it passed the state and issuer checks.
enum Outcome {
    /// Not the callback (another path, oversized, or unreadable): keep waiting.
    Ignored,
    Done(Result<String, Error>),
}

impl Listener {
    pub fn bind() -> Result<Listener, Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| Error::usage(format!("cannot listen on 127.0.0.1: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::usage(format!("cannot listen on 127.0.0.1: {e}")))?;
        Ok(Listener { listener, addr })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// `http://127.0.0.1:{port}/callback`.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CLI_REDIRECT_PATH}", self.addr.port())
    }

    /// Wait at most `timeout` for the callback and return its authorization
    /// code. `state` and `issuer` are what the callback must carry.
    pub fn wait(self, state: &str, issuer: &str, timeout: Duration) -> Result<String, Error> {
        let deadline = Instant::now() + timeout;
        // A blocking accept has no timeout: a watchdog connects to the
        // listener once the deadline passes, unless told the wait is over.
        let expired = Arc::new(AtomicBool::new(false));
        let (finished, finished_rx) = mpsc::channel::<()>();
        let watchdog = {
            let expired = Arc::clone(&expired);
            let addr = self.addr;
            thread::spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) = finished_rx.recv_timeout(timeout) {
                    expired.store(true, Ordering::Release);
                    let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(1));
                }
            })
        };
        let result = loop {
            let accepted = self.listener.accept();
            if expired.load(Ordering::Acquire) || Instant::now() >= deadline {
                break Err(Error::new(
                    Exit::Auth,
                    format!(
                        "the browser sign-in did not finish within {} s; run the login again",
                        timeout.as_secs()
                    ),
                ));
            }
            let Ok((stream, _)) = accepted else { continue };
            match serve(stream, state, issuer, deadline) {
                Outcome::Ignored => continue,
                Outcome::Done(result) => break result,
            }
        };
        drop(finished);
        let _ = watchdog.join();
        result
    }
}

fn respond(mut stream: &TcpStream, status: &str, page: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\n\
         cache-control: no-store\r\nreferrer-policy: no-referrer\r\nconnection: close\r\n\r\n",
        page.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(page.as_bytes());
    let _ = stream.flush();
}

/// Read one request head of at most [`MAX_HEAD`] bytes.
fn read_head(mut stream: &TcpStream, buf: &mut [u8; MAX_HEAD]) -> Option<usize> {
    let mut len = 0;
    loop {
        if len == buf.len() {
            return None;
        }
        match stream.read(&mut buf[len..]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                let from = len.saturating_sub(3);
                len += n;
                if let Some(end) = buf[from..len].windows(4).position(|w| w == b"\r\n\r\n") {
                    return Some(from + end);
                }
            }
        }
    }
}

fn serve(stream: TcpStream, state: &str, issuer: &str, deadline: Instant) -> Outcome {
    let bound = deadline
        .saturating_duration_since(Instant::now())
        .clamp(Duration::from_millis(1), PER_REQUEST);
    let _ = stream.set_read_timeout(Some(bound));
    let _ = stream.set_write_timeout(Some(bound));
    let mut buf = [0u8; MAX_HEAD];
    let Some(head_len) = read_head(&stream, &mut buf) else {
        respond(&stream, "431 Request Header Fields Too Large", FAILED_PAGE);
        return Outcome::Ignored;
    };
    let head = &buf[..head_len];
    let line_end = head.iter().position(|b| *b == b'\r').unwrap_or(head.len());
    let mut parts = head[..line_end].split(|b| *b == b' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        respond(&stream, "400 Bad Request", FAILED_PAGE);
        return Outcome::Ignored;
    };
    let (path, query) = match target.iter().position(|b| *b == b'?') {
        Some(at) => (&target[..at], &target[at + 1..]),
        None => (target, &b""[..]),
    };
    if path != CLI_REDIRECT_PATH.as_bytes() {
        respond(&stream, "404 Not Found", FAILED_PAGE);
        return Outcome::Ignored;
    }
    if method != b"GET" {
        respond(&stream, "405 Method Not Allowed", FAILED_PAGE);
        return Outcome::Ignored;
    }
    let result = callback(query, state, issuer);
    match &result {
        Ok(_) => respond(&stream, "200 OK", DONE_PAGE),
        Err(_) => respond(&stream, "400 Bad Request", FAILED_PAGE),
    }
    Outcome::Done(result)
}

/// Constant-time equality of two strings (length is not secret).
fn same(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn refused(message: &str) -> Error {
    Error::new(Exit::Auth, message.to_owned())
}

/// Check a callback query: exactly one of each parameter, the state first,
/// then the issuer, then an error or the code.
fn callback(query: &[u8], state: &str, issuer: &str) -> Result<String, Error> {
    let (mut got_state, mut got_iss, mut code, mut error) = (None, None, None, None);
    for (name, value) in form_urlencoded::parse(query) {
        let slot = match &*name {
            "state" => &mut got_state,
            "iss" => &mut got_iss,
            "code" => &mut code,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(refused("the sign-in callback repeated a parameter"));
        }
    }
    if !got_state.as_deref().is_some_and(|s| same(s, state)) {
        return Err(refused(
            "the sign-in callback does not belong to this login (state mismatch); run the login again",
        ));
    }
    if got_iss.as_deref() != Some(issuer) {
        return Err(refused(
            "the sign-in callback came from another issuer (iss mismatch); run the login again",
        ));
    }
    if let Some(error) = error {
        let known = !error.is_empty()
            && error.len() <= 64
            && error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        return Err(refused(&format!(
            "the sign-in was not approved ({})",
            if known { error.as_str() } else { "error" }
        )));
    }
    code.filter(|c| !c.is_empty())
        .ok_or_else(|| refused("the sign-in callback carried no code"))
}
