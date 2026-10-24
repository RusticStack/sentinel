//! Only a `/callback` carrying this login's `state` (compared in constant time) decides the sign-in.
//! Any other state is answered `400` and ignored, so a stray local process or web page cannot end it.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_protocol::oauth::CLI_REDIRECT_PATH;

use crate::client::{Error, Exit};

pub const WAIT: Duration = Duration::from_secs(5 * 60);
pub const MAX_HEAD: usize = 8 << 10;
const PER_REQUEST: Duration = Duration::from_secs(10);
pub const MAX_CONNECTIONS: usize = 32;
const ACCEPT_PAUSE: Duration = Duration::from_millis(10);
const CONNECTION_STACK: usize = 64 << 10;

const DONE_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sentinel sign-in</title></head>\
<body><p>Sentinel sign-in is complete. You can close this window and return to the terminal.</p></body></html>";
const FAILED_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sentinel sign-in</title></head>\
<body><p>Sentinel sign-in did not complete. Return to the terminal for details.</p></body></html>";

pub struct Listener {
    listener: TcpListener,
    addr: SocketAddr,
}

enum Outcome {
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

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CLI_REDIRECT_PATH}", self.addr.port())
    }

    pub fn wait(self, state: &str, issuer: &str, timeout: Duration) -> Result<String, Error> {
        let deadline = Instant::now() + timeout;
        let addr = self.addr;
        // A blocking accept has no timeout, so a watchdog connects to wake it at the deadline.
        let expired = Arc::new(AtomicBool::new(false));
        let (finished, finished_rx) = mpsc::channel::<()>();
        let watchdog = {
            let expired = Arc::clone(&expired);
            thread::spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) = finished_rx.recv_timeout(timeout) {
                    expired.store(true, Ordering::Release);
                    let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(1));
                }
            })
        };
        let expected: Arc<(String, String)> = Arc::new((state.to_owned(), issuer.to_owned()));
        let active = Arc::new(AtomicUsize::new(0));
        let (decided, decision) = mpsc::channel::<Result<String, Error>>();
        let result = loop {
            let accepted = self.listener.accept();
            if let Ok(result) = decision.try_recv() {
                break result;
            }
            if expired.load(Ordering::Acquire) || Instant::now() >= deadline {
                break Err(Error::new(
                    Exit::Auth,
                    format!(
                        "the browser sign-in did not finish within {} s; run the login again",
                        timeout.as_secs()
                    ),
                ));
            }
            let stream = match accepted {
                Ok((stream, _)) => stream,
                Err(_) => {
                    thread::sleep(ACCEPT_PAUSE);
                    continue;
                }
            };
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let (expected, held, decided) =
                (Arc::clone(&expected), Arc::clone(&active), decided.clone());
            let spawned = thread::Builder::new()
                .name("sentinel-callback".into())
                .stack_size(CONNECTION_STACK)
                .spawn(move || {
                    if let Outcome::Done(result) = serve(stream, &expected.0, &expected.1, deadline)
                        && decided.send(result).is_ok()
                    {
                        let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(1));
                    }
                    held.fetch_sub(1, Ordering::AcqRel);
                });
            if spawned.is_err() {
                active.fetch_sub(1, Ordering::AcqRel);
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
    let outcome = callback(query, state, issuer);
    match &outcome {
        Outcome::Done(Ok(_)) => respond(&stream, "200 OK", DONE_PAGE),
        _ => respond(&stream, "400 Bad Request", FAILED_PAGE),
    }
    outcome
}

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

fn callback(query: &[u8], state: &str, issuer: &str) -> Outcome {
    let (mut got_iss, mut code, mut error) = (None, None, None);
    let (mut states, mut ours, mut repeated) = (0u32, false, false);
    for (name, value) in form_urlencoded::parse(query) {
        let slot = match &*name {
            "state" => {
                states += 1;
                ours |= same(&value, state);
                continue;
            }
            "iss" => &mut got_iss,
            "code" => &mut code,
            "error" => &mut error,
            _ => continue,
        };
        repeated |= slot.replace(value.into_owned()).is_some();
    }
    if !ours {
        return Outcome::Ignored;
    }
    if repeated || states > 1 {
        return Outcome::Done(Err(refused("the sign-in callback repeated a parameter")));
    }
    if got_iss.as_deref() != Some(issuer) {
        return Outcome::Done(Err(refused(
            "the sign-in callback came from another issuer (iss mismatch); run the login again",
        )));
    }
    if let Some(error) = error {
        let known = !error.is_empty()
            && error.len() <= 64
            && error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        return Outcome::Done(Err(refused(&format!(
            "the sign-in was not approved ({})",
            if known { error.as_str() } else { "error" }
        ))));
    }
    Outcome::Done(
        code.filter(|c| !c.is_empty())
            .ok_or_else(|| refused("the sign-in callback carried no code")),
    )
}
