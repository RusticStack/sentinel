//! A minimal client for Firecracker's API socket: one HTTP/1.1 request per connection, JSON bodies. Only the
//! calls the snapshot path makes (`PATCH /vm`, `PUT /snapshot/create`, `PUT /snapshot/load`) go through it.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use crate::{Error, Result};

/// Answers larger than this are not read: Firecracker's replies are a status line and a short fault message.
const MAX_ANSWER: usize = 64 << 10;

/// Sends one request and returns the body of a 2xx answer; any other status is an error naming it.
pub fn call(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let body = match body {
        Some(value) => serde_json::to_vec(value).map_err(std::io::Error::other)?,
        None => Vec::new(),
    };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    let (status, answer) = read_answer(&mut stream)?;
    if (200..300).contains(&status) {
        Ok(answer)
    } else {
        Err(Error::Runtime(format!(
            "firecracker {method} {path}: status {status}: {}",
            crate::redact::excerpt(&answer)
        )))
    }
}

/// The status and body of one answer: the head up to the blank line, then `Content-Length` bytes (none when
/// the head states none, as for 204).
fn read_answer(stream: &mut impl Read) -> std::io::Result<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > MAX_ANSWER {
            return Err(std::io::Error::other("firecracker: answer head too large"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::other(
                "firecracker closed the connection without an answer",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("firecracker: unreadable status line"))?;
    let length = head
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0)
        .min(MAX_ANSWER);
    let mut body = buf.split_off(end);
    while body.len() < length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    /// A one-shot server: reads the request, answers with `reply`, returns what it read.
    fn serve(
        dir: &Path,
        reply: &'static str,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<String>) {
        let path = dir.join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = conn.read(&mut chunk).unwrap();
                seen.extend_from_slice(&chunk[..n]);
                if let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&seen[..at]).to_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
                        .unwrap_or(0);
                    if seen.len() >= at + 4 + length {
                        break;
                    }
                }
            }
            conn.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        (path, handle)
    }

    #[test]
    fn a_204_answer_is_success_and_the_request_carries_its_json() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, server) = serve(
            dir.path(),
            "HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n",
        );
        let body = serde_json::json!({ "state": "Paused" });
        let answer = call(&socket, "PATCH", "/vm", Some(&body), Duration::from_secs(5)).unwrap();
        assert!(answer.is_empty());
        let seen = server.join().unwrap();
        assert!(seen.starts_with("PATCH /vm HTTP/1.1\r\n"), "{seen}");
        assert!(seen.ends_with("{\"state\":\"Paused\"}"), "{seen}");
    }

    #[test]
    fn an_error_status_names_the_status_and_the_fault_message() {
        let dir = tempfile::tempdir().unwrap();
        let fault = "{\"fault_message\":\"Cannot load snapshot\"}";
        let reply: &'static str = Box::leak(
            format!(
                "HTTP/1.1 400 \r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{fault}",
                fault.len()
            )
            .into_boxed_str(),
        );
        let (socket, server) = serve(dir.path(), reply);
        let err = call(
            &socket,
            "PUT",
            "/snapshot/load",
            None,
            Duration::from_secs(5),
        )
        .unwrap_err();
        server.join().unwrap();
        let text = err.to_string();
        assert!(
            text.contains("400") && text.contains("Cannot load snapshot"),
            "{text}"
        );
    }

    #[test]
    fn a_socket_that_never_answers_times_out_instead_of_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let started = std::time::Instant::now();
        assert!(call(&path, "PUT", "/x", None, Duration::from_millis(200)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
