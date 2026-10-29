//! The client against a scripted loopback server: timeout budgets and what a 404 on a delete means.
//! No signature is checked here; `compat.rs` covers real endpoints.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use sentinel_s3::{Client, Config, Credentials, Error};

struct Request {
    method: String,
    range: Option<(u64, u64)>,
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    /// The body is written in this many slices with `pause` between them.
    slices: usize,
    pause: Duration,
}

impl Reply {
    fn plain(status: u16, body: &str) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            slices: 1,
            pause: Duration::ZERO,
        }
    }
}

struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    requests: Arc<AtomicUsize>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let method = text.split_whitespace().next()?.to_owned();
    let range = text.lines().find_map(|line| {
        let value = line.to_ascii_lowercase();
        let value = value.strip_prefix("range: bytes=")?.to_owned();
        let (a, b) = value.trim().split_once('-')?;
        Some((a.parse().ok()?, b.parse().ok()?))
    });
    Some(Request { method, range })
}

fn serve(handler: impl Fn(&Request) -> Reply + Send + 'static) -> Server {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let thread = {
        let (stop, requests) = (Arc::clone(&stop), Arc::clone(&requests));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                requests.fetch_add(1, Ordering::Relaxed);
                let reply = handler(&request);
                let mut head = format!(
                    "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                if stream.write_all(head.as_bytes()).is_err() {
                    continue;
                }
                if request.method == "HEAD" {
                    continue;
                }
                let step = reply.body.len().div_ceil(reply.slices.max(1)).max(1);
                for slice in reply.body.chunks(step) {
                    if stream.write_all(slice).is_err() {
                        break;
                    }
                    let _ = stream.flush();
                    std::thread::sleep(reply.pause);
                }
            }
        })
    };
    Server {
        port,
        stop,
        thread: Some(thread),
        requests,
    }
}

fn client(port: u16, read_timeout: Duration) -> Client {
    Client::new(Config {
        endpoint: format!("http://127.0.0.1:{port}"),
        region: "us-east-1".into(),
        bucket: "bucket-one".into(),
        prefix: String::new(),
        path_style: true,
        ca_file: None,
        credentials: Credentials::new("AKIDEXAMPLE".into(), b"secret".to_vec(), None).unwrap(),
        connect_timeout: Duration::from_secs(5),
        read_timeout,
    })
    .unwrap()
}

fn object(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// Answers ranged reads of `body`, slowly: a read of `n` bytes takes 4 pauses.
fn slow_object(body: Vec<u8>, pause: Duration) -> impl Fn(&Request) -> Reply + Send + 'static {
    move |request| {
        let total = body.len() as u64;
        match request.range {
            Some((a, b)) if a < total => {
                let b = b.min(total - 1);
                Reply {
                    status: 206,
                    headers: vec![("content-range", format!("bytes {a}-{b}/{total}"))],
                    body: body[a as usize..=b as usize].to_vec(),
                    slices: 4,
                    pause,
                }
            }
            Some(_) => Reply::plain(416, ""),
            None => Reply {
                status: 200,
                headers: Vec::new(),
                body: body.clone(),
                slices: 32,
                pause,
            },
        }
    }
}

#[test]
fn a_slow_object_is_read_in_ranges_each_inside_its_own_budget() {
    let body = object(8 * 1024);
    let server = serve(slow_object(body.clone(), Duration::from_millis(60)));
    // The whole object takes about 1.9 s to arrive; one read of 1 KiB takes about 0.25 s.
    let client = client(server.port, Duration::from_secs(1));

    let started = Instant::now();
    let (len, mut reader) = client.get_object("k", None).unwrap();
    let mut whole = Vec::new();
    let single = reader.read_to_end(&mut whole);
    assert_eq!(len, body.len() as u64);
    assert!(
        single.is_err() || whole.len() < body.len(),
        "one read of the whole object outlasts the 1 s total body budget"
    );

    let mut out = Vec::new();
    let read = client.read_object("k", &mut out, 1024).unwrap();
    assert_eq!(read, body.len() as u64);
    assert_eq!(out, body);
    assert!(
        started.elapsed() > Duration::from_secs(2),
        "the chunked read took longer than one budget, yet completed"
    );
}

#[test]
fn a_server_that_ignores_ranges_is_read_whole_and_an_empty_object_reads_empty() {
    let body = object(3000);
    let whole = body.clone();
    let server = serve(move |_| Reply {
        status: 200,
        headers: Vec::new(),
        body: whole.clone(),
        slices: 1,
        pause: Duration::ZERO,
    });
    let mut out = Vec::new();
    let read = client(server.port, Duration::from_secs(5))
        .read_object("k", &mut out, 1024)
        .unwrap();
    assert_eq!((read, out), (3000, body));

    let empty = serve(|request| {
        if request.range.is_some() {
            Reply::plain(416, "<Error><Code>InvalidRange</Code></Error>")
        } else {
            Reply::plain(200, "")
        }
    });
    let mut out = Vec::new();
    let read = client(empty.port, Duration::from_secs(5))
        .read_object("k", &mut out, 1024)
        .unwrap();
    assert_eq!(read, 0);
    assert!(out.is_empty());
}

#[test]
fn a_range_answered_with_the_wrong_span_is_refused() {
    let server = serve(|_| Reply {
        status: 206,
        headers: vec![("content-range", "bytes 10-19/100".into())],
        body: vec![0; 10],
        slices: 1,
        pause: Duration::ZERO,
    });
    let mut out = Vec::new();
    let error = client(server.port, Duration::from_secs(5))
        .read_object("k", &mut out, 10)
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(_)), "{error}");
    assert!(out.is_empty());
}

fn xml_error(code: &str) -> String {
    format!("<Error><Code>{code}</Code><RequestId>R1</RequestId></Error>")
}

#[test]
fn a_404_on_a_delete_is_done_only_for_the_missing_key() {
    let missing_key = serve(|_| Reply::plain(404, &xml_error("NoSuchKey")));
    client(missing_key.port, Duration::from_secs(5))
        .delete_object("k")
        .unwrap();

    for refusal in [xml_error("NoSuchBucket"), String::new()] {
        let server = serve(move |_| Reply::plain(404, &refusal));
        let error = client(server.port, Duration::from_secs(5))
            .delete_object("k")
            .unwrap_err();
        assert!(
            matches!(error, Error::Refused { status: 404, .. }),
            "{error}"
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    }

    let no_upload = serve(|_| Reply::plain(404, &xml_error("NoSuchUpload")));
    client(no_upload.port, Duration::from_secs(5))
        .abort_multipart("k", "u")
        .unwrap();
    let no_bucket = serve(|_| Reply::plain(404, &xml_error("NoSuchBucket")));
    assert!(
        client(no_bucket.port, Duration::from_secs(5))
            .abort_multipart("k", "u")
            .is_err()
    );
}

/// Accepts one request and drains its body at about 6 MB/s, then answers 200 with an ETag.
fn slow_sink() -> (u16, JoinHandle<u64>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap() == 0 {
                return 0;
            }
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let declared: u64 = text
            .lines()
            .find_map(|line| line.strip_prefix("content-length:")?.trim().parse().ok())
            .unwrap();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut seen = 0u64;
        while seen < declared {
            let want = chunk.len().min((declared - seen) as usize);
            match stream.read(&mut chunk[..want]) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen += n as u64,
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\netag: \"e1\"\r\nconnection: close\r\n\r\n",
        );
        seen
    });
    (port, thread)
}

#[test]
fn a_part_slower_than_the_base_timeout_is_given_time_in_proportion_to_its_size() {
    // 32 MiB at the 4 MiB/s floor is a budget of 8 s; the sink takes about 5 s, far beyond the 1 s base timeout.
    // Kernel buffers hold part of the body, but not all of it, so the send itself is blocked for longer than 1 s.
    let body = vec![7u8; 32 << 20];
    let (port, sink) = slow_sink();
    let client = client(port, Duration::from_secs(1));

    let started = Instant::now();
    let etag = client
        .upload_part("k", "u", 1, &body)
        .expect("the budget scales with the part");
    assert_eq!(etag, "e1");
    assert!(
        started.elapsed() > Duration::from_secs(2),
        "the transfer outlasted the base timeout, so the scaled budget is what let it finish"
    );
    assert_eq!(sink.join().unwrap(), body.len() as u64);
}
