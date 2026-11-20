//! A real upstream registry double: a loopback listener that serves the bytes a pull asks for and
//! counts every request that reaches it, so a test can tell a cache hit from a fetch.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use sentinel_registry::Registry;

pub struct Upstream {
    addr: SocketAddr,
    pub state: Arc<UpstreamState>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub struct UpstreamState {
    requests: AtomicUsize,
    paths: Mutex<Vec<String>>,
    pub blobs: Mutex<HashMap<String, Vec<u8>>>,
    /// reference (tag or `sha256:…`) → (media type, body)
    manifests: Mutex<HashMap<String, (String, Vec<u8>)>>,
    /// The `Authorization` value a request must carry, when the registry is private.
    credential: Mutex<Option<String>>,
}

impl Upstream {
    pub fn start() -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(UpstreamState::default());
        let stop = Arc::new(AtomicBool::new(false));
        let serving = Arc::clone(&state);
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&serving);
                thread::spawn(move || answer(state, stream));
            }
        });
        Upstream {
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    pub fn registry(&self) -> Registry {
        Registry::canonical(&self.host())
    }

    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::Acquire)
    }

    pub fn paths(&self) -> Vec<String> {
        self.state.paths.lock().unwrap().clone()
    }

    pub fn put_blob(&self, bytes: &[u8]) -> String {
        let digest = format!("sha256:{}", hex(&sha256(bytes)));
        self.state
            .blobs
            .lock()
            .unwrap()
            .insert(digest.clone(), bytes.to_vec());
        digest
    }

    pub fn put_manifest(&self, reference: &str, media_type: &str, body: &[u8]) {
        self.state
            .manifests
            .lock()
            .unwrap()
            .insert(reference.to_owned(), (media_type.to_owned(), body.to_vec()));
    }

    pub fn require(&self, credential: Option<&str>) {
        *self.state.credential.lock().unwrap() = credential.map(str::to_owned);
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn answer(state: Arc<UpstreamState>, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            authorization = Some(value.trim().to_owned());
        }
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();
    state.requests.fetch_add(1, Ordering::AcqRel);
    state.paths.lock().unwrap().push(format!("{method} {path}"));
    let mut stream = stream;
    let required = state.credential.lock().unwrap().clone();
    if let Some(required) = required
        && authorization.as_deref() != Some(required.as_str())
    {
        let head = "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Basic realm=\"test\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        let _ = stream.write_all(head.as_bytes());
        return;
    }
    if path == "/v2/" {
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
        );
        return;
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let verb_at = segments.len().saturating_sub(2);
    if segments.len() >= 4 && segments[0] == "v2" {
        let reference = segments[segments.len() - 1];
        match segments[verb_at] {
            "manifests" => {
                let found = state.manifests.lock().unwrap().get(reference).cloned();
                match found {
                    Some((media_type, body)) => {
                        let mut head = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: {media_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        if method == "GET" {
                            head.push_str(&String::from_utf8_lossy(&body));
                        }
                        let _ = stream.write_all(head.as_bytes());
                    }
                    None => not_found(&mut stream),
                }
            }
            "blobs" => {
                let found = state.blobs.lock().unwrap().get(reference).cloned();
                match found {
                    Some(body) => {
                        let mut bytes = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        if method == "GET" {
                            bytes.extend_from_slice(&body);
                        }
                        let _ = stream.write_all(&bytes);
                    }
                    None => not_found(&mut stream),
                }
            }
            _ => not_found(&mut stream),
        }
        return;
    }
    not_found(&mut stream);
}

fn not_found(stream: &mut TcpStream) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
}

/// A small but real image: a config blob and a layer blob reachable from one manifest.
#[allow(dead_code)]
pub struct Image {
    pub manifest: Vec<u8>,
    pub digest: String,
    pub blobs: Vec<(String, Vec<u8>)>,
}

pub fn image(upstream: &Upstream, tag: &str, seed: u8, layer_bytes: usize) -> Image {
    let config = upstream.put_blob(&[seed; 64]);
    let layer = upstream.put_blob(&vec![seed.wrapping_add(1); layer_bytes]);
    let manifest = format!(
        "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{config}\",\"size\":64}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{layer}\",\"size\":{layer_bytes}}}]}}"
    )
    .into_bytes();
    let digest = format!("sha256:{}", hex(&sha256(&manifest)));
    upstream.put_manifest(tag, "application/vnd.oci.image.manifest.v1+json", &manifest);
    upstream.put_manifest(
        &digest,
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
    );
    Image {
        manifest,
        digest,
        blobs: vec![
            (config, vec![seed; 64]),
            (layer, vec![seed.wrapping_add(1); layer_bytes]),
        ],
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finish().as_ref());
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
