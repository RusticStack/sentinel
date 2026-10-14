//! A bounded SMTP submission client.
//!
//! One message per connection, so no state survives between sends and a relay
//! that misbehaves costs one connection. Everything on the wire is bounded: a
//! connect timeout, a per-read and per-write timeout, a deadline over the
//! whole session, reply lines of at most [`MAX_REPLY_LINE`] bytes, replies of
//! at most [`MAX_REPLY_LINES`] lines, and messages of at most
//! [`MAX_MESSAGE_BYTES`].
//!
//! Transport security is never silently downgraded. [`Tls::Implicit`] wraps
//! the connection before the greeting; [`Tls::StartTls`] refuses a relay that
//! does not offer `STARTTLS` and refuses buffered plaintext at the upgrade (the
//! STARTTLS injection attack), and credentials are sent only inside TLS.
//! [`Tls::Plain`] exists for a relay on the same host and takes no credentials.
//! Server certificates are checked against the bundled web PKI roots.
//!
//! Replies are classified by code, and an error carries the stage and the
//! code, never the relay's text (which may echo an address) and never a
//! credential.

use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use sentinel_auth::secret::{wipe, wipe_string};
use sentinel_core::{MailId, UnixMillis};

/// The longest reply line accepted (RFC 5321 allows 512).
pub const MAX_REPLY_LINE: usize = 1024;
/// The most lines in one reply.
pub const MAX_REPLY_LINES: usize = 64;
/// The largest message sent, headers included.
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024;
/// RFC 5322's line limit.
const MAX_BODY_LINE: usize = 998;
/// Addresses a relay's name may resolve to that are tried.
const MAX_ADDRESSES: usize = 4;

/// How the connection is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls {
    /// TLS from the first byte (submissions, usually port 465).
    Implicit,
    /// Plaintext greeting, then a mandatory upgrade (usually port 587).
    StartTls,
    /// No TLS: for a relay on this host (`localhost`, a loopback address)
    /// only, and without credentials.
    Plain,
}

impl Tls {
    /// The names a configuration uses: `implicit`, `starttls`, `none`.
    pub fn parse(text: &str) -> Option<Tls> {
        match text {
            "implicit" => Some(Tls::Implicit),
            "starttls" => Some(Tls::StartTls),
            "none" => Some(Tls::Plain),
            _ => None,
        }
    }
}

/// A relay account. The password never appears in `Debug` output or an error
/// and is wiped when dropped.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(..)")
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        wipe(&mut self.password);
    }
}

impl Credentials {
    pub fn new(username: String, mut password: Vec<u8>) -> Result<Credentials, String> {
        let acceptable = |bytes: &[u8]| {
            (1..=255).contains(&bytes.len())
                && bytes.iter().all(|&b| b != 0 && !b.is_ascii_control())
        };
        if !acceptable(username.as_bytes()) || !acceptable(&password) {
            wipe(&mut password);
            return Err("credentials must be 1-255 characters without control characters".into());
        }
        Ok(Credentials { username, password })
    }

    /// Read `username = …` and `password = …` lines from an owner-only file
    /// of at most 8 KiB, like the other secret files. The contents are never
    /// echoed in an error.
    pub fn from_file(path: &Path) -> Result<Credentials, String> {
        let refuse = |why: &str| format!("{}: {why}", path.display());
        let meta = std::fs::symlink_metadata(path).map_err(|_| refuse("cannot read"))?;
        if !meta.is_file() || meta.len() > 8 * 1024 {
            return Err(refuse("must be a regular file of at most 8 KiB"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(refuse("must be readable by its owner only"));
            }
        }
        let mut raw = std::fs::read(path).map_err(|_| refuse("cannot read"))?;
        let parsed = (|| {
            let text = std::str::from_utf8(&raw).map_err(|_| refuse("must be UTF-8"))?;
            let (mut username, mut password) = (None, None);
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (name, value) = line
                    .split_once('=')
                    .ok_or_else(|| refuse("lines must be `name = value`"))?;
                let value = value.trim().trim_matches('"').to_owned();
                match name.trim() {
                    "username" => username = Some(value),
                    "password" => password = Some(value.into_bytes()),
                    _ => return Err(refuse("unknown setting (username, password)")),
                }
            }
            match (username, password) {
                (Some(username), Some(password)) => {
                    Credentials::new(username, password).map_err(|why| refuse(&why))
                }
                _ => Err(refuse("needs username and password")),
            }
        })();
        wipe(&mut raw);
        parsed
    }
}

/// Where and how to submit mail.
#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub credentials: Option<Credentials>,
    /// The envelope and header sender, in canonical form.
    pub from: String,
    pub connect_timeout: Duration,
    /// Each read and each write.
    pub io_timeout: Duration,
    /// The whole session, name resolution excepted.
    pub deadline: Duration,
}

impl Config {
    /// Validate and fill in the timeouts (10 s connect, 15 s per read or
    /// write, 60 s per session). Errors name the setting, never its value.
    pub fn new(
        host: String,
        port: u16,
        tls: Tls,
        credentials: Option<Credentials>,
        from: &str,
    ) -> Result<Config, String> {
        let name_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if !name_ok {
            return Err("smtp host must be a host name or IP address".into());
        }
        if port == 0 {
            return Err("smtp port must be 1-65535".into());
        }
        let from = sentinel_store::email::normalize(from)
            .map_err(|_| "from must be a plain address such as ci@example.com".to_owned())?;
        if tls == Tls::Plain {
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if !loopback || credentials.is_some() {
                return Err(
                    "tls = \"none\" is for a relay on this host and takes no credentials".into(),
                );
            }
        }
        Ok(Config {
            host,
            port,
            tls,
            credentials,
            from,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(15),
            deadline: Duration::from_secs(60),
        })
    }
}

/// One message to send.
pub struct Mail<'a> {
    pub id: MailId,
    /// The recipient, in canonical form.
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub now: UnixMillis,
}

/// Why a send failed. `Transient` is worth retrying (the relay is down or
/// slow, or the problem is the configuration's); `Permanent` is the relay
/// refusing this message, which retrying will not change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Transient(String),
    Permanent(String),
}

/// Something that can send one message.
pub trait Transport: Send {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure>;
}

/// The SMTP transport.
pub struct Smtp {
    config: Config,
    tls: Arc<ClientConfig>,
    /// The name given in `EHLO`: the sender's domain.
    name: String,
}

impl Smtp {
    pub fn new(config: Config) -> Result<Smtp, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "cannot set up TLS".to_owned())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = sentinel_store::email::domain_of(&config.from).to_owned();
        Ok(Smtp {
            config,
            tls: Arc::new(tls),
            name,
        })
    }

    fn connect(&self) -> Result<TcpStream, Failure> {
        let addresses: Vec<SocketAddr> = (self.config.host.as_str(), self.config.port)
            .to_socket_addrs()
            .map_err(|_| transient("cannot resolve the relay"))?
            .take(MAX_ADDRESSES)
            .collect();
        for address in addresses {
            if let Ok(stream) = TcpStream::connect_timeout(&address, self.config.connect_timeout) {
                let _ = stream.set_read_timeout(Some(self.config.io_timeout));
                let _ = stream.set_write_timeout(Some(self.config.io_timeout));
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
        }
        Err(transient("cannot connect to the relay"))
    }

    fn wrap(&self, tcp: TcpStream) -> Result<StreamOwned<ClientConnection, TcpStream>, Failure> {
        let name = ServerName::try_from(self.config.host.clone())
            .map_err(|_| transient("the relay host is not a valid TLS name"))?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), name)
            .map_err(|_| transient("cannot set up TLS"))?;
        Ok(StreamOwned::new(connection, tcp))
    }

    fn ehlo<S: Read + Write>(&self, conn: &mut Conn<S>) -> Result<Vec<String>, Failure> {
        let reply = conn.command(&format!("EHLO {}", self.name))?;
        Ok(expect(reply, &[250], Stage::Ehlo)?.lines)
    }

    fn authenticate<S: Read + Write>(
        &self,
        conn: &mut Conn<S>,
        credentials: &Credentials,
        capabilities: &[String],
    ) -> Result<(), Failure> {
        let mechanisms: Vec<String> = capabilities
            .iter()
            .filter_map(|line| {
                let upper = line.to_ascii_uppercase();
                upper
                    .strip_prefix("AUTH ")
                    .or_else(|| upper.strip_prefix("AUTH="))
                    .map(str::to_owned)
            })
            .collect();
        let offers = |name: &str| {
            mechanisms
                .iter()
                .any(|line| line.split_ascii_whitespace().any(|m| m == name))
        };
        if offers("PLAIN") {
            let mut raw =
                Vec::with_capacity(2 + credentials.username.len() + credentials.password.len());
            raw.push(0);
            raw.extend_from_slice(credentials.username.as_bytes());
            raw.push(0);
            raw.extend_from_slice(&credentials.password);
            let mut line = String::from("AUTH PLAIN ");
            line.push_str(&STANDARD.encode(&raw));
            wipe(&mut raw);
            let reply = conn.command(&line);
            wipe_string(&mut line);
            expect(reply?, &[235], Stage::Auth)?;
        } else if offers("LOGIN") {
            expect(conn.command("AUTH LOGIN")?, &[334], Stage::Auth)?;
            let mut user = STANDARD.encode(credentials.username.as_bytes());
            let reply = conn.command(&user);
            wipe_string(&mut user);
            expect(reply?, &[334], Stage::Auth)?;
            let mut pass = STANDARD.encode(&credentials.password);
            let reply = conn.command(&pass);
            wipe_string(&mut pass);
            expect(reply?, &[235], Stage::Auth)?;
        } else {
            return Err(transient("the relay offers no supported AUTH mechanism"));
        }
        Ok(())
    }

    /// Everything after the connection is protected: `EHLO`, `AUTH`, the
    /// envelope and the message.
    fn transaction<S: Read + Write>(
        &self,
        conn: &mut Conn<S>,
        mail: &Mail<'_>,
        data: &[u8],
    ) -> Result<(), Failure> {
        let capabilities = self.ehlo(conn)?;
        if let Some(credentials) = &self.config.credentials {
            self.authenticate(conn, credentials, &capabilities)?;
        }
        let from = conn.command(&format!("MAIL FROM:<{}>", self.config.from))?;
        expect(from, &[250], Stage::Sender)?;
        let to = conn.command(&format!("RCPT TO:<{}>", mail.to))?;
        expect(to, &[250, 251], Stage::Recipient)?;
        expect(conn.command("DATA")?, &[354], Stage::Data)?;
        conn.write_all(data)?;
        expect(conn.read_reply()?, &[250], Stage::Accepted)?;
        // The message is accepted; a failed goodbye changes nothing.
        let _ = conn.command("QUIT");
        Ok(())
    }

    /// Build the message: headers, a CRLF body with dot-stuffing, and the
    /// terminating dot line.
    pub fn build(&self, mail: &Mail<'_>) -> Result<Vec<u8>, Failure> {
        let permanent = |why: &str| Failure::Permanent(why.to_owned());
        let address_ok = |text: &str| {
            !text.is_empty()
                && text
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
        };
        if !address_ok(mail.to) || !address_ok(&self.config.from) {
            return Err(permanent("invalid address"));
        }
        if mail.subject.is_empty()
            || !mail.subject.bytes().all(|b| (0x20..0x7f).contains(&b))
            || !mail
                .body
                .bytes()
                .all(|b| matches!(b, b'\n' | b'\t') || (0x20..0x7f).contains(&b))
        {
            return Err(permanent("message is not plain ASCII"));
        }
        let when = time::OffsetDateTime::from_unix_timestamp(mail.now.0.div_euclid(1000))
            .ok()
            .and_then(|at| {
                at.format(&time::format_description::well_known::Rfc2822)
                    .ok()
            })
            .ok_or_else(|| permanent("invalid date"))?;
        let id = mail.id.to_string();
        let unique = id.strip_prefix("mal_").unwrap_or(&id);
        let mut out = Vec::with_capacity(512 + mail.body.len());
        out.extend_from_slice(
            format!(
                "From: Sentinel <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nDate: {when}\r\n\
                 Message-ID: <{unique}@{domain}>\r\nMIME-Version: 1.0\r\n\
                 Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\
                 Auto-Submitted: auto-generated\r\n\r\n",
                from = self.config.from,
                to = mail.to,
                subject = mail.subject,
                domain = self.name,
            )
            .as_bytes(),
        );
        for line in mail.body.split_terminator('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.len() > MAX_BODY_LINE {
                return Err(permanent("message line too long"));
            }
            if line.starts_with('.') {
                out.push(b'.');
            }
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
        if out.len() > MAX_MESSAGE_BYTES {
            return Err(permanent("message too large"));
        }
        Ok(out)
    }
}

impl Transport for Smtp {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure> {
        let mut data = self.build(mail)?;
        let outcome = self.deliver(mail, &data);
        // The body carries a one-time link.
        wipe(&mut data);
        outcome
    }
}

impl Smtp {
    fn deliver(&self, mail: &Mail<'_>, data: &[u8]) -> Result<(), Failure> {
        let tcp = self.connect()?;
        let deadline = Instant::now() + self.config.deadline;
        match self.config.tls {
            Tls::Implicit => {
                let mut conn = Conn::new(self.wrap(tcp)?, deadline);
                expect(conn.read_reply()?, &[220], Stage::Greeting)?;
                self.transaction(&mut conn, mail, data)
            }
            Tls::Plain => {
                let mut conn = Conn::new(tcp, deadline);
                expect(conn.read_reply()?, &[220], Stage::Greeting)?;
                self.transaction(&mut conn, mail, data)
            }
            Tls::StartTls => {
                let mut plain = Conn::new(tcp, deadline);
                expect(plain.read_reply()?, &[220], Stage::Greeting)?;
                let capabilities = self.ehlo(&mut plain)?;
                if !capabilities
                    .iter()
                    .any(|line| line.trim().eq_ignore_ascii_case("STARTTLS"))
                {
                    // Never fall back to plaintext.
                    return Err(transient("the relay does not offer STARTTLS"));
                }
                expect(plain.command("STARTTLS")?, &[220], Stage::StartTls)?;
                if !plain.buf.is_empty() {
                    return Err(transient("unexpected data before the TLS handshake"));
                }
                let mut conn = Conn::new(self.wrap(plain.stream)?, deadline);
                self.transaction(&mut conn, mail, data)
            }
        }
    }
}

fn transient(why: &str) -> Failure {
    Failure::Transient(why.to_owned())
}

/// Where in the dialogue a reply came: decides whether a 5xx is the
/// message's fault (permanent) or the relay's setup (transient).
#[derive(Clone, Copy)]
enum Stage {
    Greeting,
    Ehlo,
    StartTls,
    Auth,
    Sender,
    Recipient,
    Data,
    Accepted,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Stage::Greeting => "greeting",
            Stage::Ehlo => "EHLO",
            Stage::StartTls => "STARTTLS",
            Stage::Auth => "AUTH",
            Stage::Sender => "MAIL",
            Stage::Recipient => "RCPT",
            Stage::Data => "DATA",
            Stage::Accepted => "end of data",
        }
    }

    /// Whether a 5xx here is the relay refusing this message.
    const fn refusal_is_final(self) -> bool {
        matches!(
            self,
            Stage::Sender | Stage::Recipient | Stage::Data | Stage::Accepted
        )
    }
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

fn expect(reply: Reply, accepted: &[u16], stage: Stage) -> Result<Reply, Failure> {
    if accepted.contains(&reply.code) {
        return Ok(reply);
    }
    let why = format!("{} replied {}", stage.name(), reply.code);
    Err(
        if (500..600).contains(&reply.code) && stage.refusal_is_final() {
            Failure::Permanent(why)
        } else {
            Failure::Transient(why)
        },
    )
}

/// A connection with a reply buffer and the session's deadline.
struct Conn<S> {
    stream: S,
    /// Bytes read and not yet consumed.
    buf: Vec<u8>,
    deadline: Instant,
}

impl<S: Read + Write> Conn<S> {
    fn new(stream: S, deadline: Instant) -> Self {
        Conn {
            stream,
            buf: Vec::with_capacity(512),
            deadline,
        }
    }

    fn io_failure(error: &io::Error) -> Failure {
        // The kind says what happened (timeout, reset, a refused handshake)
        // without echoing the peer's data; a TLS error adds its own bounded,
        // non-secret reason.
        let mut why = format!("connection failed ({:?})", error.kind());
        if matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::Other
        ) && let Some(inner) = error.get_ref()
        {
            let inner: String = inner
                .to_string()
                .chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect();
            why.push_str(": ");
            why.push_str(&inner);
        }
        Failure::Transient(why)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if Instant::now() >= self.deadline {
            return Err(transient("the session ran out of time"));
        }
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|e| Self::io_failure(&e))
    }

    fn command(&mut self, line: &str) -> Result<Reply, Failure> {
        let mut bytes = Vec::with_capacity(line.len() + 2);
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        let sent = self.write_all(&bytes);
        wipe(&mut bytes);
        sent?;
        self.read_reply()
    }

    fn read_line(&mut self) -> Result<Vec<u8>, Failure> {
        loop {
            if let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
                if end > MAX_REPLY_LINE {
                    return Err(transient("reply line too long"));
                }
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buf.len() > MAX_REPLY_LINE {
                return Err(transient("reply line too long"));
            }
            if Instant::now() >= self.deadline {
                return Err(transient("the session ran out of time"));
            }
            let mut chunk = [0u8; 512];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(transient("the relay closed the connection")),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Self::io_failure(&e)),
            }
        }
    }

    fn read_reply(&mut self) -> Result<Reply, Failure> {
        let malformed = || transient("malformed reply");
        let mut lines = Vec::new();
        let mut code = 0u16;
        loop {
            let line = self.read_line()?;
            if lines.len() >= MAX_REPLY_LINES {
                return Err(transient("reply too long"));
            }
            let digits = line.get(..3).ok_or_else(malformed)?;
            if !digits.iter().all(u8::is_ascii_digit) {
                return Err(malformed());
            }
            let this = u16::from(digits[0] - b'0') * 100
                + u16::from(digits[1] - b'0') * 10
                + u16::from(digits[2] - b'0');
            if !lines.is_empty() && this != code {
                return Err(malformed());
            }
            code = this;
            let more = match line.get(3) {
                None | Some(b' ') => false,
                Some(b'-') => true,
                Some(_) => return Err(malformed()),
            };
            lines.push(String::from_utf8_lossy(line.get(4..).unwrap_or(&[])).into_owned());
            if !more {
                return Ok(Reply { code, lines });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        thread,
    };

    use super::*;

    fn config(port: u16) -> Config {
        let mut config =
            Config::new("127.0.0.1".into(), port, Tls::Plain, None, "Ci@Example.com").unwrap();
        config.io_timeout = Duration::from_secs(5);
        config.deadline = Duration::from_secs(10);
        config
    }

    fn mail<'a>(to: &'a str, body: &'a str) -> Mail<'a> {
        Mail {
            id: MailId::new(),
            to,
            subject: "Verify your address",
            body,
            now: UnixMillis(1_760_000_000_000),
        }
    }

    /// A scripted relay: for each client command line, the reply to send.
    /// Returns the commands it saw (the message body as one entry).
    fn relay(script: Vec<(&'static str, &'static str)>) -> (u16, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut seen = Vec::new();
            writer.write_all(b"220 relay ready\r\n").unwrap();
            let mut data = false;
            let mut body = String::new();
            let mut script = script.into_iter();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if data {
                    if line == ".\r\n" {
                        data = false;
                        seen.push(std::mem::take(&mut body));
                        let (_, reply) = script.next().unwrap();
                        writer.write_all(reply.as_bytes()).unwrap();
                    } else {
                        body.push_str(&line);
                    }
                    continue;
                }
                let line = line.trim_end().to_owned();
                seen.push(line.clone());
                if line == "QUIT" {
                    let _ = writer.write_all(b"221 bye\r\n");
                    break;
                }
                let Some((_, reply)) = script.next() else {
                    break;
                };
                writer.write_all(reply.as_bytes()).unwrap();
                if line == "DATA" && reply.starts_with("354") {
                    data = true;
                }
            }
            seen
        });
        (port, handle)
    }

    fn happy() -> Vec<(&'static str, &'static str)> {
        vec![
            ("EHLO", "250-relay\r\n250 8BITMIME\r\n"),
            ("MAIL", "250 ok\r\n"),
            ("RCPT", "250 ok\r\n"),
            ("DATA", "354 go\r\n"),
            (".", "250 queued\r\n"),
        ]
    }

    #[test]
    fn a_message_is_delivered_with_a_well_formed_envelope_and_body() {
        let (port, relay) = relay(happy());
        let mut smtp = Smtp::new(config(port)).unwrap();
        smtp.send(&mail("bob@example.org", "Line one\n.leading dot\nlast\n"))
            .unwrap();
        let seen = relay.join().unwrap();
        assert_eq!(seen[0], "EHLO example.com");
        assert_eq!(seen[1], "MAIL FROM:<ci@example.com>");
        assert_eq!(seen[2], "RCPT TO:<bob@example.org>");
        assert_eq!(seen[3], "DATA");
        let message = &seen[4];
        assert!(message.contains("To: <bob@example.org>\r\n"));
        assert!(message.contains("Subject: Verify your address\r\n"));
        assert!(
            message.contains("\r\n\r\nLine one\r\n..leading dot\r\nlast\r\n"),
            "{message:?}"
        );
        assert!(message.lines().all(|l| l.len() <= 998));
    }

    #[test]
    fn a_refused_recipient_is_permanent_and_a_busy_relay_is_transient() {
        let mut script = happy();
        script[2] = ("RCPT", "550 no such user\r\n");
        let (port, relay_a) = relay(script);
        let mut smtp = Smtp::new(config(port)).unwrap();
        let failure = smtp.send(&mail("bob@example.org", "x\n")).unwrap_err();
        assert!(matches!(failure, Failure::Permanent(_)), "{failure:?}");
        // The relay's own words (which can echo an address) are not carried.
        assert!(!format!("{failure:?}").contains("no such user"));
        relay_a.join().unwrap();

        let mut script = happy();
        script[2] = ("RCPT", "451 try later\r\n");
        let (port, relay_b) = relay(script);
        let mut smtp = Smtp::new(config(port)).unwrap();
        let failure = smtp.send(&mail("bob@example.org", "x\n")).unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        relay_b.join().unwrap();
    }

    #[test]
    fn a_refused_ehlo_or_greeting_problem_is_never_the_messages_fault() {
        let (port, relay) = relay(vec![("EHLO", "554 go away\r\n")]);
        let mut smtp = Smtp::new(config(port)).unwrap();
        let failure = smtp.send(&mail("bob@example.org", "x\n")).unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        let _ = relay.join();
    }

    #[test]
    fn an_endless_reply_line_is_cut_off() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let junk = vec![b'a'; 64 * 1024];
            let _ = stream.write_all(b"220 ");
            let _ = stream.write_all(&junk);
        });
        let mut smtp = Smtp::new(config(port)).unwrap();
        let failure = smtp.send(&mail("bob@example.org", "x\n")).unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        let _ = handle.join();
    }

    #[test]
    fn starttls_is_required_when_chosen_and_never_downgraded() {
        let mut starttls = config(0);
        starttls.tls = Tls::StartTls;
        let (port, relay) = relay(vec![("EHLO", "250 relay\r\n")]);
        starttls.port = port;
        let mut smtp = Smtp::new(starttls).unwrap();
        let failure = smtp.send(&mail("bob@example.org", "x\n")).unwrap_err();
        assert_eq!(
            failure,
            Failure::Transient("the relay does not offer STARTTLS".into())
        );
        // No MAIL, RCPT or credentials followed.
        assert_eq!(relay.join().unwrap(), vec!["EHLO example.com"]);
    }

    #[test]
    fn header_injection_and_non_ascii_are_refused_before_connecting() {
        let smtp = Smtp::new(config(1)).unwrap();
        let mut bad = mail("bob@example.org", "x\n");
        bad.subject = "hi\r\nBcc: eve@example.net";
        assert!(matches!(smtp.build(&bad), Err(Failure::Permanent(_))));
        let bad = mail("bob@example.org>\r\nRCPT TO:<eve@example.net", "x\n");
        assert!(matches!(smtp.build(&bad), Err(Failure::Permanent(_))));
        let bad = mail("bob@example.org", "caf\u{e9}\n");
        assert!(matches!(smtp.build(&bad), Err(Failure::Permanent(_))));
        let long = "a".repeat(999);
        assert!(matches!(
            smtp.build(&mail("bob@example.org", &long)),
            Err(Failure::Permanent(_))
        ));
    }

    #[test]
    fn plain_transport_is_loopback_only_and_never_carries_credentials() {
        let creds = || Credentials::new("user".into(), b"pw".to_vec()).unwrap();
        assert!(
            Config::new(
                "mail.example.com".into(),
                25,
                Tls::Plain,
                None,
                "a@example.com"
            )
            .is_err()
        );
        assert!(
            Config::new(
                "127.0.0.1".into(),
                25,
                Tls::Plain,
                Some(creds()),
                "a@example.com"
            )
            .is_err()
        );
        assert!(Config::new("localhost".into(), 25, Tls::Plain, None, "a@example.com").is_ok());
        assert!(
            Config::new(
                "mail.example.com".into(),
                465,
                Tls::Implicit,
                Some(creds()),
                "a@example.com"
            )
            .is_ok()
        );
        assert!(
            Config::new(
                "mail.example.com".into(),
                0,
                Tls::Implicit,
                None,
                "a@example.com"
            )
            .is_err()
        );
        assert!(
            Config::new(
                "mail.example.com".into(),
                465,
                Tls::Implicit,
                None,
                "not an address"
            )
            .is_err()
        );
        assert_eq!(format!("{:?}", creds()), "Credentials(..)");
    }

    #[test]
    fn a_credentials_file_is_parsed_and_bounded_and_never_echoed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("smtp");
        std::fs::write(&path, "# relay\nusername = ci\npassword = \"s3cret\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let creds = Credentials::from_file(&path).unwrap();
        assert_eq!(creds.username, "ci");
        assert_eq!(creds.password, b"s3cret");
        std::fs::write(&path, "username = ci\ntoken = nope-s3cret\n").unwrap();
        let error = Credentials::from_file(&path).unwrap_err();
        assert!(!error.contains("s3cret"), "{error}");
        std::fs::write(&path, vec![b'a'; 9 * 1024]).unwrap();
        assert!(Credentials::from_file(&path).is_err());
        std::fs::write(&path, "username = ci\n").unwrap();
        assert!(Credentials::from_file(&path).is_err());
    }
}
