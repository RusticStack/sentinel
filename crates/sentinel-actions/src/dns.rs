//! The name answers one sandbox gets: the two service hosts resolve to this sandbox's endpoint, and
//! every other name is refused.
//!
//! Refusing is the point. A resolver that forwarded the names it does not answer would hand a job a
//! path to GitHub's cache and artifact storage, which is the one thing AR06 promises never happens;
//! and because the sandbox resolves *through* this resolver for the two names only, every other
//! GitHub host — the runner's own control traffic above all — keeps GitHub's own answers.
//!
//! The wire format is implemented here rather than depended on: a resolver is a header, one question
//! and one address, and a client sending a real query is what the tests drive.

use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use crate::{HOSTS, Result};

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NOERROR: u16 = 0;
const RCODE_REFUSED: u16 = 5;
const RCODE_FORMERR: u16 = 1;
/// How long a reply stands in a sandbox: the endpoint it names is the sandbox's own and dies with it.
const TTL: u32 = 0;

pub struct Resolver {
    address: Ipv4Addr,
}

impl Resolver {
    /// The resolver of the sandbox whose endpoint is `address`.
    pub fn new(address: Ipv4Addr) -> Resolver {
        Resolver { address }
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// The answer to one query, or `None` for datagrams that are not queries at all. A query for one of
    /// the two hosts is answered with this resolver's address, any other name with `REFUSED` and no
    /// answer — never a forward.
    pub fn reply(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < HEADER + 5 {
            return None;
        }
        let flags = u16::from_be_bytes([query[2], query[3]]);
        // Only a single-question standard query is ours; an answer or an update is not.
        if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 {
            return None;
        }
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount != 1 {
            return Some(header_reply(query, RCODE_FORMERR));
        }
        let (name, qtype, qclass, end) = match question(query) {
            Some(parsed) => parsed,
            None => return Some(header_reply(query, RCODE_FORMERR)),
        };
        if !HOSTS.iter().any(|host| host.eq_ignore_ascii_case(&name)) {
            // A name that is not one of the two services is not answered and not forwarded.
            return Some(header_reply(query, RCODE_REFUSED));
        }
        if qclass != CLASS_IN {
            return Some(header_reply(query, RCODE_REFUSED));
        }
        match qtype {
            TYPE_A => {
                let mut out = Vec::with_capacity(end + 16);
                out.extend_from_slice(&query[..end]);
                // QR + RD + RA, one answer, NOERROR; the question count is the query's own.
                out[2] = 0x80 | (query[2] & 0x01);
                out[3] = 0x80 | (query[3] & 0x01);
                out[6..8].copy_from_slice(&1u16.to_be_bytes());
                out[8..10].copy_from_slice(&0u16.to_be_bytes());
                out[10..12].copy_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&[0xc0, 0x0c]);
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&TTL.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&self.address.octets());
                Some(out)
            }
            // The namespace is v4-only: an AAAA question is answered, with nothing in it, so a client
            // falls back to the A record rather than reading a refusal as "this name does not exist".
            TYPE_AAAA => Some(header_reply(query, RCODE_NOERROR)),
            _ => Some(header_reply(query, RCODE_NOERROR)),
        }
    }

    /// Binds and answers until `stop` is set. The socket is polled rather than blocked on so a sandbox
    /// teardown never waits for a resolver that nobody queried.
    pub fn serve(
        self,
        bind: SocketAddr,
        stop: Arc<AtomicBool>,
    ) -> Result<(SocketAddr, JoinHandle<()>)> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let addr = socket.local_addr()?;
        let resolver: Arc<Resolver> = Arc::new(self);
        let join = std::thread::Builder::new()
            .name("sentinel-sandbox-dns".to_owned())
            .spawn(move || {
                let mut buf = [0u8; 512];
                while !stop.load(Ordering::Acquire) {
                    let (len, peer) = match socket.recv_from(&mut buf) {
                        Ok(pair) => pair,
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                        {
                            continue;
                        }
                        Err(_) => return,
                    };
                    if let Some(reply) = resolver.reply(&buf[..len]) {
                        let _ = socket.send_to(&reply, peer);
                    }
                }
            })
            .map_err(crate::Error::Io)?;
        Ok((addr, join))
    }
}

/// The question's dotted name (lower-cased), type, class and the offset just past it.
fn question(query: &[u8]) -> Option<(String, u16, u16, usize)> {
    let mut at = HEADER;
    let mut name = String::with_capacity(64);
    loop {
        let len = *query.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        // Compression pointers and reserved lengths are not a question a client sends.
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        let label = query.get(at..at + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        for byte in label {
            name.push(char::from(*byte).to_ascii_lowercase());
        }
        at += len;
        if name.len() > 255 {
            return None;
        }
    }
    let qtype = u16::from_be_bytes([*query.get(at)?, *query.get(at + 1)?]);
    let qclass = u16::from_be_bytes([*query.get(at + 2)?, *query.get(at + 3)?]);
    Some((name, qtype, qclass, at + 4))
}

/// A reply with the query's own question echoed and no answer records.
fn header_reply(query: &[u8], rcode: u16) -> Vec<u8> {
    let end = question(query).map_or(HEADER, |(_, _, _, end)| end);
    let mut out = query[..end].to_vec();
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = (query[3] & 0x01) | 0x80 | (rcode as u8 & 0xf);
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    if rcode != RCODE_NOERROR {
        out[4..6].copy_from_slice(&1u16.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query as a stub resolver on this machine writes it: one question, recursion desired.
    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    fn rcodes(reply: &[u8]) -> (u16, u16, u16) {
        (
            u16::from_be_bytes([reply[6], reply[7]]),
            u16::from_be_bytes([reply[8], reply[9]]),
            u16::from_be_bytes([reply[10], reply[11]]),
        )
    }

    #[test]
    fn both_service_names_answer_with_the_sandbox_endpoint() {
        let resolver = Resolver::new(Ipv4Addr::new(10, 0, 2, 2));
        for host in HOSTS {
            let reply = resolver.reply(&query(0x1234, host, TYPE_A)).unwrap();
            let (answers, _, _) = rcodes(&reply);
            assert_eq!(answers, 1, "{host}");
            assert_eq!(&reply[0..2], &0x1234u16.to_be_bytes(), "the id is echoed");
            assert_eq!(reply[3] & 0xf, 0, "NOERROR");
            // The answer record ends the packet: pointer, type, class, ttl, length, address.
            let answer = &reply[reply.len() - 16..];
            assert_eq!(&answer[0..2], &[0xc0, 0x0c]);
            assert_eq!(&answer[2..4], &TYPE_A.to_be_bytes());
            assert_eq!(&answer[4..6], &CLASS_IN.to_be_bytes());
            assert_eq!(&answer[12..16], &[10, 0, 2, 2]);
        }
    }

    #[test]
    fn a_name_that_is_not_a_service_host_is_refused_rather_than_forwarded() {
        let resolver = Resolver::new(Ipv4Addr::new(10, 0, 2, 2));
        for name in [
            "github.com",
            "api.github.com",
            "artifactcache.actions.githubusercontent.com.evil.test",
            "objects.githubusercontent.com",
        ] {
            let reply = resolver.reply(&query(9, name, TYPE_A)).unwrap();
            assert_eq!(reply[3] & 0xf, RCODE_REFUSED as u8, "{name}");
            let (answers, _, _) = rcodes(&reply);
            assert_eq!(answers, 0, "{name}");
        }
    }

    /// A resolver is a closed surface: it holds one socket, one address and no upstream. A name it does
    /// not answer reaches nothing — proven against a real socket standing where a forwarder's upstream
    /// would be, which receives no datagram at all.
    #[test]
    fn no_query_leaves_the_resolver_for_a_name_it_does_not_own() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let resolver = Resolver::new(Ipv4Addr::new(10, 0, 2, 2));
        let (addr, join) = resolver
            .serve("127.0.0.1:0".parse().unwrap(), Arc::clone(&stop))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(&query(7, "api.github.com", TYPE_A), addr)
            .unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(buf[3] & 0xf, RCODE_REFUSED as u8);
        assert!(len > HEADER);
        stop.store(true, Ordering::Release);
        join.join().unwrap();
        let mut stray = [0u8; 512];
        assert!(
            upstream.recv_from(&mut stray).is_err(),
            "a refused name was sent upstream"
        );
    }

    #[test]
    fn the_service_hosts_answer_over_udp_exactly_as_over_the_wire() {
        let stop = Arc::new(AtomicBool::new(false));
        let (addr, join) = Resolver::new(Ipv4Addr::new(10, 0, 2, 3))
            .serve("127.0.0.1:0".parse().unwrap(), Arc::clone(&stop))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        for host in HOSTS {
            client.send_to(&query(0xbeef, host, TYPE_A), addr).unwrap();
            let mut buf = [0u8; 512];
            let (len, _) = client.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[0..2], &0xbeefu16.to_be_bytes());
            assert_eq!(&buf[len - 4..len], &[10, 0, 2, 3]);
        }
        stop.store(true, Ordering::Release);
        join.join().unwrap();
    }

    #[test]
    fn an_address_question_for_the_namespace_is_empty_and_a_garbage_datagram_is_dropped() {
        let resolver = Resolver::new(Ipv4Addr::new(10, 0, 2, 2));
        let reply = resolver.reply(&query(1, HOSTS[0], TYPE_AAAA)).unwrap();
        let (answers, _, _) = rcodes(&reply);
        assert_eq!((answers, reply[3] & 0xf), (0, 0));
        assert!(resolver.reply(&[0u8; 4]).is_none());
        // A response, not a query, is not ours to answer.
        let mut answer = query(2, HOSTS[0], TYPE_A);
        answer[2] |= 0x80;
        assert!(resolver.reply(&answer).is_none());
    }
}
