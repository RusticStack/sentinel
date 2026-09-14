//! Output redaction (W05): registered secret values are replaced before a
//! byte reaches the spool, and therefore before it reaches the link, the
//! controller or a log reader.
//!
//! Registration is dynamic — the secret resolver (S05/S06) registers each
//! value before the step that receives it starts — and boundaries are
//! handled: the redactor holds back the last `longest - 1` bytes of each
//! stream until the next chunk arrives, so a value split across two reads
//! is still caught. Values shorter than `MIN_SECRET_BYTES` are not
//! registered: replacing every "a" in the output would be worse than
//! useless, and such a value is not a secret worth the name.

use std::collections::BTreeSet;

use sentinel_protocol::logs::Stream;

pub const MIN_SECRET_BYTES: usize = 8;
pub const REPLACEMENT: &[u8] = b"***";

#[derive(Default)]
pub struct Redactor {
    secrets: BTreeSet<Vec<u8>>,
    longest: usize,
    /// Held-back tail per stream, indexed by `Stream as usize`.
    carry: [Vec<u8>; 3],
}

impl Redactor {
    pub fn new() -> Redactor {
        Redactor::default()
    }

    /// Register a value; returns whether it was long enough to matter.
    pub fn register(&mut self, secret: &[u8]) -> bool {
        if secret.len() < MIN_SECRET_BYTES {
            return false;
        }
        self.longest = self.longest.max(secret.len());
        self.secrets.insert(secret.to_vec());
        true
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Redact `chunk` on `stream`, returning what may be emitted now. The
    /// tail that could still be the start of a secret is kept for the next
    /// call or [`Redactor::flush`].
    pub fn apply(&mut self, stream: Stream, chunk: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return chunk.to_vec();
        }
        let carry = &mut self.carry[stream as usize];
        let mut buf = std::mem::take(carry);
        buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(buf.len());
        let mut at = 0;
        // Scan every position; secrets are few and short, output is what
        // bounds this. Longest match first so a prefix of a longer secret
        // does not leave the rest exposed.
        while at < buf.len() {
            let window = &buf[at..];
            let hit = self
                .secrets
                .iter()
                .rev()
                .find(|s| window.starts_with(s))
                .map(Vec::len);
            match hit {
                Some(len) => {
                    out.extend_from_slice(REPLACEMENT);
                    at += len;
                }
                None => {
                    // Hold back a tail that is the beginning of some secret;
                    // the next chunk may complete it.
                    let partial = self
                        .secrets
                        .iter()
                        .any(|s| s.len() > window.len() && s.starts_with(window));
                    if partial {
                        break;
                    }
                    out.push(buf[at]);
                    at += 1;
                }
            }
        }
        *carry = buf[at..].to_vec();
        out
    }

    /// The stream is finished: whatever is held back is the beginning of a
    /// secret that never completed, so it is emitted as it is.
    pub fn flush(&mut self, stream: Stream) -> Vec<u8> {
        std::mem::take(&mut self.carry[stream as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(redactor: &mut Redactor, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(redactor.apply(Stream::Stdout, c));
        }
        out.extend(redactor.flush(Stream::Stdout));
        out
    }

    #[test]
    fn secrets_are_replaced_even_when_split_across_chunks() {
        let mut r = Redactor::new();
        assert!(r.register(b"ghs_supersecret_token"));
        assert!(!r.register(b"short"));
        assert_eq!(
            run(&mut r, &[b"token=ghs_supersecret_token done\n"]),
            b"token=*** done\n".to_vec()
        );
        assert_eq!(
            run(&mut r, &[b"token=ghs_super", b"secret_", b"token done\n"]),
            b"token=*** done\n".to_vec()
        );
        // A partial value at the very end is emitted at flush, not swallowed.
        assert_eq!(
            run(&mut r, &[b"tail ghs_super"]),
            b"tail ghs_super".to_vec()
        );
        // Longest match wins, and short values are left alone.
        let mut r = Redactor::new();
        r.register(b"AAAAAAAAAAAA");
        r.register(b"AAAAAAAAAAAABBBB");
        assert_eq!(run(&mut r, &[b"xAAAAAAAAAAAABBBBy"]), b"x***y".to_vec());
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAy short"]),
            b"x***y short".to_vec()
        );
        // Streams carry independently.
        let mut r = Redactor::new();
        r.register(b"stderr-only-secret");
        assert_eq!(
            r.apply(Stream::Stderr, b"a stderr-only-sec"),
            b"a ".to_vec()
        );
        assert_eq!(
            r.apply(Stream::Stdout, b"stdout untouched\n"),
            b"stdout untouched\n".to_vec()
        );
        assert_eq!(r.apply(Stream::Stderr, b"ret!\n"), b"***!\n".to_vec());
    }
}
