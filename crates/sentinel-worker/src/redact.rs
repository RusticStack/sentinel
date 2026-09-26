//! Output redaction (W05): registered secret values are replaced before a
//! byte reaches the spool, and therefore before it reaches the link, the
//! controller or a log reader.
//!
//! A redactor belongs to one attempt: registration is per attempt and
//! dynamic — the secret resolver (S05/S06) registers each value into the
//! live attempt before the step that receives it starts — so one tenant's
//! values never touch another's output, and they go with the attempt. Boundaries are
//! handled: the redactor holds back the last `longest - 1` bytes of each
//! stream until the next chunk arrives, so a value split across two reads
//! is still caught. Every non-empty secret is registered; short values can
//! cause noisy redaction, but leaving an authorized value visible is worse.

use std::{borrow::Cow, collections::BTreeSet};

use sentinel_protocol::logs::Stream;

pub const MIN_SECRET_BYTES: usize = 1;
pub const REPLACEMENT: &[u8] = b"***";

#[derive(Default)]
pub struct Redactor {
    secrets: BTreeSet<Vec<u8>>,
    /// 256-bit set of every secret's first byte — the per-byte fast path
    /// that keeps a miss at one bit test instead of a scan of all secrets.
    first: [u64; 4],
    longest: usize,
    /// Held-back tail per stream, indexed by `Stream as usize`.
    carry: [Vec<u8>; 3],
}

impl Redactor {
    pub fn new() -> Redactor {
        Redactor::default()
    }

    /// Register a non-empty value; returns whether it was accepted.
    pub fn register(&mut self, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        self.longest = self.longest.max(secret.len());
        self.first[(secret[0] >> 6) as usize] |= 1 << (secret[0] & 63);
        self.secrets.insert(secret.to_vec());
        true
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Redact `chunk` on `stream`, returning what may be emitted now. The
    /// tail that could still be the start of a secret is kept for the next
    /// call or [`Redactor::flush`]. With nothing registered the chunk is
    /// passed through borrowed — no copy on the common path.
    pub fn apply<'a>(&mut self, stream: Stream, chunk: &'a [u8]) -> Cow<'a, [u8]> {
        if self.secrets.is_empty() {
            return Cow::Borrowed(chunk);
        }
        let carry = &mut self.carry[stream as usize];
        let mut buf = std::mem::take(carry);
        buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(buf.len());
        let at = self.scan(&buf, true, &mut out);
        // The held tail becomes the next carry in place: no second copy.
        buf[..at].fill(0);
        buf.drain(..at);
        self.carry[stream as usize] = buf;
        Cow::Owned(out)
    }

    /// Redact a complete text — a diagnostic line, not a stream — holding
    /// nothing back: a partial secret at its end is left as it is.
    pub fn redact_all(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        if self.secrets.is_empty() {
            out.extend_from_slice(bytes);
            return out;
        }
        let at = self.scan(bytes, false, &mut out);
        out.extend_from_slice(&bytes[at..]);
        out
    }

    /// Copy `buf` to `out` with every registered value replaced, returning
    /// how much was consumed; with `hold`, stop before a tail that may still
    /// grow into a secret (or into a longer one than it already matches).
    fn scan(&self, buf: &[u8], hold: bool, out: &mut Vec<u8>) -> usize {
        let mut at = 0;
        // Scan every position; secrets are few and short, output is what
        // bounds this. Longest match first so a prefix of a longer secret
        // does not leave the rest exposed.
        while at < buf.len() {
            // Most bytes start no secret and can start no partial one
            // either — the partial check needs `window` to prefix a secret,
            // which needs its first byte in the set.
            if self.first[(buf[at] >> 6) as usize] & (1 << (buf[at] & 63)) == 0 {
                out.push(buf[at]);
                at += 1;
                continue;
            }
            let window = &buf[at..];
            // A tail that is the beginning of some longer secret may be
            // completed by the next chunk: hold it back — even when a
            // shorter secret already matches, or the longer one would be
            // replaced only in part.
            if hold
                && self
                    .secrets
                    .iter()
                    .any(|s| s.len() > window.len() && s.starts_with(window))
            {
                break;
            }
            let hit = self
                .secrets
                .iter()
                .filter(|s| window.starts_with(s))
                .map(Vec::len)
                .max();
            match hit {
                Some(len) => {
                    out.extend_from_slice(REPLACEMENT);
                    at += len;
                }
                None => {
                    out.push(buf[at]);
                    at += 1;
                }
            }
        }
        at
    }

    /// The stream is finished: whatever is held back is the beginning of a
    /// secret that never completed, so it is emitted as it is.
    pub fn flush(&mut self, stream: Stream) -> Vec<u8> {
        std::mem::take(&mut self.carry[stream as usize])
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        while let Some(mut secret) = self.secrets.pop_first() {
            secret.fill(0);
        }
        for carry in &mut self.carry {
            carry.fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(redactor: &mut Redactor, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(&redactor.apply(Stream::Stdout, c));
        }
        out.extend(redactor.flush(Stream::Stdout));
        out
    }

    /// P04-21: a shorter secret is not replaced while the rest of the
    /// buffer may still be the start of a longer one arriving next.
    #[test]
    fn the_longest_secret_wins_across_a_chunk_boundary() {
        let mut r = Redactor::new();
        r.register(b"AAAAAAAAAAAA");
        r.register(b"AAAAAAAAAAAABBBB");
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAB", b"BBBy"]),
            b"x***y".to_vec()
        );
        // The shorter one still wins when the longer never completes.
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAB", b"Cy"]),
            b"x***BCy".to_vec()
        );
        // One-shot redaction of a diagnostic line holds nothing back.
        assert_eq!(
            r.redact_all(b"Error: AAAAAAAAAAAABBBB and AAAAAAAAAAAA"),
            b"Error: *** and ***".to_vec()
        );
        // Nothing registered: the chunk is passed through, not copied.
        let mut empty = Redactor::new();
        assert!(matches!(
            empty.apply(Stream::Stdout, b"plain"),
            Cow::Borrowed(b"plain")
        ));
    }

    #[test]
    fn secrets_are_replaced_even_when_split_across_chunks() {
        let mut r = Redactor::new();
        assert!(r.register(b"ghs_supersecret_token"));
        assert!(r.register(b"short"));
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
            r.apply(Stream::Stderr, b"a stderr-only-sec").as_ref(),
            b"a "
        );
        assert_eq!(
            r.apply(Stream::Stdout, b"stdout untouched\n").as_ref(),
            b"stdout untouched\n"
        );
        assert_eq!(r.apply(Stream::Stderr, b"ret!\n").as_ref(), b"***!\n");
    }
}
