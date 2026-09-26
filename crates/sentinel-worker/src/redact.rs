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
/// Shortest line of a multi-line value that is registered on its own.
/// Shorter lines (`{`, `}`, blank lines) are structure, not key material,
/// and redacting them everywhere would make output unreadable.
pub const MIN_FRAGMENT_BYTES: usize = 8;

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
    ///
    /// Structured output carries values JSON-escaped (Go `test2json`,
    /// rustc/cargo JSON), and the controller's failure parser decodes them,
    /// so every escaping a standard encoder produces is registered too: the
    /// stored log never holds a decodable copy the raw value would not have
    /// matched. A multi-line value is written by line-oriented producers one
    /// record per line, never contiguously, so each line of at least
    /// [`MIN_FRAGMENT_BYTES`] is registered as well (raw and escaped). All of
    /// this is paid once here; the per-byte scan is unchanged.
    pub fn register(&mut self, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        self.insert(secret);
        json_escapings(secret, |escaped| self.insert(escaped));
        if secret.contains(&b'\n') {
            for line in secret.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.len() >= MIN_FRAGMENT_BYTES {
                    self.insert(line);
                    json_escapings(line, |escaped| self.insert(escaped));
                }
            }
        }
        true
    }

    fn insert(&mut self, value: &[u8]) {
        self.longest = self.longest.max(value.len());
        self.first[(value[0] >> 6) as usize] |= 1 << (value[0] & 63);
        if !self.secrets.contains(value) {
            self.secrets.insert(value.to_vec());
        }
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

/// Call `each` with every distinct JSON string escaping of `value` that
/// differs from it: RFC 8259 minimal escaping with and without the `\b`/`\f`
/// short forms (serde_json and Go ≥ 1.22 use them, older Go does not), each
/// with and without Go's HTML-safe `< > &    `.
/// Hex digits are lowercase, as both encoders write them.
fn json_escapings(value: &[u8], mut each: impl FnMut(&[u8])) {
    let needs = value.iter().enumerate().any(|(at, byte)| {
        matches!(byte, b'"' | b'\\' | b'<' | b'>' | b'&' | 0..=0x1f)
            || (*byte == 0xe2 && matches!(value.get(at + 1..at + 3), Some([0x80, 0xa8 | 0xa9])))
    });
    if !needs {
        return;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (short, html) in [(true, false), (false, false), (true, true), (false, true)] {
        let mut out = Vec::with_capacity(value.len() + 16);
        let mut at = 0;
        while at < value.len() {
            let byte = value[at];
            at += 1;
            match byte {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                0x08 if short => out.extend_from_slice(b"\\b"),
                0x0c if short => out.extend_from_slice(b"\\f"),
                b'<' | b'>' | b'&' if html => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[usize::from(byte >> 4)]);
                    out.push(HEX[usize::from(byte & 15)]);
                }
                0..=0x1f => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[usize::from(byte >> 4)]);
                    out.push(HEX[usize::from(byte & 15)]);
                }
                0xe2 if html && matches!(value.get(at..at + 2), Some([0x80, 0xa8 | 0xa9])) => {
                    out.extend_from_slice(if value[at + 1] == 0xa8 {
                        b"\\u2028"
                    } else {
                        b"\\u2029"
                    });
                    at += 2;
                }
                _ => out.push(byte),
            }
        }
        if out != value && !seen.contains(&out) {
            each(&out);
            seen.push(out);
        }
    }
    for mut value in seen {
        value.fill(0);
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

    /// P11D-4: a value JSON-escaped by Go's test2json or by serde-style
    /// encoders is redacted in the stored bytes, so the failure parser has
    /// nothing to decode back into the plaintext.
    #[test]
    fn json_escaped_values_are_redacted_before_a_parser_can_decode_them() {
        use sentinel_protocol::diagnostics::{StepReference, parse_go_test_json};
        let secret = b"pa&ss<word>\"q\\\x01";
        let mut r = Redactor::new();
        r.register(secret);
        let go = concat!(
            "{\"Action\":\"output\",\"Package\":\"p\",\"Test\":\"TestA\",",
            "\"Output\":\"token=pa\\u0026ss\\u003cword\\u003e\\\"q\\\\\\u0001\\n\"}\n",
            "{\"Action\":\"fail\",\"Package\":\"p\",\"Test\":\"TestA\"}\n"
        );
        let stored = run(&mut r, &[go.as_bytes()]);
        let parsed = parse_go_test_json(
            &stored,
            StepReference {
                index: 0,
                key: None,
            },
        );
        let message = &parsed.diagnostics[0].diagnostic.message;
        assert_eq!(message, "token=***\n");
        // serde_json / rustc style: no HTML escaping.
        let rustc = b"{\"message\":\"bad pa&ss<word>\\\"q\\\\\\u0001 used\"}\n";
        assert_eq!(
            run(&mut r, &[rustc]),
            b"{\"message\":\"bad *** used\"}\n".to_vec()
        );
    }

    /// A multi-line value arrives one JSON record per line; each line is
    /// redacted, so joining a test's output never reassembles the value.
    #[test]
    fn multi_line_values_are_redacted_line_by_line() {
        use sentinel_protocol::diagnostics::{StepReference, parse_go_test_json};
        let secret =
            b"-----BEGIN KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\nAASCBKcwggSjAgEAAoIBAQC7\n}\n";
        let mut r = Redactor::new();
        r.register(secret);
        let mut go = Vec::new();
        for line in [
            "-----BEGIN KEY-----",
            "MIIEvQIBADANBgkqhkiG9w0BAQEF",
            "AASCBKcwggSjAgEAAoIBAQC7",
            "}",
        ] {
            go.extend_from_slice(
                format!("{{\"Action\":\"output\",\"Package\":\"p\",\"Test\":\"TestA\",\"Output\":\"{line}\\n\"}}\n")
                    .as_bytes(),
            );
        }
        go.extend_from_slice(b"{\"Action\":\"fail\",\"Package\":\"p\",\"Test\":\"TestA\"}\n");
        let stored = run(&mut r, &[&go]);
        let parsed = parse_go_test_json(
            &stored,
            StepReference {
                index: 0,
                key: None,
            },
        );
        let message = &parsed.diagnostics[0].diagnostic.message;
        assert_eq!(message, "***\n***\n***\n}\n");
        // Short structural lines are not registered on their own.
        assert_eq!(run(&mut r, &[b"{ok}\n"]), b"{ok}\n".to_vec());
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
