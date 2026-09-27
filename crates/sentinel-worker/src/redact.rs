//! Output redaction (W05): registered secret values are replaced before a
//! byte reaches the spool, and therefore before it reaches the link, the
//! controller or a log reader.
//!
//! A redactor belongs to one attempt: registration is per attempt and
//! dynamic — the secret resolver (S05/S06) registers each value into the
//! live attempt before the step that receives it starts — so one tenant's
//! values never touch another's output, and they go with the attempt.
//! Boundaries are handled: the redactor holds back the shortest tail of each
//! stream that may still grow into a registered value, so a value split
//! across two reads is still caught. Every non-empty secret is registered;
//! short values can cause noisy redaction, but leaving an authorized value
//! visible is worse.
//!
//! Matching is leftmost-longest (at each position the longest value that
//! starts there wins; the scan resumes after it) and costs O(bytes) whatever
//! the number or length of the registered values (P10D-10): two
//! Aho–Corasick automata built once per registration set — one over the
//! values reversed, which gives the longest value starting at every
//! position in one backward pass, and one over the values as they are,
//! whose state at the end of the buffer is the longest tail that is still
//! the beginning of a value. The work runs on the worker's log thread, so a
//! job cannot buy quadratic CPU there with a long near-miss value.

use std::borrow::Cow;

use sentinel_protocol::logs::Stream;

pub const MIN_SECRET_BYTES: usize = 1;
pub const REPLACEMENT: &[u8] = b"***";
/// Characters a diagnostic excerpt keeps: the verdict detail and the stored
/// summary are bounded, whatever a step printed.
pub const EXCERPT_CHARS: usize = 200;

/// A byte trie with Aho–Corasick failure links. Node 0 is the root; its
/// transitions are dense (the path every byte of ordinary output takes),
/// every other node's are a sorted run in `edges`.
#[derive(Default)]
struct Automaton {
    root: Box<[u32]>,
    /// `(byte, child)` runs, one per node, sorted by byte.
    edges: Vec<(u8, u32)>,
    /// Node `n`'s run is `edges[first[n]..first[n + 1]]`.
    first: Vec<u32>,
    fail: Vec<u32>,
    depth: Vec<u32>,
    /// Length of the longest value that is a suffix of the node's string.
    out: Vec<u32>,
}

impl Automaton {
    fn build<'a>(values: impl Iterator<Item = &'a [u8]> + Clone) -> Automaton {
        // The trie, children as small per-node lists while it grows.
        let mut children: Vec<Vec<(u8, u32)>> = vec![Vec::new()];
        let mut depth: Vec<u32> = vec![0];
        let mut terminal: Vec<bool> = vec![false];
        for value in values {
            let mut node = 0usize;
            for &byte in value {
                node = match children[node].iter().find(|(b, _)| *b == byte) {
                    Some(&(_, child)) => child as usize,
                    None => {
                        let child = children.len();
                        children.push(Vec::new());
                        depth.push(depth[node] + 1);
                        terminal.push(false);
                        children[node].push((byte, child as u32));
                        child
                    }
                };
            }
            terminal[node] = true;
        }
        let nodes = children.len();
        let mut first = Vec::with_capacity(nodes + 1);
        let mut edges = Vec::with_capacity(nodes.saturating_sub(1));
        let mut root = vec![0u32; 256].into_boxed_slice();
        for (node, list) in children.iter_mut().enumerate() {
            list.sort_unstable_by_key(|(b, _)| *b);
            first.push(edges.len() as u32);
            if node == 0 {
                for &(b, child) in list.iter() {
                    root[b as usize] = child;
                }
            }
            edges.extend_from_slice(list);
            list.fill((0, 0));
        }
        first.push(edges.len() as u32);
        let mut automaton = Automaton {
            root,
            edges,
            first,
            fail: vec![0; nodes],
            depth,
            out: vec![0; nodes],
        };
        // Breadth first, so a node's failure target is final before its
        // children need it.
        let mut queue = std::collections::VecDeque::with_capacity(nodes);
        for &(_, child) in automaton.children(0) {
            queue.push_back(child);
        }
        while let Some(node) = queue.pop_front() {
            let n = node as usize;
            automaton.out[n] = if terminal[n] {
                automaton.depth[n]
            } else {
                automaton.out[automaton.fail[n] as usize]
            };
            let (start, end) = (automaton.first[n] as usize, automaton.first[n + 1] as usize);
            for index in start..end {
                let (byte, child) = automaton.edges[index];
                automaton.fail[child as usize] = automaton.next(automaton.fail[n], byte);
                queue.push_back(child);
            }
        }
        automaton
    }

    fn children(&self, node: u32) -> &[(u8, u32)] {
        let n = node as usize;
        &self.edges[self.first[n] as usize..self.first[n + 1] as usize]
    }

    fn child(&self, node: u32, byte: u8) -> Option<u32> {
        let run = self.children(node);
        if run.len() <= 8 {
            run.iter().find(|(b, _)| *b == byte).map(|(_, c)| *c)
        } else {
            run.binary_search_by_key(&byte, |(b, _)| *b)
                .ok()
                .map(|i| run[i].1)
        }
    }

    /// The Aho–Corasick transition: amortized O(1) per byte.
    #[inline]
    fn next(&self, mut state: u32, byte: u8) -> u32 {
        loop {
            if state == 0 {
                return self.root[byte as usize];
            }
            if let Some(child) = self.child(state, byte) {
                return child;
            }
            state = self.fail[state as usize];
        }
    }

    fn wipe(&mut self) {
        // The edges spell the registered values.
        self.edges.fill((0, 0));
        self.root.fill(0);
        core::hint::black_box((&mut self.edges, &mut self.root));
    }
}

#[derive(Default)]
struct Matcher {
    /// Over the values reversed: the longest value starting at a position.
    reversed: Automaton,
    /// Over the values: the longest tail that is still a value's prefix.
    forward: Automaton,
}

#[derive(Default)]
pub struct Redactor {
    /// Registered values with their escaped forms and lines; distinct and
    /// sorted whenever a matcher exists.
    secrets: Vec<Vec<u8>>,
    longest: usize,
    /// Built on first use after a registration; `None` means stale.
    matcher: Option<Matcher>,
    /// `(position, length)` of the longest value starting at each position
    /// of the buffer being scanned where one starts, decreasing position;
    /// reused between calls.
    starts: Vec<(u32, u32)>,
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
    /// so every escaping a standard encoder produces is registered too
    /// (P11D-4): the stored log never holds a decodable copy the raw value
    /// would not have matched. A multi-line value is written by
    /// line-oriented producers one record per line, never contiguously, so
    /// each of its lines that [`carries_material`] is registered as well,
    /// raw and escaped, whatever its length. All of this is paid once here;
    /// the per-byte scan stays O(output).
    pub fn register(&mut self, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        if self.secrets.iter().any(|known| known.as_slice() == secret) {
            return true;
        }
        self.insert(secret);
        json_escapings(secret, |escaped| self.insert(escaped));
        if secret.contains(&b'\n') {
            for line in secret.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if carries_material(line) {
                    self.insert(line);
                    json_escapings(line, |escaped| self.insert(escaped));
                }
            }
        }
        if let Some(mut stale) = self.matcher.take() {
            stale.reversed.wipe();
            stale.forward.wipe();
        }
        true
    }

    /// Duplicates are removed (and wiped) when the matcher is next built,
    /// so a value with many lines costs no quadratic search here.
    fn insert(&mut self, value: &[u8]) {
        self.longest = self.longest.max(value.len());
        self.secrets.push(value.to_vec());
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    fn matcher(&mut self) -> &Matcher {
        if self.matcher.is_none() {
            // Sorting moves the owned buffers, not their bytes; a removed
            // duplicate is wiped before it is freed.
            self.secrets.sort_unstable();
            self.secrets.dedup_by(|later, kept| {
                let same = later == kept;
                if same {
                    later.fill(0);
                }
                same
            });
            let reversed: Vec<Vec<u8>> = self
                .secrets
                .iter()
                .map(|s| s.iter().rev().copied().collect())
                .collect();
            let matcher = Matcher {
                reversed: Automaton::build(reversed.iter().map(Vec::as_slice)),
                forward: Automaton::build(self.secrets.iter().map(Vec::as_slice)),
            };
            for mut value in reversed {
                value.fill(0);
            }
            self.matcher = Some(matcher);
        }
        self.matcher.as_ref().expect("built above")
    }

    /// Redact `chunk` on `stream`, returning what may be emitted now. The
    /// tail that could still be the start of a secret is kept for the next
    /// call or [`Redactor::flush`]. With nothing registered the chunk is
    /// passed through borrowed — no copy on the common path.
    pub fn apply<'a>(&mut self, stream: Stream, chunk: &'a [u8]) -> Cow<'a, [u8]> {
        if self.secrets.is_empty() {
            return Cow::Borrowed(chunk);
        }
        let mut buf = std::mem::take(&mut self.carry[stream as usize]);
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
    pub fn redact_all(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        if self.secrets.is_empty() {
            out.extend_from_slice(bytes);
            return out;
        }
        let at = self.scan(bytes, false, &mut out);
        out.extend_from_slice(&bytes[at..]);
        out
    }

    /// The bounded, printable excerpt of a step's stderr tail that a
    /// failure detail carries (P10D-2): redacted **before** anything
    /// transforms it — lossy UTF-8 decoding, line selection, control
    /// filtering and the length cut could otherwise leave a value no longer
    /// matching exactly. A multi-line value is also redacted line by line,
    /// so its later lines are caught where the tail began inside it; and a
    /// tail that filled its ring (`wrapped`) loses its first, possibly cut,
    /// line.
    pub fn excerpt(&self, tail: &[u8], wrapped: bool) -> String {
        let tail = if wrapped {
            match tail.iter().position(|b| *b == b'\n') {
                Some(end) => &tail[end + 1..],
                None => &[][..],
            }
        } else {
            tail
        };
        if self.secrets.is_empty() {
            return excerpt(tail);
        }
        let mut lines = Redactor::new();
        for secret in &self.secrets {
            lines.register(secret);
            for line in secret.split(|b| matches!(*b, b'\n' | b'\r')) {
                lines.register(line);
            }
        }
        let mut redacted = lines.redact_all(tail);
        let text = excerpt(&redacted);
        redacted.fill(0);
        text
    }

    /// Copy `buf` to `out` with every registered value replaced, returning
    /// how much was consumed; with `hold`, stop before the first tail the
    /// scan reaches that may still grow into a value (or into a longer one
    /// than it already matches).
    fn scan(&mut self, buf: &[u8], hold: bool, out: &mut Vec<u8>) -> usize {
        let longest = self.longest;
        let mut starts = std::mem::take(&mut self.starts);
        let matcher = self.matcher();
        // Backward over the reversed values: every position at which a
        // value begins (and ends inside `buf`), with the longest such
        // value, in decreasing position. Output that starts no value stays
        // at the dense root: one table load per byte, nothing written.
        starts.clear();
        let reversed = &matcher.reversed;
        let mut state = 0u32;
        for i in (0..buf.len()).rev() {
            let byte = buf[i];
            state = if state == 0 {
                reversed.root[byte as usize]
            } else {
                reversed.next(state, byte)
            };
            if state != 0 {
                let len = reversed.out[state as usize];
                if len != 0 {
                    starts.push((i as u32, len));
                }
            }
        }
        // Where a held tail may begin: every tail of `buf` that is a
        // proper prefix of some value — the forward state's failure chain,
        // restricted to nodes that continue, walked lazily longest tail
        // (smallest position) first.
        let mut chain = 0u32;
        if hold {
            let from = buf.len().saturating_sub(longest);
            for &byte in &buf[from..] {
                chain = matcher.forward.next(chain, byte);
            }
        }
        let forward = &matcher.forward;
        let mut candidate = || -> Option<usize> {
            while chain != 0 {
                let n = chain as usize;
                chain = forward.fail[n];
                if forward.first[n + 1] > forward.first[n] {
                    return Some(buf.len() - forward.depth[n] as usize);
                }
            }
            None
        };
        // Leftmost-longest replacement up to the first hold candidate the
        // scan actually reaches; a candidate inside a replaced value is not
        // reached and cannot hold.
        let mut next_hold = candidate();
        // `starts` is in decreasing position: its tail is the next match.
        let mut next = starts.len();
        let mut at = 0;
        loop {
            while next_hold.is_some_and(|q| q < at) {
                next_hold = candidate();
            }
            let stop = next_hold.unwrap_or(buf.len());
            let mut plain = at;
            loop {
                // A value starting inside one already replaced is skipped.
                while next > 0 && (starts[next - 1].0 as usize) < at {
                    next -= 1;
                }
                if next == 0 || starts[next - 1].0 as usize >= stop {
                    at = stop;
                    break;
                }
                let (pos, len) = starts[next - 1];
                next -= 1;
                out.extend_from_slice(&buf[plain..pos as usize]);
                out.extend_from_slice(REPLACEMENT);
                at = pos as usize + len as usize;
                plain = at;
                if at > stop {
                    break;
                }
            }
            if at == stop {
                out.extend_from_slice(&buf[plain..at]);
                break;
            }
            // A value ran past the candidate: the scan never reached it.
        }
        self.starts = starts;
        at
    }

    /// The stream is finished: whatever is held back is the beginning of a
    /// secret that never completed, so it is emitted as it is.
    pub fn flush(&mut self, stream: Stream) -> Vec<u8> {
        std::mem::take(&mut self.carry[stream as usize])
    }
}

/// The last non-empty line of `bytes`, printable characters only, at most
/// [`EXCERPT_CHARS`]: what a failure detail shows of a helper's stderr.
/// Callers holding secrets redact first ([`Redactor::excerpt`]).
pub fn excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let mut out: String = line
        .chars()
        .filter(|c| !c.is_control())
        .take(EXCERPT_CHARS)
        .collect();
    if out.is_empty() {
        out.push_str("no diagnostic output");
    }
    out
}

/// Whether a line of a multi-line value is registered on its own: any line
/// holding a byte other than ASCII punctuation or whitespace, however
/// short. A line of only punctuation and whitespace (`{`, `}`, `-----`, a
/// blank line) is structure a producer prints everywhere; redacting it would
/// erase that character from all later output while hiding nothing a reader
/// could not already guess from the value's format.
fn carries_material(line: &[u8]) -> bool {
    line.iter()
        .any(|byte| !(byte.is_ascii_punctuation() || byte.is_ascii_whitespace()))
}

/// Call `each` with every distinct JSON string escaping of `value` that
/// differs from it: RFC 8259 minimal escaping with and without the `\b`/`\f`
/// short forms (serde_json and Go ≥ 1.22 use them, older Go does not), each
/// with and without Go's HTML-safe `\u003c \u003e \u0026 \u2028 \u2029`.
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
        for secret in &mut self.secrets {
            secret.fill(0);
        }
        if let Some(matcher) = self.matcher.as_mut() {
            matcher.reversed.wipe();
            matcher.forward.wipe();
        }
        for carry in &mut self.carry {
            carry.fill(0);
        }
        core::hint::black_box((&mut self.secrets, &mut self.carry));
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
        // Punctuation-only structural lines are not registered on their own.
        assert_eq!(run(&mut r, &[b"{ok}\n"]), b"{ok}\n".to_vec());
    }

    /// The short-line residual of P11D-4: a line of a multi-line value is
    /// registered whatever its length once it holds anything but
    /// punctuation and whitespace, so a short password on its own line, a
    /// PEM's short last base64 line or a one-letter line never survives a
    /// line-by-line print; only punctuation-only lines do.
    #[test]
    fn short_lines_of_a_multi_line_value_are_redacted() {
        let mut r = Redactor::new();
        r.register(b"user: deploy\npw1\nZw==\nx\n  }\n\n");
        assert_eq!(
            run(&mut r, &[b"pw1\n", b"Zw==\n", b"x\n", b"  }\n"]),
            b"***\n***\n***\n  }\n".to_vec()
        );
        // Each line is also caught JSON-escaped.
        let mut r = Redactor::new();
        r.register(b"line one\np\"w\n");
        assert_eq!(
            run(&mut r, &[b"{\"Output\":\"p\\\"w\\n\"}"]),
            b"{\"Output\":\"***\\n\"}".to_vec()
        );
        // Registering the same value again changes nothing.
        let known = r.secrets.len();
        r.register(b"line one\np\"w\n");
        assert_eq!(r.secrets.len(), known);
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

    /// The scan the automata replaced, kept as the specification: at each
    /// reached position hold a tail that is a proper prefix of a longer
    /// value, else replace the longest value starting there.
    fn reference(secrets: &[Vec<u8>], buf: &[u8], hold: bool, out: &mut Vec<u8>) -> usize {
        let mut at = 0;
        while at < buf.len() {
            let window = &buf[at..];
            if hold
                && secrets
                    .iter()
                    .any(|s| s.len() > window.len() && s.starts_with(window))
            {
                break;
            }
            match secrets
                .iter()
                .filter(|s| window.starts_with(s))
                .map(Vec::len)
                .max()
            {
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

    /// A small deterministic generator: the property test needs no crate.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// P10D-10: the automata keep the exact leftmost-longest semantics and
    /// hold-back of the scan they replaced, over many random value sets
    /// (overlapping prefixes and suffixes over a tiny alphabet), texts and
    /// chunkings.
    #[test]
    fn the_automaton_matches_the_reference_scan() {
        let mut rng = Lcg(0x5eed);
        for case in 0..2_000 {
            let alphabet = 1 + rng.below(3) as u8;
            let mut secrets: Vec<Vec<u8>> = Vec::new();
            for _ in 0..1 + rng.below(5) {
                let len = 1 + rng.below(6) as usize;
                let value: Vec<u8> = (0..len)
                    .map(|_| b'a' + rng.below(alphabet.into()) as u8)
                    .collect();
                if !secrets.contains(&value) {
                    secrets.push(value);
                }
            }
            let text: Vec<u8> = (0..rng.below(40))
                .map(|_| b'a' + rng.below(u64::from(alphabet) + 1) as u8)
                .collect();
            // One-shot.
            let mut r = Redactor::new();
            for s in &secrets {
                r.register(s);
            }
            let mut expected = Vec::new();
            let at = reference(&secrets, &text, false, &mut expected);
            expected.extend_from_slice(&text[at..]);
            assert_eq!(
                r.redact_all(&text),
                expected,
                "case {case}: {secrets:?} {text:?}"
            );
            // Streamed in random chunks: the reference applied to the same
            // carry discipline.
            let mut streamed = Vec::new();
            let mut model = Vec::new();
            let mut carry: Vec<u8> = Vec::new();
            let mut rest = text.as_slice();
            while !rest.is_empty() {
                let n = 1 + rng.below(rest.len() as u64) as usize;
                let (chunk, tail) = rest.split_at(n);
                rest = tail;
                streamed.extend_from_slice(&r.apply(Stream::Stdout, chunk));
                carry.extend_from_slice(chunk);
                let at = reference(&secrets, &carry, true, &mut model);
                carry.drain(..at);
            }
            streamed.extend(r.flush(Stream::Stdout));
            model.extend(carry);
            assert_eq!(streamed, model, "case {case}: {secrets:?} {text:?}");
        }
    }

    /// P10D-10: 16 near-miss values of 64 KiB (a full 1 MiB bundle)
    /// against a stream that keeps almost matching them cost O(output), not
    /// O(output × values × length): a MiB of such output is redacted within
    /// a bound the old scan (16 comparisons of up to 64 KiB per byte) did
    /// not meet.
    #[test]
    fn a_near_miss_value_costs_linear_time() {
        let mut r = Redactor::new();
        let mut values = Vec::new();
        for tail in b'B'..b'R' {
            let mut value = vec![b'A'; 65_535 - usize::from(tail - b'B')];
            value.push(tail);
            r.register(&value);
            values.push(value);
        }
        r.register(b"A-short");
        let chunk = vec![b'A'; 8 * 1024];
        let started = std::time::Instant::now();
        let mut emitted = 0usize;
        for _ in 0..128 {
            emitted += r.apply(Stream::Stdout, &chunk).len();
        }
        emitted += r.flush(Stream::Stdout).len();
        let took = started.elapsed();
        assert_eq!(emitted, 128 * 8 * 1024, "nothing matched, nothing lost");
        assert!(
            took < std::time::Duration::from_secs(5),
            "1 MiB of near-miss output took {took:?}"
        );
        // And a full value is still caught when it does arrive, split.
        let value = &values[0];
        let mut r = Redactor::new();
        r.register(value);
        let mut out = Vec::new();
        for part in value.chunks(8 * 1024) {
            out.extend_from_slice(&r.apply(Stream::Stdout, part));
        }
        out.extend(r.flush(Stream::Stdout));
        assert_eq!(out, REPLACEMENT);
    }

    /// P10D-2: the excerpt is redacted before it is transformed. Each of
    /// the transformations that used to run first — lossy decoding, line
    /// selection, control filtering, the 200-character cut and the tail
    /// ring's cut — leaves no fragment of a value.
    #[test]
    fn a_failure_excerpt_carries_no_fragment_of_a_value() {
        // A multi-line file secret whose last line is the token.
        let mut r = Redactor::new();
        r.register(b"user: deploy\nhunter2-token");
        let tail = b"step output\nuser: deploy\nhunter2-token\n";
        let excerpt = r.excerpt(tail, false);
        assert!(!excerpt.contains("hunter2"), "{excerpt}");
        // The tail ring began inside it: its later lines are still caught.
        let excerpt = r.excerpt(b"ploy\nhunter2-token", true);
        assert!(!excerpt.contains("hunter2"), "{excerpt}");
        // A tab inside the value; control filtering would have joined it.
        let mut r = Redactor::new();
        r.register(b"tab\tsecret-value");
        let excerpt = r.excerpt(b"error: tab\tsecret-value\n", false);
        assert!(!excerpt.contains("secret-value"), "{excerpt}");
        assert!(excerpt.contains("***"), "{excerpt}");
        // A binary value: lossy decoding would have changed its bytes.
        let mut r = Redactor::new();
        let binary = b"\xff\xfebinary-secret\x80";
        r.register(binary);
        let mut tail = b"dump: ".to_vec();
        tail.extend_from_slice(binary);
        let excerpt = r.excerpt(&tail, false);
        assert!(!excerpt.contains("binary-secret"), "{excerpt}");
        // A value straddling the 200-character cut.
        let mut r = Redactor::new();
        r.register(b"straddling-secret-value");
        let mut line = "x".repeat(190);
        line.push_str("straddling-secret-value");
        let excerpt = r.excerpt(line.as_bytes(), false);
        assert!(!excerpt.contains("straddl"), "{excerpt}");
        // A value cut at the start of a wrapped ring: its suffix is on the
        // first, dropped line.
        let excerpt = r.excerpt(b"ing-secret-value\nError: step failed\n", true);
        assert_eq!(excerpt, "Error: step failed");
        // Nothing registered, nothing wrapped: the plain excerpt.
        assert_eq!(Redactor::new().excerpt(b"a\nlast\n\n", false), "last");
        assert_eq!(Redactor::new().excerpt(b"", false), "no diagnostic output");
    }
}
