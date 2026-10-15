//! Redaction runs before any byte reaches the spool, so a stored log never holds a registered value.

use std::borrow::Cow;

use sentinel_protocol::logs::Stream;

pub const MIN_SECRET_BYTES: usize = 4;
pub const MAX_ENCODED_SOURCE_BYTES: usize = 16 * 1024;
const MIN_FRAGMENT_BYTES: usize = 8;
pub const REPLACEMENT: &[u8] = b"***";
pub const EXCERPT_CHARS: usize = 200;

#[derive(Default)]
struct Automaton {
    root: Box<[u32]>,
    edges: Vec<(u8, u32)>,
    first: Vec<u32>,
    fail: Vec<u32>,
    depth: Vec<u32>,
    out: Vec<u32>,
}

impl Automaton {
    fn build<'a>(values: impl Iterator<Item = &'a [u8]> + Clone) -> Automaton {
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
        self.edges.fill((0, 0));
        self.root.fill(0);
        core::hint::black_box((&mut self.edges, &mut self.root));
    }
}

#[derive(Default)]
struct Matcher {
    reversed: Automaton,
    forward: Automaton,
}

#[derive(Default)]
pub struct Redactor {
    secrets: Vec<Vec<u8>>,
    longest: usize,
    matcher: Option<Matcher>,
    starts: Vec<(u32, u32)>,
    carry: [Vec<u8>; 3],
}

impl Redactor {
    pub fn new() -> Redactor {
        Redactor::default()
    }

    /// Structured output is JSON-escaped and the controller decodes it, so every standard escaping is registered.
    /// Multi-line values arrive one record per line, so each line that carries material is registered alone.
    pub fn register(&mut self, secret: &[u8]) -> bool {
        if secret.len() < MIN_SECRET_BYTES {
            return false;
        }
        if self.secrets.iter().any(|known| known.as_slice() == secret) {
            return true;
        }
        self.register_exact(secret);
        if secret.len() <= MAX_ENCODED_SOURCE_BYTES {
            base64_fragments(secret, |fragment| self.insert(fragment));
            percent_encodings(secret, |encoded| self.insert(encoded));
        }
        true
    }

    fn register_exact(&mut self, secret: &[u8]) {
        if secret.is_empty() {
            return;
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
    }

    fn insert(&mut self, value: &[u8]) {
        self.longest = self.longest.max(value.len());
        self.secrets.push(value.to_vec());
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    fn matcher(&mut self) -> &Matcher {
        if self.matcher.is_none() {
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

    pub fn apply<'a>(&mut self, stream: Stream, chunk: &'a [u8]) -> Cow<'a, [u8]> {
        if self.secrets.is_empty() {
            return Cow::Borrowed(chunk);
        }
        let mut buf = std::mem::take(&mut self.carry[stream as usize]);
        buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(buf.len());
        let at = self.scan(&buf, true, &mut out);
        buf[..at].fill(0);
        buf.drain(..at);
        self.carry[stream as usize] = buf;
        Cow::Owned(out)
    }

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
            lines.register_exact(secret);
            for line in secret.split(|b| matches!(*b, b'\n' | b'\r')) {
                lines.register_exact(line);
            }
        }
        let mut redacted = lines.redact_all(tail);
        let text = excerpt(&redacted);
        redacted.fill(0);
        text
    }

    fn scan(&mut self, buf: &[u8], hold: bool, out: &mut Vec<u8>) -> usize {
        let longest = self.longest;
        let mut starts = std::mem::take(&mut self.starts);
        let matcher = self.matcher();
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
        let mut next_hold = candidate();
        let mut next = starts.len();
        let mut at = 0;
        loop {
            while next_hold.is_some_and(|q| q < at) {
                next_hold = candidate();
            }
            let stop = next_hold.unwrap_or(buf.len());
            let mut plain = at;
            loop {
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
        }
        self.starts = starts;
        at
    }

    pub fn flush(&mut self, stream: Stream) -> Vec<u8> {
        std::mem::take(&mut self.carry[stream as usize])
    }
}

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

fn carries_material(line: &[u8]) -> bool {
    line.iter()
        .any(|byte| !(byte.is_ascii_punctuation() || byte.is_ascii_whitespace()))
}

/// Registers the base64 alignments of a value, keeping only characters that depend on the value alone.
fn base64_fragments(value: &[u8], mut each: impl FnMut(&[u8])) {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut input = Vec::with_capacity(value.len() + 2);
    let mut encoded = Vec::with_capacity((value.len() + 2).div_ceil(3) * 4);
    for (url, table) in [(false, STD), (true, URL)] {
        for shift in 0..3usize {
            input.clear();
            input.resize(shift, 0);
            input.extend_from_slice(value);
            encoded.clear();
            for group in input.chunks(3) {
                let n = group.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
                    << (8 * (3 - group.len()));
                for i in 0..=group.len() {
                    encoded.push(table[((n >> (18 - 6 * i)) & 63) as usize]);
                }
            }
            let lead = [0, 2, 3][shift];
            let complete = (shift + value.len()).is_multiple_of(3);
            let trims: &[usize] = match (shift, complete) {
                (0, false) => &[0, 1],
                (0, true) | (_, true) => &[0],
                (_, false) => &[1],
            };
            for &trim in trims {
                let end = encoded.len() - trim;
                let fragment = &encoded[lead.min(end)..end];
                let distinct = !url || fragment.iter().any(|b| matches!(b, b'-' | b'_'));
                let standalone = shift == 0 && trim == 0;
                if distinct && (standalone || fragment.len() >= MIN_FRAGMENT_BYTES) {
                    each(fragment);
                }
            }
        }
    }
    input.fill(0);
    encoded.fill(0);
    core::hint::black_box((&mut input, &mut encoded));
}

fn percent_encodings(value: &[u8], mut each: impl FnMut(&[u8])) {
    let unreserved = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
    if value.iter().all(|b| unreserved(*b)) {
        return;
    }
    for (hex, form) in [
        (b"0123456789ABCDEF", false),
        (b"0123456789abcdef", false),
        (b"0123456789ABCDEF", true),
    ] {
        let mut out = Vec::with_capacity(value.len() * 3);
        for &byte in value {
            if unreserved(byte) {
                out.push(byte);
            } else if form && byte == b' ' {
                out.push(b'+');
            } else {
                out.push(b'%');
                out.push(hex[usize::from(byte >> 4)]);
                out.push(hex[usize::from(byte & 15)]);
            }
        }
        each(&out);
        out.fill(0);
    }
}

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

    #[test]
    fn the_longest_secret_wins_across_a_chunk_boundary() {
        let mut r = Redactor::new();
        r.register(b"AAAAAAAAAAAA");
        r.register(b"AAAAAAAAAAAABBBB");
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAB", b"BBBy"]),
            b"x***y".to_vec()
        );
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAB", b"Cy"]),
            b"x***BCy".to_vec()
        );
        assert_eq!(
            r.redact_all(b"Error: AAAAAAAAAAAABBBB and AAAAAAAAAAAA"),
            b"Error: *** and ***".to_vec()
        );
        let mut empty = Redactor::new();
        assert!(matches!(
            empty.apply(Stream::Stdout, b"plain"),
            Cow::Borrowed(b"plain")
        ));
    }

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
        let rustc = b"{\"message\":\"bad pa&ss<word>\\\"q\\\\\\u0001 used\"}\n";
        assert_eq!(
            run(&mut r, &[rustc]),
            b"{\"message\":\"bad *** used\"}\n".to_vec()
        );
    }

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
        assert_eq!(run(&mut r, &[b"{ok}\n"]), b"{ok}\n".to_vec());
    }

    #[test]
    fn short_lines_of_a_multi_line_value_are_redacted() {
        let mut r = Redactor::new();
        r.register(b"user: deploy\npw1\nZw==\nx\n  }\n\n");
        assert_eq!(
            run(&mut r, &[b"pw1\n", b"Zw==\n", b"x\n", b"  }\n"]),
            b"***\n***\n***\n  }\n".to_vec()
        );
        let mut r = Redactor::new();
        r.register(b"line one\np\"w\n");
        assert_eq!(
            run(&mut r, &[b"{\"Output\":\"p\\\"w\\n\"}"]),
            b"{\"Output\":\"***\\n\"}".to_vec()
        );
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
        assert_eq!(
            run(&mut r, &[b"tail ghs_super"]),
            b"tail ghs_super".to_vec()
        );
        let mut r = Redactor::new();
        r.register(b"AAAAAAAAAAAA");
        r.register(b"AAAAAAAAAAAABBBB");
        assert_eq!(run(&mut r, &[b"xAAAAAAAAAAAABBBBy"]), b"x***y".to_vec());
        assert_eq!(
            run(&mut r, &[b"xAAAAAAAAAAAAy short"]),
            b"x***y short".to_vec()
        );
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

    #[test]
    fn the_automaton_matches_the_reference_scan() {
        let mut rng = Lcg(0x5eed);
        for case in 0..2_000 {
            let alphabet = 1 + rng.below(3) as u8;
            let mut secrets: Vec<Vec<u8>> = Vec::new();
            for _ in 0..1 + rng.below(5) {
                let len = MIN_SECRET_BYTES + rng.below(5) as usize;
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

    #[test]
    fn a_failure_excerpt_carries_no_fragment_of_a_value() {
        let mut r = Redactor::new();
        r.register(b"user: deploy\nhunter2-token");
        let tail = b"step output\nuser: deploy\nhunter2-token\n";
        let excerpt = r.excerpt(tail, false);
        assert!(!excerpt.contains("hunter2"), "{excerpt}");
        let excerpt = r.excerpt(b"ploy\nhunter2-token", true);
        assert!(!excerpt.contains("hunter2"), "{excerpt}");
        let mut r = Redactor::new();
        r.register(b"tab\tsecret-value");
        let excerpt = r.excerpt(b"error: tab\tsecret-value\n", false);
        assert!(!excerpt.contains("secret-value"), "{excerpt}");
        assert!(excerpt.contains("***"), "{excerpt}");
        let mut r = Redactor::new();
        let binary = b"\xff\xfebinary-secret\x80";
        r.register(binary);
        let mut tail = b"dump: ".to_vec();
        tail.extend_from_slice(binary);
        let excerpt = r.excerpt(&tail, false);
        assert!(!excerpt.contains("binary-secret"), "{excerpt}");
        let mut r = Redactor::new();
        r.register(b"straddling-secret-value");
        let mut line = "x".repeat(190);
        line.push_str("straddling-secret-value");
        let excerpt = r.excerpt(line.as_bytes(), false);
        assert!(!excerpt.contains("straddl"), "{excerpt}");
        let excerpt = r.excerpt(b"ing-secret-value\nError: step failed\n", true);
        assert_eq!(excerpt, "Error: step failed");
        assert_eq!(Redactor::new().excerpt(b"a\nlast\n\n", false), "last");
        assert_eq!(Redactor::new().excerpt(b"", false), "no diagnostic output");
    }

    #[test]
    fn a_value_below_the_floor_is_refused_and_blanks_nothing() {
        let mut r = Redactor::new();
        assert!(!r.register(b""));
        assert!(!r.register(b"a"));
        assert!(!r.register(b"abc"));
        assert!(r.is_empty());
        assert_eq!(
            run(&mut r, &[b"a b c abc abcd"]),
            b"a b c abc abcd".to_vec()
        );
        assert!(r.register(b"abcd"));
        assert_eq!(run(&mut r, &[b"a abc abcd"]), b"a abc ***".to_vec());
    }

    #[test]
    fn a_secret_printed_as_base64_is_redacted() {
        let mut r = Redactor::new();
        assert!(r.register(b"s3cr3t-value!"));
        assert_eq!(
            run(&mut r, &[b"token=czNjcjN0LXZhbHVlIQ==\n"]),
            b"token=***==\n".to_vec()
        );
        let mut r = Redactor::new();
        assert!(r.register(b"\xfb\xff\xfe\xfa\xfbxyz!"));
        assert_eq!(run(&mut r, &[b"std +//++vt4eXoh."]), b"std ***.".to_vec());
        assert_eq!(run(&mut r, &[b"url -__--vt4eXoh."]), b"url ***.".to_vec());
    }

    #[test]
    fn a_secret_inside_a_larger_base64_string_is_redacted_at_every_alignment() {
        let mut r = Redactor::new();
        assert!(r.register(b"s3cr3t-value!"));
        for (haystack, expected) in [
            ("czNjcjN0LXZhbHVlIS10YWls", "***S10YWls"),
            ("dXMzY3IzdC12YWx1ZSEtdGFpbA==", "dX***EtdGFpbA=="),
            ("dXNzM2NyM3QtdmFsdWUhLXRhaWw=", "dXN***LXRhaWw="),
            ("dXNyOnMzY3IzdC12YWx1ZSEtdGFpbA==", "dXNyOn***EtdGFpbA=="),
        ] {
            assert_eq!(
                run(&mut r, &[haystack.as_bytes()]),
                expected.as_bytes(),
                "{haystack}"
            );
        }
    }

    #[test]
    fn a_secret_printed_percent_encoded_is_redacted() {
        let mut r = Redactor::new();
        assert!(r.register(b"p@ss word/1+2"));
        assert_eq!(
            run(
                &mut r,
                &[b"q=p%40ss%20word%2F1%2B2&r=p%40ss+word%2F1%2B2&s=p%40ss%20word%2f1%2b2"]
            ),
            b"q=***&r=***&s=***".to_vec()
        );
    }

    #[test]
    fn encodings_are_derived_up_to_the_cap_only() {
        let encoded = |len: usize| -> Vec<u8> { b"YWFh".repeat(len / 3) };
        let mut within = Redactor::new();
        assert!(within.register(&vec![b'a'; 3000]));
        assert_eq!(run(&mut within, &[&encoded(3000)]), REPLACEMENT);
        let over = MAX_ENCODED_SOURCE_BYTES + 3;
        let mut beyond = Redactor::new();
        assert!(beyond.register(&vec![b'a'; over]));
        assert_eq!(run(&mut beyond, &[&encoded(over)]), encoded(over));
    }
}
