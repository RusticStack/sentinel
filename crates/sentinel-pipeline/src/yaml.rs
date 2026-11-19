//! Anchors, aliases, tags, extra documents and duplicate keys are rejected: each is an
//! amplification or ambiguity vector the pipeline schema never needs.
use std::fmt;

use yaml_rust2::{
    parser::{Event, MarkedEventReceiver, Parser, Tag},
    scanner::{Marker, TScalarStyle},
};

pub use sentinel_protocol::limits::MAX_PIPELINE_FILE_BYTES;

pub const MAX_DEPTH: usize = 16;
pub const MAX_NODES: usize = 10_000;
pub const MAX_KEY_BYTES: usize = 128;
pub const MAX_SCALAR_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    pub fn kind(&self) -> &'static str {
        match self {
            Node::Null => "null",
            Node::Bool(_) => "boolean",
            Node::Int(_) => "integer",
            Node::Str(_) => "string",
            Node::Seq(_) => "sequence",
            Node::Map(_) => "mapping",
        }
    }
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    pub line: usize,
    pub col: usize,
    pub kind: YamlErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YamlErrorKind {
    TooLarge { bytes: usize, limit: usize },
    Syntax(String),
    Anchor,
    Alias,
    Tag,
    MultipleDocuments,
    EmptyDocument,
    TooDeep { limit: usize },
    TooManyNodes { limit: usize },
    KeyTooLong { limit: usize },
    ScalarTooLong { limit: usize },
    NonStringKey,
    DuplicateKey,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}: ", self.line, self.col)?;
        match &self.kind {
            YamlErrorKind::TooLarge { bytes, limit } => {
                write!(f, "file is {bytes} bytes; limit is {limit}")
            }
            YamlErrorKind::Syntax(msg) => write!(f, "invalid YAML: {msg}"),
            YamlErrorKind::Anchor => f.write_str("anchors are not allowed"),
            YamlErrorKind::Alias => f.write_str("aliases are not allowed"),
            YamlErrorKind::Tag => f.write_str("tags are not allowed"),
            YamlErrorKind::MultipleDocuments => f.write_str("only one document is allowed"),
            YamlErrorKind::EmptyDocument => f.write_str("document is empty"),
            YamlErrorKind::TooDeep { limit } => write!(f, "nesting deeper than {limit} levels"),
            YamlErrorKind::TooManyNodes { limit } => write!(f, "more than {limit} nodes"),
            YamlErrorKind::KeyTooLong { limit } => write!(f, "key longer than {limit} bytes"),
            YamlErrorKind::ScalarTooLong { limit } => {
                write!(f, "value longer than {limit} bytes")
            }
            YamlErrorKind::NonStringKey => f.write_str("mapping keys must be plain strings"),
            YamlErrorKind::DuplicateKey => f.write_str("duplicate key"),
        }
    }
}
impl std::error::Error for YamlError {}

enum Frame {
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>, Option<String>),
}

struct Receiver {
    stack: Vec<Frame>,
    root: Option<Node>,
    nodes: usize,
    documents: usize,
    error: Option<YamlError>,
}

impl Receiver {
    fn fail(&mut self, mark: Marker, kind: YamlErrorKind) {
        if self.error.is_none() {
            self.error = Some(YamlError {
                line: mark.line(),
                col: mark.col() + 1,
                kind,
            });
        }
    }

    fn count(&mut self, mark: Marker) -> bool {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            self.fail(mark, YamlErrorKind::TooManyNodes { limit: MAX_NODES });
            return false;
        }
        true
    }

    fn push_value(&mut self, node: Node, mark: Marker) {
        match self.stack.last_mut() {
            None => self.root = Some(node),
            Some(Frame::Seq(items)) => items.push(node),
            Some(Frame::Map(entries, pending)) => match pending.take() {
                Some(key) => entries.push((key, node)),
                None => {
                    let key = match node {
                        Node::Str(s) => s,
                        _ => return self.fail(mark, YamlErrorKind::NonStringKey),
                    };
                    if key.len() > MAX_KEY_BYTES {
                        return self.fail(
                            mark,
                            YamlErrorKind::KeyTooLong {
                                limit: MAX_KEY_BYTES,
                            },
                        );
                    }
                    if entries.iter().any(|(k, _)| *k == key) {
                        return self.fail(mark, YamlErrorKind::DuplicateKey);
                    }
                    *pending = Some(key);
                }
            },
        }
    }

    fn open(&mut self, frame: Frame, anchor: usize, tag: Option<Tag>, mark: Marker) {
        if anchor != 0 {
            return self.fail(mark, YamlErrorKind::Anchor);
        }
        if tag.is_some() {
            return self.fail(mark, YamlErrorKind::Tag);
        }
        if self.stack.len() >= MAX_DEPTH {
            return self.fail(mark, YamlErrorKind::TooDeep { limit: MAX_DEPTH });
        }
        if !self.count(mark) {
            return;
        }
        self.stack.push(frame);
    }

    fn close(&mut self, mark: Marker) {
        let node = match self.stack.pop() {
            Some(Frame::Seq(items)) => Node::Seq(items),
            Some(Frame::Map(entries, _)) => Node::Map(entries),
            None => return,
        };
        self.push_value(node, mark);
    }
}

impl MarkedEventReceiver for Receiver {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart => {
                self.documents += 1;
                if self.documents > 1 {
                    self.fail(mark, YamlErrorKind::MultipleDocuments);
                }
            }
            Event::Alias(_) => self.fail(mark, YamlErrorKind::Alias),
            Event::Scalar(value, style, anchor, tag) => {
                if anchor != 0 {
                    return self.fail(mark, YamlErrorKind::Anchor);
                }
                if tag.is_some() {
                    return self.fail(mark, YamlErrorKind::Tag);
                }
                if value.len() > MAX_SCALAR_BYTES {
                    return self.fail(
                        mark,
                        YamlErrorKind::ScalarTooLong {
                            limit: MAX_SCALAR_BYTES,
                        },
                    );
                }
                if !self.count(mark) {
                    return;
                }
                let node = if style == TScalarStyle::Plain {
                    resolve_plain(value)
                } else {
                    Node::Str(value)
                };
                self.push_value(node, mark);
            }
            Event::SequenceStart(anchor, tag) => {
                self.open(Frame::Seq(Vec::new()), anchor, tag, mark)
            }
            Event::MappingStart(anchor, tag) => {
                self.open(Frame::Map(Vec::new(), None), anchor, tag, mark)
            }
            Event::SequenceEnd | Event::MappingEnd => self.close(mark),
        }
    }
}

/// Only null, booleans and decimal integers resolve; anything else stays a string, never coerced.
fn resolve_plain(value: String) -> Node {
    match value.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => Node::Null,
        "true" | "True" | "TRUE" => Node::Bool(true),
        "false" | "False" | "FALSE" => Node::Bool(false),
        s => {
            let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
            if !digits.is_empty()
                && digits.len() <= 19
                && digits.bytes().all(|b| b.is_ascii_digit())
                && let Ok(i) = s.parse::<i64>()
            {
                Node::Int(i)
            } else {
                Node::Str(value)
            }
        }
    }
}

pub fn load(text: &str) -> Result<Node, YamlError> {
    if text.len() > MAX_PIPELINE_FILE_BYTES {
        return Err(YamlError {
            line: 1,
            col: 1,
            kind: YamlErrorKind::TooLarge {
                bytes: text.len(),
                limit: MAX_PIPELINE_FILE_BYTES,
            },
        });
    }
    let mut receiver = Receiver {
        stack: Vec::with_capacity(8),
        root: None,
        nodes: 0,
        documents: 0,
        error: None,
    };
    let mut parser = Parser::new_from_str(text);
    if let Err(scan) = parser.load(&mut receiver, true) {
        if let Some(e) = receiver.error {
            return Err(e);
        }
        return Err(YamlError {
            line: scan.marker().line(),
            col: scan.marker().col() + 1,
            kind: YamlErrorKind::Syntax(scan.info().to_owned()),
        });
    }
    if let Some(e) = receiver.error {
        return Err(e);
    }
    match receiver.root {
        Some(Node::Null) | None => Err(YamlError {
            line: 1,
            col: 1,
            kind: YamlErrorKind::EmptyDocument,
        }),
        Some(root) => Ok(root),
    }
}

/// Where one value sits in the source text.
///
/// A rewrite that changes only labels needs the bytes of a value, not its content: the
/// analyzer's inventory holds names and keys and never a script or a value, so the one
/// place a migration edits is found by the parser's own positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueSpan {
    /// Keys and sequence indices from the document root, `.`-separated:
    /// `jobs.build.runs-on`, `jobs.test.strategy.matrix.os.0`.
    pub path: String,
    /// Byte offset of the value's first byte. Exact for a scalar; for a block mapping the
    /// parser's mark sits on the first `:` of its first entry, so a rewrite replaces from
    /// the key's colon through to `end` rather than from here.
    pub start: usize,
    /// Byte offset one past its last byte: the closing quote or bracket, or the end of a
    /// block's last line (which includes that line's newline).
    pub end: usize,
    /// Byte offset of the key that introduced the value, for a mapping's value.
    pub key: Option<usize>,
}

enum LocateFrame {
    Map {
        path: String,
        /// The key whose value comes next, with the key token's first byte.
        pending: Option<(String, usize)>,
        start: usize,
    },
    Seq {
        path: String,
        index: usize,
        start: usize,
    },
}

struct Locator<'a> {
    text: &'a str,
    stack: Vec<LocateFrame>,
    /// The key each open collection is the value of, for the span it produces when it closes.
    keys: Vec<Option<usize>>,
    spans: Vec<ValueSpan>,
}

impl Locator<'_> {
    /// The segment a value takes in its container, consuming a mapping's pending key or a
    /// sequence's next index.
    fn segment(&mut self) -> Option<(String, Option<usize>)> {
        match self.stack.last_mut()? {
            LocateFrame::Map { pending, .. } => {
                let (key, start) = pending.take()?;
                Some((key, Some(start)))
            }
            LocateFrame::Seq { index, .. } => {
                let current = *index;
                *index += 1;
                Some((current.to_string(), None))
            }
        }
    }

    fn parent(&self) -> &str {
        match self.stack.last() {
            Some(LocateFrame::Map { path, .. } | LocateFrame::Seq { path, .. }) => path,
            None => "",
        }
    }

    /// The indentation of the key a value hangs from, which is where a block scalar's
    /// content stops being part of it.
    fn key_indent(&self) -> usize {
        match self.stack.last() {
            Some(LocateFrame::Map {
                pending: Some((_, start)),
                ..
            }) => line_indent(self.text, *start),
            _ => 0,
        }
    }
}

fn join(parent: &str, segment: &str) -> String {
    if parent.is_empty() {
        segment.to_owned()
    } else {
        let mut out = String::with_capacity(parent.len() + 1 + segment.len());
        out.push_str(parent);
        out.push('.');
        out.push_str(segment);
        out
    }
}

/// The indentation width of the line `at` sits on.
fn line_indent(text: &str, at: usize) -> usize {
    let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    text[line_start..at]
        .bytes()
        .take_while(|b| *b == b' ')
        .count()
}

impl MarkedEventReceiver for Locator<'_> {
    fn on_event(&mut self, event: Event, mark: Marker) {
        match event {
            Event::Scalar(value, style, _, _) => {
                // A scalar in a mapping is its next key, until a value takes that slot.
                if let Some(LocateFrame::Map { pending, .. }) = self.stack.last_mut()
                    && pending.is_none()
                {
                    *pending = Some((value, mark.index()));
                    return;
                }
                let indent = self.key_indent();
                let (path, key) = match self.segment() {
                    Some((segment, key)) => (join(self.parent(), &segment), key),
                    None => (String::new(), None),
                };
                let start = mark.index();
                let end = scalar_end(self.text, start, style, indent);
                self.spans.push(ValueSpan {
                    path,
                    start,
                    end,
                    key,
                });
            }
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                let start = mark.index();
                let (path, key) = match self.segment() {
                    Some((segment, key)) => (join(self.parent(), &segment), key),
                    None => (String::new(), None),
                };
                let frame = match event {
                    Event::SequenceStart(..) => LocateFrame::Seq {
                        path,
                        index: 0,
                        start,
                    },
                    _ => LocateFrame::Map {
                        path,
                        pending: None,
                        start,
                    },
                };
                self.stack.push(frame);
                self.keys.push(key);
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let Some(frame) = self.stack.pop() else {
                    return;
                };
                let key = self.keys.pop().flatten();
                let (path, start) = match frame {
                    LocateFrame::Seq { path, start, .. } => (path, start),
                    LocateFrame::Map { path, start, .. } => (path, start),
                };
                let end = collection_end(self.text, start, mark.index());
                self.spans.push(ValueSpan {
                    path,
                    start,
                    end,
                    key,
                });
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd
            | Event::Alias(_) => {}
        }
    }
}

/// One past the last byte of a collection, from the mark that closes it.
///
/// A flow collection's mark sits on its closing bracket, which the span keeps. A block
/// collection's sits on the first token after it, already past that line's indentation, so
/// the span ends where the block's last line does instead.
fn collection_end(text: &str, start: usize, end: usize) -> usize {
    match text.as_bytes().get(start) {
        Some(b'[') | Some(b'{') => match text.as_bytes().get(end) {
            Some(b']') | Some(b'}') => end + 1,
            _ => end,
        },
        _ if !text[..end].ends_with('\n') => text[..end].rfind('\n').map_or(end, |nl| nl + 1),
        _ => end,
    }
}

/// One past the last byte of the scalar that starts at `start`.
///
/// A plain or quoted scalar ends within its line(s); a block scalar ends where its
/// indentation returns to the key's, so the span covers the whole block.
fn scalar_end(text: &str, start: usize, style: TScalarStyle, indent: usize) -> usize {
    let bytes = text.as_bytes();
    match style {
        TScalarStyle::SingleQuoted | TScalarStyle::DoubleQuoted => {
            let quote = bytes.get(start).copied().unwrap_or(b'\'');
            let mut i = start + 1;
            while i < bytes.len() {
                let b = bytes[i];
                if style == TScalarStyle::DoubleQuoted && b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == quote {
                    if style == TScalarStyle::SingleQuoted && bytes.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    return i + 1;
                }
                i += 1;
            }
            bytes.len()
        }
        TScalarStyle::Literal | TScalarStyle::Folded => {
            // The block's lines are indented past the key; the first line back at or
            // before it ends the span.
            let mut line = text[start..]
                .find('\n')
                .map_or(text.len(), |i| start + i + 1);
            while line < text.len() {
                let end = text[line..].find('\n').map_or(text.len(), |i| line + i + 1);
                let content = &text[line..end];
                let blank = content.trim().is_empty();
                let width = content.len() - content.trim_start_matches(' ').len();
                if !blank && width <= indent {
                    return line;
                }
                line = end;
            }
            text.len()
        }
        TScalarStyle::Plain => {
            let line_end = text[start..].find('\n').map_or(text.len(), |i| start + i);
            let line = &text[start..line_end];
            let mut end = line.len();
            // A comment starts at ` #`; the space before it is not part of the value.
            let mut at = 0;
            let b = line.as_bytes();
            while at < b.len() {
                if b[at] == b'#' && (at == 0 || b[at - 1] == b' ' || b[at - 1] == b'\t') {
                    end = at;
                    break;
                }
                at += 1;
            }
            let trimmed = line[..end].trim_end().len();
            start + trimmed
        }
    }
}

/// The byte spans of every value in a document, by key path.
pub fn spans(text: &str) -> Result<Vec<ValueSpan>, YamlError> {
    if text.len() > MAX_PIPELINE_FILE_BYTES {
        return Err(YamlError {
            line: 1,
            col: 1,
            kind: YamlErrorKind::TooLarge {
                bytes: text.len(),
                limit: MAX_PIPELINE_FILE_BYTES,
            },
        });
    }
    let mut locator = Locator {
        text,
        stack: Vec::with_capacity(8),
        keys: Vec::with_capacity(8),
        spans: Vec::new(),
    };
    let mut parser = Parser::new_from_str(text);
    if let Err(scan) = parser.load(&mut locator, true) {
        return Err(YamlError {
            line: scan.marker().line(),
            col: scan.marker().col() + 1,
            kind: YamlErrorKind::Syntax(scan.info().to_owned()),
        });
    }
    Ok(locator.spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span<'a>(spans: &'a [ValueSpan], path: &str) -> &'a ValueSpan {
        spans
            .iter()
            .find(|s| s.path == path)
            .unwrap_or_else(|| panic!("no span for {path}"))
    }

    #[test]
    fn spans_point_at_scalars_flow_and_block_values() {
        let text =
            "a: ubuntu-latest\nb: [x, y]\nc:\n  - p\n  - q\nd: 'q, uoted'\ne: \"dq \\\" x\"\n";
        let spans = spans(text).unwrap();
        let a = span(&spans, "a");
        assert_eq!(&text[a.start..a.end], "ubuntu-latest");
        let b = span(&spans, "b");
        assert_eq!(&text[b.start..b.end], "[x, y]");
        let c = span(&spans, "c");
        assert_eq!(&text[c.start..c.end], "- p\n  - q\n");
        let d = span(&spans, "d");
        assert_eq!(&text[d.start..d.end], "'q, uoted'");
        let e = span(&spans, "e");
        assert_eq!(&text[e.start..e.end], "\"dq \\\" x\"");
    }

    #[test]
    fn a_value_span_keeps_a_trailing_comment_and_names_its_key() {
        let text = "jobs:\n  build:\n    runs-on: ubuntu-latest # linux\n";
        let spans = spans(text).unwrap();
        let runs_on = span(&spans, "jobs.build.runs-on");
        assert_eq!(&text[runs_on.start..runs_on.end], "ubuntu-latest");
        let key = runs_on.key.unwrap();
        assert_eq!(&text[key..key + "runs-on".len()], "runs-on");
        // A block collection's end mark is where it stops, which is what a rewrite keeps.
        let build = span(&spans, "jobs.build");
        assert_eq!(build.end, text.len());
        assert!(build.start < runs_on.start);
    }

    #[test]
    fn a_block_scalar_ends_where_its_indentation_does() {
        let text = "a:\n  run: |\n    echo one\n    echo two\n  b: 1\n";
        let spans = spans(text).unwrap();
        let run = span(&spans, "a.run");
        // libyaml marks a block scalar at its content, so the span stops at the dedent.
        assert_eq!(&text[run.start..run.end], "echo one\n    echo two\n");
        let b = span(&spans, "a.b");
        assert_eq!(&text[b.start..b.end], "1");
    }

    fn kind(text: &str) -> YamlErrorKind {
        load(text).unwrap_err().kind
    }

    #[test]
    fn a_duplicate_key_diagnostic_never_echoes_the_key() {
        let message = load("hunter2_token: 1\nhunter2_token: 2\n")
            .unwrap_err()
            .to_string();
        assert!(message.contains("duplicate key"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn plain_scalars_resolve_conservatively() {
        let n = load("a: 1\nb: -2\nc: yes\nd: 1.5\ne: '3'\nf: ~\ng: true\nh: 0x10\n").unwrap();
        assert_eq!(n.get("a"), Some(&Node::Int(1)));
        assert_eq!(n.get("b"), Some(&Node::Int(-2)));
        assert_eq!(n.get("c"), Some(&Node::Str("yes".into())));
        assert_eq!(n.get("d"), Some(&Node::Str("1.5".into())));
        assert_eq!(n.get("e"), Some(&Node::Str("3".into())));
        assert_eq!(n.get("f"), Some(&Node::Null));
        assert_eq!(n.get("g"), Some(&Node::Bool(true)));
        assert_eq!(n.get("h"), Some(&Node::Str("0x10".into())));
    }

    #[test]
    fn rejects_duplicates_anchors_aliases_tags_and_multiple_documents() {
        assert_eq!(kind("a: 1\na: 2\n"), YamlErrorKind::DuplicateKey);
        assert_eq!(kind("a: &x 1\nb: *x\n"), YamlErrorKind::Anchor);
        assert_eq!(kind("a: !!str 1\n"), YamlErrorKind::Tag);
        assert_eq!(kind("a: 1\n---\nb: 2\n"), YamlErrorKind::MultipleDocuments);
        assert_eq!(kind("[1, 2]: x\n"), YamlErrorKind::NonStringKey);
        assert_eq!(kind("1: x\n"), YamlErrorKind::NonStringKey);
        assert_eq!(kind(""), YamlErrorKind::EmptyDocument);
        assert!(matches!(kind("a: [1, 2\n"), YamlErrorKind::Syntax(_)));
    }

    #[test]
    fn enforces_depth_node_and_length_limits() {
        let deep = "a: ".repeat(MAX_DEPTH + 1) + "1";
        let deep = deep.replace("a: a", "a:\n a").replace(": a", ":\n a");
        let _ = deep;
        let mut nested = String::new();
        for i in 0..=MAX_DEPTH {
            nested.push_str(&" ".repeat(i));
            nested.push_str("k:\n");
        }
        nested.push_str(&" ".repeat(MAX_DEPTH + 1));
        nested.push_str("v: 1\n");
        assert_eq!(kind(&nested), YamlErrorKind::TooDeep { limit: MAX_DEPTH });
        let many = "- 1\n".repeat(MAX_NODES);
        assert_eq!(
            kind(&many),
            YamlErrorKind::TooManyNodes { limit: MAX_NODES }
        );
        let long_key = format!("{}: 1\n", "k".repeat(MAX_KEY_BYTES + 1));
        assert_eq!(
            kind(&long_key),
            YamlErrorKind::KeyTooLong {
                limit: MAX_KEY_BYTES
            }
        );
        let long_val = format!("k: {}\n", "v".repeat(MAX_SCALAR_BYTES + 1));
        assert_eq!(
            kind(&long_val),
            YamlErrorKind::ScalarTooLong {
                limit: MAX_SCALAR_BYTES
            }
        );
        let big = "# ".to_owned() + &"x".repeat(MAX_PIPELINE_FILE_BYTES);
        assert!(matches!(kind(&big), YamlErrorKind::TooLarge { .. }));
    }

    #[test]
    fn errors_carry_positions() {
        let e = load("a: 1\nb: 2\na: 3\n").unwrap_err();
        assert_eq!((e.line, e.col), (3, 1));
        assert!(e.to_string().contains("duplicate key"));
    }
}
