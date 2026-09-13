//! Bounded YAML loading. The event parser feeds a receiver that builds a
//! compact tree while enforcing limits as events arrive, so an oversized or
//! hostile document is rejected before it is fully materialised. Anchors,
//! aliases, tags, multiple documents and duplicate keys are errors: the
//! pipeline schema needs none of them and each is a classic amplification
//! or ambiguity vector.
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
    /// Insertion-ordered; duplicate keys were rejected at load time, so a
    /// linear scan on lookup is correct and, for schema-sized maps, faster
    /// than hashing.
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
    DuplicateKey(String),
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
            YamlErrorKind::DuplicateKey(k) => write!(f, "duplicate key `{k}`"),
        }
    }
}
impl std::error::Error for YamlError {}

enum Frame {
    Seq(Vec<Node>),
    /// Entries plus the pending key awaiting its value.
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
                // The scanner reports zero-based columns; humans expect one-based.
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
                    // This node is a key.
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
                        return self.fail(mark, YamlErrorKind::DuplicateKey(key));
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
        // A collection used as a mapping key is rejected when it closes.
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

/// YAML 1.2 core schema for plain scalars: null, booleans, decimal integers;
/// everything else (including `yes`, `on`, octal, floats) stays a string so
/// nothing is silently coerced. Hex/octal ints are strings too: the schema
/// never needs them and `0o` forms are a known foot-gun.
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

/// Load one document under the limits above.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(text: &str) -> YamlErrorKind {
        load(text).unwrap_err().kind
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
        assert_eq!(
            kind("a: 1\na: 2\n"),
            YamlErrorKind::DuplicateKey("a".into())
        );
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
        assert!(e.to_string().contains("duplicate key `a`"));
    }
}
