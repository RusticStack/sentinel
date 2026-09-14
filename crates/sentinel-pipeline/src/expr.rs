//! Bounded expression language for `${{ … }}` and `if:`.
//!
//! The grammar is deliberately tiny: literals, dotted context paths, `==`,
//! `!=`, `!`, `&&`, `||`, parentheses and a fixed set of functions. There
//! are no loops, no user functions, no string building beyond templates,
//! no filesystem or network access: `hash_files` is the only input that
//! touches disk and it is resolved by the worker against the pinned source
//! under documented limits. Expressions are parsed once at compile time
//! into an AST that is stored with the run spec, then evaluated in phases:
//! a value that is not yet known in the current phase is `Unresolved`, never
//! a default.
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_EXPR_BYTES: usize = 1024;
pub const MAX_TOKENS: usize = 256;
pub const MAX_DEPTH: usize = 16;
pub const MAX_ARGS: usize = 8;
pub const MAX_PATH_SEGMENTS: usize = 4;
/// `hash_files` limits enforced by the worker's resolver.
pub const MAX_HASH_PATTERNS: usize = 8;
pub const MAX_HASH_FILES: usize = 10_000;
pub const MAX_HASH_BYTES: u64 = 256 << 20;

/// When an expression is evaluated. Each context path and function has a
/// minimum phase; earlier evaluation yields `Unresolved`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Phase {
    /// Only structure is known; nothing evaluates.
    Compile = 0,
    /// Event, repository and run context are known (intake/dispatch).
    Dispatch = 1,
    /// Dependency outcomes are known (job `if`, before queueing).
    Schedule = 2,
    /// The worker has the pinned checkout (`hash_files`, step `if`).
    Worker = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
}

impl Value {
    pub const fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Int(_) => "integer",
            Value::Str(_) => "string",
        }
    }
    /// Truthiness for `if`: only `true` passes. Strings and integers are
    /// not conditions; requiring a boolean catches `if: ${{ event.ref }}`.
    pub const fn as_condition(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Func {
    /// `success()`: every dependency passed or was skipped.
    Success,
    /// `failure()`: at least one dependency failed, timed out or infra-failed.
    Failure,
    /// `always()`: true regardless of dependencies (but not after cancel).
    Always,
    /// `cancelled()`: the run has cancellation desired.
    Cancelled,
    /// `contains(haystack, needle)` on strings.
    Contains,
    /// `starts_with(s, prefix)` on strings.
    StartsWith,
    /// `ends_with(s, suffix)` on strings.
    EndsWith,
    /// `hash_files('pattern', …)`: content hash of matching pinned-source files.
    HashFiles,
}

impl Func {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "always" => Self::Always,
            "cancelled" => Self::Cancelled,
            "contains" => Self::Contains,
            "starts_with" => Self::StartsWith,
            "ends_with" => Self::EndsWith,
            "hash_files" => Self::HashFiles,
            _ => return None,
        })
    }
    const fn arity(self) -> (usize, usize) {
        match self {
            Self::Success | Self::Failure | Self::Always | Self::Cancelled => (0, 0),
            Self::Contains | Self::StartsWith | Self::EndsWith => (2, 2),
            Self::HashFiles => (1, MAX_HASH_PATTERNS),
        }
    }
    pub const fn min_phase(self) -> Phase {
        match self {
            Self::Contains | Self::StartsWith | Self::EndsWith => Phase::Compile,
            Self::Cancelled => Phase::Dispatch,
            Self::Success | Self::Failure | Self::Always => Phase::Schedule,
            Self::HashFiles => Phase::Worker,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BinOp {
    Eq,
    Ne,
    And,
    Or,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Lit(Value),
    /// Dotted context path, e.g. `event.ref` or `needs.test.result`.
    Path(Vec<String>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Call(Func, Vec<Expr>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Str(s) => write!(f, "'{}'", s.replace('\'', "''")),
        }
    }
}

impl Func {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Always => "always",
            Self::Cancelled => "cancelled",
            Self::Contains => "contains",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::HashFiles => "hash_files",
        }
    }
}

/// Canonical text: fully parenthesised binary operations, so printing and
/// re-parsing yields the same tree and diagnostics show exactly what runs.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Lit(v) => write!(f, "{v}"),
            Expr::Path(p) => f.write_str(&p.join(".")),
            Expr::Not(e) => write!(f, "!{e}"),
            Expr::Bin(op, a, b) => {
                let sym = match op {
                    BinOp::Eq => "==",
                    BinOp::Ne => "!=",
                    BinOp::And => "&&",
                    BinOp::Or => "||",
                };
                write!(f, "({a} {sym} {b})")
            }
            Expr::Call(func, args) => {
                write!(f, "{}(", func.name())?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{a}")?;
                }
                f.write_str(")")
            }
        }
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for p in &self.parts {
            match p {
                Part::Lit(s) => f.write_str(s)?,
                Part::Expr(e) => write!(f, "${{{{ {e} }}}}")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the expression text.
    pub at: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: {}", self.at, self.message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok<'a> {
    Str(String),
    Int(i64),
    Ident(&'a str),
    Dot,
    Comma,
    LParen,
    RParen,
    Bang,
    EqEq,
    NotEq,
    AndAnd,
    OrOr,
}

fn tokenize(src: &str) -> Result<Vec<(usize, Tok<'_>)>, ParseError> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    let err = |at: usize, m: &str| ParseError {
        at,
        message: m.to_owned(),
    };
    while i < b.len() {
        let c = b[i];
        let start = i;
        let tok = match c {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
                continue;
            }
            b'(' => {
                i += 1;
                Tok::LParen
            }
            b')' => {
                i += 1;
                Tok::RParen
            }
            b',' => {
                i += 1;
                Tok::Comma
            }
            b'.' => {
                i += 1;
                Tok::Dot
            }
            b'!' if b.get(i + 1) == Some(&b'=') => {
                i += 2;
                Tok::NotEq
            }
            b'!' => {
                i += 1;
                Tok::Bang
            }
            b'=' if b.get(i + 1) == Some(&b'=') => {
                i += 2;
                Tok::EqEq
            }
            b'&' if b.get(i + 1) == Some(&b'&') => {
                i += 2;
                Tok::AndAnd
            }
            b'|' if b.get(i + 1) == Some(&b'|') => {
                i += 2;
                Tok::OrOr
            }
            b'\'' => {
                // Single-quoted string; '' escapes a quote. No other escapes.
                let mut s = String::new();
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err(err(start, "unterminated string")),
                        Some(b'\'') if b.get(i + 1) == Some(&b'\'') => {
                            s.push('\'');
                            i += 2;
                        }
                        Some(b'\'') => {
                            i += 1;
                            break;
                        }
                        Some(_) => {
                            let ch = src[i..].chars().next().unwrap_or('\0');
                            s.push(ch);
                            i += ch.len_utf8();
                        }
                    }
                }
                Tok::Str(s)
            }
            b'0'..=b'9' | b'-' => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                let text = &src[i..j];
                let v: i64 = text.parse().map_err(|_| err(start, "invalid integer"))?;
                i = j;
                Tok::Int(v)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'-')
                {
                    j += 1;
                }
                i = j;
                Tok::Ident(&src[start..j])
            }
            _ => return Err(err(start, "unexpected character")),
        };
        out.push((start, tok));
        if out.len() > MAX_TOKENS {
            return Err(err(start, "expression has too many tokens"));
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<(usize, Tok<'a>)>,
    pos: usize,
    end: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok<'a>> {
        self.toks.get(self.pos).map(|(_, t)| t)
    }
    fn at(&self) -> usize {
        self.toks.get(self.pos).map_or(self.end, |(a, _)| *a)
    }
    fn next(&mut self) -> Option<Tok<'a>> {
        let t = self.toks.get(self.pos).map(|(_, t)| t.clone());
        self.pos += 1;
        t
    }
    fn err(&self, m: &str) -> ParseError {
        ParseError {
            at: self.at(),
            message: m.to_owned(),
        }
    }
    fn expect(&mut self, want: Tok<'a>, what: &str) -> Result<(), ParseError> {
        if self.peek() == Some(&want) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(what))
        }
    }

    // Precedence: || < && < (== !=) < unary !
    fn parse_or(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and(depth)?;
        while self.peek() == Some(&Tok::OrOr) {
            self.pos += 1;
            let rhs = self.parse_and(depth)?;
            lhs = Expr::Bin(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_and(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_eq(depth)?;
        while self.peek() == Some(&Tok::AndAnd) {
            self.pos += 1;
            let rhs = self.parse_eq(depth)?;
            lhs = Expr::Bin(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_eq(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let lhs = self.parse_unary(depth)?;
        let op = match self.peek() {
            Some(Tok::EqEq) => BinOp::Eq,
            Some(Tok::NotEq) => BinOp::Ne,
            _ => return Ok(lhs),
        };
        self.pos += 1;
        let rhs = self.parse_unary(depth)?;
        // Non-associative: `a == b == c` is an error, not a surprise.
        if matches!(self.peek(), Some(Tok::EqEq | Tok::NotEq)) {
            return Err(self.err("comparisons cannot be chained; use parentheses"));
        }
        Ok(Expr::Bin(op, Box::new(lhs), Box::new(rhs)))
    }
    fn parse_unary(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("expression nests too deeply"));
        }
        if self.peek() == Some(&Tok::Bang) {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.parse_unary(depth + 1)?)));
        }
        self.parse_primary(depth)
    }
    fn parse_primary(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let at = self.at();
        match self.next() {
            Some(Tok::Str(s)) => Ok(Expr::Lit(Value::Str(s))),
            Some(Tok::Int(i)) => Ok(Expr::Lit(Value::Int(i))),
            Some(Tok::LParen) => {
                let inner = self.parse_or(depth + 1)?;
                self.expect(Tok::RParen, "expected `)`")?;
                Ok(inner)
            }
            Some(Tok::Ident(name)) => {
                if self.peek() == Some(&Tok::LParen) {
                    self.pos += 1;
                    let func = Func::parse(name).ok_or_else(|| ParseError {
                        at,
                        message: format!("unknown function `{name}`"),
                    })?;
                    let mut args = Vec::new();
                    if self.peek() != Some(&Tok::RParen) {
                        loop {
                            if args.len() >= MAX_ARGS {
                                return Err(self.err("too many arguments"));
                            }
                            args.push(self.parse_or(depth + 1)?);
                            if self.peek() == Some(&Tok::Comma) {
                                self.pos += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(Tok::RParen, "expected `)`")?;
                    let (min, max) = func.arity();
                    if args.len() < min || args.len() > max {
                        return Err(ParseError {
                            at,
                            message: format!("`{name}` takes {min} to {max} arguments"),
                        });
                    }
                    if func == Func::HashFiles {
                        for a in &args {
                            match a {
                                Expr::Lit(Value::Str(p))
                                    if crate::schema::valid_relative_path(p) => {}
                                _ => {
                                    return Err(ParseError {
                                        at,
                                        message:
                                            "hash_files patterns must be literal relative paths"
                                                .into(),
                                    });
                                }
                            }
                        }
                    }
                    return Ok(Expr::Call(func, args));
                }
                match name {
                    "true" => return Ok(Expr::Lit(Value::Bool(true))),
                    "false" => return Ok(Expr::Lit(Value::Bool(false))),
                    "null" => return Ok(Expr::Lit(Value::Null)),
                    _ => {}
                }
                let mut path = vec![name.to_owned()];
                while self.peek() == Some(&Tok::Dot) {
                    self.pos += 1;
                    match self.next() {
                        Some(Tok::Ident(seg)) => path.push(seg.to_owned()),
                        _ => return Err(self.err("expected a name after `.`")),
                    }
                    if path.len() > MAX_PATH_SEGMENTS {
                        return Err(self.err("context path too long"));
                    }
                }
                validate_path(&path).map_err(|m| ParseError {
                    at,
                    message: m.to_owned(),
                })?;
                Ok(Expr::Path(path))
            }
            Some(_) => Err(ParseError {
                at,
                message: "unexpected token".into(),
            }),
            None => Err(ParseError {
                at,
                message: "unexpected end of expression".into(),
            }),
        }
    }
}

/// Known context roots and their shapes. Unknown paths are compile errors so
/// a typo cannot silently evaluate to null.
fn validate_path(path: &[String]) -> Result<(), &'static str> {
    let seg = |i: usize| path.get(i).map(String::as_str);
    match (seg(0), seg(1), seg(2)) {
        (Some("event"), Some("name" | "ref" | "base_ref" | "sha" | "key" | "pr_number"), None) => {
            Ok(())
        }
        (Some("repo"), Some("id" | "name"), None) => Ok(()),
        (Some("run"), Some("id"), None) => Ok(()),
        (Some("job"), Some("id" | "name"), None) => Ok(()),
        (Some("needs"), Some(job), Some("result")) if seg(3).is_none() => {
            if crate::schema::valid_id(job) {
                Ok(())
            } else {
                Err("needs.<job> must be a valid job name")
            }
        }
        (Some("event" | "repo" | "run" | "job" | "needs"), _, _) => Err("unknown context field"),
        _ => Err("unknown context; expected event, repo, run, job or needs"),
    }
}

impl Expr {
    pub fn parse(src: &str) -> Result<Expr, ParseError> {
        if src.len() > MAX_EXPR_BYTES {
            return Err(ParseError {
                at: 0,
                message: format!("expression longer than {MAX_EXPR_BYTES} bytes"),
            });
        }
        let toks = tokenize(src)?;
        if toks.is_empty() {
            return Err(ParseError {
                at: 0,
                message: "empty expression".into(),
            });
        }
        let mut p = Parser {
            toks,
            pos: 0,
            end: src.len(),
        };
        let e = p.parse_or(0)?;
        if p.pos != p.toks.len() {
            return Err(p.err("unexpected trailing input"));
        }
        Ok(e)
    }

    /// Earliest phase at which every part of this expression can resolve.
    pub fn min_phase(&self) -> Phase {
        match self {
            Expr::Lit(_) => Phase::Compile,
            Expr::Path(p) => {
                if p[0] == "needs" {
                    Phase::Schedule
                } else {
                    Phase::Dispatch
                }
            }
            Expr::Not(e) => e.min_phase(),
            Expr::Bin(_, a, b) => a.min_phase().max(b.min_phase()),
            Expr::Call(f, args) => args
                .iter()
                .map(Expr::min_phase)
                .fold(f.min_phase(), Phase::max),
        }
    }

    /// Job names referenced through `needs.<job>.result`.
    pub fn referenced_needs(&self, out: &mut Vec<String>) {
        match self {
            Expr::Path(p) if p[0] == "needs" => {
                if !out.contains(&p[1]) {
                    out.push(p[1].clone());
                }
            }
            Expr::Lit(_) | Expr::Path(_) => {}
            Expr::Not(e) => e.referenced_needs(out),
            Expr::Bin(_, a, b) => {
                a.referenced_needs(out);
                b.referenced_needs(out);
            }
            Expr::Call(_, args) => args.iter().for_each(|a| a.referenced_needs(out)),
        }
    }
}

/// What the evaluator asks of its environment. Implementations return
/// `Unresolved` for anything not known in their phase.
pub trait Context {
    fn phase(&self) -> Phase;
    /// Look up a validated context path.
    fn lookup(&self, path: &[String]) -> Lookup;
    fn dependency_summary(&self) -> Option<DependencySummary>;
    fn cancelled(&self) -> Option<bool>;
    /// Resolve `hash_files` patterns; only called in `Phase::Worker`.
    fn hash_files(&self, patterns: &[&str]) -> Result<String, HashFilesError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Value(Value),
    /// Known path, value not available in this phase.
    Unresolved,
}

/// Aggregate of a job's dependencies for `success()`/`failure()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DependencySummary {
    pub all_succeeded: bool,
    pub any_failed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashFilesError {
    /// Secure worker filesystem resolution is currently Linux-only.
    UnsupportedPlatform,
    TraversalLimit,
    DepthLimit,
    PathLimit,
    InvalidFileName,
    UnsafeFile,
    ChangedFile,
    /// No file matched any pattern: a misconfiguration, never a silent key.
    NoMatch,
    TooManyFiles {
        limit: usize,
    },
    TooManyBytes {
        limit: u64,
    },
    InvalidPattern(String),
    Io(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    /// A path or function is not available in the current phase.
    Unresolved {
        phase: Phase,
        needs: Phase,
    },
    TypeMismatch {
        expected: &'static str,
        found: &'static str,
    },
    HashFiles(HashFilesError),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved { phase, needs } => {
                write!(f, "not resolvable in phase {phase:?}; needs {needs:?}")
            }
            Self::TypeMismatch { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            Self::HashFiles(e) => write!(f, "hash_files: {e:?}"),
        }
    }
}

fn expect_str(v: Value) -> Result<String, EvalError> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(EvalError::TypeMismatch {
            expected: "string",
            found: other.type_name(),
        }),
    }
}

fn expect_bool(v: Value) -> Result<bool, EvalError> {
    match v {
        Value::Bool(b) => Ok(b),
        other => Err(EvalError::TypeMismatch {
            expected: "boolean",
            found: other.type_name(),
        }),
    }
}

impl Expr {
    pub fn eval(&self, ctx: &dyn Context) -> Result<Value, EvalError> {
        let unresolved = |needs: Phase| EvalError::Unresolved {
            phase: ctx.phase(),
            needs,
        };
        match self {
            Expr::Lit(v) => Ok(v.clone()),
            Expr::Path(p) => match ctx.lookup(p) {
                Lookup::Value(v) => Ok(v),
                Lookup::Unresolved => Err(unresolved(self.min_phase())),
            },
            Expr::Not(e) => Ok(Value::Bool(!expect_bool(e.eval(ctx)?)?)),
            Expr::Bin(op, a, b) => match op {
                BinOp::And => {
                    // Short-circuit, but both sides must be booleans when evaluated.
                    if !expect_bool(a.eval(ctx)?)? {
                        return Ok(Value::Bool(false));
                    }
                    Ok(Value::Bool(expect_bool(b.eval(ctx)?)?))
                }
                BinOp::Or => {
                    if expect_bool(a.eval(ctx)?)? {
                        return Ok(Value::Bool(true));
                    }
                    Ok(Value::Bool(expect_bool(b.eval(ctx)?)?))
                }
                BinOp::Eq | BinOp::Ne => {
                    let (l, r) = (a.eval(ctx)?, b.eval(ctx)?);
                    let same_type = std::mem::discriminant(&l) == std::mem::discriminant(&r);
                    if !same_type && l != Value::Null && r != Value::Null {
                        return Err(EvalError::TypeMismatch {
                            expected: l.type_name(),
                            found: r.type_name(),
                        });
                    }
                    let eq = l == r;
                    Ok(Value::Bool(if *op == BinOp::Eq { eq } else { !eq }))
                }
            },
            Expr::Call(f, args) => {
                if ctx.phase() < f.min_phase() {
                    return Err(unresolved(f.min_phase()));
                }
                match f {
                    Func::Success | Func::Failure | Func::Always => {
                        let deps = ctx
                            .dependency_summary()
                            .ok_or(unresolved(Phase::Schedule))?;
                        let cancelled = ctx.cancelled().ok_or(unresolved(Phase::Dispatch))?;
                        Ok(Value::Bool(match f {
                            Func::Success => deps.all_succeeded && !cancelled,
                            Func::Failure => deps.any_failed && !cancelled,
                            _ => !cancelled,
                        }))
                    }
                    Func::Cancelled => Ok(Value::Bool(
                        ctx.cancelled().ok_or(unresolved(Phase::Dispatch))?,
                    )),
                    Func::Contains | Func::StartsWith | Func::EndsWith => {
                        let a = expect_str(args[0].eval(ctx)?)?;
                        let b = expect_str(args[1].eval(ctx)?)?;
                        Ok(Value::Bool(match f {
                            Func::Contains => a.contains(b.as_str()),
                            Func::StartsWith => a.starts_with(b.as_str()),
                            _ => a.ends_with(b.as_str()),
                        }))
                    }
                    Func::HashFiles => {
                        let patterns: Vec<&str> = args
                            .iter()
                            .map(|a| match a {
                                Expr::Lit(Value::Str(s)) => s.as_str(),
                                _ => "",
                            })
                            .collect();
                        ctx.hash_files(&patterns)
                            .map(Value::Str)
                            .map_err(EvalError::HashFiles)
                    }
                }
            }
        }
    }
}

/// A string with `${{ … }}` interpolations, parsed once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    pub parts: Vec<Part>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Part {
    Lit(String),
    Expr(Expr),
}

impl Template {
    pub fn parse(src: &str) -> Result<Template, ParseError> {
        let mut parts = Vec::new();
        let mut rest = src;
        let mut offset = 0;
        while let Some(start) = rest.find("${{") {
            if start > 0 {
                parts.push(Part::Lit(rest[..start].to_owned()));
            }
            let after = &rest[start + 3..];
            let end = after.find("}}").ok_or(ParseError {
                at: offset + start,
                message: "unterminated `${{`".into(),
            })?;
            let expr = Expr::parse(&after[..end]).map_err(|e| ParseError {
                at: offset + start + 3 + e.at,
                message: e.message,
            })?;
            parts.push(Part::Expr(expr));
            let consumed = start + 3 + end + 2;
            offset += consumed;
            rest = &rest[consumed..];
        }
        if rest.contains("}}") {
            return Err(ParseError {
                at: offset,
                message: "`}}` without `${{`".into(),
            });
        }
        if !rest.is_empty() {
            parts.push(Part::Lit(rest.to_owned()));
        }
        Ok(Template { parts })
    }

    pub fn is_literal(&self) -> bool {
        self.parts.iter().all(|p| matches!(p, Part::Lit(_)))
    }

    pub fn min_phase(&self) -> Phase {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Lit(_) => Phase::Compile,
                Part::Expr(e) => e.min_phase(),
            })
            .fold(Phase::Compile, Phase::max)
    }

    pub fn referenced_needs(&self, out: &mut Vec<String>) {
        for p in &self.parts {
            if let Part::Expr(e) = p {
                e.referenced_needs(out);
            }
        }
    }

    /// Render with bounded output; null interpolations are errors.
    pub fn render(&self, ctx: &dyn Context, max_bytes: usize) -> Result<String, EvalError> {
        let mut out = String::new();
        for p in &self.parts {
            let piece = match p {
                Part::Lit(s) => s.clone(),
                Part::Expr(e) => match e.eval(ctx)? {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => {
                        return Err(EvalError::TypeMismatch {
                            expected: "string, integer or boolean",
                            found: "null",
                        });
                    }
                },
            };
            out.push_str(&piece);
            if out.len() > max_bytes {
                return Err(EvalError::TypeMismatch {
                    expected: "rendered value within limit",
                    found: "longer output",
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        phase: Phase,
        deps: Option<DependencySummary>,
    }
    impl Context for Ctx {
        fn phase(&self) -> Phase {
            self.phase
        }
        fn lookup(&self, path: &[String]) -> Lookup {
            let key: Vec<&str> = path.iter().map(String::as_str).collect();
            match key.as_slice() {
                ["event", "ref"] if self.phase >= Phase::Dispatch => {
                    Lookup::Value(Value::Str("refs/heads/main".into()))
                }
                ["event", "pr_number"] if self.phase >= Phase::Dispatch => {
                    Lookup::Value(Value::Null)
                }
                ["repo", "id"] if self.phase >= Phase::Dispatch => Lookup::Value(Value::Int(7)),
                ["needs", "test", "result"] if self.phase >= Phase::Schedule => {
                    Lookup::Value(Value::Str("passed".into()))
                }
                _ => Lookup::Unresolved,
            }
        }
        fn dependency_summary(&self) -> Option<DependencySummary> {
            self.deps
        }
        fn cancelled(&self) -> Option<bool> {
            (self.phase >= Phase::Dispatch).then_some(false)
        }
        fn hash_files(&self, patterns: &[&str]) -> Result<String, HashFilesError> {
            if self.phase < Phase::Worker {
                unreachable!("gated by phase");
            }
            if patterns.contains(&"none/*") {
                return Err(HashFilesError::NoMatch);
            }
            Ok(format!("h:{}", patterns.join(",")))
        }
    }

    fn dispatch() -> Ctx {
        Ctx {
            phase: Phase::Dispatch,
            deps: None,
        }
    }

    #[test]
    fn parses_precedence_and_paths() {
        let e = Expr::parse("!a.b == 'x' && event.ref != null || repo.id == 7");
        assert!(e.is_err(), "unknown context root");
        let e = Expr::parse("event.ref == 'refs/heads/main' && (repo.id == 7 || !cancelled())")
            .unwrap();
        assert_eq!(e.min_phase(), Phase::Dispatch);
        assert_eq!(e.eval(&dispatch()), Ok(Value::Bool(true)));
        let e = Expr::parse("starts_with(event.ref, 'refs/heads/') && event.pr_number == null")
            .unwrap();
        assert_eq!(e.eval(&dispatch()), Ok(Value::Bool(true)));
    }

    #[test]
    fn rejects_unknown_functions_paths_chaining_and_limits() {
        let bad = [
            "exec('rm')",
            "env.HOME",
            "event.unknown",
            "needs.Test.result",
            "needs.test",
            "a == b == c",
            "contains('a')",
            "hash_files(event.ref)",
            "hash_files('../x')",
            "'unterminated",
            "",
            "1 +",
            "(event.ref",
            "event.ref)",
        ];
        for src in bad {
            assert!(Expr::parse(src).is_err(), "{src}");
        }
        assert!(Expr::parse(&"x".repeat(MAX_EXPR_BYTES + 1)).is_err());
        assert!(Expr::parse(&"(".repeat(MAX_DEPTH + 2)).is_err());
        assert!(Expr::parse(&format!("{}true", "!".repeat(MAX_DEPTH + 2))).is_err());
        let many = format!("contains('a', 'b') {}", "&& true".repeat(MAX_TOKENS));
        assert!(Expr::parse(&many).is_err());
    }

    #[test]
    fn phases_gate_needs_and_hash_files() {
        let e = Expr::parse("needs.test.result == 'passed'").unwrap();
        assert_eq!(e.min_phase(), Phase::Schedule);
        assert_eq!(
            e.eval(&dispatch()),
            Err(EvalError::Unresolved {
                phase: Phase::Dispatch,
                needs: Phase::Schedule
            })
        );
        let sched = Ctx {
            phase: Phase::Schedule,
            deps: Some(DependencySummary {
                all_succeeded: true,
                any_failed: false,
            }),
        };
        assert_eq!(e.eval(&sched), Ok(Value::Bool(true)));
        assert_eq!(
            Expr::parse("success()").unwrap().eval(&sched),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            Expr::parse("failure()").unwrap().eval(&sched),
            Ok(Value::Bool(false))
        );
        assert!(matches!(
            Expr::parse("success()").unwrap().eval(&dispatch()),
            Err(EvalError::Unresolved { .. })
        ));
        let h = Expr::parse("hash_files('Cargo.lock', 'crates/*/Cargo.toml')").unwrap();
        assert_eq!(h.min_phase(), Phase::Worker);
        assert!(matches!(h.eval(&sched), Err(EvalError::Unresolved { .. })));
        let worker = Ctx {
            phase: Phase::Worker,
            deps: sched.deps,
        };
        assert_eq!(
            h.eval(&worker),
            Ok(Value::Str("h:Cargo.lock,crates/*/Cargo.toml".into()))
        );
        assert_eq!(
            Expr::parse("hash_files('none/*')").unwrap().eval(&worker),
            Err(EvalError::HashFiles(HashFilesError::NoMatch))
        );
        let mut refs = Vec::new();
        e.referenced_needs(&mut refs);
        assert_eq!(refs, ["test"]);
    }

    #[test]
    fn evaluation_is_typed() {
        let c = dispatch();
        assert!(matches!(
            Expr::parse("event.ref == 7").unwrap().eval(&c),
            Err(EvalError::TypeMismatch { .. })
        ));
        assert!(matches!(
            Expr::parse("!event.ref").unwrap().eval(&c),
            Err(EvalError::TypeMismatch { .. })
        ));
        assert!(matches!(
            Expr::parse("event.ref && true").unwrap().eval(&c),
            Err(EvalError::TypeMismatch { .. })
        ));
        assert_eq!(Value::Str("x".into()).as_condition(), None);
        assert_eq!(
            Expr::parse("'it''s'").unwrap(),
            Expr::Lit(Value::Str("it's".into()))
        );
    }

    #[test]
    fn display_is_canonical_and_round_trips() {
        for src in [
            "event.ref == 'refs/heads/main' && (repo.id == 7 || !cancelled())",
            "starts_with(event.ref, 'x''y') && event.pr_number == null",
            "hash_files('Cargo.lock', 'crates/*/Cargo.toml')",
            "!!true",
        ] {
            let e = Expr::parse(src).unwrap();
            let printed = e.to_string();
            assert_eq!(Expr::parse(&printed).unwrap(), e, "{printed}");
        }
        assert_eq!(
            Expr::parse("a.b").unwrap_err().message,
            "unknown context; expected event, repo, run, job or needs"
        );
        let t = Template::parse("k-${{ repo.id }}:${{ hash_files('x') }}").unwrap();
        assert_eq!(t.to_string(), "k-${{ repo.id }}:${{ hash_files('x') }}");
        assert_eq!(Template::parse(&t.to_string()).unwrap(), t);
    }

    #[test]
    fn templates_interpolate_and_bound_output() {
        let t = Template::parse("${{ repo.id }}:${{ event.ref }}").unwrap();
        assert!(!t.is_literal());
        assert_eq!(t.min_phase(), Phase::Dispatch);
        assert_eq!(t.render(&dispatch(), 256), Ok("7:refs/heads/main".into()));
        assert!(t.render(&dispatch(), 8).is_err());
        assert!(Template::parse("plain").unwrap().is_literal());
        assert!(Template::parse("${{ event.ref").is_err());
        assert!(Template::parse("x }} y").is_err());
        assert!(Template::parse("${{ nope.x }}").is_err());
        let null = Template::parse("pr-${{ event.pr_number }}").unwrap();
        assert!(
            null.render(&dispatch(), 256).is_err(),
            "null cannot be interpolated"
        );
        let cache = Template::parse("cargo-${{ hash_files('Cargo.lock') }}").unwrap();
        assert_eq!(cache.min_phase(), Phase::Worker);
    }
}
