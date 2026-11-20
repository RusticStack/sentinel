//! Typed manual inputs: a declaration states the bound a value must respect, and a value outside it
//! is refused before a run exists. Nothing here reads a repository or a store.
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_INPUTS: usize = 16;
pub const MAX_INPUT_NAME: usize = 32;
pub const MAX_INPUT_STRING_BYTES: usize = 1024;
pub const MAX_CHOICE_VALUES: usize = 32;
pub const MAX_CHOICE_BYTES: usize = 128;
/// Choices listed in a refusal: the message names the bound without echoing an unbounded list.
const LISTED_CHOICES: usize = 8;

/// An input's name: `[a-z][a-z0-9_]*`, so it is also a path segment in `${{ inputs.<name> }}`.
pub fn valid_input_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_INPUT_NAME
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputValue {
    Str(String),
    Bool(bool),
    Int(i64),
}

impl InputValue {
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Str(_) => "string",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "integer",
        }
    }

    pub fn expr_value(&self) -> crate::expr::Value {
        match self {
            Self::Str(s) => crate::expr::Value::Str(s.clone()),
            Self::Bool(b) => crate::expr::Value::Bool(*b),
            Self::Int(i) => crate::expr::Value::Int(*i),
        }
    }
}

/// The type and bound a declaration states; every kind carries a finite one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputKind {
    Str { min_length: u16, max_length: u16 },
    Choice { values: Vec<String> },
    Bool,
    Int { min: i64, max: i64 },
}

impl InputKind {
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Str { .. } => "string",
            Self::Choice { .. } => "choice",
            Self::Bool => "boolean",
            Self::Int { .. } => "integer",
        }
    }

    /// The bound, as a refusal states it.
    pub fn bound(&self) -> String {
        match self {
            Self::Str {
                min_length,
                max_length,
            } => match min_length {
                0 => format!("at most {max_length} bytes"),
                min => format!("{min} to {max_length} bytes"),
            },
            Self::Choice { values } => {
                let mut out = String::from("one of ");
                for (i, value) in values.iter().take(LISTED_CHOICES).enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(value);
                }
                if values.len() > LISTED_CHOICES {
                    out.push_str(", ...");
                }
                out
            }
            Self::Bool => "true or false".to_owned(),
            Self::Int { min, max } => format!("{min} to {max}"),
        }
    }

    /// Whether a value's type is the one this kind carries; a mismatch is not a bound failure.
    pub const fn accepts_type(&self, value: &InputValue) -> bool {
        matches!(
            (self, value),
            (Self::Str { .. } | Self::Choice { .. }, InputValue::Str(_))
                | (Self::Bool, InputValue::Bool(_))
                | (Self::Int { .. }, InputValue::Int(_))
        )
    }

    pub fn holds(&self, value: &InputValue) -> bool {
        match (self, value) {
            (
                Self::Str {
                    min_length,
                    max_length,
                },
                InputValue::Str(s),
            ) => {
                let len = s.len();
                len >= *min_length as usize && len <= *max_length as usize
            }
            (Self::Choice { values }, InputValue::Str(s)) => values.iter().any(|v| v == s),
            (Self::Bool, InputValue::Bool(_)) => true,
            (Self::Int { min, max }, InputValue::Int(i)) => i >= min && i <= max,
            _ => false,
        }
    }

    /// The expression type a value of this kind reads as.
    pub const fn expr_type(&self) -> u8 {
        match self {
            Self::Str { .. } | Self::Choice { .. } => TY_STR,
            Self::Bool => TY_BOOL,
            Self::Int { .. } => TY_INT,
        }
    }
}

const TY_STR: u8 = 1;
const TY_INT: u8 = 2;
const TY_BOOL: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSpec {
    pub kind: InputKind,
    /// Present makes the input optional; absent makes it required of a manual dispatch.
    pub default: Option<InputValue>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inputs(Vec<(String, InputSpec)>);

impl Inputs {
    /// `entries` come sorted by name, which is how a resolved value list is stored and digested.
    pub fn new(mut entries: Vec<(String, InputSpec)>) -> Self {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Self(entries)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, InputSpec)> {
        self.0.iter()
    }

    pub fn get(&self, name: &str) -> Option<&InputSpec> {
        self.0
            .binary_search_by(|(n, _)| n.as_str().cmp(name))
            .ok()
            .map(|i| &self.0[i].1)
    }

    /// The values an event-driven or scheduled run starts with: every default, in declaration order.
    pub fn defaults(&self) -> Result<Vec<(String, InputValue)>, InputError> {
        self.resolve(&[])
    }

    /// Check every provided value against its declaration and fill in the defaults.
    ///
    /// The first failure is the one reported, in declaration order, so one request answers one
    /// reason and a caller never has to guess which of several bounds it missed.
    pub fn resolve(
        &self,
        provided: &[(String, InputValue)],
    ) -> Result<Vec<(String, InputValue)>, InputError> {
        for (name, _) in provided {
            if self.get(name).is_none() {
                return Err(InputError::Unknown { name: name.clone() });
            }
        }
        let mut out: Vec<(String, InputValue)> = Vec::with_capacity(self.0.len());
        for (name, spec) in &self.0 {
            let value = match provided.iter().find(|(n, _)| n == name) {
                Some((_, value)) => value.clone(),
                None => match &spec.default {
                    Some(default) => default.clone(),
                    None => {
                        return Err(InputError::Missing { name: name.clone() });
                    }
                },
            };
            // A default is checked by the loader, so this only ever refuses what a request sent.
            if !spec.kind.accepts_type(&value) {
                return Err(InputError::WrongType {
                    name: name.clone(),
                    expected: spec.kind.type_name(),
                    found: value.type_name(),
                });
            }
            if !spec.kind.holds(&value) {
                return Err(InputError::OutOfBound {
                    name: name.clone(),
                    bound: spec.kind.bound(),
                    // A refusal never echoes the value itself, only the figure its bound compares.
                    found: match &value {
                        InputValue::Str(_) => None,
                        InputValue::Bool(_) | InputValue::Int(_) => Some(describe(&value)),
                    },
                });
            }
            out.push((name.clone(), value));
        }
        Ok(out)
    }
}

fn describe(value: &InputValue) -> String {
    match value {
        InputValue::Str(s) => format!("{} bytes", s.len()),
        InputValue::Bool(b) => b.to_string(),
        InputValue::Int(i) => i.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    Missing {
        name: String,
    },
    Unknown {
        name: String,
    },
    /// The value's type is not the declared one.
    WrongType {
        name: String,
        expected: &'static str,
        found: &'static str,
    },
    /// A value of the declared type that breaks the declared bound.
    OutOfBound {
        name: String,
        bound: String,
        found: Option<String>,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { name } => write!(f, "inputs.{name}: required"),
            Self::Unknown { name } => {
                write!(f, "inputs.{name}: no input of this pipeline has that name")
            }
            Self::WrongType {
                name,
                expected,
                found,
            } => write!(f, "inputs.{name}: expected a {expected}, found a {found}"),
            Self::OutOfBound { name, bound, found } => match found {
                Some(found) => write!(f, "inputs.{name}: {bound}, found {found}"),
                None => write!(f, "inputs.{name}: {bound}"),
            },
        }
    }
}
impl std::error::Error for InputError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Inputs {
        Inputs::new(vec![
            (
                "target".into(),
                InputSpec {
                    kind: InputKind::Str {
                        min_length: 1,
                        max_length: 4,
                    },
                    default: None,
                },
            ),
            (
                "count".into(),
                InputSpec {
                    kind: InputKind::Int { min: 1, max: 3 },
                    default: Some(InputValue::Int(1)),
                },
            ),
            (
                "profile".into(),
                InputSpec {
                    kind: InputKind::Choice {
                        values: vec!["debug".into(), "release".into()],
                    },
                    default: Some(InputValue::Str("debug".into())),
                },
            ),
            (
                "dry".into(),
                InputSpec {
                    kind: InputKind::Bool,
                    default: Some(InputValue::Bool(false)),
                },
            ),
        ])
    }

    #[test]
    fn a_value_outside_its_bound_is_refused_by_name_and_bound() {
        let i = inputs();
        let ok = i
            .resolve(&[("target".to_owned(), InputValue::Str("main".into()))])
            .unwrap();
        assert_eq!(
            ok,
            vec![
                ("count".to_owned(), InputValue::Int(1)),
                ("dry".to_owned(), InputValue::Bool(false)),
                ("profile".to_owned(), InputValue::Str("debug".into())),
                ("target".to_owned(), InputValue::Str("main".into())),
            ]
        );
        let error = |provided: &[(&str, InputValue)]| {
            let provided: Vec<(String, InputValue)> = provided
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect();
            i.resolve(&provided).unwrap_err().to_string()
        };
        assert_eq!(
            error(&[("target", InputValue::Str("develop".into()))]),
            "inputs.target: 1 to 4 bytes"
        );
        assert_eq!(
            error(&[
                ("target", InputValue::Str("main".into())),
                ("count", InputValue::Int(4))
            ]),
            "inputs.count: 1 to 3, found 4"
        );
        assert_eq!(
            error(&[
                ("target", InputValue::Str("main".into())),
                ("profile", InputValue::Str("fast".into()))
            ]),
            "inputs.profile: one of debug, release"
        );
        assert_eq!(
            error(&[("target", InputValue::Bool(true))]),
            "inputs.target: expected a string, found a boolean"
        );
        assert_eq!(error(&[]), "inputs.target: required");
        assert_eq!(
            error(&[
                ("target", InputValue::Str("main".into())),
                ("extra", InputValue::Int(1))
            ]),
            "inputs.extra: no input of this pipeline has that name"
        );
    }

    #[test]
    fn a_namespaced_message_never_echoes_a_value_the_input_bounds() {
        let i = inputs();
        let long = "x".repeat(10);
        let out = i
            .resolve(&[("target".to_owned(), InputValue::Str(long))])
            .unwrap_err();
        assert_eq!(out.to_string(), "inputs.target: 1 to 4 bytes");
        assert!(!out.to_string().contains("xxxx"));
    }
}
