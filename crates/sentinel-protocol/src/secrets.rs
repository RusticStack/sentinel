//! Strict parser for the explicit secret env-file format.
//!
//! This is data parsing only: no quotes, escapes, interpolation, shell or
//! dotenv rules are applied. Values are the bytes after the first `=` up to
//! the line ending; use `secret set --file` for multiline values.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_SECRET_BYTES: usize = 65_536;
pub const MAX_IMPORT_ENTRIES: usize = 100;
pub const MAX_IMPORT_BYTES: usize = super::limits::MAX_API_BODY_BYTES;
pub const MAX_DELIVERY_BYTES: usize = 1024 * 1024;
pub const MAX_DELIVERY_TARGETS: usize = 16 * 64 + 1;
pub const MAX_DELIVERY_VALUES: usize = MAX_DELIVERY_TARGETS;
const DELIVERY_VALUE_WIRE_OVERHEAD: usize = 16;
const DELIVERY_TARGET_WIRE_UPPER_BOUND: usize = 384;

/// Byte storage used for a serialized secret bundle. Its debug view exposes
/// only the size, and every owned buffer is wiped when released.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn copy_from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        core::hint::black_box(&mut self.0);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryValue {
    value: SecretBytes,
}

impl DeliveryValue {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value: SecretBytes::new(value),
        }
    }

    pub fn expose(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl fmt::Debug for DeliveryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryValue([redacted])")
    }
}

/// An explicitly authorized use of one value by one compiled step.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeliveryTarget {
    pub step: u16,
    pub name: String,
    pub value: u16,
    pub target: TargetKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    Environment,
    File {
        path: String,
    },
    /// OCI `auth.json` bytes kept on the host and used only for this job's
    /// image pull. `step` is zero by convention; it is never exposed to a step.
    RegistryAuth,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryBundle {
    pub values: Vec<DeliveryValue>,
    pub targets: Vec<DeliveryTarget>,
}

impl fmt::Debug for DeliveryBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryBundle")
            .field("values", &self.values.len())
            .field("targets", &self.targets.len())
            .finish()
    }
}

impl DeliveryBundle {
    pub fn empty() -> Self {
        Self {
            values: Vec::new(),
            targets: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// A conservative allocation-free upper bound for its postcard wire
    /// size. The target bound covers both maximum-length names and file
    /// paths; value overhead covers the byte-string length prefix and struct
    /// framing. Preparation checks this as it grows so oversized bundles do
    /// not first allocate every secret value.
    pub fn within_wire_limit(&self) -> bool {
        if self.values.len() > MAX_DELIVERY_VALUES || self.targets.len() > MAX_DELIVERY_TARGETS {
            return false;
        }
        let Some(size) = self
            .values
            .iter()
            .try_fold(16usize, |size, value| {
                size.checked_add(value.value.len())?
                    .checked_add(DELIVERY_VALUE_WIRE_OVERHEAD)
            })
            .and_then(|size| {
                size.checked_add(
                    self.targets
                        .len()
                        .checked_mul(DELIVERY_TARGET_WIRE_UPPER_BOUND)?,
                )
            })
        else {
            return false;
        };
        size <= MAX_DELIVERY_BYTES
    }

    /// Bound the decoded control data before any worker filesystem work.
    pub fn valid(&self) -> bool {
        self.within_wire_limit()
            && self
                .values
                .iter()
                .all(|v| (1..=MAX_SECRET_BYTES).contains(&v.value.len()))
            && self.targets.iter().all(|target| {
                target.step < 64
                    && valid_secret_name(&target.name)
                    && (target.value as usize) < self.values.len()
                    && match &target.target {
                        TargetKind::Environment => true,
                        TargetKind::File { path } => valid_delivery_path(path),
                        TargetKind::RegistryAuth => target.step == 0,
                    }
            })
    }
}

fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && !bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn valid_delivery_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.contains("//")
        && !path.ends_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

struct WipeEntries(Vec<(String, Vec<u8>)>);
impl Drop for WipeEntries {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.fill(0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    TooLarge,
    NotUtf8,
    InvalidLine,
    InvalidName,
    EmptyValue,
    ValueTooLarge,
    DuplicateName,
    TooManyEntries,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "env file exceeds the byte limit",
            Self::NotUtf8 => "env file must be UTF-8",
            Self::InvalidLine => "env file line must be NAME=value",
            Self::InvalidName => "env file contains an invalid secret name",
            Self::EmptyValue => "env file contains an empty value",
            Self::ValueTooLarge => "env file contains a value over the byte limit",
            Self::DuplicateName => "env file contains a duplicate secret name",
            Self::TooManyEntries => "env file contains too many secrets",
        })
    }
}

/// Parse `NAME=value` records. Blank and `#` comment lines are ignored;
/// names are case-sensitive and must match `[A-Z_][A-Z0-9_]*`. One CR is
/// removed before LF for CRLF files. A final newline is syntax, not part of
/// a value. No value is included in an error.
pub fn parse_env_file(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| ImportError::NotUtf8)?;
    let mut entries = WipeEntries(Vec::new());
    for raw in bytes.split(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(eq) = line.iter().position(|byte| *byte == b'=') else {
            return Err(ImportError::InvalidLine);
        };
        let name = &line[..eq];
        let valid = (1..=64).contains(&name.len())
            && (name[0].is_ascii_uppercase() || name[0] == b'_')
            && name
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_');
        if !valid {
            return Err(ImportError::InvalidName);
        }
        let value = &line[eq + 1..];
        if value.is_empty() {
            return Err(ImportError::EmptyValue);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(ImportError::ValueTooLarge);
        }
        if entries.0.iter().any(|(old, _)| old.as_bytes() == name) {
            return Err(ImportError::DuplicateName);
        }
        if entries.0.len() == MAX_IMPORT_ENTRIES {
            return Err(ImportError::TooManyEntries);
        }
        // Names were checked as ASCII and the file as UTF-8.
        entries.0.push((
            String::from_utf8(name.to_vec()).expect("ASCII name"),
            value.to_vec(),
        ));
    }
    if entries.0.is_empty() {
        return Err(ImportError::InvalidLine);
    }
    Ok(std::mem::take(&mut entries.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_size_bound_rejects_oversized_values_before_encoding() {
        let too_large = DeliveryBundle {
            values: (0..16)
                .map(|_| DeliveryValue::new(vec![b'x'; MAX_SECRET_BYTES]))
                .collect(),
            targets: Vec::new(),
        };
        assert!(!too_large.within_wire_limit());

        let bounded = DeliveryBundle {
            values: (0..16)
                .map(|_| DeliveryValue::new(vec![b'x'; 60 * 1024]))
                .collect(),
            targets: Vec::new(),
        };
        assert!(bounded.within_wire_limit());
    }

    #[test]
    fn parses_literal_values_and_crlf_without_expansion() {
        let parsed = parse_env_file(b"# copied literally\r\nTOKEN=$HOME\nURL=a=b=c\n").unwrap();
        assert_eq!(
            parsed,
            [
                ("TOKEN".into(), b"$HOME".to_vec()),
                ("URL".into(), b"a=b=c".to_vec())
            ]
        );
    }

    #[test]
    fn rejects_duplicate_invalid_empty_and_oversized_values_without_echoing_them() {
        for (body, error) in [
            (&b"A=one\nA=two"[..], ImportError::DuplicateName),
            (&b"A"[..], ImportError::InvalidLine),
            (&b"A="[..], ImportError::EmptyValue),
            (&b"bad-name=x"[..], ImportError::InvalidName),
        ] {
            assert_eq!(parse_env_file(body), Err(error));
        }
        assert_eq!(
            parse_env_file(&[b"A=".as_slice(), &vec![b'x'; MAX_SECRET_BYTES + 1]].concat()),
            Err(ImportError::ValueTooLarge)
        );
        assert!(!ImportError::DuplicateName.to_string().contains("one"));
    }
}
