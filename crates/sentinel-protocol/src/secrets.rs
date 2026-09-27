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
pub enum ImportFault {
    TooLarge,
    NotUtf8,
    /// A UTF-16 byte-order mark: PowerShell 5.1's default `>` encoding.
    Utf16,
    /// A carriage return that does not end a CRLF line: records written
    /// with bare CR would otherwise merge into one value.
    BareCarriageReturn,
    InvalidLine,
    InvalidName,
    EmptyValue,
    ValueTooLarge,
    DuplicateName,
    TooManyEntries,
}

/// Why an env file was refused, and the 1-based line when one is to blame.
/// Neither ever includes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportError {
    pub fault: ImportFault,
    /// 0 when the fault is the file as a whole.
    pub line: usize,
}

impl ImportError {
    const fn file(fault: ImportFault) -> Self {
        Self { fault, line: 0 }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self.fault {
            ImportFault::TooLarge => "env file exceeds the byte limit",
            ImportFault::NotUtf8 => "env file must be UTF-8",
            ImportFault::Utf16 => {
                "env file is UTF-16; save it as UTF-8 (PowerShell: Set-Content -Encoding utf8)"
            }
            ImportFault::BareCarriageReturn => {
                "env file has a carriage return that does not end a CRLF line"
            }
            ImportFault::InvalidLine => "env file line must be NAME=value",
            ImportFault::InvalidName => "env file contains an invalid secret name",
            ImportFault::EmptyValue => "env file contains an empty value",
            ImportFault::ValueTooLarge => "env file contains a value over the byte limit",
            ImportFault::DuplicateName => "env file contains a duplicate secret name",
            ImportFault::TooManyEntries => "env file contains too many secrets",
        };
        if self.line == 0 {
            f.write_str(text)
        } else {
            write!(f, "{text} (line {})", self.line)
        }
    }
}

/// Hints about a literal value that is probably not what the author meant,
/// for the metadata-only import preview: whether it is wrapped in matching
/// quotes (stored with them) or starts or ends with whitespace. Only these
/// booleans leave; never the value.
pub fn literal_hints(value: &[u8]) -> (bool, bool) {
    let quoted =
        value.len() >= 2 && matches!(value[0], b'"' | b'\'') && value[value.len() - 1] == value[0];
    let padded = value.first().is_some_and(u8::is_ascii_whitespace)
        || value.last().is_some_and(u8::is_ascii_whitespace);
    (quoted, padded)
}

/// Parse `NAME=value` records. Blank and `#` comment lines are ignored;
/// names are case-sensitive and must match `[A-Z_][A-Z0-9_]*`. A UTF-8 BOM
/// at the start is skipped. Lines end with LF or CRLF; any other CR is
/// refused. A final newline is syntax, not part of a value. Everything
/// after the first `=` is the literal value: quotes, `#`, spaces and `$` are
/// kept as written. Errors name the line, never a value.
pub fn parse_env_file(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::file(ImportFault::TooLarge));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err(ImportError::file(ImportFault::Utf16));
    }
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| ImportError::file(ImportFault::NotUtf8))?;
    let mut entries = WipeEntries(Vec::new());
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    for (index, raw) in body.split(|byte| *byte == b'\n').enumerate() {
        let at = |fault| ImportError {
            fault,
            line: index + 1,
        };
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.contains(&b'\r') {
            return Err(at(ImportFault::BareCarriageReturn));
        }
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(eq) = line.iter().position(|byte| *byte == b'=') else {
            return Err(at(ImportFault::InvalidLine));
        };
        let name = &line[..eq];
        let valid = (1..=64).contains(&name.len())
            && (name[0].is_ascii_uppercase() || name[0] == b'_')
            && name
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_');
        if !valid {
            return Err(at(ImportFault::InvalidName));
        }
        let value = &line[eq + 1..];
        if value.is_empty() {
            return Err(at(ImportFault::EmptyValue));
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(at(ImportFault::ValueTooLarge));
        }
        if entries.0.iter().any(|(old, _)| old.as_bytes() == name) {
            return Err(at(ImportFault::DuplicateName));
        }
        if entries.0.len() == MAX_IMPORT_ENTRIES {
            return Err(at(ImportFault::TooManyEntries));
        }
        // Names were checked as ASCII and the file as UTF-8.
        entries.0.push((
            String::from_utf8(name.to_vec()).expect("ASCII name"),
            value.to_vec(),
        ));
    }
    if entries.0.is_empty() {
        return Err(ImportError::file(ImportFault::InvalidLine));
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
        let parsed =
            parse_env_file(b"# copied literally\r\nTOKEN=$HOME\nURL=a=b=c\nQ=\"x\" # c\n").unwrap();
        assert_eq!(
            parsed,
            [
                ("TOKEN".into(), b"$HOME".to_vec()),
                ("URL".into(), b"a=b=c".to_vec()),
                ("Q".into(), b"\"x\" # c".to_vec()),
            ]
        );
    }

    #[test]
    fn a_utf8_bom_is_skipped_and_utf16_is_named() {
        assert_eq!(
            parse_env_file(b"\xEF\xBB\xBFA=1\r\n").unwrap(),
            [("A".into(), b"1".to_vec())]
        );
        let utf16 = parse_env_file(b"\xFF\xFEA\x00=\x001\x00").unwrap_err();
        assert_eq!(utf16.fault, ImportFault::Utf16);
        assert!(utf16.to_string().contains("UTF-8"));
        assert_eq!(
            parse_env_file(b"A=\xff").unwrap_err().fault,
            ImportFault::NotUtf8
        );
    }

    #[test]
    fn a_bare_carriage_return_is_refused_with_its_line() {
        // Old Mac line endings used to merge `B` into `A`'s value.
        let error = parse_env_file(b"A=1\rB=2\r").unwrap_err();
        assert_eq!(
            error,
            ImportError {
                fault: ImportFault::BareCarriageReturn,
                line: 1
            }
        );
        assert_eq!(parse_env_file(b"A=1\nB=2\rC=3\n").unwrap_err().line, 2);
    }

    #[test]
    fn rejects_duplicate_invalid_empty_and_oversized_values_without_echoing_them() {
        for (body, fault, line) in [
            (&b"A=one\nA=two"[..], ImportFault::DuplicateName, 2),
            (&b"A"[..], ImportFault::InvalidLine, 1),
            (&b"A=1\n\nB="[..], ImportFault::EmptyValue, 3),
            (&b"bad-name=x"[..], ImportFault::InvalidName, 1),
            (&b"export A=1"[..], ImportFault::InvalidName, 1),
            (&b"   "[..], ImportFault::InvalidLine, 1),
        ] {
            let error = parse_env_file(body).unwrap_err();
            assert_eq!((error.fault, error.line), (fault, line), "{body:?}");
        }
        let error = parse_env_file(&[b"A=".as_slice(), &vec![b'x'; MAX_SECRET_BYTES + 1]].concat())
            .unwrap_err();
        assert_eq!(error.fault, ImportFault::ValueTooLarge);
        let message = parse_env_file(b"A=one\nA=two").unwrap_err().to_string();
        assert!(message.ends_with("(line 2)") && !message.contains("one"));
        assert_eq!(
            parse_env_file(&vec![b'#'; MAX_IMPORT_BYTES + 1])
                .unwrap_err()
                .fault,
            ImportFault::TooLarge
        );
        let many: String = (0..=MAX_IMPORT_ENTRIES)
            .map(|i| format!("K{i}=v\n"))
            .collect();
        assert_eq!(
            parse_env_file(many.as_bytes()).unwrap_err(),
            ImportError {
                fault: ImportFault::TooManyEntries,
                line: MAX_IMPORT_ENTRIES + 1
            }
        );
    }

    #[test]
    fn literal_hints_flag_quotes_and_padding_only() {
        assert_eq!(literal_hints(b"\"x\""), (true, false));
        assert_eq!(literal_hints(b"'x'"), (true, false));
        assert_eq!(literal_hints(b"\"x'"), (false, false));
        assert_eq!(literal_hints(b"x "), (false, true));
        assert_eq!(literal_hints(b"\""), (false, false));
    }
}
