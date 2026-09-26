//! Strict parser for the explicit secret env-file format.
//!
//! This is data parsing only: no quotes, escapes, interpolation, shell or
//! dotenv rules are applied. Values are the bytes after the first `=` up to
//! the line ending; use `secret set --file` for multiline values.

use std::fmt;

pub const MAX_SECRET_BYTES: usize = 65_536;
pub const MAX_IMPORT_ENTRIES: usize = 100;
pub const MAX_IMPORT_BYTES: usize = super::limits::MAX_API_BODY_BYTES;

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
