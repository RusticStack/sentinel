//! Declared outputs: the values a step writes for the steps after it, bounded and plain text.
//!
//! An output is a small piece of text, never a secret: the worker refuses one that repeats a value it delivered as
//! a secret this attempt, and the controller stores what it accepts as plain text in the run's record, where every
//! member of the tenant reads it.

pub use sentinel_pipeline::schema::MAX_OUTPUT_BYTES;
use sentinel_pipeline::schema::MAX_OUTPUT_NAME_BYTES;

/// The file a step writes its declared outputs into, relative to the mounted output directory.
pub const FILE: &str = "step.out";
/// The script the worker writes before a step: the outputs its earlier steps produced, exported into the step.
pub const VALUES: &str = "values.sh";
/// The container path the output directory is mounted at, and the guest path it is delivered to.
pub const MOUNT: &str = "/run/sentinel-output";
/// The most a step's output file may hold: every declared output at its own bound, plus room for the names and
/// newlines. A file past this is not read into memory, and the step fails rather than grow with what it wrote.
pub const MAX_FILE_BYTES: usize =
    MAX_OUTPUT_BYTES * sentinel_pipeline::schema::MAX_OUTPUTS + 4 * 1024;
/// The environment variable naming the file a step writes its outputs into.
pub const FILE_VAR: &str = "SENTINEL_OUTPUT";
/// What an output's environment variable starts with, so a job's own environment never collides by accident.
pub const ENV_PREFIX: &str = "SENTINEL_OUTPUT_";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A line that is not `name=value`.
    Malformed,
    /// A name this step does not declare.
    Undeclared(String),
    /// A name this step wrote twice.
    Duplicate(String),
    /// A value past [`MAX_OUTPUT_BYTES`]; the limit and the name, never the value.
    TooLong(String),
    /// Bytes that are not text: an output is stored as plain text.
    NotText(String),
    /// A value the attempt was given as a secret. Outputs are public within the tenant, so it is refused.
    Secret(String),
}

impl Violation {
    /// The verdict text for the step that wrote it. Nothing here echoes a value.
    pub fn reason(&self) -> String {
        match self {
            Violation::Malformed => "its output file holds a line that is not `name=value`".into(),
            Violation::Undeclared(name) => {
                format!("its output file writes `{name}`, which the step does not declare")
            }
            Violation::Duplicate(name) => {
                format!("its output file writes `{name}` twice")
            }
            Violation::TooLong(name) => format!(
                "its output `{name}` is longer than the {MAX_OUTPUT_BYTES} bytes a declared output may hold"
            ),
            Violation::NotText(name) => {
                format!("its output `{name}` is not text; an output is stored as plain text")
            }
            Violation::Secret(name) => format!(
                "its output `{name}` repeats a delivered secret, and an output is public within the tenant"
            ),
        }
    }
}

/// The outputs `bytes` declares, in the order the step wrote them. `declared` is the step's own list, so a name no
/// step declares is a violation rather than a silently dropped line. An empty file is no output at all; a declared
/// output the step never wrote is absent, not empty.
pub fn parse(bytes: &[u8], declared: &[String]) -> Result<Vec<(String, String)>, Violation> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(declared.len());
    if bytes.is_empty() {
        return Ok(out);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Violation::Malformed)?;
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(Violation::Malformed);
        };
        if name.len() > MAX_OUTPUT_NAME_BYTES || !declared.iter().any(|d| d == name) {
            return Err(Violation::Undeclared(name.to_owned()));
        }
        if value.len() > MAX_OUTPUT_BYTES {
            return Err(Violation::TooLong(name.to_owned()));
        }
        if !is_text(value) {
            return Err(Violation::NotText(name.to_owned()));
        }
        if out.iter().any(|(existing, _)| existing == name) {
            return Err(Violation::Duplicate(name.to_owned()));
        }
        out.push((name.to_owned(), value.to_owned()));
    }
    Ok(out)
}

/// Text as the run's record holds it: UTF-8 without a control byte that would break the line or the file it is
/// stored in.
fn is_text(value: &str) -> bool {
    value
        .chars()
        .all(|c| !c.is_control() && c != '\u{7f}' && c != '\0')
}

/// The environment variable an output takes. A job's own outputs are `SENTINEL_OUTPUT_<NAME>`; a job it needs
/// publishes `SENTINEL_OUTPUT_<JOB>_<NAME>`, so the two never collide.
pub fn env_name(from: Option<&str>, name: &str) -> String {
    let mut out = String::with_capacity(ENV_PREFIX.len() + 72);
    out.push_str(ENV_PREFIX);
    for (at, part) in from.into_iter().chain(std::iter::once(name)).enumerate() {
        if at > 0 {
            out.push('_');
        }
        for c in part.chars() {
            out.push(if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            });
        }
    }
    out
}

/// The script a step sources to see the outputs its earlier steps wrote, for both shells. Values are quoted with
/// single quotes, so a value holding a quote, `$`, a backtick or a newline cannot run anything.
pub fn script(values: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 64);
    for (env, value) in values {
        out.extend_from_slice(b"export ");
        out.extend_from_slice(env.as_bytes());
        out.extend_from_slice(b"='");
        for c in value.chars() {
            if c == '\'' {
                out.extend_from_slice(b"'\\''");
            } else {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        out.extend_from_slice(b"'\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_declared_output_is_read_and_an_undeclared_one_is_not() {
        let values = parse(
            b"version=1.4.0\nchannel=stable\n",
            &declared(&["version", "channel", "sha"]),
        )
        .unwrap();
        assert_eq!(
            values,
            vec![
                ("version".to_owned(), "1.4.0".to_owned()),
                ("channel".to_owned(), "stable".to_owned())
            ],
            "a declared output the step never wrote is absent, not empty"
        );
        assert_eq!(
            parse(b"version=1\nother=2\n", &declared(&["version"])),
            Err(Violation::Undeclared("other".to_owned()))
        );
        assert_eq!(
            parse(b"not a line\n", &declared(&["version"])),
            Err(Violation::Malformed)
        );
        assert_eq!(
            parse(b"version=1\nversion=2\n", &declared(&["version"])),
            Err(Violation::Duplicate("version".to_owned()))
        );
    }

    #[test]
    fn a_value_past_the_bound_is_refused_without_echoing_it() {
        let long = format!("version={}\n", "a".repeat(MAX_OUTPUT_BYTES + 1));
        let refused = parse(long.as_bytes(), &declared(&["version"])).unwrap_err();
        assert_eq!(refused, Violation::TooLong("version".to_owned()));
        assert!(
            !refused.reason().contains("aaaa"),
            "the verdict names the limit, never the value"
        );
        let at_bound = format!("version={}\n", "a".repeat(MAX_OUTPUT_BYTES));
        assert!(parse(at_bound.as_bytes(), &declared(&["version"])).is_ok());
    }

    #[test]
    fn a_value_that_is_not_text_is_refused() {
        let mut bytes = b"version=".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.push(b'\n');
        assert_eq!(
            parse(&bytes, &declared(&["version"])),
            Err(Violation::Malformed)
        );
        assert_eq!(
            parse(b"version=a\x01b\n", &declared(&["version"])),
            Err(Violation::NotText("version".to_owned()))
        );
    }

    #[test]
    fn the_values_script_quotes_a_value_that_would_otherwise_run() {
        let script = script(&[
            (env_name(None, "version"), "1.4.0".to_owned()),
            (env_name(None, "notes"), "it's $(rm -rf /) `x`".to_owned()),
            (env_name(Some("build"), "sha"), "abc".to_owned()),
        ]);
        let text = String::from_utf8(script).unwrap();
        assert_eq!(
            text,
            concat!(
                "export SENTINEL_OUTPUT_VERSION='1.4.0'\n",
                "export SENTINEL_OUTPUT_NOTES='it'\\''s $(rm -rf /) `x`'\n",
                "export SENTINEL_OUTPUT_BUILD_SHA='abc'\n"
            )
        );
    }

    #[test]
    fn environment_names_separate_a_job_from_the_job_it_needs() {
        assert_eq!(env_name(None, "version"), "SENTINEL_OUTPUT_VERSION");
        assert_eq!(
            env_name(Some("build-api"), "release-tag"),
            "SENTINEL_OUTPUT_BUILD_API_RELEASE_TAG"
        );
    }
}
