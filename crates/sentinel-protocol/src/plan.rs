//! `sentinel.ai-plan/1`: the bounded plan a log-search question becomes (Part 22 Y07).
//!
//! A question never reaches a log directly. It becomes a list of at most [`MAX_PLAN_READS`] reads
//! of what the controller already serves — an indexed literal search across the repository's recent
//! runs, or one attempt's failure context — and the controller executes that list under the
//! requester's own authority. The plan is what bounds the work: a read count, a needle, a run
//! window and a match count are all stated here and checked again where the reads run, so no
//! question can scan a deployment however it is worded.
//!
//! A read the requester cannot perform is refused, never skipped: the caller learns the read's
//! index and stops, which is why the plan is decoded strictly and every field is a value the
//! controller can execute rather than prose it would have to interpret.

use serde::Deserialize;

use sentinel_core::AttemptId;

/// The document's version. A changed shape is a new version, never a reused one.
pub const PLAN_SCHEMA: &str = "sentinel.ai-plan/1";
/// The most reads one question may become. Six covers a failure and its history without letting a
/// question become a crawl of the repository.
pub const MAX_PLAN_READS: usize = 6;
/// The longest literal a read may search for, matching the search route's own needle bound.
pub const MAX_NEEDLE: usize = 256;
/// The oldest run window a read may name, matching the cross-run search's own window.
pub const MAX_RUNS: u16 = 100;
/// The most matching lines one read may ask for. A plan is read by a model, so a read that returned
/// thousands of lines would be a prompt nobody bounded.
pub const MAX_MATCHES: u16 = 25;
/// The largest plan document, which is also what the route that executes one accepts.
pub const MAX_PLAN_BYTES: usize = 4 << 10;
/// The longest question one request may carry. A question is a sentence, not a document: what it
/// becomes is the plan, and the plan is what bounds the reads.
pub const MAX_QUESTION_BYTES: usize = 512;

/// One read of evidence the controller already serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    /// A literal search across the repository's newest `runs` runs, at most `limit` matching lines.
    Search {
        needle: String,
        runs: u16,
        limit: u16,
    },
    /// One attempt's failure context, in the same bounded document the evidence bundle is.
    Context { attempt: AttemptId },
}

/// A question as the reads that answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub reads: Vec<Read>,
}

impl Plan {
    /// The document as the controller receives it: the schema, then each read in order, keys in a
    /// fixed order so two encodings of one plan are equal.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(64 + 96 * self.reads.len());
        out.push_str("{\"schema\":\"");
        out.push_str(PLAN_SCHEMA);
        out.push_str("\",\"reads\":[");
        for (at, read) in self.reads.iter().enumerate() {
            if at > 0 {
                out.push(',');
            }
            match read {
                Read::Search {
                    needle,
                    runs,
                    limit,
                } => {
                    out.push_str("{\"kind\":\"search\",\"q\":");
                    quote(needle, &mut out);
                    out.push_str(",\"runs\":");
                    out.push_str(&runs.to_string());
                    out.push_str(",\"limit\":");
                    out.push_str(&limit.to_string());
                    out.push('}');
                }
                Read::Context { attempt } => {
                    out.push_str("{\"kind\":\"context\",\"attempt\":\"");
                    out.push_str(&attempt.to_string());
                    out.push_str("\"}");
                }
            }
        }
        out.push_str("]}");
        out
    }

    /// A model's document, decoded strictly: this schema, no field this build does not execute, and
    /// every bound kept. What does not decode is refused, never repaired and never partly run.
    pub fn decode(bytes: &[u8]) -> Result<Self, PlanError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(PlanError::TooLarge);
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| PlanError::Decode)?;
        if wire.schema != PLAN_SCHEMA {
            return Err(PlanError::Invalid(PlanError::SCHEMA_FIELD));
        }
        if wire.reads.is_empty() || wire.reads.len() > MAX_PLAN_READS {
            return Err(PlanError::Invalid(PlanError::READS_FIELD));
        }
        let mut reads = Vec::with_capacity(wire.reads.len());
        for read in wire.reads {
            reads.push(match read {
                WireRead::Search { q, runs, limit } => {
                    if q.is_empty() || q.trim().is_empty() || q.len() > MAX_NEEDLE {
                        return Err(PlanError::Invalid(PlanError::NEEDLE_FIELD));
                    }
                    if runs == 0 || runs > MAX_RUNS {
                        return Err(PlanError::Invalid(PlanError::RUNS_FIELD));
                    }
                    if limit == 0 || limit > MAX_MATCHES {
                        return Err(PlanError::Invalid(PlanError::LIMIT_FIELD));
                    }
                    Read::Search {
                        needle: q,
                        runs,
                        limit,
                    }
                }
                WireRead::Context { attempt } => Read::Context {
                    attempt: attempt
                        .parse()
                        .map_err(|_| PlanError::Invalid(PlanError::ATTEMPT_FIELD))?,
                },
            });
        }
        Ok(Self { reads })
    }
}

/// The document as a client sends it. Unknown fields are refused: a plan this build would partly
/// execute is not a plan it can bound.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    reads: Vec<WireRead>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum WireRead {
    Search { q: String, runs: u16, limit: u16 },
    Context { attempt: String },
}

/// Appends `text` as a JSON string, with only the escapes JSON requires.
fn quote(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                out.push_str("\\u00");
                out.push(char::from_digit(u32::from(control) >> 4, 16).unwrap_or('0'));
                out.push(char::from_digit(u32::from(control) & 0xf, 16).unwrap_or('0'));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Why a plan cannot be executed. The field is what a refusal names, never the question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// Past the bound the route accepts for one plan.
    TooLarge,
    /// Not JSON, or a shape with a field this version does not have.
    Decode,
    /// A field that is present and outside what this version allows, named by `field()`.
    Invalid(&'static str),
}

impl PlanError {
    pub const SCHEMA_FIELD: &'static str = "schema";
    pub const READS_FIELD: &'static str = "reads";
    pub const NEEDLE_FIELD: &'static str = "reads[].q";
    pub const RUNS_FIELD: &'static str = "reads[].runs";
    pub const LIMIT_FIELD: &'static str = "reads[].limit";
    pub const ATTEMPT_FIELD: &'static str = "reads[].attempt";

    /// The field a refusal names, or the document itself.
    pub const fn field(self) -> &'static str {
        match self {
            Self::TooLarge | Self::Decode => "plan",
            Self::Invalid(field) => field,
        }
    }

    /// The bounded sentence a refused request carries.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "plan: the plan is over its bound",
            Self::Decode => "plan: the plan is not a sentinel.ai-plan/1 document",
            Self::Invalid(PlanError::SCHEMA_FIELD) => "plan: the plan names another schema",
            Self::Invalid(_) => "plan: the plan names a read this build cannot execute",
        }
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for PlanError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            reads: vec![
                Read::Search {
                    needle: "wanted 201, got 500".into(),
                    runs: 20,
                    limit: 10,
                },
                Read::Context {
                    attempt: AttemptId::new(),
                },
            ],
        }
    }

    #[test]
    fn a_plan_round_trips_through_its_wire_form() {
        let document = plan();
        let bytes = document.encode();
        assert!(
            bytes.starts_with("{\"schema\":\"sentinel.ai-plan/1\",\"reads\":[{\"kind\":\"search\"")
        );
        assert_eq!(Plan::decode(bytes.as_bytes()), Ok(document));
    }

    #[test]
    fn the_wire_form_is_the_document_a_reader_sees() {
        let document = plan();
        let value: serde_json::Value = serde_json::from_str(&document.encode()).unwrap();
        assert_eq!(value["schema"], PLAN_SCHEMA);
        assert_eq!(value["reads"][0]["kind"], "search");
        assert_eq!(value["reads"][0]["q"], "wanted 201, got 500");
        assert_eq!(value["reads"][0]["runs"], 20);
        assert_eq!(value["reads"][1]["kind"], "context");
        assert_eq!(
            value["reads"][1]["attempt"],
            match &document.reads[1] {
                Read::Context { attempt } => attempt.to_string(),
                Read::Search { .. } => unreachable!(),
            }
        );
    }

    #[test]
    fn a_partial_or_unknown_shape_is_refused() {
        let attempt = AttemptId::new();
        let base = format!(
            "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{{\"kind\":\"search\",\"q\":\"panic\",\
             \"runs\":5,\"limit\":5}}]}}"
        );
        assert!(Plan::decode(base.as_bytes()).is_ok());
        // A field this version does not execute, at either level: a plan is not partly run.
        for (from, to) in [
            ("\"schema\"", "\"schema\",\"confidence\":1"),
            ("\"runs\":5", "\"runs\":5,\"grep\":\"-i\""),
        ] {
            let changed = base.replacen(from, to, 1);
            assert_eq!(
                Plan::decode(changed.as_bytes()),
                Err(PlanError::Decode),
                "{changed}"
            );
        }
        // A read of a kind this build does not serve.
        let unknown = format!(
            "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{{\"kind\":\"artifact\",\"attempt\":\"{attempt}\"}}]}}"
        );
        assert_eq!(Plan::decode(unknown.as_bytes()), Err(PlanError::Decode));
        // Another schema, and no reads at all.
        assert_eq!(
            Plan::decode(base.replace(PLAN_SCHEMA, "sentinel.ai-plan/2").as_bytes()),
            Err(PlanError::Invalid(PlanError::SCHEMA_FIELD))
        );
        assert_eq!(
            Plan::decode(format!("{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[]}}").as_bytes()),
            Err(PlanError::Invalid(PlanError::READS_FIELD))
        );
    }

    #[test]
    fn a_plan_past_any_of_its_bounds_is_refused_whole() {
        let attempt = AttemptId::new();
        let read = format!("{{\"kind\":\"context\",\"attempt\":\"{attempt}\"}}");
        let too_many = format!(
            "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{}]}}",
            [read.as_str(); MAX_PLAN_READS + 1].join(",")
        );
        assert_eq!(
            Plan::decode(too_many.as_bytes()),
            Err(PlanError::Invalid(PlanError::READS_FIELD))
        );
        for (q, runs, limit, expected) in [
            ("", 5, 5, PlanError::NEEDLE_FIELD),
            ("  ", 5, 5, PlanError::NEEDLE_FIELD),
            ("panic", 0, 5, PlanError::RUNS_FIELD),
            ("panic", MAX_RUNS + 1, 5, PlanError::RUNS_FIELD),
            ("panic", 5, 0, PlanError::LIMIT_FIELD),
            ("panic", 5, MAX_MATCHES + 1, PlanError::LIMIT_FIELD),
        ] {
            let document = format!(
                "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{{\"kind\":\"search\",\"q\":\"{q}\",\
                 \"runs\":{runs},\"limit\":{limit}}}]}}"
            );
            assert_eq!(
                Plan::decode(document.as_bytes()),
                Err(PlanError::Invalid(expected)),
                "{document}"
            );
        }
        let long = format!(
            "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{{\"kind\":\"search\",\"q\":\"{}\",\
             \"runs\":5,\"limit\":5}}]}}",
            "x".repeat(MAX_NEEDLE + 1)
        );
        assert_eq!(
            Plan::decode(long.as_bytes()),
            Err(PlanError::Invalid(PlanError::NEEDLE_FIELD))
        );
        assert_eq!(
            Plan::decode(&vec![b' '; MAX_PLAN_BYTES + 1]),
            Err(PlanError::TooLarge)
        );
    }

    #[test]
    fn a_read_naming_an_identifier_the_controller_could_not_have_is_refused() {
        for attempt in ["not-an-attempt", "", "att_"] {
            let document = format!(
                "{{\"schema\":\"{PLAN_SCHEMA}\",\"reads\":[{{\"kind\":\"context\",\
                 \"attempt\":\"{attempt}\"}}]}}"
            );
            assert_eq!(
                Plan::decode(document.as_bytes()),
                Err(PlanError::Invalid(PlanError::ATTEMPT_FIELD)),
                "{attempt}"
            );
        }
    }

    #[test]
    fn a_refusal_names_the_field_never_the_question() {
        assert_eq!(PlanError::Decode.field(), "plan");
        assert_eq!(
            PlanError::Invalid(PlanError::NEEDLE_FIELD).field(),
            "reads[].q"
        );
        assert_eq!(
            PlanError::TooLarge.reason(),
            "plan: the plan is over its bound"
        );
    }
}
