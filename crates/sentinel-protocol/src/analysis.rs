//! `sentinel.ai-analysis/1`: the one document a model's answer may be (Part 22 Y05).
//!
//! The deterministic diagnostics are the account of what failed. An analysis is advisory text on
//! top of them, so the shape is fixed and narrow: a summary, a bounded list of claims, and for
//! every claim the evidence it rests on — an attempt and the bundle's own identifier for a log
//! frame (`log-<sequence>`) or a diagnostic (`diag-<n>`). Anything else is refused rather than
//! stored, so no reader ever has to guess what a field means or whether a claim was checked.
//!
//! The controller decodes this document before it stores an answer, and again before it serves
//! one; `sentinel-ai` decodes it too, so a provider's malformed answer never reaches the
//! controller at all. Citations are resolved against the evidence the controller stored, and one
//! that does not resolve is dropped before an analysis is shown.

use sentinel_core::AttemptId;
use serde::Deserialize;

/// The document's version. A changed shape is a new version, never a reused one.
pub const ANALYSIS_SCHEMA: &str = "sentinel.ai-analysis/1";
/// The largest analysis the store holds for one request, which is also `ai_requests.result`'s own
/// bound. A model that answers longer than this is refused, never truncated: a citation cut off
/// the end would be a claim nobody can check.
pub const MAX_ANALYSIS_BYTES: usize = 8 << 10;
/// At most eight claims: an analysis is a short account of one failure, not a report.
pub const MAX_CLAIMS: usize = 8;
pub const MAX_CLAIM_BYTES: usize = 1_024;
pub const MAX_SUMMARY_BYTES: usize = 2_048;
/// At most eight citations per claim, and at most twenty diagnostics to cite: the bundle's own cap.
pub const MAX_CITATIONS: usize = 8;
pub const MAX_DIAGNOSTICS: u16 = 20;
/// The longest evidence identifier the bundle assigns (`log-` and twenty decimal digits, or
/// `diag-` and two). Anything longer never came from a bundle this controller served.
const MAX_EVIDENCE_TEXT: usize = 24;

/// What a claim rests on: a log frame or a diagnostic of one attempt's stored evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// `log-<sequence>`: one frame of the attempt's redacted log.
    Log { sequence: u64 },
    /// `diag-<n>`: the nth diagnostic the bundle derived from those frames, failures first.
    Diagnostic { id: u16 },
}

impl Evidence {
    /// The identifier as the bundle states it and as the model cites it.
    pub fn id(self) -> String {
        match self {
            Self::Log { sequence } => format!("log-{sequence}"),
            Self::Diagnostic { id } => format!("diag-{id}"),
        }
    }

    /// Reads an identifier the bundle could have assigned, or nothing.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_EVIDENCE_TEXT {
            return None;
        }
        if let Some(rest) = text.strip_prefix("log-") {
            return decimal(rest).map(|sequence| Self::Log { sequence });
        }
        let id = decimal(text.strip_prefix("diag-")?)?;
        u16::try_from(id)
            .ok()
            .filter(|id| (1..=MAX_DIAGNOSTICS).contains(id))
            .map(|id| Self::Diagnostic { id })
    }
}

/// A decimal `u64` with no sign, no leading zero and no padding.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Citation {
    /// The attempt whose stored evidence the identifier names.
    pub attempt: AttemptId,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub text: String,
    /// Never empty: a claim nobody can check is refused, not shown.
    pub citations: Vec<Citation>,
}

/// One advisory account of one failure, every claim citing evidence it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    pub summary: String,
    pub claims: Vec<Claim>,
}

impl Analysis {
    /// The document as it is stored and served: the schema, then the summary and the claims in
    /// order. Keys are written in a fixed order, so two encodings of one analysis are equal.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(self.summary.len() + 64 * self.claims.len() + 64);
        out.push_str("{\"schema\":\"");
        out.push_str(ANALYSIS_SCHEMA);
        out.push_str("\",\"summary\":");
        quote(&self.summary, &mut out);
        out.push_str(",\"claims\":[");
        for (at, claim) in self.claims.iter().enumerate() {
            if at > 0 {
                out.push(',');
            }
            out.push_str("{\"text\":");
            quote(&claim.text, &mut out);
            out.push_str(",\"citations\":[");
            for (at, citation) in claim.citations.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                out.push_str("{\"attempt\":\"");
                out.push_str(&citation.attempt.to_string());
                out.push_str("\",\"evidence\":\"");
                out.push_str(&citation.evidence.id());
                out.push_str("\"}");
            }
            out.push_str("]}");
        }
        out.push_str("]}");
        out
    }

    /// A client's document, decoded strictly: the schema this build states, no field it does not
    /// know, and every bound the encoder keeps. What does not decode is refused, never repaired.
    pub fn decode(bytes: &[u8]) -> Result<Self, AnalysisError> {
        if bytes.len() > MAX_ANALYSIS_BYTES {
            return Err(AnalysisError::TooLarge);
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| AnalysisError::Decode)?;
        if wire.schema != ANALYSIS_SCHEMA {
            return Err(AnalysisError::Invalid(AnalysisError::SCHEMA_FIELD));
        }
        let summary = text(
            &wire.summary,
            MAX_SUMMARY_BYTES,
            AnalysisError::SUMMARY_FIELD,
        )?;
        if wire.claims.is_empty() || wire.claims.len() > MAX_CLAIMS {
            return Err(AnalysisError::Invalid(AnalysisError::CLAIMS_FIELD));
        }
        let mut claims = Vec::with_capacity(wire.claims.len());
        for claim in wire.claims {
            let text = checked(
                &claim.text,
                MAX_CLAIM_BYTES,
                AnalysisError::CLAIM_TEXT_FIELD,
            )?;
            if claim.citations.is_empty() || claim.citations.len() > MAX_CITATIONS {
                return Err(AnalysisError::Invalid(AnalysisError::CITATIONS_FIELD));
            }
            let mut citations = Vec::with_capacity(claim.citations.len());
            for citation in claim.citations {
                let attempt = citation
                    .attempt
                    .parse()
                    .map_err(|_| AnalysisError::Invalid(AnalysisError::ATTEMPT_FIELD))?;
                let evidence = Evidence::parse(&citation.evidence)
                    .ok_or(AnalysisError::Invalid(AnalysisError::EVIDENCE_FIELD))?;
                citations.push(Citation { attempt, evidence });
            }
            claims.push(Claim { text, citations });
        }
        let analysis = Self { summary, claims };
        // The encoding is the stored form, so its bound is the one that matters.
        if analysis.encode().len() > MAX_ANALYSIS_BYTES {
            return Err(AnalysisError::TooLarge);
        }
        Ok(analysis)
    }
}

/// The document as a client sends it. Unknown fields are refused: a partially understood answer is
/// not an answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    summary: String,
    claims: Vec<WireClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClaim {
    text: String,
    citations: Vec<WireCitation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCitation {
    attempt: String,
    evidence: String,
}

/// One text field within `limit` bytes and not blank.
fn text(text: &str, limit: usize, field: &'static str) -> Result<String, AnalysisError> {
    checked(text, limit, field)
}

fn checked(text: &str, limit: usize, field: &'static str) -> Result<String, AnalysisError> {
    if text.len() > limit || text.trim().is_empty() {
        return Err(AnalysisError::Invalid(field));
    }
    Ok(text.to_owned())
}

/// Appends `text` as a JSON string. Only the escapes JSON requires, so the stored bytes are the
/// same document any JSON reader would produce for these characters.
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

/// Why an answer is not an analysis. The field is what a refusal names, never the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalysisError {
    /// Past the bound the store holds for one answer.
    TooLarge,
    /// Not JSON, or a shape with a field this version does not have.
    Decode,
    /// A field that is present and outside what this version allows, named by `field()`.
    Invalid(&'static str),
}

impl AnalysisError {
    pub const SCHEMA_FIELD: &'static str = "schema";
    pub const SUMMARY_FIELD: &'static str = "summary";
    pub const CLAIMS_FIELD: &'static str = "claims";
    pub const CLAIM_TEXT_FIELD: &'static str = "claims[].text";
    pub const CITATIONS_FIELD: &'static str = "claims[].citations";
    pub const ATTEMPT_FIELD: &'static str = "claims[].citations[].attempt";
    pub const EVIDENCE_FIELD: &'static str = "claims[].citations[].evidence";

    /// The field a refusal names, or the document itself.
    pub const fn field(self) -> &'static str {
        match self {
            Self::TooLarge => "analysis",
            Self::Decode => "analysis",
            Self::Invalid(field) => field,
        }
    }

    /// The bounded sentence a settled request carries when its answer could not be stored.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "schema: the answer is over the analysis bound",
            Self::Decode => "schema: the answer is not a sentinel.ai-analysis/1 document",
            Self::Invalid(AnalysisError::SCHEMA_FIELD) => "schema: the answer names another schema",
            Self::Invalid(_) => "schema: the answer does not decode against sentinel.ai-analysis/1",
        }
    }
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for AnalysisError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> AttemptId {
        AttemptId::new()
    }

    fn analysis() -> Analysis {
        Analysis {
            summary: "The unit step failed on an assertion in src/lib.rs.".into(),
            claims: vec![
                Claim {
                    text: "The assertion compares two values that differ.".into(),
                    citations: vec![
                        Citation {
                            attempt: attempt(),
                            evidence: Evidence::Log { sequence: 42 },
                        },
                        Citation {
                            attempt: attempt(),
                            evidence: Evidence::Diagnostic { id: 1 },
                        },
                    ],
                },
                Claim {
                    text: "Earlier lines show the request returning 500.".into(),
                    citations: vec![Citation {
                        attempt: attempt(),
                        evidence: Evidence::Log { sequence: 7 },
                    }],
                },
            ],
        }
    }

    #[test]
    fn an_analysis_round_trips_through_its_stored_form() {
        let document = analysis();
        let bytes = document.encode();
        assert!(bytes.starts_with("{\"schema\":\"sentinel.ai-analysis/1\",\"summary\":"));
        assert_eq!(Analysis::decode(bytes.as_bytes()), Ok(document));
    }

    #[test]
    fn the_stored_form_is_the_document_a_reader_sees() {
        let document = analysis();
        let value: serde_json::Value = serde_json::from_str(&document.encode()).unwrap();
        assert_eq!(value["schema"], ANALYSIS_SCHEMA);
        assert_eq!(value["claims"][0]["citations"][0]["evidence"], "log-42");
        assert_eq!(value["claims"][0]["citations"][1]["evidence"], "diag-1");
        assert_eq!(
            value["claims"][1]["citations"][0]["attempt"],
            document.claims[1].citations[0].attempt.to_string()
        );
    }

    #[test]
    fn quoting_keeps_every_character_a_model_can_write() {
        let document = Analysis {
            summary: "a \"quoted\" line\ttab\nnewline \\ backslach \u{1} control é".into(),
            claims: analysis().claims,
        };
        assert_eq!(Analysis::decode(document.encode().as_bytes()), Ok(document));
    }

    #[test]
    fn a_partial_or_unknown_shape_is_refused() {
        let attempt = attempt();
        let base = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{{\"text\":\"t\",\
             \"citations\":[{{\"attempt\":\"{attempt}\",\"evidence\":\"log-1\"}}]}}]}}"
        );
        assert!(Analysis::decode(base.as_bytes()).is_ok());
        // A field this version does not have, at either level.
        for (from, to) in [
            ("\"summary\":\"s\"", "\"summary\":\"s\",\"confidence\":0.9"),
            ("\"text\":\"t\"", "\"text\":\"t\",\"confidence\":0.9"),
            (
                "\"evidence\":\"log-1\"",
                "\"evidence\":\"log-1\",\"quote\":\"x\"",
            ),
        ] {
            let changed = base.replacen(from, to, 1);
            assert_eq!(
                Analysis::decode(changed.as_bytes()),
                Err(AnalysisError::Decode),
                "{changed}"
            );
        }
        // A field missing.
        let missing = base.replacen("\"claims\":[", "\"claims\":[],\"extra\":[", 1);
        assert_eq!(
            Analysis::decode(missing.as_bytes()),
            Err(AnalysisError::Decode)
        );
        // Another schema, and no claims.
        assert_eq!(
            Analysis::decode(
                base.replace(ANALYSIS_SCHEMA, "sentinel.ai-analysis/2")
                    .as_bytes()
            ),
            Err(AnalysisError::Invalid(AnalysisError::SCHEMA_FIELD))
        );
        let empty = format!("{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[]}}");
        assert_eq!(
            Analysis::decode(empty.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::CLAIMS_FIELD))
        );
    }

    #[test]
    fn a_claim_without_citations_is_refused_and_so_is_a_blank_claim() {
        let attempt = attempt();
        let uncited = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{{\"text\":\"t\",\
             \"citations\":[]}}]}}"
        );
        assert_eq!(
            Analysis::decode(uncited.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::CITATIONS_FIELD))
        );
        let blank = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{{\"text\":\"  \",\
             \"citations\":[{{\"attempt\":\"{attempt}\",\"evidence\":\"log-1\"}}]}}]}}"
        );
        assert_eq!(
            Analysis::decode(blank.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::CLAIM_TEXT_FIELD))
        );
        let no_summary = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"\",\"claims\":[{{\"text\":\"t\",\
             \"citations\":[{{\"attempt\":\"{attempt}\",\"evidence\":\"log-1\"}}]}}]}}"
        );
        assert_eq!(
            Analysis::decode(no_summary.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::SUMMARY_FIELD))
        );
    }

    #[test]
    fn an_evidence_identifier_the_bundle_could_not_assign_is_refused() {
        for text in [
            "log-", "log-01", "log--1", "log-1x", "diag-0", "diag-21", "diag-a", "", "log-1 ",
            "line-1",
        ] {
            assert_eq!(Evidence::parse(text), None, "{text}");
        }
        assert_eq!(
            Evidence::parse("log-0"),
            Some(Evidence::Log { sequence: 0 })
        );
        assert_eq!(
            Evidence::parse("log-18446744073709551615"),
            Some(Evidence::Log { sequence: u64::MAX })
        );
        assert_eq!(
            Evidence::parse("diag-20"),
            Some(Evidence::Diagnostic { id: 20 })
        );
        let attempt = attempt();
        let bad = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{{\"text\":\"t\",\
             \"citations\":[{{\"attempt\":\"{attempt}\",\"evidence\":\"log-01\"}}]}}]}}"
        );
        assert_eq!(
            Analysis::decode(bad.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::EVIDENCE_FIELD))
        );
        let wrong_attempt = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{{\"text\":\"t\",\
             \"citations\":[{{\"attempt\":\"not-an-attempt\",\"evidence\":\"log-1\"}}]}}]}}"
        );
        assert_eq!(
            Analysis::decode(wrong_attempt.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::ATTEMPT_FIELD))
        );
    }

    #[test]
    fn an_answer_past_its_bound_is_refused_whole() {
        let attempt = attempt();
        let claims: Vec<String> = (0..MAX_CLAIMS + 1)
            .map(|at| {
                format!(
                    "{{\"text\":\"claim {at}\",\"citations\":[{{\"attempt\":\"{attempt}\",\
                     \"evidence\":\"log-{at}\"}}]}}"
                )
            })
            .collect();
        let too_many = format!(
            "{{\"schema\":\"{ANALYSIS_SCHEMA}\",\"summary\":\"s\",\"claims\":[{}]}}",
            claims.join(",")
        );
        assert_eq!(
            Analysis::decode(too_many.as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::CLAIMS_FIELD))
        );
        let long = Analysis {
            summary: "x".repeat(MAX_SUMMARY_BYTES + 1),
            claims: analysis().claims,
        };
        assert_eq!(
            Analysis::decode(long.encode().as_bytes()),
            Err(AnalysisError::Invalid(AnalysisError::SUMMARY_FIELD))
        );
        let padded = vec![b' '; MAX_ANALYSIS_BYTES + 1];
        assert_eq!(Analysis::decode(&padded), Err(AnalysisError::TooLarge));
    }

    #[test]
    fn a_refusal_names_the_field_never_the_text() {
        assert_eq!(AnalysisError::Decode.field(), "analysis");
        assert_eq!(
            AnalysisError::Invalid(AnalysisError::EVIDENCE_FIELD).field(),
            "claims[].citations[].evidence"
        );
        assert_eq!(
            AnalysisError::TooLarge.reason(),
            "schema: the answer is over the analysis bound"
        );
    }
}
