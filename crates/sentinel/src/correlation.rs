//! Opaque correlation identifiers. They convey neither ownership nor authorization.
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a typed, canonical lowercase UUID v4 identifier")
    }
}
impl std::error::Error for InvalidId {}

macro_rules! identifier {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }
        impl FromStr for $name {
            type Err = InvalidId;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let raw = value.strip_prefix(concat!($prefix, "_")).ok_or(InvalidId)?;
                let uuid = Uuid::parse_str(raw).map_err(|_| InvalidId)?;
                if uuid.get_version_num() != 4
                    || uuid.get_variant() != uuid::Variant::RFC4122
                    || uuid.to_string() != raw
                {
                    return Err(InvalidId);
                }
                Ok(Self(uuid))
            }
        }
    };
}

identifier!(ProcessId, "prc");
identifier!(RequestId, "req");
identifier!(RunId, "run");
identifier!(JobId, "job");
identifier!(AttemptId, "att");

/// Only attach IDs that actually exist. A new process does not imply a run/job.
#[derive(Clone, Copy, Debug)]
pub struct Correlation {
    pub process_id: ProcessId,
    pub request_id: Option<RequestId>,
    pub run_id: Option<RunId>,
    pub job_id: Option<JobId>,
    pub attempt_id: Option<AttemptId>,
}

impl Correlation {
    pub fn process(process_id: ProcessId) -> Self {
        Self {
            process_id,
            request_id: None,
            run_id: None,
            job_id: None,
            attempt_id: None,
        }
    }

    pub fn span(&self) -> tracing::Span {
        // Context must remain available even when only error events are enabled.
        let span = tracing::error_span!("correlation",
            schema_version = 1_u64,
            process_id = %self.process_id,
            request_id = tracing::field::Empty,
            run_id = tracing::field::Empty,
            job_id = tracing::field::Empty,
            attempt_id = tracing::field::Empty,
        );
        if let Some(id) = self.request_id {
            span.record("request_id", tracing::field::display(id));
        }
        if let Some(id) = self.run_id {
            span.record("run_id", tracing::field::display(id));
        }
        if let Some(id) = self.job_id {
            span.record("job_id", tracing::field::display(id));
        }
        if let Some(id) = self.attempt_id {
            span.record("attempt_id", tracing::field::display(id));
        }
        span
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_roundtrip_and_reject_wrong_types_and_noncanonical_input() {
        let id = RunId::new();
        assert_eq!(id.to_string().parse::<RunId>().unwrap(), id);
        assert_ne!(RunId::new(), id);
        assert!(id.to_string().parse::<JobId>().is_err());
        assert!(id.to_string().to_uppercase().parse::<RunId>().is_err());
        assert!(
            "run_00000000-0000-0000-0000-000000000000"
                .parse::<RunId>()
                .is_err()
        );
        assert!(
            format!("run_{}", Uuid::new_v4().simple())
                .parse::<RunId>()
                .is_err()
        );
        assert!("not-an-id".parse::<RequestId>().is_err());
    }
}
