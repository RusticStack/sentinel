//! Durations are local monotonic measurements, never differences of wall clocks.
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum Phase {
    Configuration,
    Startup,
    Shutdown,
    Intake,
    SourceResolution,
    DependencyWait,
    CapacityWait,
    Dispatch,
    Checkout,
    ImagePull,
    CacheRestore,
    ContainerSetup,
    Step,
    CacheCommit,
    ArtifactUpload,
    LogFlush,
    ChecksPropagation,
    RequiredChecks,
    FirstFailure,
    Acceptance,
}

impl Phase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Startup => "startup",
            Self::Shutdown => "shutdown",
            Self::Intake => "intake",
            Self::SourceResolution => "source_resolution",
            Self::DependencyWait => "dependency_wait",
            Self::CapacityWait => "capacity_wait",
            Self::Dispatch => "dispatch",
            Self::Checkout => "checkout",
            Self::ImagePull => "image_pull",
            Self::CacheRestore => "cache_restore",
            Self::ContainerSetup => "container_setup",
            Self::Step => "step",
            Self::CacheCommit => "cache_commit",
            Self::ArtifactUpload => "artifact_upload",
            Self::LogFlush => "log_flush",
            Self::ChecksPropagation => "checks_propagation",
            Self::RequiredChecks => "required_checks",
            Self::FirstFailure => "first_failure",
            Self::Acceptance => "acceptance",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Completed,
    Failed,
    Cancelled,
}
impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

pub fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

/// Explicit completion avoids treating an unwound/dropped operation as success.
pub struct PhaseTimer {
    phase: Phase,
    start: Instant,
    span: tracing::Span,
}
impl PhaseTimer {
    pub fn start(phase: Phase) -> Self {
        Self {
            phase,
            start: Instant::now(),
            span: tracing::Span::current(),
        }
    }
    pub fn finish(self, outcome: Outcome) -> u64 {
        let duration_ns = elapsed_ns(self.start);
        self.span.in_scope(|| {
            tracing::info!(
                event = "phase_completed",
                phase = self.phase.as_str(),
                outcome = outcome.as_str(),
                duration_ns
            );
        });
        duration_ns
    }
}
