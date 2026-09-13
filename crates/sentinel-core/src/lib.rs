//! Core contracts shared by server, worker and CLI: typed identifiers, the
//! job/run state machine with fenced transitions, failure classes,
//! cancellation desired state and timestamp provenance. Pure, dependency-light
//! and allocation-free so every process can embed it without cost.

pub mod id;
pub mod state;
pub mod time;

pub use id::{AttemptId, Fence, InvalidId, JobId, RepoId, RunId, StepIndex, TenantId, WorkerId};
pub use state::{
    Actor, DependencyPolicy, Event, FailureClass, JobControl, JobState, Outcome, RunState,
    TransitionError, aggregate, dependency_decision,
};
pub use time::{AttemptTimestamps, UnixMillis};
