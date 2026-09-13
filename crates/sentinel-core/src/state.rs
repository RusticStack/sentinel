//! Job and run state machine.
//!
//! Every transition is a pure, allocation-free function of (current state,
//! event, actor). The controller applies it inside one SQLite transaction with
//! compare-and-set on the persisted state and fence, so a stale worker or a
//! duplicate message can never move a job backwards or overwrite a newer
//! attempt. All enums are `#[repr(u8)]` so they persist as one byte and match
//! by jump table.
use crate::id::Fence;

/// Final result of a job attempt or an aggregated run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Outcome {
    Passed = 0,
    /// Dependencies did not require it (condition false or an upstream failed
    /// with `skip` policy). Not a failure and never blocks a run from passing.
    Skipped = 1,
    /// Cancellation desired state was honoured.
    Canceled = 2,
    /// Queue or execution timeout fired.
    TimedOut = 3,
    /// A user command exited non-zero or was killed inside its own budget.
    Failed = 4,
    /// Sentinel or the host failed: preparation, worker loss, lease expiry,
    /// storage. Never attributed to the repository.
    InfraFailed = 5,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Skipped => "skipped",
            Self::Canceled => "canceled",
            Self::TimedOut => "timed_out",
            Self::Failed => "failed",
            Self::InfraFailed => "infra_failed",
        }
    }
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Passed | Self::Skipped)
    }
}

/// Why a non-passing outcome happened. Stored with the attempt so diagnostics
/// never have to re-derive it from logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FailureClass {
    /// A step's command returned non-zero.
    CommandFailed = 0,
    /// A step's process died from a signal (not Sentinel's own termination).
    CommandSignaled = 1,
    /// The job's cgroup memory limit killed a process.
    OutOfMemory = 2,
    /// Execution timeout; `TimedOut` outcome.
    ExecutionTimeout = 3,
    /// Waited in the queue longer than allowed; `TimedOut` outcome.
    QueueTimeout = 4,
    /// Cancel requested by an operator, supersession or tenant policy.
    Canceled = 5,
    /// Source checkout, image pull or cache restore failed.
    Preparation = 6,
    /// Heartbeats stopped and the lease could not be renewed.
    LeaseExpired = 7,
    /// Worker session closed or the worker was revoked/drained.
    WorkerLost = 8,
    /// Controller restart found the attempt in an unknown state.
    Reconciled = 9,
    /// Log spool, artifact or cache publication failed durably.
    Publication = 10,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandFailed => "command_failed",
            Self::CommandSignaled => "command_signaled",
            Self::OutOfMemory => "out_of_memory",
            Self::ExecutionTimeout => "execution_timeout",
            Self::QueueTimeout => "queue_timeout",
            Self::Canceled => "canceled",
            Self::Preparation => "preparation",
            Self::LeaseExpired => "lease_expired",
            Self::WorkerLost => "worker_lost",
            Self::Reconciled => "reconciled",
            Self::Publication => "publication",
        }
    }

    /// The only outcome each class may accompany. Persisting any other pair is a bug.
    pub const fn outcome(self) -> Outcome {
        match self {
            Self::CommandFailed | Self::CommandSignaled | Self::OutOfMemory => Outcome::Failed,
            Self::ExecutionTimeout | Self::QueueTimeout => Outcome::TimedOut,
            Self::Canceled => Outcome::Canceled,
            Self::Preparation
            | Self::LeaseExpired
            | Self::WorkerLost
            | Self::Reconciled
            | Self::Publication => Outcome::InfraFailed,
        }
    }
}

/// Lifecycle position of a job. Terminal carries the outcome so one byte plus
/// a discriminant describes the whole state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JobState {
    /// Waiting for dependencies or a condition.
    Blocked = 0,
    /// Eligible for dispatch; in the ready queue.
    Queued = 1,
    /// Offered to a worker and acknowledged; fence assigned.
    Leased = 2,
    /// Worker is checking out, pulling images, restoring caches.
    Preparing = 3,
    /// Steps are executing.
    Running = 4,
    /// Steps are done; finalizers, cache commit, log flush in progress.
    Finalizing = 5,
    Terminal(Outcome) = 6,
}

impl JobState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
    /// A worker owns the job between lease acknowledgement and terminal.
    pub const fn is_worker_owned(self) -> bool {
        matches!(
            self,
            Self::Leased | Self::Preparing | Self::Running | Self::Finalizing
        )
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Finalizing => "finalizing",
            Self::Terminal(o) => o.as_str(),
        }
    }
}

/// Who requests a transition. Permission is part of the table: a worker can
/// only advance the attempt it holds, the controller owns queueing and
/// leases, the reconciler may only fail or requeue uncertain attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Actor {
    /// Scheduler, dispatcher, timeout and cancel enforcement inside the controller.
    Controller = 0,
    /// The worker holding the attempt identified by this fence.
    Worker(Fence) = 1,
    /// Startup reconciliation after a controller or worker restart.
    Reconciler = 2,
}

/// Events that may move a job. Each names the actor allowed to raise it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Controller: all dependencies reached a satisfying outcome.
    DependenciesSatisfied,
    /// Controller: dependency outcome or condition rules the job out.
    Skip,
    /// Controller: a worker acknowledged the offer; the new fence is recorded.
    Leased(Fence),
    /// Worker: preparation began.
    PreparationStarted,
    /// Worker: first step process started.
    StepsStarted,
    /// Worker: steps finished, finalizers running.
    FinalizationStarted,
    /// Worker: everything durable, attempt succeeded.
    Passed,
    /// Worker: attempt ended without success.
    Failed(FailureClass),
    /// Controller: cancel desired state applies while no worker owns the job.
    CancelBeforeStart,
    /// Controller: queue timeout while waiting.
    QueueTimedOut,
    /// Controller or reconciler: lease renewal missed.
    LeaseExpired,
    /// Controller or reconciler: worker session gone.
    WorkerLost,
    /// Reconciler: attempt found in an unknown state after restart.
    Reconciled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The event is not defined for the current state.
    Invalid { from: JobState, event: Event },
    /// The actor may not raise this event.
    Forbidden { actor: Actor, event: Event },
    /// A worker event carried a fence other than the current one.
    StaleFence { current: Fence, presented: Fence },
    /// Terminal states absorb everything; reported separately so callers can
    /// treat duplicates as idempotent acknowledgements.
    AlreadyTerminal(Outcome),
}

/// Persisted per-job control fields the machine needs besides the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobControl {
    pub state: JobState,
    /// Fence of the current attempt; `NONE` until first lease.
    pub fence: Fence,
    /// Durable desired state: once set it is never cleared. The controller
    /// stops new starts immediately; a running attempt is asked to stop and
    /// its worker reports `Failed(Canceled)` when done (or is killed after
    /// the grace period and reported by lease expiry).
    pub cancel_requested: bool,
}

impl JobControl {
    pub const fn new() -> Self {
        Self {
            state: JobState::Blocked,
            fence: Fence::NONE,
            cancel_requested: false,
        }
    }

    /// Record the cancel desired state. Returns true if the job can be moved
    /// to terminal immediately (no worker owns it); the caller then applies
    /// `Event::CancelBeforeStart`. Otherwise the running attempt must be
    /// signalled and the job stays in its state until the worker reports.
    pub const fn request_cancel(&mut self) -> bool {
        self.cancel_requested = true;
        matches!(self.state, JobState::Blocked | JobState::Queued)
    }

    /// Apply one event. On success the state (and fence for `Leased`) are
    /// updated in place and the new state is returned; on error nothing changes.
    pub const fn apply(&mut self, actor: Actor, event: Event) -> Result<JobState, TransitionError> {
        if let JobState::Terminal(o) = self.state {
            return Err(TransitionError::AlreadyTerminal(o));
        }
        // Permission check first: a forbidden actor never learns validity details.
        match (actor, event) {
            (Actor::Controller, Event::DependenciesSatisfied | Event::Skip | Event::Leased(_))
            | (
                Actor::Controller,
                Event::CancelBeforeStart
                | Event::QueueTimedOut
                | Event::LeaseExpired
                | Event::WorkerLost,
            )
            | (
                Actor::Worker(_),
                Event::PreparationStarted
                | Event::StepsStarted
                | Event::FinalizationStarted
                | Event::Passed
                | Event::Failed(_),
            )
            | (Actor::Reconciler, Event::LeaseExpired | Event::WorkerLost | Event::Reconciled) => {}
            _ => return Err(TransitionError::Forbidden { actor, event }),
        }
        if let Actor::Worker(presented) = actor
            && presented.0 != self.fence.0
        {
            return Err(TransitionError::StaleFence {
                current: self.fence,
                presented,
            });
        }
        let next = match (self.state, event) {
            (JobState::Blocked, Event::DependenciesSatisfied) => JobState::Queued,
            (JobState::Blocked | JobState::Queued, Event::Skip) => {
                JobState::Terminal(Outcome::Skipped)
            }
            (JobState::Blocked | JobState::Queued, Event::CancelBeforeStart) => {
                JobState::Terminal(Outcome::Canceled)
            }
            (JobState::Blocked | JobState::Queued, Event::QueueTimedOut) => {
                JobState::Terminal(Outcome::TimedOut)
            }
            (JobState::Queued, Event::Leased(fence)) => {
                if fence.0 <= self.fence.0 {
                    // A lease must strictly advance the fence or stale acks could reattach.
                    return Err(TransitionError::StaleFence {
                        current: self.fence,
                        presented: fence,
                    });
                }
                self.fence = fence;
                JobState::Leased
            }
            (JobState::Leased, Event::PreparationStarted) => JobState::Preparing,
            (JobState::Leased | JobState::Preparing, Event::StepsStarted) => JobState::Running,
            (JobState::Preparing | JobState::Running, Event::FinalizationStarted) => {
                JobState::Finalizing
            }
            (JobState::Finalizing, Event::Passed) => JobState::Terminal(Outcome::Passed),
            (
                JobState::Leased | JobState::Preparing | JobState::Running | JobState::Finalizing,
                Event::Failed(class),
            ) => JobState::Terminal(class.outcome()),
            (
                JobState::Leased | JobState::Preparing | JobState::Running | JobState::Finalizing,
                Event::LeaseExpired,
            ) => JobState::Terminal(FailureClass::LeaseExpired.outcome()),
            (
                JobState::Leased | JobState::Preparing | JobState::Running | JobState::Finalizing,
                Event::WorkerLost,
            ) => JobState::Terminal(FailureClass::WorkerLost.outcome()),
            (
                JobState::Leased | JobState::Preparing | JobState::Running | JobState::Finalizing,
                Event::Reconciled,
            ) => JobState::Terminal(FailureClass::Reconciled.outcome()),
            (from, event) => return Err(TransitionError::Invalid { from, event }),
        };
        self.state = next;
        Ok(next)
    }
}

impl Default for JobControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated run state derived from its jobs. Never stored as truth; recomputed
/// from job rows inside the same transaction that changed a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RunState {
    /// No job has left `Blocked`/`Queued` yet.
    Pending = 0,
    /// At least one job is worker-owned or some are still pending after others finished.
    Active = 1,
    Terminal(Outcome) = 2,
}

/// Fold job states into the run state. Precedence among terminal outcomes is
/// `InfraFailed > Failed > TimedOut > Canceled > Passed`; `Skipped` counts as
/// success unless every job was skipped. Runs with zero jobs are rejected by
/// the compiler, so an empty iterator is reported as `Pending`.
pub fn aggregate<I: IntoIterator<Item = JobState>>(jobs: I) -> RunState {
    let mut worst: Option<Outcome> = None;
    let mut started = false;
    let mut unfinished = false;
    let mut any = false;
    let mut all_skipped = true;
    for state in jobs {
        any = true;
        match state {
            JobState::Terminal(o) => {
                if o != Outcome::Skipped {
                    all_skipped = false;
                    // `Outcome` derives `Ord` in precedence order.
                    worst = Some(match worst {
                        Some(w) if w >= o => w,
                        _ => o,
                    });
                }
            }
            JobState::Blocked | JobState::Queued => unfinished = true,
            _ => {
                started = true;
                unfinished = true;
            }
        }
    }
    if !any {
        return RunState::Pending;
    }
    if unfinished {
        return if started || worst.is_some() {
            RunState::Active
        } else {
            RunState::Pending
        };
    }
    RunState::Terminal(if all_skipped {
        Outcome::Skipped
    } else {
        worst.unwrap_or(Outcome::Passed)
    })
}

/// Whether a dependent may start given its dependency's outcome and the
/// declared policy. `Skipped` upstream satisfies `on_success` so optional
/// branches do not drag the DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DependencyPolicy {
    /// Default: upstream passed or was skipped.
    OnSuccess = 0,
    /// Upstream reached any terminal outcome except canceled.
    Always = 1,
    /// Upstream failed, timed out or infra-failed.
    OnFailure = 2,
}

/// `Some(true)` start, `Some(false)` skip, `None` keep waiting.
pub const fn dependency_decision(policy: DependencyPolicy, upstream: JobState) -> Option<bool> {
    let JobState::Terminal(o) = upstream else {
        return None;
    };
    Some(match policy {
        DependencyPolicy::OnSuccess => o.is_success(),
        DependencyPolicy::Always => !matches!(o, Outcome::Canceled),
        DependencyPolicy::OnFailure => matches!(
            o,
            Outcome::Failed | Outcome::TimedOut | Outcome::InfraFailed
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATES: [JobState; 12] = [
        JobState::Blocked,
        JobState::Queued,
        JobState::Leased,
        JobState::Preparing,
        JobState::Running,
        JobState::Finalizing,
        JobState::Terminal(Outcome::Passed),
        JobState::Terminal(Outcome::Skipped),
        JobState::Terminal(Outcome::Canceled),
        JobState::Terminal(Outcome::TimedOut),
        JobState::Terminal(Outcome::Failed),
        JobState::Terminal(Outcome::InfraFailed),
    ];
    const ALL_EVENTS: [Event; 13] = [
        Event::DependenciesSatisfied,
        Event::Skip,
        Event::Leased(Fence(1)),
        Event::PreparationStarted,
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
        Event::Failed(FailureClass::CommandFailed),
        Event::CancelBeforeStart,
        Event::QueueTimedOut,
        Event::LeaseExpired,
        Event::WorkerLost,
        Event::Reconciled,
    ];

    fn at(state: JobState, fence: Fence) -> JobControl {
        JobControl {
            state,
            fence,
            cancel_requested: false,
        }
    }

    #[test]
    fn happy_path_advances_with_fence() {
        let mut j = JobControl::new();
        assert_eq!(
            j.apply(Actor::Controller, Event::DependenciesSatisfied),
            Ok(JobState::Queued)
        );
        assert_eq!(
            j.apply(Actor::Controller, Event::Leased(Fence(1))),
            Ok(JobState::Leased)
        );
        let w = Actor::Worker(Fence(1));
        assert_eq!(
            j.apply(w, Event::PreparationStarted),
            Ok(JobState::Preparing)
        );
        assert_eq!(j.apply(w, Event::StepsStarted), Ok(JobState::Running));
        assert_eq!(
            j.apply(w, Event::FinalizationStarted),
            Ok(JobState::Finalizing)
        );
        assert_eq!(
            j.apply(w, Event::Passed),
            Ok(JobState::Terminal(Outcome::Passed))
        );
        assert_eq!(
            j.apply(w, Event::Passed),
            Err(TransitionError::AlreadyTerminal(Outcome::Passed))
        );
    }

    #[test]
    fn terminal_states_absorb_every_event_from_every_actor() {
        for state in ALL_STATES.iter().filter(|s| s.is_terminal()) {
            for event in ALL_EVENTS {
                for actor in [
                    Actor::Controller,
                    Actor::Worker(Fence(1)),
                    Actor::Reconciler,
                ] {
                    let mut j = at(*state, Fence(1));
                    assert!(matches!(
                        j.apply(actor, event),
                        Err(TransitionError::AlreadyTerminal(_))
                    ));
                    assert_eq!(j.state, *state);
                }
            }
        }
    }

    #[test]
    fn stale_or_future_worker_fence_is_rejected_without_change() {
        for presented in [Fence::NONE, Fence(1), Fence(3)] {
            let mut j = at(JobState::Running, Fence(2));
            assert_eq!(
                j.apply(Actor::Worker(presented), Event::Passed),
                Err(TransitionError::StaleFence {
                    current: Fence(2),
                    presented
                })
            );
            assert_eq!(j.state, JobState::Running);
        }
        let mut j = at(JobState::Queued, Fence(2));
        assert!(matches!(
            j.apply(Actor::Controller, Event::Leased(Fence(2))),
            Err(TransitionError::StaleFence { .. })
        ));
        assert_eq!(
            j.apply(Actor::Controller, Event::Leased(Fence(3))),
            Ok(JobState::Leased)
        );
        assert_eq!(j.fence, Fence(3));
    }

    #[test]
    fn workers_cannot_queue_lease_or_cancel_and_controller_cannot_report_steps() {
        let mut j = at(JobState::Queued, Fence::NONE);
        assert!(matches!(
            j.apply(Actor::Worker(Fence::NONE), Event::Leased(Fence(1))),
            Err(TransitionError::Forbidden { .. })
        ));
        assert!(matches!(
            j.apply(Actor::Worker(Fence::NONE), Event::CancelBeforeStart),
            Err(TransitionError::Forbidden { .. })
        ));
        let mut j = at(JobState::Running, Fence(1));
        assert!(matches!(
            j.apply(Actor::Controller, Event::Passed),
            Err(TransitionError::Forbidden { .. })
        ));
        assert!(matches!(
            j.apply(
                Actor::Reconciler,
                Event::Failed(FailureClass::CommandFailed)
            ),
            Err(TransitionError::Forbidden { .. })
        ));
        assert_eq!(j.state, JobState::Running);
    }

    #[test]
    fn every_failure_class_maps_to_one_outcome() {
        let mut j = at(JobState::Running, Fence(1));
        assert_eq!(
            j.apply(
                Actor::Worker(Fence(1)),
                Event::Failed(FailureClass::OutOfMemory)
            ),
            Ok(JobState::Terminal(Outcome::Failed))
        );
        assert_eq!(FailureClass::QueueTimeout.outcome(), Outcome::TimedOut);
        assert_eq!(FailureClass::Canceled.outcome(), Outcome::Canceled);
        assert_eq!(FailureClass::Publication.outcome(), Outcome::InfraFailed);
    }

    #[test]
    fn cancel_is_immediate_before_start_and_deferred_while_owned() {
        let mut j = at(JobState::Queued, Fence::NONE);
        assert!(j.request_cancel());
        assert_eq!(
            j.apply(Actor::Controller, Event::CancelBeforeStart),
            Ok(JobState::Terminal(Outcome::Canceled))
        );
        let mut j = at(JobState::Running, Fence(4));
        assert!(!j.request_cancel());
        assert!(j.cancel_requested);
        assert!(matches!(
            j.apply(Actor::Controller, Event::CancelBeforeStart),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(j.state, JobState::Running);
        assert_eq!(
            j.apply(
                Actor::Worker(Fence(4)),
                Event::Failed(FailureClass::Canceled)
            ),
            Ok(JobState::Terminal(Outcome::Canceled))
        );
    }

    #[test]
    fn lost_workers_and_expired_leases_are_infra_failures_from_any_owned_state() {
        for state in [
            JobState::Leased,
            JobState::Preparing,
            JobState::Running,
            JobState::Finalizing,
        ] {
            for (actor, event) in [
                (Actor::Controller, Event::LeaseExpired),
                (Actor::Reconciler, Event::WorkerLost),
                (Actor::Reconciler, Event::Reconciled),
            ] {
                let mut j = at(state, Fence(1));
                assert_eq!(
                    j.apply(actor, event),
                    Ok(JobState::Terminal(Outcome::InfraFailed))
                );
            }
        }
        let mut j = at(JobState::Queued, Fence::NONE);
        assert!(matches!(
            j.apply(Actor::Controller, Event::LeaseExpired),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn no_transition_leaves_a_non_terminal_state_without_a_defined_successor() {
        // Every (state, event) pair is either a defined move, Forbidden, Invalid,
        // StaleFence or AlreadyTerminal; the machine never panics.
        for state in ALL_STATES {
            for event in ALL_EVENTS {
                for actor in [
                    Actor::Controller,
                    Actor::Worker(Fence(1)),
                    Actor::Reconciler,
                ] {
                    let mut j = at(state, Fence(1));
                    let before = j;
                    match j.apply(actor, event) {
                        Ok(next) => assert_eq!(j.state, next),
                        Err(_) => assert_eq!(j, before),
                    }
                }
            }
        }
    }

    #[test]
    fn run_aggregation_precedence() {
        use JobState::Terminal as T;
        assert_eq!(aggregate([]), RunState::Pending);
        assert_eq!(
            aggregate([JobState::Blocked, JobState::Queued]),
            RunState::Pending
        );
        assert_eq!(
            aggregate([JobState::Blocked, JobState::Running]),
            RunState::Active
        );
        assert_eq!(
            aggregate([T(Outcome::Passed), JobState::Queued]),
            RunState::Active
        );
        assert_eq!(
            aggregate([T(Outcome::Passed), T(Outcome::Skipped)]),
            RunState::Terminal(Outcome::Passed)
        );
        assert_eq!(
            aggregate([T(Outcome::Skipped), T(Outcome::Skipped)]),
            RunState::Terminal(Outcome::Skipped)
        );
        assert_eq!(
            aggregate([T(Outcome::Passed), T(Outcome::Canceled), T(Outcome::Failed)]),
            RunState::Terminal(Outcome::Failed)
        );
        assert_eq!(
            aggregate([
                T(Outcome::Failed),
                T(Outcome::InfraFailed),
                T(Outcome::TimedOut)
            ]),
            RunState::Terminal(Outcome::InfraFailed)
        );
        assert_eq!(
            aggregate([T(Outcome::TimedOut), T(Outcome::Canceled)]),
            RunState::Terminal(Outcome::TimedOut)
        );
    }

    #[test]
    fn dependency_policies() {
        use JobState::Terminal as T;
        assert_eq!(
            dependency_decision(DependencyPolicy::OnSuccess, JobState::Running),
            None
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::OnSuccess, T(Outcome::Skipped)),
            Some(true)
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::OnSuccess, T(Outcome::Failed)),
            Some(false)
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::Always, T(Outcome::Failed)),
            Some(true)
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::Always, T(Outcome::Canceled)),
            Some(false)
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::OnFailure, T(Outcome::Passed)),
            Some(false)
        );
        assert_eq!(
            dependency_decision(DependencyPolicy::OnFailure, T(Outcome::InfraFailed)),
            Some(true)
        );
    }

    #[test]
    fn representations_are_one_byte_wide() {
        assert_eq!(std::mem::size_of::<Outcome>(), 1);
        assert_eq!(std::mem::size_of::<FailureClass>(), 1);
        assert_eq!(std::mem::size_of::<JobState>(), 2);
        assert_eq!(std::mem::size_of::<JobControl>(), 16);
    }
}
