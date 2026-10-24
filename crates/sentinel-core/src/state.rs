//! Transitions apply inside one SQLite transaction with compare-and-set on the persisted state and fence,
//! so a stale worker or a duplicate message can never move a job backwards.
use crate::id::Fence;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Outcome {
    Passed = 0,
    Skipped = 1,
    Canceled = 2,
    TimedOut = 3,
    Failed = 4,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FailureClass {
    CommandFailed = 0,
    CommandSignaled = 1,
    OutOfMemory = 2,
    ExecutionTimeout = 3,
    QueueTimeout = 4,
    Canceled = 5,
    Preparation = 6,
    LeaseExpired = 7,
    WorkerLost = 8,
    Reconciled = 9,
    Publication = 10,
    Runtime = 11,
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
            Self::Runtime => "runtime",
        }
    }

    pub const fn outcome(self) -> Outcome {
        match self {
            Self::CommandFailed | Self::CommandSignaled | Self::OutOfMemory => Outcome::Failed,
            Self::ExecutionTimeout | Self::QueueTimeout => Outcome::TimedOut,
            Self::Canceled => Outcome::Canceled,
            Self::Preparation
            | Self::LeaseExpired
            | Self::WorkerLost
            | Self::Reconciled
            | Self::Publication
            | Self::Runtime => Outcome::InfraFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JobState {
    Blocked = 0,
    Queued = 1,
    Leased = 2,
    Preparing = 3,
    Running = 4,
    Finalizing = 5,
    Terminal(Outcome) = 6,
}

impl JobState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Actor {
    Controller = 0,
    Worker(Fence) = 1,
    Reconciler = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    DependenciesSatisfied,
    Skip,
    /// A broken condition ends infra_failed, never a silent skip or a silent run.
    ConditionFailed,
    Leased(Fence),
    OfferLapsed,
    PreparationStarted,
    StepsStarted,
    FinalizationStarted,
    Passed,
    Failed(FailureClass),
    CancelBeforeStart,
    QueueTimedOut,
    LeaseExpired,
    WorkerLost,
    Reconciled,
    Rerun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    Invalid { from: JobState, event: Event },
    Forbidden { actor: Actor, event: Event },
    StaleFence { current: Fence, presented: Fence },
    AlreadyTerminal(Outcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobControl {
    pub state: JobState,
    pub fence: Fence,
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

    pub const fn request_cancel(&mut self) -> bool {
        self.cancel_requested = true;
        matches!(self.state, JobState::Blocked | JobState::Queued)
    }

    pub const fn apply(&mut self, actor: Actor, event: Event) -> Result<JobState, TransitionError> {
        if let JobState::Terminal(o) = self.state {
            return match (actor, event) {
                (Actor::Controller, Event::Rerun) if !self.cancel_requested => {
                    self.state = JobState::Queued;
                    Ok(JobState::Queued)
                }
                (Actor::Controller, Event::Rerun) => Err(TransitionError::Invalid {
                    from: self.state,
                    event,
                }),
                (Actor::Worker(_) | Actor::Reconciler, Event::Rerun) => {
                    Err(TransitionError::Forbidden { actor, event })
                }
                _ => Err(TransitionError::AlreadyTerminal(o)),
            };
        }
        match (actor, event) {
            (
                Actor::Controller,
                Event::DependenciesSatisfied
                | Event::Skip
                | Event::ConditionFailed
                | Event::Leased(_)
                | Event::OfferLapsed,
            )
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
            (JobState::Blocked, Event::ConditionFailed) => {
                JobState::Terminal(FailureClass::Preparation.outcome())
            }
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
            (JobState::Leased, Event::OfferLapsed) => JobState::Queued,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RunState {
    Pending = 0,
    Active = 1,
    Terminal(Outcome) = 2,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DependencyPolicy {
    OnSuccess = 0,
    Always = 1,
    OnFailure = 2,
}

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
    const ALL_EVENTS: [Event; 16] = [
        Event::DependenciesSatisfied,
        Event::Skip,
        Event::ConditionFailed,
        Event::Leased(Fence(1)),
        Event::OfferLapsed,
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
        Event::Rerun,
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
            for event in ALL_EVENTS.iter().copied().filter(|e| *e != Event::Rerun) {
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
        assert_eq!(FailureClass::Runtime.outcome(), Outcome::InfraFailed);
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
    fn rerun_is_the_only_exit_from_terminal_and_keeps_the_fence() {
        for state in ALL_STATES.iter().filter(|s| s.is_terminal()) {
            let mut j = at(*state, Fence(3));
            assert_eq!(
                j.apply(Actor::Controller, Event::Rerun),
                Ok(JobState::Queued)
            );
            assert_eq!(
                j.fence,
                Fence(3),
                "the next lease advances the fence, not the rerun"
            );
            assert!(matches!(
                at(*state, Fence(3)).apply(Actor::Worker(Fence(3)), Event::Rerun),
                Err(TransitionError::Forbidden { .. })
            ));
            let mut cancelled = at(*state, Fence(3));
            cancelled.cancel_requested = true;
            assert!(matches!(
                cancelled.apply(Actor::Controller, Event::Rerun),
                Err(TransitionError::Invalid { .. })
            ));
        }
        assert!(matches!(
            at(JobState::Running, Fence(1)).apply(Actor::Controller, Event::Rerun),
            Err(TransitionError::Forbidden { .. })
        ));
    }

    #[test]
    fn an_unevaluable_condition_ends_a_blocked_job_as_infra_failed() {
        let mut blocked = at(JobState::Blocked, Fence::NONE);
        assert_eq!(
            blocked.apply(Actor::Controller, Event::ConditionFailed),
            Ok(JobState::Terminal(Outcome::InfraFailed))
        );
        for state in ALL_STATES
            .iter()
            .filter(|s| !s.is_terminal() && **s != JobState::Blocked)
        {
            assert!(matches!(
                at(*state, Fence(1)).apply(Actor::Controller, Event::ConditionFailed),
                Err(TransitionError::Invalid { .. })
            ));
        }
        for actor in [Actor::Worker(Fence::NONE), Actor::Reconciler] {
            assert!(matches!(
                at(JobState::Blocked, Fence::NONE).apply(actor, Event::ConditionFailed),
                Err(TransitionError::Forbidden { .. })
            ));
        }
    }

    #[test]
    fn a_lapsed_offer_requeues_without_rewinding_the_fence() {
        let mut j = at(JobState::Queued, Fence::NONE);
        j.apply(Actor::Controller, Event::Leased(Fence(1))).unwrap();
        assert_eq!(
            j.apply(Actor::Controller, Event::OfferLapsed),
            Ok(JobState::Queued)
        );
        assert_eq!(j.fence, Fence(1));
        assert!(matches!(
            j.apply(Actor::Worker(Fence(1)), Event::PreparationStarted),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(
            j.apply(Actor::Controller, Event::Leased(Fence(2))),
            Ok(JobState::Leased)
        );
        assert!(matches!(
            j.apply(Actor::Worker(Fence(1)), Event::StepsStarted),
            Err(TransitionError::StaleFence { .. })
        ));
        for actor in [Actor::Worker(Fence(2)), Actor::Reconciler] {
            assert!(matches!(
                j.apply(actor, Event::OfferLapsed),
                Err(TransitionError::Forbidden { .. })
            ));
        }
        j.apply(Actor::Worker(Fence(2)), Event::StepsStarted)
            .unwrap();
        assert!(matches!(
            j.apply(Actor::Controller, Event::OfferLapsed),
            Err(TransitionError::Invalid { .. })
        ));
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
