//! Measured restore and rebuild cost per cache class: the basis of the costly-hit rule.
//!
//! A hit is only worth having while restoring it costs less than rebuilding what it holds. The book keeps one
//! bounded estimate of each, per class, as an exponentially weighted mean: restore samples come from the attempts'
//! own restore stats ([`CostBook::observe`]), rebuild samples from whoever measured a cold rebuild of the same
//! class on this worker ([`CostBook::record_rebuild`]), such as the B05 harness, or inferred from the attempts
//! themselves ([`CostBook::observe_run`]). An estimate is withheld until
//! [`MIN_SAMPLES`] samples exist, so one outlier never decides a class, and a class without a settled rebuild
//! estimate falls back to the fixed default in [`crate::attach`].

use std::{path::PathBuf, sync::Mutex};

use sentinel_protocol::cache::Class;

use crate::attach::Attached;

/// Samples a class needs before its estimate is used.
pub const MIN_SAMPLES: u32 = 3;

/// A new sample moves the estimate by `1 / 2^WEIGHT_SHIFT` of the difference.
const WEIGHT_SHIFT: u32 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Estimate {
    pub ns: u64,
    pub samples: u32,
}

impl Estimate {
    fn add(&mut self, sample: u64) {
        if self.samples == 0 {
            self.ns = sample;
        } else if sample >= self.ns {
            self.ns += (sample - self.ns) >> WEIGHT_SHIFT;
        } else {
            self.ns -= (self.ns - sample) >> WEIGHT_SHIFT;
        }
        self.samples = self.samples.saturating_add(1);
    }

    fn settled(self) -> Option<Estimate> {
        (self.samples >= MIN_SAMPLES).then_some(self)
    }
}

/// Entries whose cold and warm job times are tracked; the least recently seen is dropped beyond this.
pub const MAX_TRACKED_ENTRIES: usize = 128;

/// One entry's job step times (nanoseconds, exponentially weighted) after a miss and after a hit.
struct Tracked {
    entry: PathBuf,
    cold: Estimate,
    warm: Estimate,
}

#[derive(Clone, Copy, Default)]
struct ClassCost {
    restore: Estimate,
    rebuild: Estimate,
}

/// Per-class cost estimates, shared by every attempt a worker runs.
#[derive(Default)]
pub struct CostBook {
    classes: Mutex<[ClassCost; Class::ALL.len()]>,
    runs: Mutex<Vec<Tracked>>,
}

/// A class's settled estimates, for the availability summaries and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassFigures {
    pub class: Class,
    pub restore: Option<Estimate>,
    pub rebuild: Option<Estimate>,
}

impl CostBook {
    pub fn new() -> CostBook {
        CostBook::default()
    }

    fn with<R>(&self, class: Class, f: impl FnOnce(&mut ClassCost) -> R) -> R {
        let mut classes = self.classes.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut classes[usize::from(class.to_u8())])
    }

    /// A zero sample is an unmeasured phase, never a cost, and is ignored.
    pub fn record_restore(&self, class: Class, ns: u64) {
        if ns > 0 {
            self.with(class, |c| c.restore.add(ns));
        }
    }

    /// `ns` is the wall time of rebuilding what a hit of `class` would have restored, from nothing.
    pub fn record_rebuild(&self, class: Class, ns: u64) {
        if ns > 0 {
            self.with(class, |c| c.rebuild.add(ns));
        }
    }

    /// Records a hit's restore cost; a miss restored nothing and is not a sample.
    pub fn observe(&self, attached: &Attached) {
        if attached.outcome.is_hit() {
            self.record_restore(attached.scope.class, attached.restore_ns());
        }
    }

    /// What a passed attempt teaches about its cache: the job's step time after a miss against after a hit.
    ///
    /// Only a job with exactly one cache entry is attributed, since with several the saving cannot be split
    /// between them. Each entry (its scope path) keeps one weighted step time per side; once both exist, the
    /// difference — what the hit saved — is a rebuild sample for the class, floored at one nanosecond so a
    /// cache that saves nothing is recorded as exactly that rather than as an unmeasured phase. The step time
    /// includes work the cache does not touch, and it varies with the change under test, so the estimate is
    /// only as steady as the job; the class estimate settles after [`MIN_SAMPLES`] observations.
    pub fn observe_run(&self, caches: &[Attached], steps_ns: u64) {
        let [only] = caches else { return };
        if steps_ns == 0 {
            return;
        }
        let entry = only.scope.rel_path();
        let saving = {
            let mut runs = self.runs.lock().unwrap_or_else(|p| p.into_inner());
            let mut tracked = match runs.iter().position(|t| t.entry == entry) {
                Some(at) => runs.remove(at),
                None => {
                    if runs.len() >= MAX_TRACKED_ENTRIES {
                        runs.remove(0);
                    }
                    Tracked {
                        entry,
                        cold: Estimate::default(),
                        warm: Estimate::default(),
                    }
                }
            };
            if only.outcome.is_hit() {
                tracked.warm.add(steps_ns);
            } else {
                tracked.cold.add(steps_ns);
            }
            let saving = (tracked.cold.samples > 0 && tracked.warm.samples > 0)
                .then(|| tracked.cold.ns.saturating_sub(tracked.warm.ns).max(1));
            runs.push(tracked);
            saving
        };
        if let Some(saving) = saving {
            self.record_rebuild(only.scope.class, saving);
        }
    }

    /// Every class's settled estimates, in class order.
    pub fn figures(&self) -> [ClassFigures; Class::ALL.len()] {
        Class::ALL.map(|class| ClassFigures {
            class,
            restore: self.restore(class),
            rebuild: self.rebuild(class),
        })
    }

    /// The class's restore estimate once settled.
    pub fn restore(&self, class: Class) -> Option<Estimate> {
        self.with(class, |c| c.restore.settled())
    }

    /// The class's rebuild estimate once settled.
    pub fn rebuild(&self, class: Class) -> Option<Estimate> {
        self.with(class, |c| c.rebuild.settled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_estimate_is_withheld_until_it_has_enough_samples() {
        let book = CostBook::new();
        for _ in 0..MIN_SAMPLES - 1 {
            book.record_rebuild(Class::Dependencies, 1_000);
        }
        assert_eq!(book.rebuild(Class::Dependencies), None);
        book.record_rebuild(Class::Dependencies, 1_000);
        assert_eq!(
            book.rebuild(Class::Dependencies),
            Some(Estimate {
                ns: 1_000,
                samples: MIN_SAMPLES
            })
        );
    }

    #[test]
    fn classes_and_phases_keep_separate_estimates() {
        let book = CostBook::new();
        for _ in 0..MIN_SAMPLES {
            book.record_rebuild(Class::Compiler, 500);
            book.record_restore(Class::Downloads, 70);
        }
        assert_eq!(book.rebuild(Class::Compiler).map(|e| e.ns), Some(500));
        assert_eq!(book.restore(Class::Downloads).map(|e| e.ns), Some(70));
        assert_eq!(book.rebuild(Class::Downloads), None);
        assert_eq!(book.restore(Class::Compiler), None);
        assert_eq!(book.rebuild(Class::Dependencies), None);
    }

    #[test]
    fn the_estimate_follows_the_samples_without_one_outlier_taking_over() {
        let book = CostBook::new();
        for _ in 0..MIN_SAMPLES {
            book.record_rebuild(Class::Dependencies, 1_000);
        }
        book.record_rebuild(Class::Dependencies, 5_000);
        let after_outlier = book.rebuild(Class::Dependencies).unwrap().ns;
        assert_eq!(after_outlier, 2_000);
        for _ in 0..40 {
            book.record_rebuild(Class::Dependencies, 100);
        }
        let settled = book.rebuild(Class::Dependencies).unwrap().ns;
        assert!((100..=110).contains(&settled), "{settled}");
        book.record_rebuild(Class::Dependencies, u64::MAX);
        assert!(book.rebuild(Class::Dependencies).unwrap().ns > settled);
    }

    #[test]
    fn an_unmeasured_zero_is_not_a_sample() {
        let book = CostBook::new();
        for _ in 0..MIN_SAMPLES * 2 {
            book.record_restore(Class::Dependencies, 0);
            book.record_rebuild(Class::Dependencies, 0);
        }
        assert_eq!(book.restore(Class::Dependencies), None);
        assert_eq!(book.rebuild(Class::Dependencies), None);
    }

    mod runs {
        use sentinel_core::{RepoId, TenantId};
        use sentinel_protocol::{cache::Trust, negotiate::Arch};

        use super::*;
        use crate::{
            Miss,
            attach::Stats,
            manifest::{Compat, Manifest},
            outcome::{Hit, Outcome},
            scope::{Os, Platform, Scope},
        };

        fn scope(name: &str, repo: RepoId) -> Scope {
            Scope::new(
                TenantId::new(),
                repo,
                Class::Dependencies,
                Trust::Protected,
                Platform {
                    os: Os::Linux,
                    arch: Arch::X86_64,
                },
                [7; 32],
                name,
            )
            .unwrap()
        }

        fn attached(scope: &Scope, hit: bool) -> Attached {
            let compat = Compat::Downloads { tool: "t".into() };
            Attached {
                name: scope.name.clone(),
                scope: scope.clone(),
                key: "k".into(),
                compat: compat.clone(),
                generation: None,
                outcome: if hit {
                    Outcome::Hit(Box::new(Hit {
                        manifest: Manifest::writing(scope, "k", compat),
                        bytes: 0,
                    }))
                } else {
                    Outcome::Miss(Miss::Absent)
                },
                targets: Vec::new(),
                lease: None,
                stats: Stats::default(),
            }
        }

        #[test]
        fn a_cold_and_a_warm_run_of_one_entry_teach_the_rebuild_saving() {
            let book = CostBook::new();
            let scope = scope("deps", RepoId::new());
            book.observe_run(&[attached(&scope, false)], 100_000);
            assert_eq!(
                book.rebuild(Class::Dependencies),
                None,
                "one side is not a saving"
            );
            for _ in 0..MIN_SAMPLES {
                book.observe_run(&[attached(&scope, true)], 40_000);
            }
            let rebuild = book.rebuild(Class::Dependencies).expect("settled");
            assert_eq!(rebuild.ns, 60_000, "cold minus warm");
            assert_eq!(rebuild.samples, MIN_SAMPLES);
        }

        #[test]
        fn a_cache_that_saves_nothing_is_a_one_nanosecond_rebuild() {
            let book = CostBook::new();
            let scope = scope("deps", RepoId::new());
            book.observe_run(&[attached(&scope, false)], 50_000);
            for _ in 0..MIN_SAMPLES {
                book.observe_run(&[attached(&scope, true)], 80_000);
            }
            assert_eq!(book.rebuild(Class::Dependencies).map(|e| e.ns), Some(1));
            let mut hit = attached(&scope, true);
            hit.stats.clone_ns = Some(2);
            assert_eq!(hit.costly_hit_with(&book), Some(crate::Costly::Slow));
        }

        #[test]
        fn a_job_with_several_entries_or_no_step_time_teaches_nothing() {
            let book = CostBook::new();
            let a = scope("a", RepoId::new());
            let b = scope("b", RepoId::new());
            for _ in 0..MIN_SAMPLES * 2 {
                book.observe_run(&[attached(&a, false), attached(&b, true)], 10_000);
                book.observe_run(&[attached(&a, false)], 0);
                book.observe_run(&[], 10_000);
            }
            book.observe_run(&[attached(&a, true)], 5_000);
            assert_eq!(book.rebuild(Class::Dependencies), None);
        }

        #[test]
        fn entries_do_not_borrow_each_others_times_and_tracking_is_bounded() {
            let book = CostBook::new();
            let a = scope("deps", RepoId::new());
            let b = scope("deps", RepoId::new());
            book.observe_run(&[attached(&a, false)], 90_000);
            book.observe_run(&[attached(&b, true)], 10_000);
            assert_eq!(
                book.runs.lock().unwrap().len(),
                2,
                "a cold run of one entry and a warm run of another make no pair"
            );
            for _ in 0..MAX_TRACKED_ENTRIES * 2 {
                book.observe_run(&[attached(&scope("deps", RepoId::new()), false)], 1);
            }
            assert_eq!(book.runs.lock().unwrap().len(), MAX_TRACKED_ENTRIES);
        }

        #[test]
        fn figures_list_every_class_with_only_settled_estimates() {
            let book = CostBook::new();
            for _ in 0..MIN_SAMPLES {
                book.record_restore(Class::Compiler, 9);
            }
            let figures = book.figures();
            assert_eq!(figures.map(|f| f.class), Class::ALL);
            assert_eq!(figures[2].restore.map(|e| e.ns), Some(9));
            assert!(figures[2].rebuild.is_none() && figures[0].restore.is_none());
        }
    }
}
