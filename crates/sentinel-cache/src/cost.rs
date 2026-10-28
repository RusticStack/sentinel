//! Measured restore and rebuild cost per cache class: the basis of the costly-hit rule.
//!
//! A hit is only worth having while restoring it costs less than rebuilding what it holds. The book keeps one
//! bounded estimate of each, per class, as an exponentially weighted mean: restore samples come from the attempts'
//! own restore stats ([`CostBook::observe`]), rebuild samples from whoever measured a cold rebuild of the same
//! class on this worker ([`CostBook::record_rebuild`]), such as the B05 harness. An estimate is withheld until
//! [`MIN_SAMPLES`] samples exist, so one outlier never decides a class, and a class without a settled rebuild
//! estimate falls back to the fixed default in [`crate::attach`].

use std::sync::Mutex;

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

#[derive(Clone, Copy, Default)]
struct ClassCost {
    restore: Estimate,
    rebuild: Estimate,
}

/// Per-class cost estimates, shared by every attempt a worker runs.
#[derive(Default)]
pub struct CostBook {
    classes: Mutex<[ClassCost; Class::ALL.len()]>,
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
}
