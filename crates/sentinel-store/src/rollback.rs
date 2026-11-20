//! Guided migration's rollback: what a rollback step did, in the repository's own source audit
//! trail. Every step is one row, so what a person ran, in which order, survives the call — the
//! gate's own refusal is written by [`crate::migration::authorize`] before any step here, and these
//! are the steps that reached GitHub.
//!
//! The rows carry no revision and no settings document: GitHub holds the workflow bytes at the
//! revision a rollback names, and the pre-switch document is the switch's own preview, so a copy in
//! this table could only go stale. What is left is the step, the actor and the clock.

use rusqlite::Transaction;
use sentinel_core::{RepoId, TenantId, UnixMillis, UserId};

use crate::{Result, intake};

/// The revert pull request was opened or updated on `sentinel/migrate`; the answer states which.
pub const REVERTED: &str = "migration_rollback_revert";
/// Shadow mode was re-entered: the shadow revision's workflows were put back on the branch.
pub const SHADOW_ENTERED: &str = "migration_shadow_enter";
/// The required-check change back was shown, and nothing was written to the branch's protection.
pub const SETTINGS_SHOWN: &str = "migration_rollback_settings";
/// The required-check change back was applied and verified.
pub const SETTINGS_APPLIED: &str = "migration_rollback_settings_applied";
/// The required-check change back was not applied, or what GitHub stated afterwards did not match:
/// the answer names which.
pub const SETTINGS_FAILED: &str = "migration_rollback_settings_failed";
/// GitHub declined a write the rollback made.
pub const DECLINED: &str = "migration_rollback_refused";

/// One step of a rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Reverted,
    Shadow,
    SettingsShown,
    SettingsApplied,
    SettingsFailed,
    Declined,
}

impl Step {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reverted => REVERTED,
            Self::Shadow => SHADOW_ENTERED,
            Self::SettingsShown => SETTINGS_SHOWN,
            Self::SettingsApplied => SETTINGS_APPLIED,
            Self::SettingsFailed => SETTINGS_FAILED,
            Self::Declined => DECLINED,
        }
    }
}

/// Record one step in the repository's source audit trail, in the caller's own statement: who ran
/// the rollback and when survives the call, and a step that failed is recorded as the step it was.
pub fn record(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    actor: Option<UserId>,
    step: Step,
    now: UnixMillis,
) -> Result<()> {
    intake::audit(tx, tenant, repo, actor, step.as_str(), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_is_one_distinct_action_a_source_trail_states() {
        let steps = [
            Step::Reverted,
            Step::Shadow,
            Step::SettingsShown,
            Step::SettingsApplied,
            Step::SettingsFailed,
            Step::Declined,
        ];
        let mut actions: Vec<&str> = steps.iter().map(|step| step.as_str()).collect();
        let count = actions.len();
        actions.sort_unstable();
        actions.dedup();
        assert_eq!(actions.len(), count);
        // A source trail's actions are short, lower-case words a person reads in a listing.
        for action in actions {
            assert!(!action.is_empty() && action.len() <= 48);
            assert!(
                action
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
            );
        }
    }
}
