//! The required status checks a guided migration's switch changes, and the rulesets behind them.
//!
//! Branch protection itself is read and written by [`crate::rollback`]'s client: the switch and the
//! rollback write the same set in opposite directions, so one client does both and this module is
//! what sits on top of it for the switch. Two things are its own. A branch's rulesets can require a
//! check too, and a context a ruleset states is one this deployment does not edit — GitHub answers
//! `required_status_checks` from branch protection and from every active ruleset in one read, so a
//! switch that ignored the second would remove a check it could not put back. And the change itself:
//! each context a replaced job answers moves to the check Sentinel publishes for it, which is
//! `sentinel / <context>` so a matrix cell stays the cell it was ([migration switch](../../../docs/migration-switch.md)).

use serde_json::Value;

use crate::{
    Error, Result,
    app::{App, Token, valid_path_part},
    rollback::{Protected, RequiredCheck, RequiredChecks, Set},
};

/// The prefix a per-job check carries: the same spelling [`sentinel_store::checks::JOB_PREFIX`]
/// publishes with, so a check this change adds is the one Sentinel will publish.
pub const PREFIX: &str = "sentinel / ";
/// The most required checks one branch may state: the rollback client's own bound.
pub const MAX_CHECKS: usize = crate::rollback::MAX_CHECKS;
/// The longest context one may name: the rollback client's own bound.
pub const MAX_CONTEXT: usize = crate::rollback::MAX_CONTEXT;

/// What one branch requires before a merge: branch protection's own set, and the rulesets that
/// require a check on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Required {
    pub branch: String,
    /// The contexts, sorted and deduplicated, with the ones a ruleset states unioned in: what a
    /// required check may name, and what a comparison reads.
    pub contexts: Vec<String>,
    pub strict: bool,
    /// Whether the branch has a protection rule at all. A branch that has none is not one this
    /// deployment writes: creating protection is a person's decision, not a migration's.
    pub protected: bool,
    /// Branch protection's own set with each check's App binding, which is what a write puts back:
    /// writing a context without its App would unbind it.
    pub checks: RequiredChecks,
    /// The active rulesets that require a status check on this branch, by name, sorted.
    pub rulesets: Vec<String>,
    /// The contexts only a ruleset states, sorted: this deployment never edits a ruleset.
    pub from_rulesets: Vec<String>,
}

impl Required {
    /// Whether the change may be made at all: a context the change removes that only a ruleset
    /// states is refused, because the ruleset is not this deployment's to edit and a write that
    /// removed it would be a write that could not be undone here.
    pub fn editable(&self, removed: &[String]) -> std::result::Result<(), &'static str> {
        if removed
            .iter()
            .any(|context| self.from_rulesets.contains(context))
        {
            return Err("ruleset");
        }
        Ok(())
    }
}

/// The exact change a native switch makes to one branch's required checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The set the change produces, with the App binding of every check it keeps.
    pub settings: RequiredChecks,
    /// (the required context a replaced job answers to, the `sentinel / …` check that replaces it),
    /// in context order.
    pub replaced: Vec<(String, String)>,
}

impl Change {
    /// The contexts the change produces, sorted: what a read back is compared with.
    pub fn contexts(&self) -> Vec<&str> {
        self.settings
            .checks
            .iter()
            .map(|check| check.context.as_str())
            .collect()
    }
}

/// The change for the jobs a native pipeline replaced: each replaced job's required context becomes
/// the per-job check Sentinel publishes for it.
///
/// `replaced` is each served job as (its id, its `name:` when it states one). A required context
/// belongs to a job when it equals the job's name — or its id, for a job that states no name — or
/// when it starts with `<name> (`, which is how GitHub writes a matrix cell: cell `1.24` of job
/// `build` reports `build (1.24)`. A context no replaced job answers is left exactly as it was.
pub fn change(before: &Required, replaced: &[(String, Option<String>)]) -> Change {
    let mut checks: Vec<RequiredCheck> = Vec::with_capacity(before.contexts.len());
    let mut replaced_checks: Vec<(String, String)> = Vec::new();
    for context in &before.contexts {
        let served = replaced.iter().any(|(id, name)| {
            let name = name.as_deref().unwrap_or(id);
            context == name
                || context
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with(" ("))
        });
        // A context branch protection states keeps the App it is bound to; one only a ruleset
        // states has no App to keep. Both are in the union the branch waits for, so both are what
        // the change has to account for.
        let app_id = before
            .checks
            .checks
            .iter()
            .find(|check| &check.context == context)
            .and_then(|check| check.app_id);
        if !served {
            checks.push(RequiredCheck {
                context: context.clone(),
                app_id,
            });
            continue;
        }
        let mut check_name = String::with_capacity(PREFIX.len() + context.len());
        check_name.push_str(PREFIX);
        check_name.push_str(context);
        // The new check is Sentinel's own: it names no App, because the App that publishes it is
        // this deployment's and a `app_id` binding is only ever that App's.
        checks.push(RequiredCheck {
            context: check_name.clone(),
            app_id: None,
        });
        replaced_checks.push((context.clone(), check_name));
    }
    checks.sort_by(|a, b| a.context.cmp(&b.context));
    checks.dedup_by(|a, b| a.context == b.context);
    if checks.len() > MAX_CHECKS {
        // The bound GitHub states for one branch's protection. A set past it is refused rather
        // than truncated: a truncated set is a gate that silently moved.
        checks.truncate(MAX_CHECKS);
    }
    Change {
        settings: RequiredChecks {
            strict: before.checks.strict,
            checks,
        },
        replaced: replaced_checks,
    }
}

impl App {
    /// What one repository's default branch requires now: the branch a migration proposes into, read
    /// through the App, and the rulesets that require a check on it.
    pub fn protection(&self, token: &Token, owner: &str, repo: &str) -> Result<Required> {
        let branch = self.default_branch(token, owner, repo)?;
        self.protection_of(token, owner, repo, &branch)
    }

    /// What one branch requires now, protection and rulesets together.
    pub fn protection_of(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<Required> {
        let (checks, protected) = match self.required_checks(token, owner, repo, branch)? {
            Protected::Checks(checks) => (checks, true),
            Protected::Unprotected | Protected::NotPermitted => (RequiredChecks::default(), false),
        };
        let (rulesets, from_rulesets) = self.rules(token, owner, repo, branch)?;
        let mut contexts: Vec<String> =
            Vec::with_capacity(checks.checks.len().saturating_add(from_rulesets.len()));
        for context in checks
            .checks
            .iter()
            .map(|check| &check.context)
            .chain(from_rulesets.iter())
        {
            if !contexts.contains(context) {
                contexts.push(context.clone());
            }
        }
        contexts.sort_unstable();
        Ok(Required {
            branch: branch.to_owned(),
            contexts,
            strict: checks.strict,
            protected,
            checks,
            rulesets,
            from_rulesets,
        })
    }

    /// Replace branch protection's required status check set with `checks`, and nothing else.
    pub fn set_required(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        branch: &str,
        checks: &RequiredChecks,
    ) -> Result<()> {
        match self.set_required_checks(token, owner, repo, branch, checks)? {
            Set::Applied => Ok(()),
            // A branch with no protection rule is not one a migration creates, and a token the
            // installation does not grant administration to is a person's decision.
            Set::Unprotected | Set::NotPermitted => Err(Error::Denied("branch protection".into())),
        }
    }

    /// The rules that apply to one branch, from branch protection and from rulesets in one answer:
    /// the contexts they require and the active rulesets that state some.
    fn rules(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        if !valid_path_part(owner) || !valid_path_part(repo) || !valid_path_part(branch) {
            return Err(Error::Config("branch"));
        }
        let listing = self.http.send_json(
            "GET",
            &self.api(&format!("/repos/{owner}/{repo}/rules/branches/{branch}")),
            &token.secret,
            None,
        )?;
        let mut rules: Vec<Value> = match listing.status {
            200 => match listing.body.as_array() {
                Some(rules) => rules.clone(),
                // An answer that is not a list of rules is not a branch with no rules: a set read
                // from it would be smaller than the branch's gate, so it is refused.
                None => return Err(Error::Response("branch rules")),
            },
            404 => return Ok((Vec::new(), Vec::new())),
            401 | 403 => return Err(Error::Denied("administration".into())),
            _ => return Err(Error::Transport(format!("status {}", listing.status))),
        };
        if rules.len() > MAX_CHECKS {
            return Err(Error::Response("branch rules"));
        }
        let mut from_rulesets: Vec<String> = Vec::new();
        let mut ids: Vec<u64> = Vec::new();
        for rule in rules.drain(..) {
            if rule["type"].as_str() != Some("required_status_checks") {
                continue;
            }
            if let Some(id) = rule["ruleset_id"].as_u64()
                && !ids.contains(&id)
            {
                ids.push(id);
            }
            let stated = rule["parameters"]["required_status_checks"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if stated.len() > MAX_CHECKS {
                return Err(Error::Response("branch rules"));
            }
            for check in stated {
                let context = check["context"]
                    .as_str()
                    .filter(|context| {
                        !context.is_empty()
                            && context.len() <= MAX_CONTEXT
                            && !context.chars().any(char::is_control)
                    })
                    .ok_or(Error::Response("branch rules"))?;
                if !from_rulesets.iter().any(|held| held == context) {
                    from_rulesets.push(context.to_owned());
                }
            }
        }
        from_rulesets.sort_unstable();
        ids.sort_unstable();
        Ok((self.ruleset_names(token, owner, repo, &ids)?, from_rulesets))
    }

    /// The names of the rulesets that contributed a rule, read from the repository's own listing. An
    /// id the listing does not name is stated as `#<id>`: a rule whose owner cannot be named is
    /// still a rule, and a switch that dropped it from the answer would understate the gate.
    fn ruleset_names(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        ids: &[u64],
    ) -> Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let listing = self.http.send_json(
            "GET",
            &self.api(&format!("/repos/{owner}/{repo}/rulesets")),
            &token.secret,
            None,
        )?;
        let Some(listed) = (match listing.status {
            200 => listing.body.as_array().cloned(),
            // A listing the token may not read names no ruleset, and the ids stand in for it.
            401 | 403 | 404 => None,
            _ => return Err(Error::Transport(format!("status {}", listing.status))),
        }) else {
            return Ok(ids
                .iter()
                .map(|id| {
                    let mut name = String::with_capacity(20);
                    name.push('#');
                    name.push_str(&id.to_string());
                    name
                })
                .collect());
        };
        if listed.len() > MAX_CHECKS {
            return Err(Error::Response("ruleset count"));
        }
        let mut names = Vec::with_capacity(ids.len());
        for id in ids {
            let found = listed
                .iter()
                .find(|ruleset| ruleset["id"].as_u64() == Some(*id));
            let named = found
                .and_then(|ruleset| ruleset["name"].as_str())
                .filter(|name| !name.is_empty() && name.len() <= MAX_CONTEXT)
                .map(str::to_owned);
            names.push(match named {
                Some(name) => name,
                None => {
                    let mut name = String::with_capacity(20);
                    name.push('#');
                    name.push_str(&id.to_string());
                    name
                }
            });
        }
        names.sort_unstable();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(strict: bool, contexts: &[&str], from_rulesets: &[&str]) -> Required {
        let checks = RequiredChecks {
            strict,
            checks: contexts
                .iter()
                .map(|context| RequiredCheck {
                    context: (*context).to_owned(),
                    app_id: None,
                })
                .collect(),
        };
        let mut all: Vec<String> = contexts
            .iter()
            .map(|context| (*context).to_owned())
            .collect();
        for context in from_rulesets {
            if !all.iter().any(|held| held == context) {
                all.push((*context).to_owned());
            }
        }
        all.sort_unstable();
        Required {
            branch: "main".to_owned(),
            contexts: all,
            strict,
            protected: true,
            checks,
            rulesets: Vec::new(),
            from_rulesets: from_rulesets
                .iter()
                .map(|context| (*context).to_owned())
                .collect(),
        }
    }

    #[test]
    fn every_context_a_replaced_job_answers_moves_to_its_sentinel_check() {
        let before = required(false, &["build (1.24)", "lint", "ci/external"], &[]);
        let change = change(
            &before,
            &[
                ("build".to_owned(), Some("build".to_owned())),
                ("lint".to_owned(), None),
            ],
        );
        assert_eq!(
            change.contexts(),
            ["ci/external", "sentinel / build (1.24)", "sentinel / lint"]
        );
        assert_eq!(
            change.replaced,
            [
                (
                    "build (1.24)".to_owned(),
                    "sentinel / build (1.24)".to_owned()
                ),
                ("lint".to_owned(), "sentinel / lint".to_owned()),
            ]
        );
        assert!(!change.settings.strict);
    }

    #[test]
    fn a_context_no_replaced_job_answers_is_left_alone() {
        let before = required(true, &["build", "ci/external"], &[]);
        let change = change(&before, &[("build".to_owned(), None)]);
        assert_eq!(change.contexts(), ["ci/external", "sentinel / build"]);
        assert!(
            change.settings.strict,
            "strict is not this change's to move"
        );
    }

    #[test]
    fn a_ruleset_context_a_replaced_job_answers_is_a_change_this_deployment_cannot_make() {
        let before = required(false, &[], &["build"]);
        assert_eq!(before.contexts, ["build"]);
        let change = change(&before, &[("build".to_owned(), None)]);
        assert_eq!(
            change.contexts(),
            ["sentinel / build"],
            "the ruleset's own context cannot be removed, so the change is shown and refused"
        );
        assert_eq!(
            change.replaced,
            [("build".to_owned(), "sentinel / build".to_owned())]
        );
        assert_eq!(
            before.editable(&["build".to_owned()]),
            Err("ruleset"),
            "a ruleset is not this deployment's to edit"
        );
        assert_eq!(
            before.editable(&["sentinel / build".to_owned()]),
            Ok(()),
            "a context only branch protection states is"
        );
    }

    #[test]
    fn an_empty_change_states_the_same_set() {
        let before = required(false, &["ci/external"], &[]);
        let change = change(&before, &[]);
        assert_eq!(change.contexts(), ["ci/external"]);
        assert!(change.replaced.is_empty());
    }

    #[test]
    fn a_kept_check_keeps_the_app_it_is_bound_to() {
        let mut before = required(false, &["ci/external", "build"], &[]);
        before.checks.checks[0].app_id = Some(7);
        let change = change(&before, &[("build".to_owned(), None)]);
        let kept = change
            .settings
            .checks
            .iter()
            .find(|check| check.context == "ci/external")
            .expect("the unserved check is kept");
        assert_eq!(kept.app_id, Some(7), "writing a context unbinds its App");
    }
}
