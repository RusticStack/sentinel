//! Guided migration's rollback (H07): the revert pull request that puts a repository's workflows
//! back the way they were before a switch, and the branch's required status checks put back with
//! them on the native path.
//!
//! Both halves restore a state that already exists rather than a copy Sentinel keeps: the workflow
//! bytes are GitHub's own at the revision the caller names — a file's bytes never change for a
//! given commit, so restoring them restores exactly what the switch replaced — and the required
//! checks are the document the switch's preview promised, compared against the branch's protection
//! as GitHub states it now. Nothing here stores a revision, a pull request number or a settings
//! copy that could go stale.
//!
//! The revert is the migration's own write, inverted: the same `sentinel/migrate` branch, one
//! commit whose parent is the default branch's head, and the same single pull request opened or
//! updated. A revert can therefore never push to a default branch, and re-running it as often as a
//! person likes leaves one branch and one pull request behind.

use serde_json::{Value, json};

use crate::{
    Error, Result,
    app::{App, Token, valid_path_part},
    migration::{BRANCH, Migrate, Outcome, Pull, WORKFLOWS, workflow_path},
};

/// The permission the native path's settings step needs beyond the migration's three: reading a
/// branch's protection and putting its required checks back is repository administration. It is
/// opt-in, so a tenant that never asks for the settings step never has it asked of its
/// installations.
pub const ADMINISTRATION: &[(&str, &str)] = &[("administration", "write")];

/// The most required checks one branch may state, and the longest context one may name: a
/// protection rule's own bound, refused rather than truncated.
pub const MAX_CHECKS: usize = 100;
pub const MAX_CONTEXT: usize = 512;

/// One required status check: the context GitHub waits for, and the App it must be published by
/// when the branch binds it to one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredCheck {
    pub context: String,
    pub app_id: Option<u64>,
}

/// A branch's required status checks, in the order the branch states them: the shape both halves of
/// the rollback's settings step compare, byte for byte once rendered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequiredChecks {
    /// Whether a pull request must be up to date with the base branch before it merges.
    pub strict: bool,
    pub checks: Vec<RequiredCheck>,
}

impl RequiredChecks {
    /// What turns `self` into `target`: the checks the branch states that the pre-switch document
    /// does not hold, the ones it holds that the branch no longer does, and the `strict` flag when
    /// it moved. A check is the same check only when it names the same App too, so a context
    /// re-bound to another App is both removed and restored rather than left where it is.
    pub fn change_to(&self, target: &Self) -> Change {
        Change {
            remove: self
                .checks
                .iter()
                .filter(|check| !target.holds(check))
                .cloned()
                .collect(),
            restore: target
                .checks
                .iter()
                .filter(|check| !self.holds(check))
                .cloned()
                .collect(),
            strict: (self.strict != target.strict).then_some(target.strict),
        }
    }

    fn holds(&self, check: &RequiredCheck) -> bool {
        self.checks.iter().any(|held| held == check)
    }

    /// The document as GitHub states it, read from a branch's protection: `checks` when the branch
    /// binds each context to an App, and the older `contexts` alone when it does not. `None` for an
    /// answer this module does not model, so a body it cannot read is never mistaken for no checks.
    fn read(body: &Value) -> Option<Self> {
        let required = body.get("required_status_checks")?;
        if required.is_null() {
            return Some(Self::default());
        }
        let strict = required.get("strict")?.as_bool()?;
        let mut checks = Vec::new();
        match required.get("checks").and_then(Value::as_array) {
            Some(stated) => {
                checks.reserve(stated.len().min(MAX_CHECKS));
                for check in stated {
                    let context = check.get("context")?.as_str()?;
                    if !context_text(context) || checks.len() == MAX_CHECKS {
                        return None;
                    }
                    checks.push(RequiredCheck {
                        context: context.to_owned(),
                        app_id: check.get("app_id").and_then(Value::as_u64),
                    });
                }
            }
            None => {
                for context in required.get("contexts")?.as_array()? {
                    let context = context.as_str()?;
                    if !context_text(context) || checks.len() == MAX_CHECKS {
                        return None;
                    }
                    checks.push(RequiredCheck {
                        context: context.to_owned(),
                        app_id: None,
                    });
                }
            }
        }
        Some(Self { strict, checks })
    }

    /// The document as a write states it: the whole set, in order, so putting the branch back is
    /// one statement of what it must hold rather than a series of edits.
    fn write(&self) -> Value {
        json!({
            "strict": self.strict,
            "checks": self.checks.iter().map(|check| match check.app_id {
                Some(app_id) => json!({"context": check.context, "app_id": app_id}),
                None => json!({"context": check.context}),
            }).collect::<Vec<Value>>(),
        })
    }
}

/// What a settings step moves, in the direction it moves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The branch's checks the pre-switch document does not hold, in the branch's own order.
    pub remove: Vec<RequiredCheck>,
    /// The pre-switch document's checks the branch no longer holds, in the document's order.
    pub restore: Vec<RequiredCheck>,
    /// The `strict` flag to put back, when the branch states another one.
    pub strict: Option<bool>,
}

impl Change {
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.restore.is_empty() && self.strict.is_none()
    }
}

/// A branch's required checks as GitHub answers them to the token in hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protected {
    /// The branch's protection states these.
    Checks(RequiredChecks),
    /// The branch has no protection rule: GitHub answers 404, and a required check a ruleset holds
    /// is not visible here either.
    Unprotected,
    /// The token in hand may not read protection: GitHub answers 403.
    NotPermitted,
}

/// What putting a branch's required checks back did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set {
    Applied,
    /// The branch has no protection rule to put them on.
    Unprotected,
    /// The token in hand may not write protection.
    NotPermitted,
}

/// What a restore is built on: the branch a pull request proposes into, the commit it holds now,
/// and the workflow files that commit holds. The revert's parent is that commit, so the write is
/// the state as it is today with the pre-switch workflows in it, never a state that also undoes
/// whatever merged since the switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub name: String,
    pub head: String,
    /// Sorted by path, as the analyzer reads them.
    pub workflows: Vec<String>,
}

/// One restore: the migration's write, with the files a switch added taken back out.
pub struct Restore<'a> {
    /// The parent commit, the files it rewrites and the pull request's text.
    pub write: Migrate<'a>,
    /// Workflow files the commit deletes: paths the parent commit holds that the restore does not.
    pub remove: &'a [&'a str],
}

/// A context a branch may wait for: bounded, and never something a diagnostic could not state.
pub fn context_text(context: &str) -> bool {
    !context.is_empty() && context.len() <= MAX_CONTEXT && !context.chars().any(char::is_control)
}

impl App {
    /// An installation token that may read a branch's protection and put its required checks back,
    /// on top of what a migration writes with. GitHub mints a token carrying what the installation
    /// grants: one that comes back without `administration`, or a mint GitHub declines, is that
    /// permission not granted — a person's decision, answered as such and never retried.
    pub fn administration_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        now_ms: i64,
    ) -> Result<Token> {
        match self.repository_token(installation, account, repo, remote, now_ms, ADMINISTRATION) {
            Ok(token) => Ok(token),
            // GitHub answers a token that asks for more than the installation grants with `422`,
            // and a token minted without the permission fails this module's own scope check.
            Err(Error::Response("token permission scope")) => {
                Err(Error::Denied(ADMINISTRATION[0].0.to_owned()))
            }
            Err(Error::Transport(status))
                if matches!(status.as_str(), "status 422" | "status 403") =>
            {
                Err(Error::Denied(ADMINISTRATION[0].0.to_owned()))
            }
            Err(other) => Err(other),
        }
    }

    /// The commit a restore is built on and the workflow files it holds. The default branch is
    /// read, never assumed, and a repository whose default branch is the migration branch has
    /// nowhere to open a pull request.
    pub fn branch_workflows(&self, token: &Token, owner: &str, repo: &str) -> Result<Branch> {
        let base = self.default_branch(token, owner, repo)?;
        let head = self
            .branch_head(token, owner, repo, &base)?
            .ok_or(Error::Response("default branch"))?;
        let listing = self.http.send_json(
            "GET",
            &self.api(&format!(
                "/repos/{owner}/{repo}/contents/{WORKFLOWS}?ref={head}"
            )),
            &token.secret,
            None,
        )?;
        let mut workflows = Vec::new();
        match listing.status {
            200 => {
                let entries = listing
                    .body
                    .as_array()
                    .ok_or(Error::Response("workflow listing"))?;
                if entries.len() > crate::migration::MAX_WORKFLOW_FILES {
                    return Err(Error::Response("workflow count"));
                }
                for entry in entries {
                    if entry["type"].as_str() != Some("file") {
                        continue;
                    }
                    let Some(name) = entry["name"].as_str() else {
                        continue;
                    };
                    if let Some(path) = workflow_path(name) {
                        workflows.push(path);
                    }
                }
            }
            // A repository with no workflows directory holds none: the restore puts every one of
            // the revision's files back.
            404 => {}
            401 | 403 => return Err(Error::Response("workflow listing refused")),
            _ => return Err(Error::Transport(format!("status {}", listing.status))),
        }
        workflows.sort_unstable();
        Ok(Branch {
            name: base,
            head,
            workflows,
        })
    }

    /// Put `request`'s files on the migration branch and open or update its pull request, deleting
    /// the paths it names. This is the migration's write with deletions, and `migrate` is it with
    /// none: one branch, one commit over the revision named, one pull request.
    pub fn restore(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        request: &Restore<'_>,
    ) -> Result<Outcome> {
        self.checked(owner, repo, &request.write)?;
        for path in request.remove {
            let named = path
                .strip_prefix(WORKFLOWS)
                .and_then(|rest| rest.strip_prefix('/'))
                .filter(|name| workflow_path(name).as_deref() == Some(*path));
            // A path a restore both writes and deletes states nothing, and a path outside the
            // workflows directory is not one a migration ever wrote.
            if named.is_none() || request.write.files.iter().any(|file| file.path == *path) {
                return Err(Error::Config("rollback file"));
            }
        }
        let base = self.default_branch(token, owner, repo)?;
        let parent = self
            .tree_of(token, owner, repo, request.write.commit)?
            .ok_or(Error::Response("commit tree"))?;
        let tree = self.write_tree(
            token,
            owner,
            repo,
            &parent,
            request.write.files,
            request.remove,
        )?;
        // A restore of the tree the branch already holds writes no commit, so re-entering the same
        // state twice leaves one commit and one pull request.
        let head = self.branch_head(token, owner, repo, BRANCH)?;
        let unchanged = match &head {
            Some(commit) => self.tree_of(token, owner, repo, commit)?.as_deref() == Some(&tree),
            None => false,
        };
        let commit = match (&head, unchanged) {
            (Some(commit), true) => commit.clone(),
            _ => {
                let commit = self.write_commit(token, owner, repo, &request.write, &tree)?;
                self.move_branch(token, owner, repo, &commit, head.is_none())?;
                commit
            }
        };
        let pull: Pull = self.publish(token, owner, repo, &base, &commit, &request.write)?;
        Ok(if head.is_some() {
            Outcome::Updated(pull)
        } else {
            Outcome::Opened(pull)
        })
    }

    /// What the branch's protection states it waits for. `404` is a branch with no protection rule
    /// and `403` is a token that may not read one — both are answers, not failures.
    pub fn required_checks(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<Protected> {
        if !valid_path_part(owner) || !valid_path_part(repo) || !valid_path_part(branch) {
            return Err(Error::Config("branch"));
        }
        let reply = self.http.send_json(
            "GET",
            &self.api(&format!(
                "/repos/{owner}/{repo}/branches/{branch}/protection"
            )),
            &token.secret,
            None,
        )?;
        match reply.status {
            200 => match RequiredChecks::read(&reply.body) {
                Some(checks) => Ok(Protected::Checks(checks)),
                None => Err(Error::Response("branch protection")),
            },
            403 => Ok(Protected::NotPermitted),
            404 => Ok(Protected::Unprotected),
            401 => Err(Error::Response("branch protection refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// Put the branch's required status checks back as `checks` states them, as one statement of
    /// the whole set rather than a series of edits.
    pub fn set_required_checks(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        branch: &str,
        checks: &RequiredChecks,
    ) -> Result<Set> {
        if !valid_path_part(owner) || !valid_path_part(repo) || !valid_path_part(branch) {
            return Err(Error::Config("branch"));
        }
        if checks.checks.len() > MAX_CHECKS
            || checks.checks.iter().any(|c| !context_text(&c.context))
        {
            return Err(Error::Config("required checks"));
        }
        let reply = self.http.send_json(
            "PATCH",
            &self.api(&format!(
                "/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
            )),
            &token.secret,
            Some(&checks.write()),
        )?;
        match reply.status {
            200 => Ok(Set::Applied),
            403 => Ok(Set::NotPermitted),
            404 => Ok(Set::Unprotected),
            401 => Err(Error::Response("branch protection refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks(strict: bool, stated: &[(&str, Option<u64>)]) -> RequiredChecks {
        RequiredChecks {
            strict,
            checks: stated
                .iter()
                .map(|(context, app_id)| RequiredCheck {
                    context: (*context).to_owned(),
                    app_id: *app_id,
                })
                .collect(),
        }
    }

    #[test]
    fn the_change_back_is_what_the_branch_states_and_what_it_must_hold() {
        let before = checks(true, &[("build", Some(15368)), ("test", Some(15368))]);
        let switched = checks(
            true,
            &[("build", Some(15368)), ("sentinel / test", Some(42))],
        );
        let change = switched.change_to(&before);
        assert_eq!(
            change.remove,
            [RequiredCheck {
                context: "sentinel / test".into(),
                app_id: Some(42)
            }]
        );
        assert_eq!(
            change.restore,
            [RequiredCheck {
                context: "test".into(),
                app_id: Some(15368)
            }]
        );
        assert_eq!(change.strict, None);
        assert!(!change.is_empty());

        // The same document on both sides moves nothing.
        assert!(before.change_to(&before).is_empty());

        // A context re-bound to another App is a different check: it is taken out and put back.
        let rebound = checks(true, &[("build", Some(42))]);
        let change = rebound.change_to(&before);
        assert_eq!(change.remove.len(), 1);
        assert_eq!(change.restore.len(), 2);

        // The strict flag is restoration too.
        let loose = checks(false, &[("build", Some(15368))]);
        let change = loose.change_to(&before);
        assert_eq!(change.strict, Some(true));
        assert!(!change.is_empty());
    }

    #[test]
    fn a_protection_answer_is_read_or_refused() {
        let body = json!({"required_status_checks": {"strict": true,
            "checks": [{"context": "build", "app_id": 42}, {"context": "test"}]}});
        let read = RequiredChecks::read(&body).unwrap();
        assert_eq!(read, checks(true, &[("build", Some(42)), ("test", None)]));
        // The older spelling of the same statement.
        let body = json!({"required_status_checks": {"strict": false, "contexts": ["build"]}});
        assert_eq!(
            RequiredChecks::read(&body).unwrap(),
            checks(false, &[("build", None)])
        );
        // No required checks at all, and a body this module does not model.
        assert_eq!(
            RequiredChecks::read(&json!({"required_status_checks": null})).unwrap(),
            RequiredChecks::default()
        );
        assert!(
            RequiredChecks::read(&json!({"required_status_checks": {"strict": "yes"}})).is_none()
        );
        assert!(RequiredChecks::read(&json!({"enforce_admins": true})).is_none());
        let wide = json!({"required_status_checks": {"strict": true, "checks": vec![
            json!({"context": "c"}); MAX_CHECKS + 1]}});
        assert!(RequiredChecks::read(&wide).is_none());
        assert!(!context_text(""));
        assert!(!context_text(&"a".repeat(MAX_CONTEXT + 1)));
        assert!(!context_text("tab\there"));
        assert!(context_text("sentinel / build"));
    }

    #[test]
    fn the_write_states_the_whole_set_in_the_documents_order() {
        let document = checks(true, &[("test", Some(15368)), ("build", None)]);
        let written = document.write();
        assert_eq!(
            written,
            json!({"strict": true, "checks": [
                {"context": "test", "app_id": 15368},
                {"context": "build"}
            ]})
        );
        // What is written reads back as what was stated.
        let body = json!({"required_status_checks": written});
        assert_eq!(RequiredChecks::read(&body).unwrap(), document);
    }

    #[test]
    fn a_revision_that_is_not_a_commit_is_never_a_restore() {
        assert!(crate::migration::commit_id(&"a".repeat(40)));
        assert!(!crate::migration::commit_id("main"));
    }
}
