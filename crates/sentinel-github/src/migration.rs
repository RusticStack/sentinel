//! Guided migration's writes through the App's migration permissions (H04): the workflow files a
//! repository holds at the analysed commit, the `sentinel/migrate` branch built from it, and the
//! pull request against the default branch.
//!
//! The branch is the only ref this module ever moves, and its name is a constant: a request whose
//! head would be anything else is refused before a request is made, so a migration can never push
//! to the repository's default branch. Re-running is the same call — the branch it already has is
//! fast-forwarded to the new commit and the pull request it already has is updated, so a migration
//! runs as often as it likes and leaves one branch and one pull request behind.
//!
//! A refusal a person's setting decides is reported, never forced: branch protection declining the
//! update answers [`Error::Refused`], and the ref is left as it is ([GitHub App](../../../docs/github-app.md#migration-permissions)).

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;

use crate::{
    Error, Result,
    app::{App, Token, valid_path_part},
};

/// The one branch a migration commits to.
pub const BRANCH: &str = "sentinel/migrate";

/// Where a repository's workflows live: the analyzer's own directory.
pub const WORKFLOWS: &str = ".github/workflows";

/// The workflow files one migration reads or writes: the analyzer's `MAX_WORKFLOW_FILES`.
pub const MAX_WORKFLOW_FILES: usize = 64;
/// One workflow file: the pipeline loader's `MAX_PIPELINE_FILE_BYTES`, so a file the analyzer would
/// read is a file this module can carry.
pub const MAX_WORKFLOW_BYTES: usize = 256 * 1024;
/// The largest commit this module sends: 64 files of at most 256 KiB, and never more than this.
pub const MAX_COMMIT_BYTES: usize = 8 << 20;
const MAX_TITLE: usize = 256;
const MAX_TEXT: usize = 60 * 1024;
const MAX_COMMIT: usize = 40 * 1024;
/// A body read back for one workflow: its base64, which is a third larger than the bytes.
const READ_BYTES: u64 = (MAX_WORKFLOW_BYTES * 2) as u64;
/// A tree, commit or pull request answered in one small body.
const SMALL_BODY: u64 = 64 * 1024;

/// The permission triple an installation token needs to make a migration write. All three are
/// repository permissions, so a personal namespace asks for exactly what an organization does.
pub const PERMISSIONS: &[(&str, &str)] = &[
    ("contents", "write"),
    ("pull_requests", "write"),
    ("workflows", "write"),
];

/// One workflow file as the repository holds it at a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workflow {
    pub path: String,
    pub text: String,
}

/// One workflow file a commit writes, as the change generator produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewritten<'a> {
    pub path: &'a str,
    pub text: &'a str,
}

/// What to commit and open: the commit the branch is built from, the files the commit rewrites,
/// and the pull request's message, title and body.
pub struct Migrate<'a> {
    pub commit: &'a str,
    pub files: &'a [Rewritten<'a>],
    pub message: &'a str,
    pub title: &'a str,
    pub body: &'a str,
}

/// The pull request one write addressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pull {
    pub number: u64,
    pub url: String,
    /// The commit the branch holds after the write.
    pub head: String,
    /// The branch the pull request proposes into: the repository's default branch, as it is now.
    pub base: String,
}

/// What a migration write did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The branch did not exist: it was created and the pull request opened.
    Opened(Pull),
    /// The branch existed: it was fast-forwarded and its pull request updated, never a second one.
    Updated(Pull),
    /// The open pull request was closed, with the branch it came from left in place.
    Closed(Pull),
    /// There was no open pull request to close.
    Nothing,
}

/// Whether `commit` is a commit id: what GitHub states and what the analyzer pins.
pub fn commit_id(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A workflow file's name as a path this module may address: unreserved characters only, so the
/// request path it builds needs no escaping and cannot leave the directory.
fn workflow_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && !name.eq_ignore_ascii_case("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The path of one workflow file under the workflows directory, when the name is one this module
/// can address and the file is one the analyzer reads.
fn workflow_path(name: &str) -> Option<String> {
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    (yaml && workflow_name(name)).then(|| format!("{WORKFLOWS}/{name}"))
}

fn bounded_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty()
        && text.len() <= max
        && !text.chars().any(|c| c.is_control() && c != '\n')
}

impl App {
    /// An installation token that may commit the migration branch and its pull request, scoped to
    /// one repository and verified to still be the one the binding names.
    pub fn migration_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        now_ms: i64,
    ) -> Result<Token> {
        self.repository_token(installation, account, repo, remote, now_ms, PERMISSIONS)
    }

    /// The workflow files `.github/workflows` holds at `commit`, in path order. A repository with
    /// no workflows directory holds none, which a migration treats as nothing to migrate.
    pub fn workflows(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Vec<Workflow>> {
        if !valid_path_part(owner) || !valid_path_part(repo) || !commit_id(commit) {
            return Err(Error::Config("migration revision"));
        }
        let listing = self.http.send_json(
            "GET",
            &self.api(&format!(
                "/repos/{owner}/{repo}/contents/{WORKFLOWS}?ref={commit}"
            )),
            &token.secret,
            None,
        )?;
        let entries = match listing.status {
            200 => listing.body,
            404 => return Ok(Vec::new()),
            401 | 403 => return Err(Error::Response("workflow listing refused")),
            _ => return Err(Error::Transport(format!("status {}", listing.status))),
        };
        let entries = entries
            .as_array()
            .ok_or(Error::Response("workflow listing"))?;
        if entries.len() > MAX_WORKFLOW_FILES {
            return Err(Error::Response("workflow count"));
        }
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry["type"].as_str() != Some("file") {
                continue;
            }
            let Some(name) = entry["name"].as_str() else {
                continue;
            };
            let Some(path) = workflow_path(name) else {
                continue;
            };
            out.push(Workflow {
                text: self.workflow_text(token, owner, repo, commit, name)?,
                path,
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// One workflow file's text at a commit: the Contents API states it base64, and a file larger
    /// than the pipeline loader reads is refused rather than truncated.
    fn workflow_text(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        commit: &str,
        name: &str,
    ) -> Result<String> {
        let reply = self.http.send_json_at_most(
            "GET",
            &self.api(&format!(
                "/repos/{owner}/{repo}/contents/{WORKFLOWS}/{name}?ref={commit}"
            )),
            &token.secret,
            None,
            MAX_COMMIT_BYTES,
            READ_BYTES,
        )?;
        if reply.status != 200 {
            return Err(Error::Transport(format!("status {}", reply.status)));
        }
        let encoded = reply.body["content"]
            .as_str()
            .filter(|text| text.len() <= READ_BYTES as usize)
            .ok_or(Error::Response("workflow content"))?;
        if reply.body["encoding"].as_str() != Some("base64") {
            return Err(Error::Response("workflow encoding"));
        }
        let mut bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Response("workflow content"))?;
        if bytes.len() > MAX_WORKFLOW_BYTES {
            return Err(Error::Response("workflow size"));
        }
        let text = String::from_utf8(std::mem::take(&mut bytes))
            .map_err(|_| Error::Response("workflow encoding"))?;
        Ok(text)
    }

    /// Open the migration pull request, or update the one the branch already has: the branch is
    /// created from `request.commit` or fast-forwarded to it, the commit carries exactly the files
    /// the diff rewrote, and the pull request's base is the repository's default branch.
    pub fn migrate(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        request: &Migrate<'_>,
    ) -> Result<Outcome> {
        self.checked(owner, repo, request)?;
        let base = self.default_branch(token, owner, repo)?;
        let parent = self
            .tree_of(token, owner, repo, request.commit)?
            .ok_or(Error::Response("commit tree"))?;
        let tree = self.write_tree(token, owner, repo, &parent, request.files)?;
        // A re-run at a commit nothing has changed at writes no commit: the branch already holds
        // this tree, so the history stays one commit per analysis that changed something.
        let head = self.branch_head(token, owner, repo)?;
        let unchanged = match &head {
            Some(commit) => self.tree_of(token, owner, repo, commit)?.as_deref() == Some(&tree),
            None => false,
        };
        let commit = match (&head, unchanged) {
            (Some(commit), true) => commit.clone(),
            _ => {
                let commit = self.write_commit(token, owner, repo, request, &tree)?;
                self.move_branch(token, owner, repo, &commit, head.is_none())?;
                commit
            }
        };
        let pull = self.publish(token, owner, repo, &base, &commit, request)?;
        Ok(if head.is_some() {
            Outcome::Updated(pull)
        } else {
            Outcome::Opened(pull)
        })
    }

    /// Close the migration branch's open pull request, leaving the branch in place: what a tenant
    /// that stops at this point keeps is the branch it can re-run, not a proposal it withdrew.
    pub fn close_migration(&self, token: &Token, owner: &str, repo: &str) -> Result<Outcome> {
        if !valid_path_part(owner) || !valid_path_part(repo) {
            return Err(Error::Config("repository"));
        }
        let Some((number, url, head, base)) = self.open_pull_request(token, owner, repo)? else {
            return Ok(Outcome::Nothing);
        };
        let reply = self.http.send_json(
            "PATCH",
            &self.api(&format!("/repos/{owner}/{repo}/pulls/{number}")),
            &token.secret,
            Some(&json!({"state": "closed"})),
        )?;
        match reply.status {
            200 => Ok(Outcome::Closed(Pull {
                number,
                url,
                head,
                base,
            })),
            404 => Ok(Outcome::Nothing),
            401 | 403 => Err(Error::Response("pull request refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// What this module sends, bounded before any request is made.
    fn checked(&self, owner: &str, repo: &str, request: &Migrate<'_>) -> Result<()> {
        if !valid_path_part(owner) || !valid_path_part(repo) {
            return Err(Error::Config("repository"));
        }
        if !commit_id(request.commit) {
            return Err(Error::Config("migration revision"));
        }
        if request.files.is_empty() || request.files.len() > MAX_WORKFLOW_FILES {
            return Err(Error::Config("migration files"));
        }
        let mut total = 0usize;
        for file in request.files {
            let name = file
                .path
                .strip_prefix(WORKFLOWS)
                .and_then(|rest| rest.strip_prefix('/'))
                .filter(|name| workflow_path(name).as_deref() == Some(file.path));
            if name.is_none() || file.text.len() > MAX_WORKFLOW_BYTES {
                return Err(Error::Config("migration file"));
            }
            total += file.text.len();
        }
        if total > MAX_COMMIT_BYTES {
            return Err(Error::Config("migration size"));
        }
        if !bounded_text(request.title, MAX_TITLE)
            || !bounded_text(request.body, MAX_TEXT)
            || !bounded_text(request.message, MAX_COMMIT)
        {
            return Err(Error::Config("migration text"));
        }
        Ok(())
    }

    /// The branch a pull request proposes into. It is read, never assumed, and a repository whose
    /// default branch is the migration branch has nowhere to open one.
    fn default_branch(&self, token: &Token, owner: &str, repo: &str) -> Result<String> {
        let reply = self.http.send_json(
            "GET",
            &self.api(&format!("/repos/{owner}/{repo}")),
            &token.secret,
            None,
        )?;
        match reply.status {
            200 => {}
            401 | 403 => return Err(Error::Response("repository refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        let base = reply.body["default_branch"]
            .as_str()
            .filter(|branch| valid_path_part(branch))
            .ok_or(Error::Response("repository default branch"))?;
        if base == BRANCH {
            return Err(Error::Config("migration base branch"));
        }
        Ok(base.to_owned())
    }

    /// The tree one commit holds. `None` for a commit the repository no longer holds, which a
    /// branch someone deleted leaves behind.
    fn tree_of(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Option<String>> {
        let reply = self.http.send_json(
            "GET",
            &self.api(&format!("/repos/{owner}/{repo}/git/commits/{commit}")),
            &token.secret,
            None,
        )?;
        match reply.status {
            200 => {}
            404 => return Ok(None),
            401 | 403 => return Err(Error::Response("commit refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        reply.body["tree"]["sha"]
            .as_str()
            .filter(|sha| commit_id(sha))
            .map(|sha| Some(sha.to_owned()))
            .ok_or(Error::Response("commit tree"))
    }

    /// The commit `sentinel/migrate` holds, if the branch exists at all.
    fn branch_head(&self, token: &Token, owner: &str, repo: &str) -> Result<Option<String>> {
        let reply = self.http.send_json(
            "GET",
            &self.api(&format!("/repos/{owner}/{repo}/git/ref/heads/{BRANCH}")),
            &token.secret,
            None,
        )?;
        match reply.status {
            200 => {}
            404 => return Ok(None),
            401 | 403 => return Err(Error::Response("branch refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        reply.body["object"]["sha"]
            .as_str()
            .filter(|sha| commit_id(sha))
            .map(|sha| Some(sha.to_owned()))
            .ok_or(Error::Response("branch"))
    }

    /// One tree over `base_tree` with the rewritten files in it, so the commit replaces exactly the
    /// workflows the diff changed and every other path stays as it was.
    fn write_tree(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        base_tree: &str,
        files: &[Rewritten<'_>],
    ) -> Result<String> {
        let mut entries = Vec::with_capacity(files.len());
        for file in files {
            entries.push(json!({
                "path": file.path,
                "mode": "100644",
                "type": "blob",
                "content": file.text,
            }));
        }
        let reply = self.http.send_json_at_most(
            "POST",
            &self.api(&format!("/repos/{owner}/{repo}/git/trees")),
            &token.secret,
            Some(&json!({"base_tree": base_tree, "tree": entries})),
            MAX_COMMIT_BYTES,
            SMALL_BODY,
        )?;
        match reply.status {
            200 | 201 => {}
            401 | 403 => return Err(Error::Response("tree refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        reply.body["sha"]
            .as_str()
            .filter(|sha| commit_id(sha))
            .map(str::to_owned)
            .ok_or(Error::Response("tree"))
    }

    fn write_commit(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        request: &Migrate<'_>,
        tree: &str,
    ) -> Result<String> {
        let reply = self.http.send_json(
            "POST",
            &self.api(&format!("/repos/{owner}/{repo}/git/commits")),
            &token.secret,
            Some(&json!({
                "message": request.message,
                "tree": tree,
                "parents": [request.commit],
            })),
        )?;
        match reply.status {
            200 | 201 => {}
            401 | 403 => return Err(Error::Response("commit refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        reply.body["sha"]
            .as_str()
            .filter(|sha| commit_id(sha))
            .map(str::to_owned)
            .ok_or(Error::Response("commit"))
    }

    /// Point `sentinel/migrate` at the new commit, creating it the first time. A refusal is the
    /// protection rule's answer, reported as such and never forced past.
    fn move_branch(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        commit: &str,
        create: bool,
    ) -> Result<()> {
        let reply = if create {
            self.http.send_json(
                "POST",
                &self.api(&format!("/repos/{owner}/{repo}/git/refs")),
                &token.secret,
                Some(&json!({"ref": format!("refs/heads/{BRANCH}"), "sha": commit})),
            )?
        } else {
            self.http.send_json(
                "PATCH",
                &self.api(&format!("/repos/{owner}/{repo}/git/refs/heads/{BRANCH}")),
                &token.secret,
                Some(&json!({"sha": commit, "force": true})),
            )?
        };
        match reply.status {
            200 | 201 => Ok(()),
            422 => Err(Error::Refused("branch protection")),
            401 | 403 => Err(Error::Response("branch refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// The open pull request the branch already has, if any: its number, page, head commit and the
    /// branch it proposes into.
    fn open_pull_request(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
    ) -> Result<Option<(u64, String, String, String)>> {
        let listing = self.http.send_json(
            "GET",
            &self.api(&format!(
                "/repos/{owner}/{repo}/pulls?state=open&per_page=1&head={owner}:{BRANCH}"
            )),
            &token.secret,
            None,
        )?;
        match listing.status {
            200 => {}
            401 | 403 => return Err(Error::Response("pull request listing refused")),
            _ => return Err(Error::Transport(format!("status {}", listing.status))),
        }
        let pulls = listing
            .body
            .as_array()
            .ok_or(Error::Response("pull request listing"))?;
        let Some(pull) = pulls.first() else {
            return Ok(None);
        };
        let number = pull["number"]
            .as_u64()
            .filter(|number| *number > 0)
            .ok_or(Error::Response("pull request number"))?;
        let url = pull["html_url"]
            .as_str()
            .filter(|url| crate::app::valid_page(url))
            .ok_or(Error::Response("pull request page"))?;
        let head = pull["head"]["sha"]
            .as_str()
            .filter(|sha| commit_id(sha))
            .unwrap_or_default();
        let base = pull["base"]["ref"]
            .as_str()
            .filter(|branch| valid_path_part(branch))
            .unwrap_or_default();
        Ok(Some((
            number,
            url.to_owned(),
            head.to_owned(),
            base.to_owned(),
        )))
    }

    /// Open the pull request, or update the one this branch already has. The base is the
    /// repository's default branch and the head is the migration branch, never the reverse.
    fn publish(
        &self,
        token: &Token,
        owner: &str,
        repo: &str,
        base: &str,
        commit: &str,
        request: &Migrate<'_>,
    ) -> Result<Pull> {
        if base == BRANCH {
            return Err(Error::Config("migration base branch"));
        }
        if let Some((number, url, _, _)) = self.open_pull_request(token, owner, repo)? {
            let reply = self.http.send_json(
                "PATCH",
                &self.api(&format!("/repos/{owner}/{repo}/pulls/{number}")),
                &token.secret,
                Some(&json!({"title": request.title, "body": request.body, "base": base})),
            )?;
            return match reply.status {
                200 => Ok(Pull {
                    number,
                    url,
                    head: commit.to_owned(),
                    base: base.to_owned(),
                }),
                422 => Err(Error::Refused("pull request update")),
                401 | 403 => Err(Error::Response("pull request refused")),
                _ => Err(Error::Transport(format!("status {}", reply.status))),
            };
        }
        let reply = self.http.send_json(
            "POST",
            &self.api(&format!("/repos/{owner}/{repo}/pulls")),
            &token.secret,
            Some(&json!({
                "title": request.title,
                "body": request.body,
                "head": BRANCH,
                "base": base,
            })),
        )?;
        match reply.status {
            200 | 201 => {}
            422 => return Err(Error::Refused("pull request")),
            401 | 403 => return Err(Error::Response("pull request refused")),
            _ => return Err(Error::Transport(format!("status {}", reply.status))),
        }
        let number = reply.body["number"]
            .as_u64()
            .filter(|number| *number > 0)
            .ok_or(Error::Response("pull request number"))?;
        let url = reply.body["html_url"]
            .as_str()
            .filter(|url| crate::app::valid_page(url))
            .ok_or(Error::Response("pull request page"))?;
        Ok(Pull {
            number,
            url: url.to_owned(),
            head: commit.to_owned(),
            base: base.to_owned(),
        })
    }

    fn api(&self, path: &str) -> String {
        let mut url = String::with_capacity(self.endpoint.len() + path.len());
        url.push_str(&self.endpoint);
        url.push_str(path);
        url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_migration_branch_and_a_workflow_file_are_addressable() {
        assert!(commit_id(&"a".repeat(40)));
        assert!(commit_id(&"0".repeat(64)));
        assert!(!commit_id("main"));
        assert!(!commit_id(&"a".repeat(39)));
        assert!(!commit_id(&format!("{}g", "a".repeat(39))));
        assert_eq!(
            workflow_path("ci.yml").as_deref(),
            Some(".github/workflows/ci.yml")
        );
        assert!(workflow_path("ci.yaml").is_some());
        assert!(workflow_path("ci.json").is_none());
        assert!(workflow_path("../escape.yml").is_none());
        assert!(workflow_path("a/b.yml").is_none());
        assert!(workflow_path("ci yml.yml").is_none());
        assert!(workflow_path(".yml").is_some());
        assert!(!workflow_name(".."));
        assert!(bounded_text("line\nline", 32));
        assert!(!bounded_text(" \n ", 32));
        assert!(!bounded_text("bell\u{7}", 32));
        assert!(!bounded_text("long", 2));
    }
}
