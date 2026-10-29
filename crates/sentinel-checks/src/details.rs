//! The `details_url` a check carries: where a person lands from the GitHub UI.
//!
//! The route contract is owned here and documented in `docs/checks.md`: the
//! web interface (whatever it is built with) serves `GET <base>/runs/<run id>`
//! for the whole life of the check, signed-out visitors included (it asks them
//! to sign in and returns them). Nothing else is promised, so no check ever
//! links to a page that only one implementation of the interface happens to
//! serve.

use sentinel_core::RunId;
use sentinel_store::checks::{AGGREGATE_SCOPE, Publication};

/// Path of the run page, relative to the configured base.
pub const RUN_ROUTE: &str = "/runs";
/// Advisory query name on a per-job check. A page that ignores it still shows
/// the whole run, jobs included.
pub const JOB_PARAM: &str = "job";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Details {
    base: Option<String>,
}

impl Details {
    /// `base` is the deployment-facing origin (`https://ci.example.com`); a
    /// trailing slash is dropped and an empty one means no links.
    pub fn new(base: Option<String>) -> Details {
        Details {
            base: base
                .map(|url| url.trim_end_matches('/').to_owned())
                .filter(|url| !url.is_empty()),
        }
    }

    /// The run page, or `None` without a base.
    pub fn run(&self, run: RunId) -> Option<String> {
        Some(format!("{}{RUN_ROUTE}/{run}", self.base.as_deref()?))
    }

    /// The link for one publication, by kind:
    ///
    /// - aggregate check of a run: the run page;
    /// - per-job check: the run page with `?job=<job id>`;
    /// - a check that belongs to no run (a refused delivery): none.
    pub fn of(&self, publication: &Publication) -> Option<String> {
        let mut url = self.run(publication.run?)?;
        if publication.scope != AGGREGATE_SCOPE
            && publication.scope.parse::<sentinel_core::JobId>().is_ok()
        {
            url.push_str(&format!("?{JOB_PARAM}={}", publication.scope));
        }
        Some(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{CheckId, JobId, RepoId, TenantId};
    use sentinel_store::checks::{Conclusion, State, Status};

    fn publication(run: Option<RunId>, scope: &str) -> Publication {
        Publication {
            id: CheckId::new(),
            tenant: TenantId::new(),
            repo: RepoId::new(),
            run,
            delivery: None,
            scope: scope.to_owned(),
            name: "sentinel / ci".into(),
            head_sha: "0".repeat(40),
            external_id: String::new(),
            status: Status::Completed,
            conclusion: Some(Conclusion::Success),
            title: String::new(),
            summary: String::new(),
            check_run_id: None,
            check_suite_id: None,
            create_started_ms: None,
            create_seq: None,
            seq: 1,
            published_seq: 0,
            state: State::Pending,
            reason: None,
        }
    }

    #[test]
    fn each_check_kind_gets_its_documented_route() {
        let details = Details::new(Some("https://ci.example.com/".into()));
        let (run, job) = (RunId::new(), JobId::new());
        assert_eq!(
            details.of(&publication(Some(run), AGGREGATE_SCOPE)),
            Some(format!("https://ci.example.com/runs/{run}"))
        );
        assert_eq!(
            details.of(&publication(Some(run), &job.to_string())),
            Some(format!("https://ci.example.com/runs/{run}?job={job}"))
        );
        // A refused delivery belongs to no run, so it has no page to link.
        assert_eq!(details.of(&publication(None, AGGREGATE_SCOPE)), None);
    }

    #[test]
    fn an_unrecognised_scope_links_the_run_without_a_job_hint() {
        let details = Details::new(Some("https://ci.example.com".into()));
        let run = RunId::new();
        assert_eq!(
            details.of(&publication(Some(run), "not a job?x=1&y")),
            Some(format!("https://ci.example.com/runs/{run}"))
        );
    }

    #[test]
    fn without_a_base_no_check_carries_a_link() {
        let run = RunId::new();
        for base in [None, Some(String::new()), Some("/".into())] {
            let details = Details::new(base);
            assert_eq!(details.run(run), None);
            assert_eq!(details.of(&publication(Some(run), AGGREGATE_SCOPE)), None);
        }
    }
}
