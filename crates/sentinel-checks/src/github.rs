//! The GitHub publisher: turns a stored publication into a check run.
//!
//! It mints one `checks: write` token per repository and reuses it until it is
//! close to expiring, adopts a check run an earlier attempt may have created
//! before creating another one, and maps GitHub's refusals onto the lane's
//! three outcomes: retry, refuse, or pause the lane when the rate limit is
//! spent.

use std::collections::HashMap;
use std::sync::Arc;

use sentinel_core::{RepoId, UnixMillis};
use sentinel_github::{
    app::App,
    checks::{self as api, Check, Lookup, Refusal},
    http::Client,
};
use sentinel_store::{Error as StoreError, Store, checks, sources, sources_forge};

use crate::lane::Publish;

/// How long before expiry a cached token is replaced.
const TOKEN_MARGIN_MS: i64 = 120_000;
const MAX_CACHED_TOKENS: usize = 1024;
/// Longest rate-limit pause accepted, whatever GitHub says.
const MAX_PAUSE_MS: i64 = 60 * 60 * 1000;

struct CachedToken {
    secret: String,
    expires_ms: i64,
}

pub struct GithubChecks {
    store: Arc<Store>,
    app: Arc<App>,
    client: Client,
    /// Public base URL of this deployment for `details_url`; absent means the
    /// checks carry no link.
    public_url: Option<String>,
    /// One token per repository: an installation token is repository-scoped.
    tokens: HashMap<RepoId, CachedToken>,
}

impl GithubChecks {
    pub fn new(store: Arc<Store>, app: Arc<App>, public_url: Option<String>) -> GithubChecks {
        GithubChecks {
            store,
            app,
            client: Client::new(),
            public_url: public_url.map(|url| url.trim_end_matches('/').to_owned()),
            tokens: HashMap::new(),
        }
    }

    /// A token for this repository, cached until close to expiry. The
    /// installation, account and clone URL are verified by the App client.
    fn token(
        &mut self,
        repo: RepoId,
        installation: u64,
        account: u64,
        forge_repo: u64,
        remote: &str,
        now: UnixMillis,
    ) -> Result<String, Publish> {
        if let Some(cached) = self.tokens.get(&repo)
            && cached.expires_ms > now.0 + TOKEN_MARGIN_MS
        {
            return Ok(cached.secret.clone());
        }
        let token = self
            .app
            .checks_token(installation, account, forge_repo, remote, now.0)
            .map_err(|error| match error {
                sentinel_github::Error::Config(_) => Publish::Refused {
                    reason: "app_config".into(),
                },
                other => Publish::Retry {
                    after_ms: 0,
                    detail: format!("token: {other}"),
                },
            })?;
        self.tokens.retain(|_, cached| cached.expires_ms > now.0);
        if self.tokens.len() >= MAX_CACHED_TOKENS
            && !self.tokens.contains_key(&repo)
            && let Some(oldest) = self
                .tokens
                .iter()
                .min_by_key(|(_, cached)| cached.expires_ms)
                .map(|(repo, _)| *repo)
        {
            self.tokens.remove(&oldest);
        }
        self.tokens.insert(
            repo,
            CachedToken {
                expires_ms: token.expires_ms,
                secret: token.secret.clone(),
            },
        );
        Ok(token.secret)
    }

    fn details_url(&self, run: Option<sentinel_core::RunId>) -> Option<String> {
        let base = self.public_url.as_deref()?;
        let run = run?;
        Some(format!("{base}/#/runs/{run}"))
    }

    fn check(&self, publication: &checks::Publication, now: UnixMillis) -> Result<Check, Publish> {
        let status =
            api::Status::parse(publication.status.as_str()).ok_or_else(|| Publish::Refused {
                reason: "check status".into(),
            })?;
        let conclusion = match publication.conclusion {
            None => None,
            Some(text) => {
                Some(
                    api::Conclusion::parse(text.as_str()).ok_or_else(|| Publish::Refused {
                        reason: "check conclusion".into(),
                    })?,
                )
            }
        };
        Ok(Check {
            name: publication.name.clone(),
            head_sha: publication.head_sha.clone(),
            status,
            conclusion,
            title: publication.title.clone(),
            summary: publication.summary.clone(),
            external_id: publication.external_id.clone(),
            details_url: self.details_url(publication.run),
            completed_at: (status == api::Status::Completed).then(|| api::timestamp(now.0)),
        })
    }
}

/// What the store needs to publish one row: the binding under it, the forge
/// association, and the canonical `owner/name` GitHub knows it by.
struct Source {
    remote: String,
    installation: u64,
    account: u64,
    forge_repo: u64,
}

fn load_source(store: &Store, publication: &checks::Publication) -> Result<Source, Publish> {
    let (tenant, repo) = (publication.tenant, publication.repo);
    let loaded = store
        .read(move |c| {
            let metadata = sources::load_metadata(c, repo)?;
            let grant = match metadata.forge {
                Some(_) => Some(sources_forge::grant(c, tenant, repo)?),
                None => None,
            };
            Ok((metadata.revoked, metadata.binding.remote, grant))
        })
        .map_err(|error| match error {
            StoreError::NotFound => Publish::Refused {
                reason: "binding_revoked".into(),
            },
            _ => Publish::Retry {
                after_ms: 0,
                detail: "store".into(),
            },
        })?;
    let (revoked, remote, grant) = loaded;
    let Some(grant) = grant else {
        return Err(Publish::Refused {
            reason: "binding_revoked".into(),
        });
    };
    if revoked {
        return Err(Publish::Refused {
            reason: "binding_revoked".into(),
        });
    }
    Ok(Source {
        remote,
        installation: grant.installation,
        account: grant.account,
        forge_repo: grant.repo,
    })
}

impl crate::lane::Publisher for GithubChecks {
    fn publish(&mut self, publication: &checks::Publication) -> Publish {
        let now = UnixMillis::now();
        let source = match load_source(&self.store, publication) {
            Ok(source) => source,
            Err(outcome) => return outcome,
        };
        let Some((owner, name)) = api::repository_path(&source.remote) else {
            return Publish::Refused {
                reason: "repository path".into(),
            };
        };
        let token = match self.token(
            publication.repo,
            source.installation,
            source.account,
            source.forge_repo,
            &source.remote,
            now,
        ) {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        let check = match self.check(publication, now) {
            Ok(check) => check,
            Err(outcome) => return outcome,
        };
        // An earlier attempt may have created the run and timed out before
        // recording it: adopt it by our own external ID before creating
        // another one.
        let existing = match publication.check_run_id {
            Some(id) => Some(id),
            None => match api::find(
                &self.client,
                self.app.endpoint(),
                &token,
                &Lookup {
                    owner: &owner,
                    repo: &name,
                    head_sha: &publication.head_sha,
                    name: &publication.name,
                    external_id: &publication.external_id,
                },
            ) {
                Ok(found) => found.map(|found| found.check_run_id),
                Err(refusal) => return self.refusal(publication, refusal, true),
            },
        };
        let outcome = match existing {
            Some(id) => api::update(
                &self.client,
                self.app.endpoint(),
                &token,
                &owner,
                &name,
                id,
                &check,
            ),
            None => api::create(
                &self.client,
                self.app.endpoint(),
                &token,
                &owner,
                &name,
                &check,
            ),
        };
        match outcome {
            Ok(published) => Publish::Published {
                check_run_id: published.check_run_id,
            },
            Err(refusal) => self.refusal(publication, refusal, false),
        }
    }
}

impl GithubChecks {
    fn refusal(
        &mut self,
        publication: &checks::Publication,
        refusal: Refusal,
        during_find: bool,
    ) -> Publish {
        match refusal {
            Refusal::RateLimited { retry_after_ms } => Publish::Throttled {
                until_ms: UnixMillis::now()
                    .0
                    .saturating_add(retry_after_ms.clamp(1_000, MAX_PAUSE_MS)),
            },
            Refusal::Unauthorized => {
                // The cached token is stale or the permission was withdrawn:
                // drop it and let the next attempt mint a fresh one.
                self.tokens.remove(&publication.repo);
                Publish::Retry {
                    after_ms: 0,
                    detail: "token refused".into(),
                }
            }
            Refusal::Unavailable { reason } => Publish::Retry {
                after_ms: 0,
                detail: format!("github: {reason}"),
            },
            Refusal::Refused { reason } => {
                // A check run that vanished is not worth recreating under the
                // same name: report it rather than publishing a duplicate.
                let reason = if during_find {
                    format!("lookup: {reason}")
                } else {
                    reason
                };
                Publish::Refused { reason }
            }
        }
    }
}
