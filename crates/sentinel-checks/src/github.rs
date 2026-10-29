use std::collections::HashMap;
use std::sync::Arc;

use sentinel_core::{RepoId, UnixMillis};
use sentinel_github::{
    app::App,
    checks::{self as api, Check, Lookup, Refusal},
    http::Client,
};
use sentinel_store::{Error as StoreError, Store, checks, sources, sources_forge};

use crate::details::Details;
use crate::lane::Publish;

const TOKEN_MARGIN_MS: i64 = 120_000;
const MAX_CACHED_TOKENS: usize = 1024;
const MAX_PAUSE_MS: i64 = 60 * 60 * 1000;

struct CachedToken {
    secret: String,
    expires_ms: i64,
}

impl Drop for CachedToken {
    fn drop(&mut self) {
        sentinel_auth::secret::wipe_string(&mut self.secret);
    }
}

/// The installation token a publish holds for the length of its requests: it derefs to the secret text and
/// is wiped when released, like the cache entry it was copied from.
struct Secret(String);

impl Secret {
    fn wipe(&mut self) {
        sentinel_auth::secret::wipe_string(&mut self.0);
    }
}

impl std::ops::Deref for Secret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct GithubChecks {
    store: Arc<Store>,
    app: Arc<App>,
    client: Client,
    details: Details,
    tokens: HashMap<RepoId, CachedToken>,
    // GitHub rate-limits per installation, which is the lane's throttle scope.
    installations: HashMap<RepoId, u64>,
}

impl GithubChecks {
    pub fn new(store: Arc<Store>, app: Arc<App>, public_url: Option<String>) -> GithubChecks {
        GithubChecks {
            store,
            app,
            client: Client::new(),
            details: Details::new(public_url),
            tokens: HashMap::new(),
            installations: HashMap::new(),
        }
    }

    fn remember_installation(&mut self, repo: RepoId, installation: u64) {
        if self.installations.len() >= MAX_CACHED_TOKENS && !self.installations.contains_key(&repo)
        {
            self.installations.clear();
        }
        self.installations.insert(repo, installation);
    }

    fn token(
        &mut self,
        repo: RepoId,
        installation: u64,
        account: u64,
        forge_repo: u64,
        remote: &str,
        now: UnixMillis,
    ) -> Result<Secret, Publish> {
        if let Some(cached) = self.tokens.get(&repo)
            && cached.expires_ms > now.0 + TOKEN_MARGIN_MS
        {
            return Ok(Secret(cached.secret.clone()));
        }
        let mut token = self
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
        Ok(Secret(std::mem::take(&mut token.secret)))
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
            external_id: publication.created_identity(),
            details_url: self.details.of(publication),
            completed_at: (status == api::Status::Completed).then(|| api::timestamp(now.0)),
        })
    }
}

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

const UNKNOWN_SCOPE: u64 = u64::MAX;

impl crate::lane::Publisher for GithubChecks {
    fn scope(&self, publication: &checks::Publication) -> u64 {
        self.installations
            .get(&publication.repo)
            .copied()
            .unwrap_or(UNKNOWN_SCOPE)
    }

    fn publish(&mut self, publication: &checks::Publication) -> Publish {
        let now = UnixMillis::now();
        let source = match load_source(&self.store, publication) {
            Ok(source) => source,
            Err(outcome) => return outcome,
        };
        self.remember_installation(publication.repo, source.installation);
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
        let mut check = match self.check(publication, now) {
            Ok(check) => check,
            Err(outcome) => return outcome,
        };
        // A create may have landed before its answer was recorded, so the lookup
        // is owed only when the durable create_started mark says one may exist.
        let existing = match publication.check_run_id {
            Some(id) => Some(id),
            None if publication.create_started_ms.is_some() => match api::find(
                &self.client,
                self.app.endpoint(),
                &token,
                &Lookup {
                    owner: &owner,
                    repo: &name,
                    head_sha: &publication.head_sha,
                    name: &publication.name,
                    external_id: &check.external_id,
                    any_status: publication.create_seq.is_some(),
                },
            ) {
                Ok(found) => found.map(|found| found.check_run_id),
                Err(refusal) => return self.refusal(publication, refusal, true),
            },
            None => None,
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
            None => {
                let (id, seq) = (publication.id, publication.seq);
                match self
                    .store
                    .writer()
                    .write(move |tx| checks::create_started(tx, id, seq, UnixMillis::now()))
                {
                    Ok(()) => {
                        check.external_id = checks::create_identity(&publication.external_id, seq);
                        api::create(
                            &self.client,
                            self.app.endpoint(),
                            &token,
                            &owner,
                            &name,
                            &check,
                        )
                    }
                    Err(StoreError::Conflict) => {
                        return Publish::Retry {
                            after_ms: 0,
                            detail: "generation moved".into(),
                        };
                    }
                    Err(_) => {
                        return Publish::Retry {
                            after_ms: 0,
                            detail: "store".into(),
                        };
                    }
                }
            }
        };
        match outcome {
            Ok(published) => Publish::Published {
                check_run_id: published.check_run_id,
                check_suite_id: published.check_suite_id,
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
                scope: self
                    .installations
                    .get(&publication.repo)
                    .copied()
                    .unwrap_or(UNKNOWN_SCOPE),
            },
            Refusal::Unauthorized => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_token_is_wiped_and_never_printed() {
        let mut secret = Secret("ghs_canary_token_value".to_owned());
        assert_eq!(&*secret, "ghs_canary_token_value");
        assert!(!format!("{secret:?}").contains("canary"));
        secret.wipe();
        assert!(
            secret.is_empty(),
            "the buffer is cleared before it is freed"
        );
    }
}
