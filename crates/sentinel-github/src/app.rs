//! GitHub App identity is separate from human OAuth. Tokens are minted for
//! one immutable repository ID and contents:read only, without a token cache.
use crate::{Error, Result, http::Client};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde_json::{Value, json};

pub struct App {
    id: u64,
    key: RsaKeyPair,
    http: Client,
    endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    pub id: u64,
    pub account_id: u64,
    pub login: String,
    pub personal: bool,
    pub suspended: bool,
    pub permissions_valid: bool,
}

pub struct Token {
    pub secret: String,
    pub expires_ms: i64,
}

/// A repository an installation currently covers, as the API reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationRepo {
    pub id: u64,
    /// `owner/name`, GitHub's canonical spelling of the repository.
    pub full_name: String,
    pub archived: bool,
}

/// The answer to "which repositories does this installation cover".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallationRepos {
    pub repos: Vec<InstallationRepo>,
    /// The page cap stopped the walk: the list proves membership, never
    /// absence.
    pub truncated: bool,
}

/// What the reconcile lane learned about one bound repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoState {
    /// Id, owner and clone URL still match the approved binding.
    Verified,
    /// Renamed, transferred, archived or disabled: the approved remote no
    /// longer describes it.
    Changed,
    /// The API answered 404: deleted or removed from the installation.
    Gone,
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token(redacted)")
    }
}

impl App {
    /// GitHub's downloaded PKCS#1 PEM or unencrypted PKCS#8 PEM. Keep the
    /// protected key file outside SQLite and replace/restart for key rotation.
    pub fn new(id: u64, pem: &str) -> Result<Self> {
        if id == 0 || pem.len() > 16 * 1024 {
            return Err(Error::Config("App key"));
        }
        let pkcs8 = pem.starts_with("-----BEGIN PRIVATE KEY-----");
        let (begin, end) = if pkcs8 {
            ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
        } else {
            (
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
            )
        };
        let content = pem
            .trim()
            .strip_prefix(begin)
            .and_then(|s| s.strip_suffix(end))
            .ok_or(Error::Config("App key"))?;
        let encoded: String = content
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let mut bytes = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Config("App key"))?;
        let key = if pkcs8 {
            RsaKeyPair::from_pkcs8(&bytes)
        } else {
            RsaKeyPair::from_der(&bytes)
        };
        bytes.fill(0);
        let key = key.map_err(|_| Error::Config("App RSA key"))?;
        Ok(Self {
            id,
            key,
            http: Client::new(),
            endpoint: "https://api.github.com".into(),
        })
    }

    /// The same App against another API endpoint: a GitHub Enterprise host,
    /// or a test stub. The URL must be absolute, bounded, free of query and
    /// fragment, and use HTTPS — HTTP is accepted only for a loopback host,
    /// which is how the token and Checks paths are exercised offline.
    pub fn with_endpoint(mut self, endpoint: &str) -> Result<Self> {
        let trimmed = endpoint.trim_end_matches('/');
        let loopback = trimmed
            .strip_prefix("http://")
            .is_some_and(|rest| rest.starts_with("127.0.0.1:") || rest.starts_with("localhost:"));
        if !(trimmed.starts_with("https://") || loopback)
            || trimmed.len() > 256
            || trimmed.contains(['?', '#', ' '])
        {
            return Err(Error::Config("github endpoint"));
        }
        self.endpoint = trimmed.to_owned();
        Ok(self)
    }

    /// The endpoint this App talks to, for diagnostics (never a secret).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn jwt(&self, now_ms: i64) -> Result<String> {
        if now_ms < 60_000 {
            return Err(Error::Config("App clock"));
        }
        let claims = json!({"iss":self.id.to_string(),"iat":now_ms/1000-60,"exp":now_ms/1000+540});
        let mut jwt = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                jwt.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Config("App signing"))?;
        jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(signature, &mut jwt);
        Ok(jwt)
    }

    pub fn installation(&self, id: u64, now_ms: i64) -> Result<Installation> {
        let value = self.http.get_authenticated(
            &format!("{}/app/installations/{id}", self.endpoint),
            &self.jwt(now_ms)?,
        )?;
        parse_installation(&value, self.id, id)
    }

    /// The same read for the reconcile lane (G05): `Ok(None)` is a verified
    /// 404 — the installation is gone for good — while any other non-200 is a
    /// transport-class failure the caller retries.
    pub fn installation_status(&self, id: u64, now_ms: i64) -> Result<Option<Installation>> {
        let reply = self.http.send_json(
            "GET",
            &format!("{}/app/installations/{id}", self.endpoint),
            &self.jwt(now_ms)?,
            None,
        )?;
        match reply.status {
            200 => parse_installation(&reply.body, self.id, id).map(Some),
            404 => Ok(None),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// An installation-wide read token for reconciliation: `contents: read`
    /// over every repository the installation covers, minted only for an
    /// installation a fresh snapshot just proved usable. The token stays in
    /// the controller — it is never issued to a workload — and expires like
    /// every other installation token.
    pub fn reconciliation_token(&self, installation: &Installation, now_ms: i64) -> Result<Token> {
        if installation.suspended || !installation.permissions_valid {
            return Err(Error::Response("installation access refused"));
        }
        let value = self.http.post_authenticated(
            &format!(
                "{}/app/installations/{}/access_tokens",
                self.endpoint, installation.id
            ),
            &self.jwt(now_ms)?,
            &json!({"permissions":{"contents":"read"}}),
        )?;
        parse_token(&value, now_ms, &[("contents", "read")])
    }

    /// The repositories an installation currently covers, in bounded pages.
    /// `truncated` means the page cap stopped the walk: the list then proves
    /// membership and naming, never absence — a caller must not revoke what
    /// it did not see.
    pub fn installation_repositories(&self, token: &Token) -> Result<InstallationRepos> {
        const PER_PAGE: u32 = 100;
        const MAX_PAGES: u32 = 10;
        let mut repos = Vec::new();
        for page in 1..=MAX_PAGES {
            let reply = self.http.send_json_bounded(
                "GET",
                &format!(
                    "{}/installation/repositories?per_page={PER_PAGE}&page={page}",
                    self.endpoint
                ),
                &token.secret,
                None,
                1024 * 1024,
            )?;
            if reply.status != 200 {
                return Err(Error::Transport(format!("status {}", reply.status)));
            }
            let list = reply.body["repositories"]
                .as_array()
                .ok_or(Error::Response("repository list"))?;
            for repo in list {
                repos.push(InstallationRepo {
                    id: repo["id"]
                        .as_u64()
                        .filter(|id| *id > 0)
                        .ok_or(Error::Response("repository id"))?,
                    full_name: repo["full_name"]
                        .as_str()
                        .filter(|name| !name.is_empty() && name.len() <= 255)
                        .ok_or(Error::Response("repository name"))?
                        .to_owned(),
                    archived: repo["archived"].as_bool().unwrap_or(false),
                });
            }
            if (list.len() as u32) < PER_PAGE {
                return Ok(InstallationRepos {
                    repos,
                    truncated: false,
                });
            }
        }
        Ok(InstallationRepos {
            repos,
            truncated: true,
        })
    }

    /// Whether the repository a binding approved still is that repository.
    /// `Gone` and `Changed` both revoke: an approved remote never silently
    /// follows a removal, rename, transfer or archival. Any other non-200 is
    /// transport-class — the caller retries rather than revoking on a guess.
    pub fn repository_state(
        &self,
        token: &Token,
        repo: u64,
        remote: &str,
        account: u64,
    ) -> Result<RepoState> {
        let reply = self.http.send_json(
            "GET",
            &format!("{}/repositories/{repo}", self.endpoint),
            &token.secret,
            None,
        )?;
        match reply.status {
            200 => {
                let v = &reply.body;
                let same = v["id"].as_u64() == Some(repo)
                    && v["owner"]["id"].as_u64() == Some(account)
                    && v["clone_url"].as_str() == Some(remote);
                if !same || v["archived"].as_bool().unwrap_or(false) {
                    return Ok(RepoState::Changed);
                }
                Ok(RepoState::Verified)
            }
            404 => Ok(RepoState::Gone),
            401 => Err(Error::Response("token refused")),
            _ => Err(Error::Transport(format!("status {}", reply.status))),
        }
    }

    /// Validate the installation, restrict token scope explicitly, then verify
    /// repository ownership and the exact approved clone URL using that token.
    pub fn source_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        now_ms: i64,
    ) -> Result<Token> {
        self.repository_token(
            installation,
            account,
            repo,
            remote,
            now_ms,
            &[("contents", "read")],
        )
    }

    /// A token for publishing Checks (G04): `checks: write` and nothing else,
    /// for the same one immutable repository and with the same verification.
    /// A different permission set is a different token, never a wider one.
    pub fn checks_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        now_ms: i64,
    ) -> Result<Token> {
        self.repository_token(
            installation,
            account,
            repo,
            remote,
            now_ms,
            &[("checks", "write")],
        )
    }

    fn repository_token(
        &self,
        installation: u64,
        account: u64,
        repo: u64,
        remote: &str,
        now_ms: i64,
        permissions: &[(&str, &str)],
    ) -> Result<Token> {
        let installed = self.installation(installation, now_ms)?;
        if installed.suspended
            || !installed.permissions_valid
            || installed.account_id != account
            || repo == 0
        {
            return Err(Error::Response("installation access refused"));
        }
        let granted: serde_json::Map<String, Value> = permissions
            .iter()
            .map(|(key, value)| ((*key).to_owned(), Value::from(*value)))
            .collect();
        let value = self.http.post_authenticated(
            &format!(
                "{}/app/installations/{installation}/access_tokens",
                self.endpoint
            ),
            &self.jwt(now_ms)?,
            &json!({"repository_ids":[repo],"permissions":granted}),
        )?;
        let token = parse_token(&value, now_ms, permissions)?;
        let repository = self.http.get_authenticated(
            &format!("{}/repositories/{repo}", self.endpoint),
            &token.secret,
        )?;
        if repository["id"].as_u64() != Some(repo)
            || repository["owner"]["id"].as_u64() != Some(account)
            || repository["clone_url"].as_str() != Some(remote)
        {
            return Err(Error::Response("repository identity or remote changed"));
        }
        Ok(token)
    }
}

fn parse_installation(v: &Value, app: u64, id: u64) -> Result<Installation> {
    let account_id = v["account"]["id"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(Error::Response("installation account"))?;
    let login = v["account"]["login"]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .ok_or(Error::Response("installation login"))?;
    let personal = match v["account"]["type"].as_str() {
        Some("User") => true,
        Some("Organization") => false,
        _ => return Err(Error::Response("installation account type")),
    };
    if v["id"].as_u64() != Some(id)
        || v["app_id"].as_u64() != Some(app)
        || v.get("suspended_at").is_none()
    {
        return Err(Error::Response("installation identity"));
    }
    Ok(Installation {
        id,
        account_id,
        login: login.into(),
        personal,
        suspended: !v["suspended_at"].is_null(),
        permissions_valid: matches!(
            v["permissions"]["contents"].as_str(),
            Some("read" | "write")
        ) && v["permissions"]["checks"].as_str() == Some("write"),
    })
}

fn parse_token(v: &Value, now_ms: i64, requested: &[(&str, &str)]) -> Result<Token> {
    let secret = v["token"]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 4096
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .ok_or(Error::Response("installation token"))?;
    let permissions = v["permissions"]
        .as_object()
        .ok_or(Error::Response("token permissions"))?;
    // The token must carry exactly what was requested (metadata read is the
    // implicit companion), never more: a narrowed token is the whole point.
    let allows_metadata = permissions
        .iter()
        .all(|(key, _)| key == "metadata" || requested.iter().any(|(k, _)| k == key));
    let exact = requested
        .iter()
        .all(|(key, value)| permissions.get(*key).and_then(Value::as_str) == Some(*value));
    if !allows_metadata || !exact {
        return Err(Error::Response("token permission scope"));
    }
    let expiry = v["expires_at"]
        .as_str()
        .ok_or(Error::Response("token expiry"))?;
    let expires_ms =
        time::OffsetDateTime::parse(expiry, &time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Response("token expiry"))?
            .unix_timestamp_nanos()
            / 1_000_000;
    let expires_ms = i64::try_from(expires_ms).map_err(|_| Error::Response("token expiry"))?;
    if expires_ms <= now_ms + 60_000 || expires_ms > now_ms + 3_660_000 {
        return Err(Error::Response("token lifetime"));
    }
    Ok(Token {
        secret: secret.into(),
        expires_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_identity_permissions_and_account_types() {
        let mut v = json!({"id":4,"app_id":2,"account":{"id":9,"login":"sample","type":"Organization"},"suspended_at":null,"permissions":{"contents":"read","checks":"write"}});
        assert!(!parse_installation(&v, 2, 4).unwrap().personal);
        v["account"]["type"] = json!("User");
        assert!(parse_installation(&v, 2, 4).unwrap().personal);
        assert!(parse_installation(&v, 3, 4).is_err());
        v["permissions"]["checks"] = json!("read");
        assert!(!parse_installation(&v, 2, 4).unwrap().permissions_valid);
        v["suspended_at"] = json!("2026-09-14T00:00:00Z");
        assert!(parse_installation(&v, 2, 4).unwrap().suspended);
    }
    #[test]
    fn token_is_read_only_short_lived_and_debug_redacted() {
        let now = 1_789_344_000_000;
        let mut v = json!({"token":"ghs_private_value","expires_at":"2026-09-14T01:00:00Z","permissions":{"contents":"read","metadata":"read"}});
        let source = [("contents", "read")];
        let token = parse_token(&v, now, &source).unwrap();
        assert!(!format!("{token:?}").contains("private"));
        v["permissions"]["checks"] = json!("write");
        assert!(parse_token(&v, now, &source).is_err());
        v["permissions"].as_object_mut().unwrap().remove("checks");
        assert!(parse_token(&v, token.expires_ms, &source).is_err());
        // The checks token is a different, equally exact permission set.
        assert!(parse_token(&v, now, &[("checks", "write")]).is_err());
        v["permissions"] = json!({"checks":"write","metadata":"read"});
        assert!(parse_token(&v, now, &[("checks", "write")]).is_ok());
        assert!(parse_token(&v, now, &source).is_err());
        // A wider grant than requested is refused, not narrowed silently.
        v["permissions"] = json!({"checks":"write","contents":"read","metadata":"read"});
        assert!(parse_token(&v, now, &[("checks", "write")]).is_err());
    }
}
