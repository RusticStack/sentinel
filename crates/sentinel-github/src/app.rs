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
        let installed = self.installation(installation, now_ms)?;
        if installed.suspended
            || !installed.permissions_valid
            || installed.account_id != account
            || repo == 0
        {
            return Err(Error::Response("installation access refused"));
        }
        let value = self.http.post_authenticated(
            &format!(
                "{}/app/installations/{installation}/access_tokens",
                self.endpoint
            ),
            &self.jwt(now_ms)?,
            &json!({"repository_ids":[repo],"permissions":{"contents":"read"}}),
        )?;
        let token = parse_token(&value, now_ms)?;
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

fn parse_token(v: &Value, now_ms: i64) -> Result<Token> {
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
    if permissions.get("contents").and_then(Value::as_str) != Some("read")
        || permissions.iter().any(|(k, v)| {
            !matches!(k.as_str(), "contents" | "metadata") || v.as_str() != Some("read")
        })
    {
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
        let token = parse_token(&v, now).unwrap();
        assert!(!format!("{token:?}").contains("private"));
        v["permissions"]["checks"] = json!("write");
        assert!(parse_token(&v, now).is_err());
        v["permissions"].as_object_mut().unwrap().remove("checks");
        assert!(parse_token(&v, token.expires_ms).is_err());
    }
}
