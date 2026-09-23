//! Named sign-in profiles (O04): `profiles.json` (schema
//! `sentinel.profiles/1`, no secrets) in the configuration directory, the
//! credential blob in the OS store or an owner-only file, and access-token
//! refresh serialized across processes by a lock file.
//!
//! Stub: the signatures are the contract [`crate::client`] builds on; Unit D
//! implements them. Until then no profile exists, so commands need a static
//! credential (`--token-file` or `SENTINEL_TOKEN`).

use crate::client::{self, Exit};

/// One resolved profile: its name, the normalized server it belongs to, the
/// default tenant, and access to its stored credential.
pub struct Handle {
    name: String,
    server: String,
    tenant: Option<String>,
}

/// Resolve `name`, or the `current` profile when `None`. `Ok(None)` means
/// no profile is configured at all.
pub fn resolve(name: Option<&str>) -> Result<Option<Handle>, client::Error> {
    let _ = name;
    Ok(None)
}

impl Handle {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The profile's server (normalized when the profile was written).
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The default tenant chosen with `sentinel context use`.
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// A usable access token, refreshed under the profile lock when fewer
    /// than 30 seconds remain.
    pub fn access_token(&self, agent: &ureq::Agent) -> Result<String, client::Error> {
        let _ = agent;
        Err(client::Error::new(
            Exit::Usage,
            "profiles are not available yet",
        ))
    }

    /// Refresh after the server rejected `rejected`; if another process has
    /// already replaced it, use the newer token instead of refreshing again.
    pub fn force_refresh(
        &self,
        agent: &ureq::Agent,
        rejected: &str,
    ) -> Result<String, client::Error> {
        let _ = (agent, rejected);
        Err(client::Error::new(
            Exit::Usage,
            "profiles are not available yet",
        ))
    }
}
