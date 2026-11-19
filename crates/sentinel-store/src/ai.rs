//! AI assistance policy (Part 22 Y01). Nothing here talks to a provider: this module
//! decides whether a request may be made at all, which is the whole of Y01.
//!
//! Two administrators must agree before one can be. A platform administrator allows
//! AI for the deployment and names the providers it may use; a tenant administrator
//! then opts that tenant in under a data policy. Off is the default on both sides, so
//! a fresh deployment and an upgraded one have nothing to switch on. There is no
//! cache: [`admit`] reads the policy per request, so a disable applies to the next
//! request that would have been made, and nothing is left queued to expire.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{TenantId, UnixMillis, UserId};

use crate::{
    Error, Result,
    auth::{Authority, require_tenant_admin},
    local_auth::{Event, audit},
};

/// The providers this deployment can speak to, in the order the allow-list lists
/// them. Bit `n` of `deployment_policy.ai_providers` is `Provider::ALL[n]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Provider {
    /// An OpenAI-compatible endpoint on loopback or a private network: Ollama, vLLM, a LiteLLM gateway.
    Local = 0,
    /// The default hosted provider: one key for many models, zero data retention enforced per request.
    OpenRouter = 1,
    Anthropic = 2,
    OpenAi = 3,
}

impl Provider {
    pub const ALL: [Provider; 4] = [Self::Local, Self::OpenRouter, Self::Anthropic, Self::OpenAi];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::OpenRouter => "openrouter",
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str() == text)
    }

    const fn mask(self) -> i64 {
        1 << self as u8
    }

    /// Whether every byte of a request stays inside the operator's own network.
    const fn stays_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// A set of providers, as the deployment's allow-list is stored and returned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Providers(i64);

impl Providers {
    pub const NONE: Self = Self(0);

    pub fn insert(&mut self, provider: Provider) {
        self.0 |= provider.mask();
    }

    pub const fn contains(self, provider: Provider) -> bool {
        self.0 & provider.mask() != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// In the providers' own order, so two readings of one policy print alike.
    pub fn list(self) -> impl Iterator<Item = Provider> {
        Provider::ALL
            .into_iter()
            .filter(move |provider| self.contains(*provider))
    }

    fn from_bits(bits: i64) -> Result<Self> {
        let known = Provider::ALL.iter().fold(0, |all, p| all | p.mask());
        if bits < 0 || bits & !known != 0 {
            return Err(Error::Corrupt("deployment_policy.ai_providers"));
        }
        Ok(Self(bits))
    }
}

/// What a tenant's opt-in commits to on the provider's side ([ai](../docs/ai.md)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataPolicy {
    /// Only an allow-listed endpoint inside the operator's own network.
    LocalOnly = 0,
    /// Only providers that keep neither the prompt nor the answer after the response.
    ZeroRetention = 1,
    /// The provider's own terms, which the operator accepts for this tenant.
    ProviderTerms = 2,
}

impl DataPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::ZeroRetention => "zero_retention",
            Self::ProviderTerms => "provider_terms",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::LocalOnly, Self::ZeroRetention, Self::ProviderTerms]
            .into_iter()
            .find(|policy| policy.as_str() == text)
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::LocalOnly,
            1 => Self::ZeroRetention,
            2 => Self::ProviderTerms,
            _ => return None,
        })
    }

    /// Whether a request to `provider` is within this policy. `zero_retention` allows
    /// every allow-listed provider because the retention it demands is a property of
    /// the request Y03 sends (`provider.zdr`, `data_collection: deny`), refused there
    /// for a provider that cannot honor it; `local_only` is a property of the provider
    /// the controller knows, so it is enforced here.
    pub const fn allows(self, provider: Provider) -> bool {
        match self {
            Self::LocalOnly => provider.stays_local(),
            Self::ZeroRetention | Self::ProviderTerms => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deployment {
    pub enabled: bool,
    pub providers: Providers,
}

pub fn deployment(conn: &Connection) -> Result<Deployment> {
    let (enabled, providers) = conn
        .prepare_cached("SELECT ai_enabled, ai_providers FROM deployment_policy WHERE id = 1")?
        .query_row([], |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(Deployment {
        enabled,
        providers: Providers::from_bits(providers)?,
    })
}

/// A platform administrator's decision, stepped up like every other deployment policy.
pub fn set_deployment(
    tx: &Transaction<'_>,
    authority: Authority,
    policy: Deployment,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    let bits = policy.providers.list().fold(0, |bits, p| bits | p.mask());
    tx.prepare_cached(
        "UPDATE deployment_policy SET ai_enabled = ?1, ai_providers = ?2,
         updated_ms = ?3, updated_by = ?4 WHERE id = 1",
    )?
    .execute(params![
        policy.enabled,
        bits,
        now.0,
        authority.actor().as_ref().map(UserId::as_bytes)
    ])?;
    let mut detail = String::from(if policy.enabled { "ai=on" } else { "ai=off" });
    detail.push_str(" providers=");
    for (at, provider) in policy.providers.list().enumerate() {
        if at > 0 {
            detail.push(',');
        }
        detail.push_str(provider.as_str());
    }
    audit(
        tx,
        Event::AiPolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub enabled: bool,
    pub data_policy: DataPolicy,
}

/// `None` until the tenant's administrator opts in: no row is off.
pub fn tenant(conn: &Connection, tenant: TenantId) -> Result<Option<Tenant>> {
    let row = conn
        .prepare_cached("SELECT enabled, data_policy FROM tenant_ai WHERE tenant_id = ?1")?
        .query_row([tenant.as_bytes()], |r| {
            Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?))
        })
        .optional()?;
    let (enabled, code) = match row {
        Some(row) => row,
        None => return Ok(None),
    };
    Ok(Some(Tenant {
        enabled,
        data_policy: DataPolicy::from_code(code).ok_or(Error::Corrupt("tenant_ai.data_policy"))?,
    }))
}

/// A tenant administrator's decision, refused without a live step-up. Disabling is
/// this one transaction: the request queue Y03 adds is deleted from here, in the same
/// commit that turns the tenant off.
pub fn set_tenant(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    policy: Tenant,
    now: UnixMillis,
) -> Result<()> {
    let principal = authority.principal().ok_or(Error::Forbidden)?;
    require_tenant_admin(tx, principal, tenant)?;
    authority.require_fresh(tx)?;
    if policy.enabled {
        let deployment = deployment(tx)?;
        if !deployment.enabled || deployment.providers.is_empty() {
            return Err(Error::Forbidden);
        }
    }
    tx.prepare_cached(
        "INSERT INTO tenant_ai(tenant_id, enabled, data_policy, updated_ms, updated_by)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(tenant_id) DO UPDATE SET enabled = ?2, data_policy = ?3,
         updated_ms = ?4, updated_by = ?5",
    )?
    .execute(params![
        tenant.as_bytes(),
        policy.enabled,
        policy.data_policy as u8,
        now.0,
        principal.user.as_bytes()
    ])?;
    let detail = format!(
        "tenant={tenant} ai={} data_policy={}",
        if policy.enabled { "on" } else { "off" },
        policy.data_policy.as_str()
    );
    audit(
        tx,
        Event::TenantAiPolicyChanged,
        Some(principal.user),
        None,
        false,
        Some(&detail),
    )
}

/// What `tenant` may use right now, and under which data policy; `NONE` and `None` while
/// either side is off. One statement for both rows, because the deployment's allow-list
/// and the tenant's opt-in decide together.
pub fn effective(conn: &Connection, tenant: TenantId) -> Result<(Providers, Option<DataPolicy>)> {
    let (enabled, providers, tenant_enabled, code) = conn
        .prepare_cached(
            "SELECT p.ai_enabled, p.ai_providers, t.enabled, t.data_policy
             FROM deployment_policy p LEFT JOIN tenant_ai t ON t.tenant_id = ?1
             WHERE p.id = 1",
        )?
        .query_row([tenant.as_bytes()], |r| {
            Ok((
                r.get::<_, bool>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<bool>>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
    if !enabled || tenant_enabled != Some(true) {
        return Ok((Providers::NONE, None));
    }
    let code = code.ok_or(Error::Corrupt("tenant_ai.data_policy"))?;
    let data_policy = DataPolicy::from_code(code).ok_or(Error::Corrupt("tenant_ai.data_policy"))?;
    let mut allowed = Providers::NONE;
    for provider in Providers::from_bits(providers)?.list() {
        if data_policy.allows(provider) {
            allowed.insert(provider);
        }
    }
    Ok((allowed, Some(data_policy)))
}

/// The single gate every AI request passes: `Some(policy)` is what a request for
/// `provider` on `tenant`'s behalf may be made under, `None` is no request at all.
pub fn admit(
    conn: &Connection,
    tenant: TenantId,
    provider: Provider,
) -> Result<Option<DataPolicy>> {
    let (providers, policy) = effective(conn, tenant)?;
    Ok(policy.filter(|_| providers.contains(provider)))
}
