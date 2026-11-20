//! AI assistance policy and its durable request queue (Part 22 Y01, Y03). Nothing here talks to a
//! provider: the first half decides whether a request may be made at all, and the second stores
//! each one as a row that `sentinel-ai` consumes through the API.
//!
//! Two administrators must agree before one can be. A platform administrator allows
//! AI for the deployment and names the providers it may use; a tenant administrator
//! then opts that tenant in under a data policy. Off is the default on both sides, so
//! a fresh deployment and an upgraded one have nothing to switch on. There is no
//! cache: [`admit`] reads the policy per request, so a disable applies to the next
//! request that would have been made, and nothing is left queued to expire.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AiRequestId, AttemptId, RepoId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Permissions, Scopes},
};

use crate::{
    Error, Result,
    auth::{Authority, require_repo, require_tenant_admin},
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
    // A disable takes the queue with it, and a withdrawn provider takes its queued requests: the
    // next request that would have been made is refused, and nothing is left waiting to expire.
    if policy.enabled {
        drop_providers(tx, policy.providers)?;
    } else {
        drop_requests(tx, None, now)?;
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
    if !policy.enabled {
        drop_requests(tx, Some(tenant), now)?;
    }
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

/// The gate the evidence bundle passes (Y02): whether `tenant` may have one at all, which is
/// whether [`admit`] would admit any allow-listed provider. It reads the policy the same way and
/// caches nothing, so a disable refuses the next bundle; the bundle names no provider because it
/// is built before a request picks one, and a tenant with none allowed has no bundle to build.
pub fn permits(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let (providers, policy) = effective(conn, tenant)?;
    Ok(policy.is_some() && !providers.is_empty())
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

// ---------------------------------------------------------------------------------------------
// Durable requests (Y03). The controller never calls a provider: it writes a row, and the AI
// process consumes it through the API. A row is the whole contract — who asked, about which
// attempt, under which data policy, by when it must be answered, and what the answer was.
// ---------------------------------------------------------------------------------------------

/// How long a request may stay unanswered. Its deadline is also the ceiling on its delegation, so
/// nothing a request minted outlives the request itself.
pub const REQUEST_LIFETIME_MS: i64 = 10 * 60 * 1000;
/// A delegation's own lifetime: the plan's ten minutes, shortened to the request's deadline.
pub const DELEGATION_MS: i64 = 10 * 60 * 1000;
/// How long a claim holds a row before the sweep may settle it as unavailable.
pub const CLAIM_LEASE_MS: i64 = 60 * 1000;
/// The answer's bound. A model's answer is advisory text; Y05 replaces it with a cited analysis.
pub const MAX_RESULT_BYTES: usize = 8 << 10;
/// The bound on a stated reason, which is a sentence, never a payload.
pub const MAX_REASON_BYTES: usize = 512;
/// The delegation credentials are named `ai-delegate:<request>`: an operator sees what they are.
const DELEGATION_NAME_PREFIX: &str = "ai-delegate:";

/// Where a request is in its life. It moves forward only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Queued = 1,
    Claimed = 2,
    Settled = 3,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            1 => Self::Queued,
            2 => Self::Claimed,
            3 => Self::Settled,
            _ => return None,
        })
    }
}

/// How a request ended. There is no third answer and no partial one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    Unavailable = 1,
    Completed = 2,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Completed => "completed",
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            1 => Self::Unavailable,
            2 => Self::Completed,
            _ => return None,
        })
    }
}

/// One durable request, as every reader of it sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: AiRequestId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub attempt: AttemptId,
    pub requester: UserId,
    pub provider: Provider,
    pub data_policy: DataPolicy,
    pub state: State,
    pub outcome: Option<Outcome>,
    pub reason: Option<String>,
    pub result: Option<String>,
    pub created: UnixMillis,
    pub deadline: UnixMillis,
}
const REQUEST_COLUMNS: &str = "id, tenant_id, repo_id, attempt_id, requester_id, provider,
     data_policy, state_code, outcome, reason, result, created_ms, deadline_ms";

/// One row's bytes, as the store holds them. Decoded once, outside the query closure.
type Raw = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    [u8; 16],
    [u8; 16],
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
    i64,
);

fn raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn decode(raw: Raw) -> Result<Request> {
    let (
        id,
        tenant,
        repo,
        attempt,
        requester,
        provider,
        policy,
        state,
        outcome,
        reason,
        result,
        created,
        deadline,
    ) = raw;
    Ok(Request {
        id: AiRequestId::from_bytes(id).map_err(|_| Error::Corrupt("ai_requests.id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        attempt: AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?,
        requester: UserId::from_bytes(requester).map_err(|_| Error::Corrupt("requester_id"))?,
        provider: Provider::ALL
            .get(usize::try_from(provider).unwrap_or(usize::MAX))
            .copied()
            .ok_or(Error::Corrupt("ai_requests.provider"))?,
        data_policy: DataPolicy::from_code(policy)
            .ok_or(Error::Corrupt("ai_requests.data_policy"))?,
        state: State::from_code(state).ok_or(Error::Corrupt("ai_requests.state_code"))?,
        outcome: match outcome {
            None => None,
            Some(code) => {
                Some(Outcome::from_code(code).ok_or(Error::Corrupt("ai_requests.outcome"))?)
            }
        },
        reason,
        result,
        created: UnixMillis(created),
        deadline: UnixMillis(deadline),
    })
}

/// One request by id, for the service that consumes it.
pub fn by_id(conn: &Connection, id: AiRequestId) -> Result<Request> {
    let raw = conn
        .prepare_cached(&format!(
            "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE id = ?1"
        ))?
        .query_row(params![id.as_bytes()], raw)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(raw)
}

/// One request by id within a tenant. A row of another tenant is simply not found, as everywhere
/// else in the store.
pub fn request(conn: &Connection, tenant: TenantId, id: AiRequestId) -> Result<Request> {
    let raw = conn
        .prepare_cached(&format!(
            "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE id = ?1 AND tenant_id = ?2"
        ))?
        .query_row(params![id.as_bytes(), tenant.as_bytes()], raw)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(raw)
}

/// A member's request about one attempt. It is refused unless the requester can read the
/// repository, the tenant's policy admits `provider` right now, and the requester holds every
/// read-only scope — which is what makes the delegation minted at claim time a subset of their
/// own set rather than a substitute for it.
#[allow(clippy::too_many_arguments)]
pub fn enqueue(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    repo: RepoId,
    attempt: AttemptId,
    provider: Provider,
    requester_scopes: Scopes,
    now: UnixMillis,
) -> Result<Request> {
    let principal = authority.principal().ok_or(Error::Forbidden)?;
    require_repo(tx, principal, repo, Permissions::READ)?;
    if !requester_scopes.contains(Scopes::READ_ONLY) {
        return Err(Error::Forbidden);
    }
    let data_policy = admit(tx, tenant, provider)?.ok_or(Error::Forbidden)?;
    let owned: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN jobs j ON j.id = a.job_id
                JOIN runs r ON r.id = j.run_id
              WHERE a.id = ?1 AND r.repo_id = ?2 AND r.tenant_id = ?3)",
        )?
        .query_row(
            params![attempt.as_bytes(), repo.as_bytes(), tenant.as_bytes()],
            |r| r.get(0),
        )?;
    if !owned {
        return Err(Error::NotFound);
    }
    let id = AiRequestId::new();
    let deadline = now.0.saturating_add(REQUEST_LIFETIME_MS);
    tx.prepare_cached(
        "INSERT INTO ai_requests(id, tenant_id, repo_id, attempt_id, requester_id,
            requester_scopes, provider, data_policy, created_ms, deadline_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?
    .execute(params![
        id.as_bytes(),
        tenant.as_bytes(),
        repo.as_bytes(),
        attempt.as_bytes(),
        principal.user.as_bytes(),
        requester_scopes.bits(),
        provider as u8,
        data_policy as u8,
        now.0,
        deadline
    ])?;
    Ok(Request {
        id,
        tenant,
        repo,
        attempt,
        requester: principal.user,
        provider,
        data_policy,
        state: State::Queued,
        outcome: None,
        reason: None,
        result: None,
        created: now,
        deadline: UnixMillis(deadline),
    })
}

/// The oldest queued requests: what the AI process consumes, one page at a time.
pub fn queued(conn: &Connection, limit: u32) -> Result<Vec<Request>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE state_code = 1
         ORDER BY created_ms, id LIMIT ?1"
    ))?;
    let mut rows = statement.query([i64::from(limit)])?;
    let mut found = Vec::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        found.push(decode(raw(row)?)?);
    }
    Ok(found)
}

/// A claim: the row's lease, and the delegation that reads its evidence.
pub struct Claimed {
    pub request: Request,
    /// The `api_tokens` row the delegation is; naming it is what binds the credential to the request.
    pub token: TokenId,
    pub access: Secret,
    pub expires: UnixMillis,
}

/// Claims one request for the AI process: `queued` becomes `claimed` in the same transaction that
/// mints the delegation, so a request is never claimed without the credential that reads it and
/// never read without a claim.
pub fn claim(tx: &Transaction<'_>, id: AiRequestId, now: UnixMillis) -> Result<Claimed> {
    let (bits, requester, repo, deadline, state, tenant) = tx
        .prepare_cached(
            "SELECT requester_scopes, requester_id, repo_id, deadline_ms, state_code, tenant_id
             FROM ai_requests WHERE id = ?1",
        )?
        .query_row(params![id.as_bytes()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, [u8; 16]>(5)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if State::from_code(state) != Some(State::Queued) || deadline <= now.0 {
        return Err(Error::Conflict);
    }
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let scopes =
        Scopes::from_bits(u32::try_from(bits).map_err(|_| Error::Corrupt("requester_scopes"))?)
            .ok_or(Error::Corrupt("requester_scopes"))?
            .intersect(Scopes::READ_ONLY);
    if scopes.is_empty() {
        return Err(Error::Forbidden);
    }
    let lifetime = DELEGATION_MS.min(deadline - now.0);
    let name = format!("{DELEGATION_NAME_PREFIX}{id}");
    let granted = crate::tokens::insert(
        tx,
        &crate::tokens::Grant {
            user: UserId::from_bytes(requester).map_err(|_| Error::Corrupt("requester_id"))?,
            name: &name,
            permissions: Permissions::READ,
            tenant: Some(tenant),
            repo: Some(RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?),
            lifetime_ms: lifetime,
        },
        now,
    )?;
    let lease = deadline.min(now.0.saturating_add(CLAIM_LEASE_MS));
    let claimed = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 2, claimed_ms = ?2, lease_until_ms = ?3,
                delegation_id = ?4
              WHERE id = ?1 AND state_code = 1",
        )?
        .execute(params![id.as_bytes(), now.0, lease, granted.id.as_bytes()])?;
    if claimed == 0 {
        // Lost to another claim between the read and the write: the delegation minted above has no
        // request to belong to, so it is revoked here rather than left to expire.
        tx.prepare_cached(
            "UPDATE api_tokens SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![granted.id.as_bytes(), now.0])?;
        return Err(Error::Conflict);
    }
    Ok(Claimed {
        request: by_id(tx, id)?,
        token: granted.id,
        access: granted.secret,
        expires: granted.expires,
    })
}

/// Settles a request exactly once: the answer, or the reason there is none. Its delegation is
/// revoked in the same transaction, so nothing survives a request that has ended.
pub fn settle(
    tx: &Transaction<'_>,
    id: AiRequestId,
    outcome: Outcome,
    text: Option<&str>,
    reason: Option<&str>,
    now: UnixMillis,
) -> Result<Request> {
    if text.is_some_and(|t| t.len() > MAX_RESULT_BYTES) {
        return Err(Error::InvalidInput("ai request result"));
    }
    if reason.is_some_and(|r| r.is_empty() || r.len() > MAX_REASON_BYTES) {
        return Err(Error::InvalidInput("ai request reason"));
    }
    let (outcome, text, reason) = match outcome {
        Outcome::Completed => (outcome, text, None),
        Outcome::Unavailable => (outcome, None, reason.or(Some("unavailable"))),
    };
    let settled = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 3, outcome = ?2, result = ?3, reason = ?4,
                settled_ms = ?5
              WHERE id = ?1 AND state_code != 3",
        )?
        .execute(params![id.as_bytes(), outcome as u8, text, reason, now.0])?;
    if settled == 0 {
        return Err(Error::Conflict);
    }
    tx.prepare_cached(
        "UPDATE api_tokens SET revoked_ms = ?1
          WHERE revoked_ms IS NULL AND id IN (
              SELECT delegation_id FROM ai_requests WHERE id = ?2 AND delegation_id IS NOT NULL)",
    )?
    .execute(params![now.0, id.as_bytes()])?;
    by_id(tx, id)
}

/// Whether `token` is the live delegation of the request about `attempt`: the check the evidence
/// route makes when the presented credential holds no `ai:context` grant. One index probe, and a
/// settled or expired request ends it.
pub fn delegates(
    conn: &Connection,
    token: TokenId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<bool> {
    let live: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM ai_requests
              WHERE delegation_id = ?1 AND attempt_id = ?2 AND state_code = 2
                AND settled_ms IS NULL AND deadline_ms > ?3)",
        )?
        .query_row(params![token.as_bytes(), attempt.as_bytes(), now.0], |r| {
            r.get(0)
        })?;
    Ok(live)
}

/// Settles every request past its deadline as `unavailable`, up to `limit`, and returns how many.
/// A provider outage, a disabled tenant and a killed AI process all end this way; nothing waits.
pub fn sweep(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<usize> {
    let swept = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 3, outcome = 1, reason = 'the request deadline passed',
                settled_ms = ?1, lease_until_ms = NULL
              WHERE id IN (SELECT id FROM ai_requests
                            WHERE state_code != 3 AND deadline_ms <= ?1
                            ORDER BY deadline_ms LIMIT ?2)",
        )?
        .execute(params![now.0, i64::from(limit)])?;
    if swept == 0 {
        return Ok(0);
    }
    tx.prepare_cached(
        "UPDATE api_tokens SET revoked_ms = ?1
          WHERE revoked_ms IS NULL AND id IN (
              SELECT delegation_id FROM ai_requests
               WHERE delegation_id IS NOT NULL AND state_code = 3 AND deadline_ms <= ?1)",
    )?
    .execute([now.0])?;
    Ok(swept)
}

/// A policy change's queue: queued requests naming a provider the allow-list no longer holds are
/// deleted, because they could never be admitted again. A claimed request keeps its lease and its
/// own deadline ends it.
fn drop_providers(tx: &Transaction<'_>, providers: Providers) -> Result<usize> {
    let mut allowed = Vec::with_capacity(Provider::ALL.len());
    for provider in providers.list() {
        allowed.push(provider as u8);
    }
    let mut kept = String::with_capacity(allowed.len() * 2);
    for (at, _) in allowed.iter().enumerate() {
        if at > 0 {
            kept.push(',');
        }
        kept.push('?');
    }
    let sql = if allowed.is_empty() {
        "DELETE FROM ai_requests WHERE state_code = 1".to_owned()
    } else {
        format!("DELETE FROM ai_requests WHERE state_code = 1 AND provider NOT IN ({kept})")
    };
    let deleted = tx
        .prepare_cached(&sql)?
        .execute(rusqlite::params_from_iter(allowed))?;
    Ok(deleted)
}

/// A disable's first act (Y01's promise, kept by Y03): every request of `tenant` is deleted, and
/// the delegations it minted are revoked, in the same transaction that turns its AI off. The whole
/// deployment's disable passes `None`.
pub fn drop_requests(
    tx: &Transaction<'_>,
    tenant: Option<TenantId>,
    now: UnixMillis,
) -> Result<usize> {
    let deleted = match tenant {
        Some(tenant) => {
            tx.prepare_cached(
                "UPDATE api_tokens SET revoked_ms = ?1
                  WHERE revoked_ms IS NULL AND id IN (
                      SELECT delegation_id FROM ai_requests
                       WHERE delegation_id IS NOT NULL AND tenant_id = ?2)",
            )?
            .execute(params![now.0, tenant.as_bytes()])?;
            tx.prepare_cached("DELETE FROM ai_requests WHERE tenant_id = ?1")?
                .execute(params![tenant.as_bytes()])?
        }
        None => {
            tx.prepare_cached(
                "UPDATE api_tokens SET revoked_ms = ?1
                  WHERE revoked_ms IS NULL AND id IN (
                      SELECT delegation_id FROM ai_requests WHERE delegation_id IS NOT NULL)",
            )?
            .execute([now.0])?;
            tx.prepare_cached("DELETE FROM ai_requests")?.execute([])?
        }
    };
    Ok(deleted)
}
